// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const posix = std.posix;
const protocol = @import("protocol.zig");
const args = @import("args.zig");
const platform = @import("platform/main.zig");

const eloop = if (builtin.os.tag == .linux)
    @import("eloop/linux.zig")
else if (builtin.os.tag.isBSD())
    @import("eloop/kqueue.zig")
else if (builtin.os.tag == .windows)
    @import("eloop/windows.zig")
else
    @compileError("unsupported OS");

const max_socket_path = 256;

const restart_hint = switch (builtin.os.tag) {
    .linux => "systemctl --user restart julia-daemon",
    .macos => "launchctl kickstart -k gui/$(id -u)/org.julialang.julia-daemon",
    .windows => "taskkill /F /IM julia-conductor.exe & schtasks /run /tn \"Julia\\JuliaDaemon\"",
    else => "pkill -f julia-conductor && julia-conductor &",
};

// --- Types ---

const SocketWriter = struct {
    buf: [8192]u8 = undefined,
    pos: usize = 0,
    handle: posix.socket_t,
    fn flush(self: *SocketWriter) void {
        if (self.pos > 0) {
            platform.socketWrite(self.handle, self.buf[0..self.pos]);
            self.pos = 0;
        }
    }
    fn writeInt(self: *SocketWriter, comptime T: type, val: T) void {
        if (self.pos + @sizeOf(T) > self.buf.len) self.flush();
        std.mem.writeInt(T, self.buf[self.pos..][0..@sizeOf(T)], val, .little);
        self.pos += @sizeOf(T);
    }
    fn writeSlice(self: *SocketWriter, data: []const u8) void {
        var remaining = data;
        while (remaining.len > 0) {
            if (self.pos == self.buf.len) self.flush();
            const n = @min(remaining.len, self.buf.len - self.pos);
            @memcpy(self.buf[self.pos..][0..n], remaining[0..n]);
            self.pos += n;
            remaining = remaining[n..];
        }
    }
    fn writeLenPrefixed(self: *SocketWriter, comptime T: type, data: []const u8) void {
        self.writeInt(T, @intCast(data.len));
        self.writeSlice(data);
    }
};

const SocketSet = struct {
    stdin: posix.socket_t,
    stdout: posix.socket_t,
    stderr: posix.socket_t,
    signals: posix.socket_t,
};

const EnvInfo = struct {
    fingerprint: u64,
    count: u16,
    server_path: ?[]const u8,
    runtime_dir: ?[]const u8,
    xdg_runtime_dir: ?[]const u8,
    home: ?[]const u8,
};

/// UTF-8, whatever the OS hands over.
const Inputs = struct { args: []const []const u8, env: []const []const u8 };

// <id:u8><len:u8><data>, possibly fragmented across reads.
const SignalParser = struct {
    buf: [256]u8 = undefined,
    len: usize = 0,
    sync_mode: bool = false,
    worker_wants_raw: bool = false,
    const header_size = 2;

    pub const Result = union(enum) {
        none,
        exit: u8,
    };

    pub fn feed(self: *@This(), input: []const u8, fd: posix.socket_t) Result {
        if (self.len + input.len > self.buf.len) {
            platform.eprint("[client] signal buffer overflow\n", .{});
            self.len = 0;
            return .none;
        }
        @memcpy(self.buf[self.len..][0..input.len], input);
        self.len += input.len;
        return self.process(fd);
    }

    fn process(self: *@This(), fd: posix.socket_t) Result {
        var result: Result = .none;
        var pos: usize = 0;
        while (pos + header_size <= self.len) {
            const id = self.buf[pos];
            const data_len: usize = self.buf[pos + 1];
            const total_len = header_size + data_len;
            if (pos + total_len > self.len) break;
            const signal = self.dispatch(id, self.buf[pos + header_size .. pos + total_len], fd);
            if (result != .exit) result = signal; // exit is terminal
            pos += total_len;
        }
        if (pos > 0) {
            const remaining = self.len - pos;
            if (remaining > 0) {
                std.mem.copyForwards(u8, self.buf[0..remaining], self.buf[pos..self.len]);
            }
            self.len = remaining;
        }
        return result;
    }

    fn dispatch(self: *@This(), id: u8, data: []const u8, fd: posix.socket_t) Result {
        return switch (id) {
            protocol.signals.exit => .{ .exit = if (data.len >= 1) data[0] else 1 },
            protocol.signals.raw_mode => blk: {
                if (data.len == 1) {
                    platform.setWorkerRawMode(data[0] != 0);
                    if (self.sync_mode) {
                        // Sync mode stays raw, emulating cooked input itself.
                        self.worker_wants_raw = data[0] != 0;
                    } else {
                        platform.setRawMode(data[0] != 0);
                    }
                }
                platform.socketWrite(fd, &[_]u8{ id, 0 }); // ack
                break :blk .none;
            },
            protocol.signals.executing => blk: {
                // No ack: a stray one would be taken for the next raw_mode ack.
                if (data.len == 1) platform.setWorkerExecuting(data[0] != 0);
                break :blk .none;
            },
            protocol.signals.query_size => blk: {
                const size = getTerminalSize();
                var resp: [6]u8 = undefined;
                resp[0] = id;
                resp[1] = 4;
                std.mem.writeInt(u16, resp[2..4], size.height, .little);
                std.mem.writeInt(u16, resp[4..6], size.width, .little);
                platform.socketWrite(fd, &resp);
                break :blk .none;
            },
            protocol.signals.nodelay => blk: {
                platform.setTcpNodelay(sockets.stdin);
                platform.setTcpNodelay(fd);
                break :blk .none;
            },
            else => .none,
        };
    }
};

// --- Globals ---

// Globals, as a signal handler can't capture state.
var sockets: SocketSet = undefined;
var conductor_path_buf: [max_socket_path]u8 = undefined;
var conductor_path: []const u8 = &.{};
var transport_mode: protocol.TransportMode = .local;
// Kept because a signal handler cannot resolve the conductor's name again.
var conductor_peer: ?Io.net.IpAddress = null;
var signal_parser = SignalParser{};
var client_id: u32 = 0; // conductor-assigned

// --- Signal handler wiring ---

fn signalWriteStdin(ptr: *anyopaque, data: []const u8) void {
    const sock_set: *SocketSet = @ptrCast(@alignCast(ptr));
    platform.socketWrite(sock_set.stdin, data);
}

fn signalNotifyExit() void {
    notifyConductor(.client_exit);
    platform.setRawMode(false);
}

fn signalNotifyInterrupt() void {
    notifyConductor(.client_interrupt);
}

fn registerSignalHandlers() void {
    platform.registerSignalHandlers(.{
        .sockets_ptr = @ptrCast(&sockets),
        .write_fn = &signalWriteStdin,
        .notify_exit_fn = &signalNotifyExit,
        .notify_interrupt_fn = &signalNotifyInterrupt,
    });
}

// --- Main pipeline ---

// The segfault handler's stack traces need debug info a release lacks, and
// its signal stack is 256 KiB.
pub const std_options: std.Options = .{ .enable_segfault_handler = false, .signal_stack_size = null };

// std's default handler reaches the same stderr lock.
pub const panic = std.debug.FullPanic(struct {
    fn report(msg: []const u8, _: ?usize) noreturn {
        platform.eprint("panic: {s}\n", .{msg});
        exitClient(134);
    }
}.report);

// An error returned from main is reported through std's stderr lock, which
// links all of Io.Threaded (~110 KB); report it here instead.
pub fn main(init: std.process.Init.Minimal) void {
    run(init) catch |err| {
        platform.eprint("error: {s}\n", .{@errorName(err)});
        exitClient(1);
    };
}

fn run(init: std.process.Init.Minimal) !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const inputs = try collectInputs(arena.allocator(), init);
    var env = scanEnv(inputs.env);
    const parsed = try args.parse(arena.allocator(), inputs.args);
    if (parsed.getSwitch("--address")) |addr| if (addr.len > 0) {
        env.server_path = addr;
    };
    if (parsed.hasSwitch("--help") or parsed.hasSwitch("-h")) {
        platform.writeFile(platform.getStdoutHandle(), protocol.CLIENT_HELP);
        return;
    }
    if (parsed.hasSwitch("--version") or parsed.hasSwitch("-v")) {
        printVersion(env);
        return;
    }
    const sync = parsed.hasSwitch("--sync");
    const is_tty = platform.isatty(platform.getStdinHandle());
    const console = if (is_tty) platform.setupConsoleIo(platform.getStdoutHandle(), platform.getStderrHandle()) else null;
    defer platform.restoreConsoleIo(console);
    if (is_tty) platform.setRawMode(true);
    defer platform.setRawMode(false);
    const conductor = try connectToConductor(env);
    if (transport_mode == .tcp) platform.setTcpNodelay(conductor);
    defer notifyConductor(.client_exit);
    var w = SocketWriter{ .handle = conductor };
    // The worker's own terminal knows nothing of ours.
    const color = is_tty and !hasNoColor(inputs.env);
    try sendClientInfo(&w, env, is_tty, color, try forwardedArgs(arena.allocator(), inputs.args, &parsed));
    sockets = try connectToWorker(conductor, &w, env, inputs.env);
    registerSignalHandlers();
    signal_parser.sync_mode = sync;
    try runEventLoop(sync);
}

fn collectInputs(a: std.mem.Allocator, init: std.process.Init.Minimal) !Inputs {
    var it = try std.process.Args.Iterator.initAllocator(init.args, a);
    var argv: std.ArrayList([]const u8) = .empty;
    while (it.next()) |arg| try argv.append(a, arg);
    return .{ .args = argv.items, .env = try platform.collectEnviron(a, init.environ) };
}

fn hasNoColor(env: []const []const u8) bool {
    for (env) |kv| if (std.mem.startsWith(u8, kv, "NO_COLOR=") and kv.len > "NO_COLOR=".len) return true;
    return false;
}

fn scanEnv(kvs: []const []const u8) EnvInfo {
    var info = EnvInfo{ .fingerprint = 0, .count = 0, .server_path = null, .runtime_dir = null, .xdg_runtime_dir = null, .home = null };
    const env_vars = .{
        .{ "JULIA_DAEMON_SERVER=", "server_path" },
        .{ "JULIA_DAEMON_RUNTIME=", "runtime_dir" },
        .{ "XDG_RUNTIME_DIR=", "xdg_runtime_dir" },
        .{ "HOME=", "home" },
    };
    for (kvs) |kv| {
        if (std.mem.startsWith(u8, kv, "HYPERFINE_")) continue; // varies per benchmark run
        info.count += 1;
        // XOR, so the fingerprint ignores order.
        var h = std.hash.Wyhash.init(kv.len);
        h.update(kv);
        info.fingerprint ^= h.final();
        inline for (env_vars) |ev| {
            if (std.mem.startsWith(u8, kv, ev[0])) {
                @field(info, ev[1]) = kv[ev[0].len..];
            }
        }
    }
    return info;
}

fn locateConductor(env: EnvInfo, runtime_dir_buf: *[max_socket_path]u8) !struct { runtime_dir: []const u8, address: protocol.Address } {
    const runtime_dir = env.runtime_dir orelse
        try platform.defaultRuntimeDir(runtime_dir_buf, env.xdg_runtime_dir, env.home);
    var socket_dir_buf: [max_socket_path]u8 = undefined;
    const socket_dir = try platform.localSocketDir(&socket_dir_buf, runtime_dir);
    const raw_path = env.server_path orelse
        try platform.localSocketPath(&conductor_path_buf, socket_dir, "conductor.sock", .{});
    return .{ .runtime_dir = runtime_dir, .address = try protocol.parseAddress(raw_path) };
}

fn connectToConductor(env: EnvInfo) !posix.socket_t {
    var runtime_dir_buf: [max_socket_path]u8 = undefined;
    const located = locateConductor(env, &runtime_dir_buf) catch |err| switch (err) {
        error.UnsupportedScheme => {
            platform.eprint("Unsupported address scheme: {s}\nOnly tcp:// and local socket paths are supported.\n", .{env.server_path orelse ""});
            exitClient(1);
        },
        else => return err,
    };
    const runtime_dir = located.runtime_dir;
    transport_mode = located.address.mode;
    conductor_path = located.address.addr;
    const addr = conductor_path;
    const timeout = protocol.connect_timeout_ms;
    const first_err = if (protocol.connectAddress(transport_mode, addr, timeout)) |c| return keepConductor(c) else |err| err;
    // A refusal may be a conductor restarting, and a live conductor can be asked
    // to recreate a missing socket; a timeout is not worth repeating.
    const worth_retrying = switch (transport_mode) {
        .tcp => first_err == error.ConnectionRefused,
        .local => blk: {
            var pid_buf: [max_socket_path]u8 = undefined;
            break :blk platform.requestSocketRecreate(std.fmt.bufPrint(&pid_buf, "{s}/conductor.pid", .{runtime_dir}) catch return error.NameTooLong);
        },
    };
    if (worth_retrying) {
        for (0..20) |_| {
            platform.sleepMs(100);
            if (protocol.connectAddress(transport_mode, addr, timeout)) |c| return keepConductor(c) else |_| {}
        }
        // Alive with no local socket: it may be listening on TCP.
        if (transport_mode == .local) {
            const tcp_addr = std.fmt.comptimePrint("localhost:{d}", .{protocol.default_tcp_port});
            if (protocol.connectAddress(.tcp, tcp_addr, timeout)) |c| {
                transport_mode = .tcp;
                conductor_path = tcp_addr;
                return keepConductor(c);
            } else |_| {}
        }
    }
    if (first_err == error.UnknownHostName) {
        platform.eprint("Cannot resolve the host in {s}.\n", .{addr});
        exitClient(127);
    }
    platform.eprint(
        \\Failed to connect to {s}
        \\
        \\Try restarting the daemon:
        \\
        \\  {s}
        \\
        \\Or specify a different address with -a <addr>
        \\
    , .{ addr, restart_hint });
    exitClient(127);
}

fn printVersion(env: EnvInfo) void {
    const plain = "juliaclient " ++ protocol.VERSION;
    var runtime_dir_buf: [max_socket_path]u8 = undefined;
    const address: ?protocol.Address = if (locateConductor(env, &runtime_dir_buf)) |located|
        (if (protocol.probeAddress(located.address.mode, located.address.addr, 1000)) located.address else null)
    else |_| null;
    var line_buf: [2 * max_socket_path]u8 = undefined;
    const line = if (address) |a| std.fmt.bufPrint(&line_buf, plain ++ ", connected to conductor over {s} {s}\n", .{
        if (a.mode == .tcp) "TCP" else platform.local_transport_name, a.addr,
    }) catch plain ++ "\n" else plain ++ ", no conductor detected\n";
    platform.writeFile(platform.getStdoutHandle(), line);
}

fn keepConductor(connection: protocol.Connection) posix.socket_t {
    conductor_peer = connection.peer;
    return connection.socket;
}

fn sendClientInfo(w: *SocketWriter, env: EnvInfo, is_tty: bool, color: bool, forwarded: []const []const u8) !void {
    w.writeInt(u32, protocol.client.magic);
    w.writeInt(u8, @bitCast(protocol.client.Flags{ .tty = is_tty, .color = color }));
    w.writeSlice(&.{ 0, 0, 0 });
    w.writeInt(u32, @intCast(platform.getpid()));
    w.writeInt(u32, @intCast(platform.getppid()));
    // CWD, read straight into the buffer behind its length
    if (w.pos + 2 >= w.buf.len) w.flush();
    const len_pos = w.pos;
    w.pos += 2;
    const cwd_len = (try platform.currentDir(w.buf[w.pos..])).len;
    std.mem.writeInt(u16, w.buf[len_pos..][0..2], @intCast(cwd_len), .little);
    w.pos += cwd_len;
    w.writeInt(u64, env.fingerprint);
    w.writeInt(u16, @intCast(forwarded.len));
    for (forwarded) |arg| w.writeLenPrefixed(u16, arg);
    w.flush();
}

fn connectToWorker(conductor: posix.socket_t, w: *SocketWriter, env: EnvInfo, kvs: []const []const u8) !SocketSet {
    const reader = protocol.BufReader{ .fd = conductor };
    while (true) switch (reader.readInt(u8) catch |err| replyFailure(err)) {
        protocol.client.env_request => sendFullEnv(w, env, kvs),
        protocol.client.spawn_request => try spawnWorker(reader, kvs),
        protocol.client.socket_paths => break,
        else => replyFailure(error.BadReply),
    };
    client_id = try reader.readInt(u32);
    var paths: [4 * (max_socket_path + 1)]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&paths);
    const stdin_path = try takeString(reader, fba.allocator());
    const stdout_path = try takeString(reader, fba.allocator());
    const stderr_path = try takeString(reader, fba.allocator());
    const signals_path = try takeString(reader, fba.allocator());
    platform.close(conductor);
    const result = SocketSet{
        .stdin = connectToWorkerSocket(stdin_path, "stdin"),
        .stdout = connectToWorkerSocket(stdout_path, "stdout"),
        .stderr = connectToWorkerSocket(stderr_path, "stderr"),
        .signals = connectToWorkerSocket(signals_path, "signals"),
    };
    if (transport_mode == .tcp) platform.setTcpNodelay(result.signals);
    return result;
}

// A daemon that recognises a protocol mismatch says so; an older one just closes.
fn replyFailure(err: anyerror) noreturn {
    platform.eprint(
        \\The daemon did not reply as expected ({s}).
        \\It is probably running a different protocol version than this juliaclient:
        \\restart it after installing, or rebuild juliaclient to match.
        \\
        \\  {s}
        \\
    , .{ @errorName(err), restart_hint });
    exitClient(127);
}

/// In this client's mount namespace, which the conductor cannot see into.
fn spawnWorker(reader: protocol.BufReader, kvs: []const []const u8) !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const argc = try reader.readInt(u16);
    if (argc == 0) return error.BadSpawnRequest;
    const argv = try a.alloc(?[*:0]const u8, argc + 1);
    for (argv[0..argc]) |*arg| arg.* = (try takeString(reader, a)).ptr;
    argv[argc] = null;
    // The daemon's own settings go first, so they shadow ours for the worker.
    const envc = try reader.readInt(u16);
    const envp = try a.alloc(?[*:0]const u8, envc + kvs.len + 1);
    for (envp[0..envc]) |*entry| entry.* = (try takeString(reader, a)).ptr;
    for (kvs, envp[envc .. envc + kvs.len]) |kv, *entry| entry.* = (try a.dupeZ(u8, kv)).ptr;
    envp[envc + kvs.len] = null;
    platform.spawnDetached(@ptrCast(argv.ptr), @ptrCast(envp.ptr)) catch |err| {
        platform.eprint("Cannot start a Julia worker inside this sandbox: {s} ({s}).\n", .{
            std.mem.span(argv[0].?), @errorName(err),
        });
        if (err == error.ExecutableNotFound) platform.eprint(
            \\A sandboxed client runs its own worker, so the sandbox must also see the Julia install,
            \\the DaemonWorker project and the Julia depot (~/.julia or JULIA_DEPOT_PATH).
            \\
        , .{});
        exitClient(127);
    };
}

fn takeString(reader: protocol.BufReader, a: std.mem.Allocator) ![:0]u8 {
    const len = try reader.readInt(u16);
    const s = try a.allocSentinel(u8, len, 0);
    try reader.readSlice(s);
    return s;
}

fn sendFullEnv(w: *SocketWriter, env: EnvInfo, kvs: []const []const u8) void {
    w.writeInt(u16, env.count);
    for (kvs) |kv| {
        if (std.mem.startsWith(u8, kv, "HYPERFINE_")) continue;
        const eq = std.mem.indexOfScalar(u8, kv, '=') orelse continue;
        w.writeLenPrefixed(u16, kv[0..eq]);
        w.writeLenPrefixed(u16, kv[eq + 1 ..]);
    }
    w.flush();
}

fn runEventLoop(sync_mode: bool) !void {
    const exit_code = try eloop.run(sockets.stdin, sockets.stdout, sockets.stderr, sockets.signals, &signal_parser, sync_mode);
    notifyConductor(.client_exit);
    exitClient(exit_code);
}

// --- Helpers ---

// std.process.exit skips main's defer, which restores cooked mode.
fn exitClient(code: u8) noreturn {
    platform.setRawMode(false);
    std.process.exit(code);
}

fn connectToWorkerSocket(raw: []const u8, comptime label: []const u8) posix.socket_t {
    const connected = if (raw.len > 0 and raw[0] == ':') blk: {
        // A worker sends just `:port`, a port on the conductor's host.
        var ip = conductor_peer orelse break :blk error.NoConductorAddress;
        ip.setPort(std.fmt.parseInt(u16, raw[1..], 10) catch break :blk error.InvalidAddress);
        break :blk platform.connectTcp(ip, protocol.connect_timeout_ms);
    } else switch ((protocol.parseAddress(raw) catch unreachable).mode) {
        .local => platform.connectLocalOnce(raw),
        .tcp => if (protocol.connectAddress(.tcp, raw, protocol.connect_timeout_ms)) |c| c.socket else |e| e,
    };
    return connected catch |e| {
        platform.eprint("Client: failed to connect to " ++ label ++ ": {s}: {}\n", .{ raw, e });
        exitClient(127);
    };
}

/// Dials the conductor already reached, never resolving a name again, as
/// this also runs in signal handlers. Errors are dropped.
fn notifyConductor(kind: protocol.notification.Type) void {
    var buf: [9]u8 = undefined;
    std.mem.writeInt(u32, buf[0..4], protocol.notification.magic, .little);
    buf[4] = @intFromEnum(kind);
    std.mem.writeInt(u32, buf[5..9], client_id, .little);
    const fd = switch (transport_mode) {
        .local => platform.connectLocal(conductor_path, protocol.connect_timeout_ms),
        .tcp => platform.connectTcp(conductor_peer orelse return, protocol.connect_timeout_ms),
    } catch return;
    defer platform.close(fd);
    platform.socketWrite(fd, &buf);
}

fn getTerminalSize() struct { height: u16, width: u16 } {
    // The worker's REPL divides by the column count, so never send a 0.
    // Only an output handle answers on Windows.
    const size = platform.getTerminalSize(platform.getStdinHandle()) orelse platform.getTerminalSize(platform.getStdoutHandle());
    if (size) |sz| if (sz.rows != 0 and sz.cols != 0)
        return .{ .height = sz.rows, .width = sz.cols };
    return .{ .height = 24, .width = 80 };
}

/// argv less the client's own `--address`.
fn forwardedArgs(allocator: std.mem.Allocator, argv: []const []const u8, parsed: *const args.ParsedArgs) ![]const []const u8 {
    const keep = try allocator.alloc(bool, argv.len);
    @memset(keep, true);
    for (parsed.switches.items) |sw| if (std.mem.eql(u8, sw.name, "--address")) {
        @memset(keep[sw.index..][0..sw.words], false);
    };
    var forwarded: std.ArrayList([]const u8) = .empty;
    for (argv, keep) |arg, kept| if (kept) try forwarded.append(allocator, arg);
    return forwarded.items;
}
