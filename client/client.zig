// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const posix = std.posix;
const protocol = @import("protocol.zig");
const args = @import("args.zig");
const platform = @import("platform/main.zig");
const debuglog = @import("debuglog.zig");

const eloop = switch (builtin.target.os.tag) {
    .linux => @import("eloop/linux.zig"),
    .macos, .freebsd, .openbsd, .netbsd, .dragonfly => @import("eloop/kqueue.zig"),
    .windows => @import("eloop/windows.zig"),
    else => @compileError("unsupported OS"),
};

const max_socket_path = protocol.max_socket_path;

const restart_hint = switch (builtin.target.os.tag) {
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
    count: u32,
    server_path: ?[]const u8,
    runtime_dir: ?[]const u8,
    xdg_runtime_dir: ?[]const u8,
    home: ?[]const u8,
};

// <id:u8><len:u8><data>, possibly fragmented across reads.
const SignalParser = struct {
    // Holds a whole frame beside a part: each pass takes some of a read.
    buf: [2 * (header_size + 255)]u8 = undefined,
    len: usize = 0,
    sync_mode: bool = false,
    worker_wants_raw: bool = false,
    const header_size = 2;

    pub const Result = union(enum) {
        none,
        exit: u8,
    };

    pub fn feed(self: *@This(), input: []const u8, fd: posix.socket_t) Result {
        var result: Result = .none;
        var rest = input;
        while (rest.len > 0) {
            const n = @min(rest.len, self.buf.len - self.len);
            @memcpy(self.buf[self.len..][0..n], rest[0..n]);
            self.len += n;
            rest = rest[n..];
            const signal = self.process(fd);
            if (result != .exit) result = signal; // exit is terminal
        }
        return result;
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
                @memmove(self.buf[0..remaining], self.buf[pos..self.len]);
            }
            self.len = remaining;
        }
        return result;
    }

    fn dispatch(self: *@This(), id: u8, data: []const u8, fd: posix.socket_t) Result {
        debuglog.event("signal: {s} {f}", .{ switch (id) {
            protocol.signals.exit => "exit",
            protocol.signals.raw_mode => "raw_mode",
            protocol.signals.size => "size",
            protocol.signals.nodelay => "nodelay",
            protocol.signals.executing => "executing",
            protocol.signals.suspend_client => "suspend",
            else => "unknown",
        }, debuglog.preview(data) });
        return switch (id) {
            protocol.signals.exit => .{ .exit = if (data.len >= 1) data[0] else 1 },
            protocol.signals.raw_mode => blk: {
                // Ahead of the ack, so the worker has it as the switch is done:
                // a console reports a resize only while raw.
                reportResize();
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
                if (data.len >= 1) platform.setWorkerExecuting(data[0] != 0);
                if (data.len == 5) evaluation = std.mem.readInt(u32, data[1..5], .little);
                break :blk .none;
            },
            protocol.signals.suspend_client => blk: {
                platform.suspendSelf();
                platform.socketWrite(fd, &[_]u8{ id, 0 }); // ack
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
var watching = false;
// A view the conductor draws, whose farewell a full socket can hold back.
var viewing = false;
// Kept because a signal handler cannot resolve the conductor's name again.
var conductor_peer: ?Io.net.IpAddress = null;
var signal_parser = SignalParser{};
var client_id: u32 = 0; // conductor-assigned
var terminal_size: protocol.TerminalSize = .{}; // as the worker was last told
var client_key: u64 = 0; // with it, which proves it ours

// --- Signal handler wiring ---

fn signalWriteStdin(ptr: *anyopaque, data: []const u8) void {
    const sock_set: *SocketSet = @ptrCast(@alignCast(ptr));
    platform.socketWrite(sock_set.stdin, data);
}

/// The terminal's size, if it has changed since the worker was last told it.
fn reportResize() void {
    const size = terminalSize();
    if (std.meta.eql(size, terminal_size)) return;
    terminal_size = size;
    platform.socketWrite(sockets.signals, &size.frame());
    debuglog.event("signal: sent size {d}x{d}", .{ size.rows, size.cols });
}

fn signalNotifyExit() void {
    notifyConductor(.client_exit);
    platform.setRawMode(false);
}

fn signalNotifyInterrupt() void {
    notifyConductor(.client_interrupt);
}

fn signalGiveUp() void {
    exitClient(130);
}

// A watcher's Ctrl-C must not reach the session it watches.
fn signalStopWatching() void {
    notifyConductor(.client_exit);
    exitClient(130);
}

/// `on_resize` once the worker's sockets are open.
fn registerSignalHandlers(on_interrupt: *const fn () void, on_resize: ?*const fn () void) void {
    platform.registerSignalHandlers(.{
        .sockets_ptr = @ptrCast(&sockets),
        .write_fn = &signalWriteStdin,
        .notify_exit_fn = &signalNotifyExit,
        .notify_interrupt_fn = on_interrupt,
        .notify_resize_fn = on_resize,
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
    platform.openClosedStdio();
    const inputs = try platform.processInputs(init);
    debuglog.init(inputs.env);
    var env = scanEnv(inputs.env);
    // What Julia would refuse, the conductor refuses.
    const parsed = args.read([*:0]const u8, inputs.args);
    if (parsed.getSwitch("--address")) |addr| if (addr.len > 0) {
        env.server_path = addr;
    };
    if (parsed.hasSwitch("--help")) {
        platform.writeFile(platform.getStdoutHandle(), protocol.CLIENT_HELP);
        return;
    }
    if (parsed.hasSwitch("--help-hidden")) {
        platform.writeFile(platform.getStdoutHandle(), protocol.CLIENT_HELP_HIDDEN);
        return;
    }
    if (parsed.hasSwitch("--version")) {
        printVersion(env);
        return;
    }
    var switches = parsed.switches();
    while (switches.next()) |sw| if (!sw.isHonoured()) {
        const words = inputs.args[sw.index..][0..sw.words];
        platform.eprint("juliaclient: ignoring {s}{s}{s}, which only applies as Julia starts (set it for every worker in JULIA_DAEMON_WORKER_ARGS)\n", .{
            words[0], if (words.len > 1) " " else "", if (words.len > 1) words[1] else "",
        });
    };
    const sync = parsed.hasSwitch("--sync");
    watching = parsed.hasSwitch("--watch");
    viewing = (parsed.hasSwitch("--status") or parsed.hasSwitch("--reconfigure")) and platform.isatty(platform.getStdoutHandle());
    const is_tty = platform.isatty(platform.getStdinHandle());
    const console = if (is_tty) platform.setupConsoleIo(platform.getStdoutHandle(), platform.getStderrHandle()) else null;
    defer platform.restoreConsoleIo(console);
    defer platform.setRawMode(false);
    // Until a worker is reached, a Ctrl-C gives up, as Julia's does starting.
    registerSignalHandlers(&signalGiveUp, null);
    const conductor = try connectToConductor(env);
    debuglog.event("conductor: connected over {s} to {s}", .{ @tagName(transport_mode), conductor_path });
    if (transport_mode == .tcp) platform.setTcpNodelay(conductor);
    defer notifyConductor(.client_exit);
    var w = SocketWriter{ .handle = conductor };
    // The worker's own terminal knows nothing of ours. Colour follows where
    // output goes, as Julia's does.
    const color = colorWanted(inputs.env) orelse platform.isatty(platform.getStdoutHandle());
    terminal_size = terminalSize();
    try sendClientInfo(&w, env, is_tty, color, inputs.args);
    debuglog.event("conductor: request sent", .{});
    sockets = try connectToWorker(conductor, &w, env, inputs.env);
    registerSignalHandlers(if (watching) &signalStopWatching else &signalNotifyInterrupt, &reportResize);
    reportResize(); // since the request
    signal_parser.sync_mode = sync;
    // Cooked, as Julia's terminal is, until a REPL asks for raw; a --sync
    // client's and a view's are raw throughout.
    if (is_tty and (sync or viewing)) platform.setRawMode(true);
    try runEventLoop(sync);
}

/// As Julia's `FORCE_COLOR`, over `NO_COLOR`; null for neither.
fn colorWanted(env: []const [*:0]const u8) ?bool {
    var wanted: ?bool = null;
    for (env) |kv_z| {
        const kv = std.mem.span(kv_z);
        if (std.mem.startsWith(u8, kv, "FORCE_COLOR=") and kv.len > "FORCE_COLOR=".len) return true;
        if (std.mem.startsWith(u8, kv, "NO_COLOR=") and kv.len > "NO_COLOR=".len) wanted = false;
    }
    return wanted;
}

fn scanEnv(kvs: []const [*:0]const u8) EnvInfo {
    var info = EnvInfo{ .fingerprint = 0, .count = 0, .server_path = null, .runtime_dir = null, .xdg_runtime_dir = null, .home = null };
    const env_vars = .{
        .{ "JULIA_DAEMON_SERVER=", "server_path" },
        .{ "JULIA_DAEMON_RUNTIME=", "runtime_dir" },
        .{ "XDG_RUNTIME_DIR=", "xdg_runtime_dir" },
        .{ "HOME=", "home" },
    };
    for (kvs) |kv_z| {
        const kv = std.mem.span(kv_z);
        if (std.mem.startsWith(u8, kv, "HYPERFINE_")) continue; // varies per benchmark run
        // Only a variable is sent, so only one is counted.
        if (std.mem.findScalar(u8, kv, '=') == null) continue;
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

const Located = struct { runtime_dir: []const u8, address: protocol.Address };

fn locateConductor(env: EnvInfo, runtime_dir_buf: *[max_socket_path]u8) !Located {
    const runtime_dir = env.runtime_dir orelse
        try platform.defaultRuntimeDir(runtime_dir_buf, env.xdg_runtime_dir, env.home);
    var socket_dir_buf: [max_socket_path]u8 = undefined;
    const socket_dir = try platform.localSocketDir(&socket_dir_buf, runtime_dir);
    const raw_path = env.server_path orelse
        try platform.localSocketPath(&conductor_path_buf, socket_dir, "conductor.sock", .{});
    return .{ .runtime_dir = runtime_dir, .address = try protocol.parseAddress(raw_path) };
}

var held_port_addr_buf: [16]u8 = undefined;

/// Dials the conductor once: at its address, or given none, once the socket
/// fails, at the port a live conductor over TCP holds in the runtime dir;
/// `transport_mode` and `conductor_path` then say which.
fn dialConductor(env: EnvInfo, located: Located, timeout_ms: u32) !protocol.Connection {
    transport_mode = located.address.mode;
    conductor_path = located.address.addr;
    const err = if (protocol.connectAddress(transport_mode, conductor_path, timeout_ms)) |c| return c else |e| e;
    if (env.server_path != null) return err;
    platform.secureRuntimeDir(located.runtime_dir) catch return err;
    var path_buf: [max_socket_path + 16]u8 = undefined;
    const path = std.mem.print(&path_buf, "{s}/" ++ protocol.client.port_file, .{located.runtime_dir}) catch return err;
    var port_buf: [5]u8 = undefined;
    const port = platform.readSmallFile(path, &port_buf, true) orelse return err;
    transport_mode = .tcp;
    conductor_path = std.mem.print(&held_port_addr_buf, "127.0.0.1:{s}", .{port}) catch unreachable;
    return protocol.connectAddress(.tcp, conductor_path, timeout_ms);
}

/// Over TCP, what shows this client the host's rather than a sandbox's.
var host_key = std.mem.zeroes(protocol.client.HostKey);

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
    if (located.address.mode == .local) platform.secureRuntimeDir(runtime_dir) catch exitClient(1);
    const timeout = protocol.connect_timeout_ms;
    const first_err = if (dialConductor(env, located, timeout)) |c| return keepConductor(c, runtime_dir) else |err| err;
    // A refusal may be a conductor restarting, and a live conductor can be asked
    // to recreate a missing socket; a timeout is not worth repeating.
    const worth_retrying = switch (transport_mode) {
        .tcp => first_err == error.ConnectionRefused,
        .local => blk: {
            var pid_buf: [max_socket_path]u8 = undefined;
            break :blk platform.requestSocketRecreate(std.mem.print(&pid_buf, "{s}/conductor.pid", .{runtime_dir}) catch return error.NameTooLong);
        },
    };
    if (worth_retrying) {
        for (0..20) |_| {
            platform.sleepMs(100);
            if (dialConductor(env, located, timeout)) |c| return keepConductor(c, runtime_dir) else |_| {}
        }
    }
    if (first_err == error.UnknownHostName) {
        platform.eprint("Cannot resolve the host in {s}.\n", .{conductor_path});
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
    , .{ conductor_path, restart_hint });
    exitClient(127);
}

fn printVersion(env: EnvInfo) void {
    const plain = "juliaclient " ++ protocol.VERSION;
    var runtime_dir_buf: [max_socket_path]u8 = undefined;
    const reached = if (locateConductor(env, &runtime_dir_buf)) |located| blk: {
        const connection = dialConductor(env, located, 1000) catch break :blk false;
        platform.close(connection.socket);
        break :blk true;
    } else |_| false;
    var line_buf: [2 * max_socket_path]u8 = undefined;
    const line = if (reached) std.mem.print(&line_buf, plain ++ ", connected to conductor over {s} {s}\n", .{
        if (transport_mode == .tcp) "TCP" else platform.local_transport_name, conductor_path,
    }) catch plain ++ "\n" else plain ++ ", no conductor detected\n";
    platform.writeFile(platform.getStdoutHandle(), line);
}

/// The host key goes only to a conductor dialled on loopback, never off the host.
fn keepConductor(connection: protocol.Connection, runtime_dir: []const u8) posix.socket_t {
    conductor_peer = connection.peer;
    if (connection.peer) |ip| if (protocol.isLoopback(ip)) {
        var path_buf: [max_socket_path + 16]u8 = undefined;
        const path = std.mem.print(&path_buf, "{s}/" ++ protocol.client.host_key_file, .{runtime_dir}) catch "";
        if (platform.readSmallFile(path, &host_key, false)) |read| {
            if (read.len != host_key.len) host_key = std.mem.zeroes(protocol.client.HostKey);
        }
    };
    return connection.socket;
}

fn sendClientInfo(w: *SocketWriter, env: EnvInfo, is_tty: bool, color: bool, forwarded: []const [*:0]const u8) !void {
    w.writeInt(u32, protocol.client.magic);
    w.writeInt(u8, @bitCast(protocol.client.Flags{ .tty = is_tty, .color = color }));
    w.writeSlice(&.{ 0, 0, 0 });
    w.writeInt(u32, @intCast(platform.getpid()));
    w.writeInt(u32, @intCast(platform.getppid()));
    w.writeSlice(&host_key);
    w.writeSlice(&terminal_size.encode());
    // CWD, read straight into the buffer behind its length
    if (w.pos + 4 >= w.buf.len) w.flush();
    const len_pos = w.pos;
    w.pos += 4;
    // Julia runs on in a deleted directory; the worker stays where it is.
    const cwd: []const u8 = platform.currentDir(w.buf[w.pos..]) catch |err|
        if (err == error.CurrentDirUnavailable) "" else return err;
    std.mem.writeInt(u32, w.buf[len_pos..][0..4], @intCast(cwd.len), .little);
    w.pos += cwd.len;
    w.writeInt(u64, env.fingerprint);
    w.writeInt(u32, @intCast(forwarded.len));
    for (forwarded) |arg| w.writeLenPrefixed(u32, std.mem.span(arg));
    w.flush();
}

fn connectToWorker(conductor: posix.socket_t, w: *SocketWriter, env: EnvInfo, kvs: []const [*:0]const u8) !SocketSet {
    const reader = protocol.BufReader{ .fd = conductor };
    while (true) {
        const reply = reader.readInt(u8) catch |err| replyFailure(err);
        debuglog.event("conductor: {s}", .{switch (reply) {
            protocol.client.env_request => "wants the full environment",
            protocol.client.starting_worker => "starting a worker",
            protocol.client.spawn_request => "wants the worker spawned here",
            protocol.client.socket_paths => "assigned a worker",
            else => "unexpected reply",
        }});
        switch (reply) {
            protocol.client.env_request => sendFullEnv(w, env, kvs),
            protocol.client.starting_worker => showLaunching(true),
            protocol.client.spawn_request => try spawnWorker(reader, kvs),
            protocol.client.socket_paths => break,
            else => replyFailure(error.BadReply),
        }
    }
    showLaunching(false);
    client_id = try reader.readInt(u32);
    var paths_buf: [4 * (max_socket_path + 1)]u8 = undefined;
    var used: usize = 0;
    var paths: [4][]const u8 = undefined;
    for (&paths) |*path| path.* = try takeString(reader, &paths_buf, &used);
    client_key = try reader.readInt(u64);
    platform.close(conductor);
    const result = SocketSet{
        .stdin = connectToWorkerSocket(paths[0], "stdin"),
        .stdout = connectToWorkerSocket(paths[1], "stdout"),
        .stderr = connectToWorkerSocket(paths[2], "stderr"),
        .signals = connectToWorkerSocket(paths[3], "signals"),
    };
    if (transport_mode == .tcp) platform.setTcpNodelay(result.signals);
    return result;
}

// A daemon that recognises a protocol mismatch says so; an older one just closes.
var launching_shown = false;

/// While a worker starts, a terminal's stderr says so, dimmed, until the reply.
fn showLaunching(shown: bool) void {
    if (shown == launching_shown or !platform.isatty(platform.getStderrHandle())) return;
    platform.writeFile(platform.getStderrHandle(), if (shown) "\x1b[2mLaunching new worker...\x1b[22m" else "\r\x1b[2K");
    launching_shown = shown;
}

fn replyFailure(err: anyerror) noreturn {
    showLaunching(false);
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
fn spawnWorker(reader: protocol.BufReader, kvs: []const [*:0]const u8) !void {
    var strings: [64 << 10]u8 = undefined;
    var used: usize = 0;
    var argv: [64:null]?[*:0]const u8 = undefined;
    var envp: [4096:null]?[*:0]const u8 = undefined;
    const argc = try reader.readInt(u16);
    if (argc == 0 or argc > argv.len) return error.BadSpawnRequest;
    for (argv[0..argc]) |*arg| arg.* = (try takeString(reader, &strings, &used)).ptr;
    argv[argc] = null;
    // The daemon's own settings go first, so they shadow ours for the worker.
    const envc = try reader.readInt(u16);
    if (envc + kvs.len > envp.len) return error.BadSpawnRequest;
    for (envp[0..envc]) |*entry| entry.* = (try takeString(reader, &strings, &used)).ptr;
    for (kvs, envp[envc .. envc + kvs.len]) |kv, *entry| entry.* = kv;
    envp[envc + kvs.len] = null;
    platform.spawnDetached(&argv, &envp) catch |err| {
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

/// Into `buf` from `used.*` on, which it moves past.
fn takeString(reader: protocol.BufReader, buf: []u8, used: *usize) ![:0]u8 {
    const len = try reader.readInt(u16);
    if (len >= buf.len - used.*) return error.BadReply;
    const start = used.*;
    try reader.readSlice(buf[start..][0..len]);
    buf[start + len] = 0;
    used.* += len + 1;
    return buf[start..][0..len :0];
}

fn sendFullEnv(w: *SocketWriter, env: EnvInfo, kvs: []const [*:0]const u8) void {
    w.writeInt(u32, env.count);
    for (kvs) |kv_z| {
        const kv = std.mem.span(kv_z);
        if (std.mem.startsWith(u8, kv, "HYPERFINE_")) continue;
        const eq = std.mem.findScalar(u8, kv, '=') orelse continue;
        w.writeLenPrefixed(u32, kv[0..eq]);
        w.writeLenPrefixed(u32, kv[eq + 1 ..]);
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
    // Ends any sequence cut short, and the modes a view sets.
    if (viewing) platform.writeFile(platform.getStdoutHandle(), "\x18\x1b[0m\x1b[?2026l\x1b[?7h\x1b[?25h");
    platform.setRawMode(false);
    std.process.exit(code);
}

/// `raw` is relayed from the worker, which may be sandboxed: only an address
/// of the conductor's own transport is dialled.
fn connectToWorkerSocket(raw: []const u8, comptime label: []const u8) posix.socket_t {
    const connected = switch (transport_mode) {
        // Just `:port`, a port on the conductor's host.
        .tcp => blk: {
            if (raw.len == 0 or raw[0] != ':') break :blk error.InvalidAddress;
            var ip = conductor_peer orelse break :blk error.NoConductorAddress;
            ip.setPort(std.fmt.parseInt(u16, raw[1..], 10) catch break :blk error.InvalidAddress);
            break :blk platform.connectTcp(ip, protocol.connect_timeout_ms);
        },
        .local => blk: {
            const address = protocol.parseAddress(raw) catch break :blk error.InvalidAddress;
            if (address.mode != .local) break :blk error.InvalidAddress;
            break :blk platform.connectLocalOnce(raw);
        },
    };
    const socket = connected catch |e| {
        platform.eprint("Client: failed to connect to " ++ label ++ ": {s}: {}\n", .{ raw, e });
        exitClient(127);
    };
    debuglog.event("worker: " ++ label ++ " connected at {s}", .{raw});
    if (transport_mode == .tcp) platform.setTcpKeepalive(socket, protocol.tcp_keepalive_idle_s);
    // Whoever else reached the socket first is refused for want of the key.
    var key: [8]u8 = undefined;
    std.mem.writeInt(u64, &key, client_key, .little);
    platform.socketWrite(socket, &key);
    return socket;
}

/// The evaluation the worker last said was executing (0 if unnumbered), which
/// an interrupt names, so that one read late can't reach a later evaluation.
var evaluation: u32 = 0;

/// Dials the conductor already reached, never resolving a name again, as
/// this also runs in signal handlers. Errors are dropped.
fn notifyConductor(kind: protocol.notification.Type) void {
    var buf: [21]u8 = undefined;
    std.mem.writeInt(u32, buf[0..4], protocol.notification.magic, .little);
    buf[4] = @intFromEnum(kind);
    std.mem.writeInt(u32, buf[5..9], client_id, .little);
    std.mem.writeInt(u64, buf[9..17], client_key, .little);
    std.mem.writeInt(u32, buf[17..21], evaluation, .little);
    const len: usize = if (kind == .client_interrupt) 21 else 17;
    const fd = switch (transport_mode) {
        .local => platform.connectLocal(conductor_path, protocol.connect_timeout_ms),
        .tcp => platform.connectTcp(conductor_peer orelse return, protocol.connect_timeout_ms),
    } catch return;
    defer platform.close(fd);
    platform.socketWrite(fd, buf[0..len]);
}

/// Zeros without a terminal, which the worker takes as Julia does without one.
fn terminalSize() protocol.TerminalSize {
    // Only an output handle answers on Windows.
    const size = platform.getTerminalSize(platform.getStdinHandle()) orelse
        platform.getTerminalSize(platform.getStdoutHandle()) orelse return .{};
    if (size.rows == 0 or size.cols == 0) return .{};
    return .{ .rows = size.rows, .cols = size.cols };
}

