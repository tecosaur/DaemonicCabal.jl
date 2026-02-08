// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const posix = std.posix;
const protocol = @import("protocol.zig");
const platform = @import("platform/main.zig");

const eloop = if (builtin.os.tag == .linux)
    @import("eloop/linux.zig")
else if (builtin.os.tag.isBSD())
    @import("eloop/kqueue.zig")
else
    @compileError("unsupported OS");

// Single-threaded Io for cross-platform operations (no thread pool overhead)
const io: Io = Io.Threaded.global_single_threaded.io();

// Runtime socket paths are short (runtime_dir + hex name + suffix), 256 bytes is ample.
const max_socket_path = 256;

// --- Types ---

/// Buffered socket writer — flushes automatically when the buffer fills.
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
    stdin: Io.net.Stream,
    stdout: Io.net.Stream,
    stderr: Io.net.Stream,
    signals: Io.net.Stream,
};

const EnvInfo = struct {
    fingerprint: u64,
    count: u16,
    server_path: ?[]const u8,
    runtime_dir: ?[]const u8,
    xdg_runtime_dir: ?[]const u8,
    home: ?[]const u8,
};

const EnvBlock = std.process.Environ.Block;

// Signal parser with buffering for fragmented reads.
// Protocol: <id:u8><len:u8><data> (may contain multiple signals)
const SignalParser = struct {
    buf: [256]u8 = undefined,
    len: usize = 0,
    const header_size = 2; // id (1) + len (1)

    pub const Result = union(enum) {
        none,
        exit: u8,
    };

    pub fn feed(self: *@This(), input: []const u8, fd: posix.socket_t) Result {
        if (self.len + input.len > self.buf.len) {
            std.debug.print("[client] signal buffer overflow\n", .{});
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
            if (pos + total_len > self.len) break; // incomplete signal
            result = dispatch(id, self.buf[pos + header_size .. pos + total_len], fd);
            pos += total_len;
        }
        // Compact buffer
        if (pos > 0) {
            const remaining = self.len - pos;
            if (remaining > 0) {
                std.mem.copyForwards(u8, self.buf[0..remaining], self.buf[pos..self.len]);
            }
            self.len = remaining;
        }
        return result;
    }

    fn dispatch(id: u8, data: []const u8, fd: posix.socket_t) Result {
        return switch (id) {
            protocol.signals.exit => .{ .exit = if (data.len >= 1) data[0] else 1 },
            protocol.signals.raw_mode => blk: {
                if (data.len == 1) platform.setRawMode(data[0] != 0);
                platform.socketWrite(fd, &[_]u8{ id, 0 }); // ack: id + len:u8=0
                break :blk .none;
            },
            protocol.signals.query_size => blk: {
                const size = getTerminalSize();
                var resp: [6]u8 = undefined;
                resp[0] = id;
                resp[1] = 4; // len:u8 = 4 bytes of data
                std.mem.writeInt(u16, resp[2..4], size.height, .little);
                std.mem.writeInt(u16, resp[4..6], size.width, .little);
                platform.socketWrite(fd, &resp);
                break :blk .none;
            },
            protocol.signals.nodelay => blk: {
                protocol.setTcpNodelay(sockets.stdin.socket.handle);
                protocol.setTcpNodelay(fd); // signals socket
                break :blk .none;
            },
            else => .none,
        };
    }
};

// --- Globals ---

// Global socket set (needed for signal handler which can't capture state)
var sockets: SocketSet = undefined;
// Conductor address for exit notification (global buffer so it outlives connectToConductor)
var conductor_path_buf: [max_socket_path]u8 = undefined;
var conductor_path: []const u8 = &.{};
var transport_mode: protocol.TransportMode = .unix;
var signal_parser = SignalParser{};

// --- Signal handler wiring ---

fn signalWriteStdin(ptr: *anyopaque, data: []const u8) void {
    const sock_set: *SocketSet = @ptrCast(@alignCast(ptr));
    platform.socketWrite(sock_set.stdin.socket.handle, data);
}

fn signalNotifyExit() void {
    notifyExit();
    platform.setRawMode(false);
}

fn registerSignalHandlers() void {
    platform.registerSignalHandlers(.{
        .sockets_ptr = @ptrCast(&sockets),
        .write_fn = &signalWriteStdin,
        .notify_exit_fn = &signalNotifyExit,
    });
}

// --- Main pipeline ---

pub fn main(init: std.process.Init.Minimal) !void {
    var env = scanEnv(init.environ.block);
    const addr_arg = extractAddressArg(init.args.vector);
    if (addr_arg.value) |addr| env.server_path = addr;
    // Set raw mode for TTY to avoid line buffering
    const is_tty = platform.isatty(platform.getStdinHandle());
    if (is_tty) platform.setRawMode(true);
    defer platform.setRawMode(false);
    // Connect to conductor and send client info
    const conductor = try connectToConductor(env);
    if (transport_mode == .tcp) protocol.setTcpNodelay(conductor.socket.handle);
    defer notifyExit();
    var w = SocketWriter{ .handle = conductor.socket.handle };
    try sendClientInfo(&w, env, is_tty, init.args, addr_arg.skip);
    // Get worker socket paths (conductor may request full env on cache miss)
    sockets = try connectToWorker(conductor, &w, env, init.environ.block);
    // Forward signals to worker instead of terminating
    registerSignalHandlers();
    try runEventLoop();
}

fn scanEnv(block: EnvBlock) EnvInfo {
    var info = EnvInfo{ .fingerprint = 0, .count = 0, .server_path = null, .runtime_dir = null, .xdg_runtime_dir = null, .home = null };
    const env_vars = .{
        .{ "JULIA_DAEMON_SERVER=", "server_path" },
        .{ "JULIA_DAEMON_RUNTIME=", "runtime_dir" },
        .{ "XDG_RUNTIME_DIR=", "xdg_runtime_dir" },
        .{ "HOME=", "home" },
    };
    for (block) |entry_opt| {
        const entry = entry_opt orelse break;
        const kv = std.mem.span(entry);
        if (std.mem.startsWith(u8, kv, "HYPERFINE_")) continue; // benchmarking noise
        info.count += 1;
        // XOR hash for order-independent fingerprint
        var h = std.hash.Wyhash.init(kv.len);
        h.update(kv);
        info.fingerprint ^= h.final();
        // Extract config paths if present
        inline for (env_vars) |ev| {
            if (std.mem.startsWith(u8, kv, ev[0])) {
                @field(info, ev[1]) = kv[ev[0].len..];
            }
        }
    }
    return info;
}

fn connectToConductor(env: EnvInfo) !Io.net.Stream {
    var runtime_dir_buf: [max_socket_path]u8 = undefined;
    const runtime_dir = env.runtime_dir orelse
        try platform.defaultRuntimeDir(&runtime_dir_buf, env.xdg_runtime_dir, env.home);
    const raw_path = env.server_path orelse
        std.fmt.bufPrint(&conductor_path_buf, "{s}/conductor.sock", .{runtime_dir}) catch return error.NameTooLong;
    const parsed = protocol.parseAddress(raw_path) catch {
        std.debug.print("Unsupported address scheme: {s}\nOnly tcp:// and unix paths are supported.\n", .{raw_path});
        std.process.exit(1);
    };
    transport_mode = parsed.mode;
    conductor_path = parsed.addr;
    const addr = conductor_path;
    // First attempt
    if (protocol.connectAddress(io, transport_mode, addr)) |stream| return stream else |_| {}
    // In TCP mode, no PID file / SIGUSR1 recovery — just retry briefly
    if (transport_mode == .tcp) {
        var attempts: u32 = 0;
        while (attempts < 20) : (attempts += 1) {
            Io.sleep(io, Io.Duration.fromMilliseconds(100), .awake) catch {};
            if (protocol.connectAddress(io, transport_mode, addr)) |stream| return stream else |_| {}
        }
    } else {
        // Unix mode: try to signal conductor to recreate socket
        var pid_buf: [max_socket_path]u8 = undefined;
        const pid_path = std.fmt.bufPrint(&pid_buf, "{s}/conductor.pid", .{runtime_dir}) catch return error.NameTooLong;
        if (readPidAndSignal(pid_path)) {
            var attempts: u32 = 0;
            while (attempts < 20) : (attempts += 1) {
                Io.sleep(io, Io.Duration.fromMilliseconds(100), .awake) catch {};
                if (connectUnix(addr)) |stream| return stream else |_| {}
            }
        }
    }
    // Give up
    std.debug.print(
        \\Failed to connect to {s}
        \\
        \\Try restarting the daemon:
        \\
        \\  {s}
        \\
        \\Or specify a different address with -a <addr>
        \\
    , .{ addr, switch (builtin.os.tag) {
        .linux => "systemctl --user restart julia-daemon",
        .macos => "launchctl kickstart -k gui/$(id -u)/net.julialang.julia-daemon",
        else => "pkill -f julia-conductor && julia-conductor &",
    } });
    std.process.exit(127);
}

fn sendClientInfo(w: *SocketWriter, env: EnvInfo, is_tty: bool, raw_args: std.process.Args, skip: [2]usize) !void {
    // Header: magic + flags + reserved + pid + ppid
    w.writeInt(u32, protocol.client.magic);
    w.writeInt(u8, @bitCast(protocol.client.Flags{ .tty = is_tty }));
    w.writeSlice(&.{ 0, 0, 0 });
    w.writeInt(u32, @intCast(platform.getpid()));
    w.writeInt(u32, @intCast(platform.getppid()));
    // CWD (read directly into the writer's buffer after a 2-byte length prefix)
    if (w.pos + 2 >= w.buf.len) w.flush();
    const len_pos = w.pos;
    w.pos += 2; // reserve space for length prefix
    const cwd_len = try std.process.currentPath(io, w.buf[w.pos..]);
    std.mem.writeInt(u16, w.buf[len_pos..][0..2], @intCast(cwd_len), .little);
    w.pos += cwd_len;
    // Environment fingerprint
    w.writeInt(u64, env.fingerprint);
    // Args (skip address flag indices — client-only, not forwarded)
    const skip_count = @as(u16, if (skip[0] != sentinel) 1 else 0) +
        @as(u16, if (skip[1] != sentinel) 1 else 0);
    w.writeInt(u16, @intCast(raw_args.vector.len - skip_count));
    for (raw_args.vector, 0..) |arg_ptr, i| {
        if (i == skip[0] or i == skip[1]) continue;
        w.writeLenPrefixed(u16, std.mem.span(arg_ptr));
    }
    w.flush();
}

fn connectToWorker(conductor: Io.net.Stream, w: *SocketWriter, env: EnvInfo, block: EnvBlock) !SocketSet {
    var buf: [1024]u8 = undefined;
    var sr = conductor.reader(io, &buf);
    const reader = &sr.interface;
    // First byte is either '?' (env request) or low byte of stdin path length
    const first_byte = try reader.takeByte();
    if (first_byte == protocol.client.env_request) {
        sendFullEnv(w, env, block);
    }
    // Read 4 length-prefixed socket paths: stdin, stdout, stderr, signals
    // (reconstruct first path length if we already consumed the first byte)
    const stdin_len: usize = if (first_byte == protocol.client.env_request)
        try reader.takeInt(u16, .little)
    else
        @as(u16, first_byte) | (@as(u16, try reader.takeByte()) << 8);
    var stdin_buf: [max_socket_path]u8 = undefined;
    if (stdin_len > stdin_buf.len) return error.NameTooLong;
    const stdin_path = stdin_buf[0..stdin_len];
    try reader.readSliceAll(stdin_path);
    const stdout_len: usize = try reader.takeInt(u16, .little);
    var stdout_buf: [max_socket_path]u8 = undefined;
    if (stdout_len > stdout_buf.len) return error.NameTooLong;
    const stdout_path = stdout_buf[0..stdout_len];
    try reader.readSliceAll(stdout_path);
    const stderr_len: usize = try reader.takeInt(u16, .little);
    var stderr_buf: [max_socket_path]u8 = undefined;
    if (stderr_len > stderr_buf.len) return error.NameTooLong;
    const stderr_path = stderr_buf[0..stderr_len];
    try reader.readSliceAll(stderr_path);
    const signals_len: usize = try reader.takeInt(u16, .little);
    var signals_buf: [max_socket_path]u8 = undefined;
    if (signals_len > signals_buf.len) return error.NameTooLong;
    const signals_path = signals_buf[0..signals_len];
    try reader.readSliceAll(signals_path);
    conductor.close(io);
    // Connect to worker sockets (and clean up socket files in unix mode)
    const result = SocketSet{
        .stdin = connectToWorkerSocket(stdin_path, "stdin"),
        .stdout = connectToWorkerSocket(stdout_path, "stdout"),
        .stderr = connectToWorkerSocket(stderr_path, "stderr"),
        .signals = connectToWorkerSocket(signals_path, "signals"),
    };
    if (transport_mode == .tcp) protocol.setTcpNodelay(result.signals.socket.handle);
    return result;
}

fn sendFullEnv(w: *SocketWriter, env: EnvInfo, block: EnvBlock) void {
    w.writeInt(u16, env.count);
    for (block) |entry_opt| {
        const kv = std.mem.span(entry_opt orelse break);
        if (std.mem.startsWith(u8, kv, "HYPERFINE_")) continue;
        const eq = std.mem.indexOfScalar(u8, kv, '=') orelse continue;
        w.writeLenPrefixed(u16, kv[0..eq]);
        w.writeLenPrefixed(u16, kv[eq + 1 ..]);
    }
    w.flush();
}

fn runEventLoop() !void {
    const exit_code = try eloop.run(
        sockets.stdin.socket.handle,
        sockets.stdout.socket.handle,
        sockets.stderr.socket.handle,
        sockets.signals.socket.handle,
        &signal_parser,
    );
    notifyExit();
    std.process.exit(exit_code);
}

// --- Helpers ---

fn connectUnix(path: []const u8) !Io.net.Stream {
    return (try Io.net.UnixAddress.init(path)).connect(io);
}

fn connectToWorkerSocket(raw: []const u8, comptime label: []const u8) Io.net.Stream {
    // In TCP mode the conductor sends just `:port` — prepend the conductor host
    var addr_buf: [max_socket_path]u8 = undefined;
    const addr = if (raw.len > 0 and raw[0] == ':') blk: {
        const host = conductorHost();
        if (host.len + raw.len > addr_buf.len) {
            std.debug.print("Worker " ++ label ++ " address too long\n", .{});
            std.process.exit(127);
        }
        @memcpy(addr_buf[0..host.len], host);
        @memcpy(addr_buf[host.len..][0..raw.len], raw);
        break :blk addr_buf[0 .. host.len + raw.len];
    } else raw;
    const mode = (protocol.parseAddress(addr) catch unreachable).mode;
    const stream = protocol.connectAddress(io, mode, addr) catch |e| {
        std.debug.print("Failed to connect to worker " ++ label ++ " socket: {s}: {}\n", .{ addr, e });
        std.process.exit(127);
    };
    if (mode == .unix) Io.Dir.deleteFileAbsolute(io, raw) catch {};
    return stream;
}

fn conductorHost() []const u8 {
    const colon = std.mem.lastIndexOfScalar(u8, conductor_path, ':') orelse return conductor_path;
    return conductor_path[0..colon];
}

fn readPidAndSignal(pid_path: []const u8) bool {
    // Read PID from file
    var buf: [16]u8 = undefined;
    const content = Io.Dir.readFile(.cwd(), io, pid_path, &buf) catch return false;
    const pid_str = std.mem.trimEnd(u8, content, &.{ '\n', '\r', ' ' });
    const pid = std.fmt.parseInt(i32, pid_str, 10) catch return false;
    // Send SIGUSR1
    _ = platform.kill(pid, platform.SIG.USR1);
    return true;
}

fn notifyExit() void {
    const stream = protocol.connectAddress(io, transport_mode, conductor_path) catch return;
    defer stream.close(io);
    var buf: [9]u8 = undefined;
    std.mem.writeInt(u32, buf[0..4], protocol.notification.magic, .little);
    buf[4] = @intFromEnum(protocol.notification.Type.client_exit);
    std.mem.writeInt(u32, buf[5..9], @intCast(platform.getpid()), .little);
    platform.socketWrite(stream.socket.handle, &buf);
}

fn getTerminalSize() struct { height: u16, width: u16 } {
    if (platform.getTerminalSize(platform.getStdinHandle())) |size| {
        return .{ .height = size.rows, .width = size.cols };
    }
    return .{ .height = 24, .width = 80 }; // fallback
}

const sentinel = std.math.maxInt(usize);

const AddressArg = struct {
    value: ?[]const u8,
    skip: [2]usize, // indices to omit when forwarding; sentinel = unused
};

fn extractAddressArg(vector: []const ?[*:0]const u8) AddressArg {
    const none = AddressArg{ .value = null, .skip = .{ sentinel, sentinel } };
    for (vector, 0..) |entry, i| {
        if (i == 0) continue;
        const arg = std.mem.span(entry orelse continue);
        if (std.mem.eql(u8, arg, "--")) return none;
        // --address=<value> or -a<value>
        if (std.mem.startsWith(u8, arg, "--address="))
            return .{ .value = arg["--address=".len..], .skip = .{ i, sentinel } };
        if (arg.len > 2 and arg[0] == '-' and arg[1] == 'a')
            return .{ .value = arg[2..], .skip = .{ i, sentinel } };
        // --address <value> or -a <value>
        if (std.mem.eql(u8, arg, "--address") or std.mem.eql(u8, arg, "-a")) {
            const next = if (i + 1 < vector.len) vector[i + 1] else null;
            if (next) |v| return .{ .value = std.mem.span(v), .skip = .{ i, i + 1 } };
            return none;
        }
    }
    return none;
}
