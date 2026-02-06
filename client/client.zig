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

const BufWriter = protocol.BufWriter;

const SocketSet = struct {
    stdio: Io.net.Stream,
    signals: Io.net.Stream,
};

// Global socket set (needed for signal handler which can't capture state)
var sockets: SocketSet = undefined;

// Conductor socket path for exit notification
var conductor_path: []const u8 = undefined;

// Forward process signals to the worker
fn signalHandler(
    sig: posix.SIG,
    _: *const posix.siginfo_t,
    _: ?*anyopaque,
) callconv(.c) void {
    switch (sig) {
        .INT => _ = platform.write(sockets.stdio.socket.handle, "\x03"),
        .TERM => {
            notifyExit();
            std.process.exit(128 + @intFromEnum(posix.SIG.TERM));
        },
        else => {},
    }
}

fn registerSignalHandlers() void {
    var mask = std.mem.zeroes(posix.sigset_t);
    posix.sigaddset(&mask, posix.SIG.INT);
    posix.sigaddset(&mask, posix.SIG.TERM);
    const sigact = posix.Sigaction{
        .handler = .{ .sigaction = signalHandler },
        .mask = mask,
        .flags = 0,
    };
    posix.sigaction(posix.SIG.INT, &sigact, null);
    posix.sigaction(posix.SIG.TERM, &sigact, null);
}

fn connectUnix(path: []const u8) !Io.net.Stream {
    return (try Io.net.UnixAddress.init(path)).connect(io);
}

fn connectToConductor(allocator: std.mem.Allocator, env: EnvInfo) !Io.net.Stream {
    const runtime_dir = env.runtime_dir orelse
        try platform.defaultRuntimeDir(allocator, env.xdg_runtime_dir, env.home);
    const path = env.server_path orelse
        try std.fmt.allocPrint(allocator, "{s}/conductor.sock", .{runtime_dir});
    conductor_path = path;
    // First attempt
    if (connectUnix(path)) |stream| return stream else |_| {}
    // Connection failed - try to signal conductor to recreate socket
    const pid_path = try std.fmt.allocPrint(allocator, "{s}/conductor.pid", .{runtime_dir});
    if (readPidAndSignal(pid_path)) {
        // Wait up to 2 seconds for socket to be recreated, checking every 100ms
        var attempts: u32 = 0;
        while (attempts < 20) : (attempts += 1) {
            Io.sleep(io, Io.Duration.fromMilliseconds(100), .awake) catch {};
            if (connectUnix(path)) |stream| return stream else |_| {}
        }
    }
    // Give up
    std.debug.print(
        \\Failed to connect to {s}
        \\
        \\Try restarting the daemon:
        \\
        \\  systemctl --user restart julia-daemon
        \\
    , .{path});
    std.process.exit(127);
}

fn readPidAndSignal(pid_path: []const u8) bool {
    // Read PID from file
    var buf: [16]u8 = undefined;
    const content = Io.Dir.readFile(.cwd(), io, pid_path, &buf) catch return false;
    const pid_str = std.mem.trimEnd(u8, content, &.{ '\n', '\r', ' ' });
    const pid = std.fmt.parseInt(i32, pid_str, 10) catch return false;
    // Send SIGUSR1
    _ = platform.kill(pid, posix.SIG.USR1);
    return true;
}

fn sendClientInfo(socket: Io.net.Stream, env: EnvInfo, is_tty: bool, args: []const [*:0]const u8) !void {
    var buf: [8192]u8 = undefined;
    var w = BufWriter{ .buf = &buf };
    // Header: magic (4) + flags (1) + reserved (3)
    w.writeInt(u32, protocol.client.magic);
    w.writeInt(u8, @bitCast(protocol.client.Flags{ .tty = is_tty }));
    w.writeSlice(&.{ 0, 0, 0 }); // reserved
    // PID and PPID
    w.writeInt(u32, @intCast(platform.getpid()));
    w.writeInt(u32, @intCast(platform.getppid()));
    // CWD (length-prefixed)
    var cwd_buf: [std.fs.max_path_bytes]u8 = undefined;
    const cwd_len = try std.process.currentPath(io, &cwd_buf);
    w.writeLenPrefixed(u16, cwd_buf[0..cwd_len]);
    // Environment fingerprint
    w.writeInt(u64, env.fingerprint);
    // Args (count + length-prefixed strings)
    w.writeInt(u16, @intCast(args.len));
    for (args) |arg_ptr| {
        w.writeLenPrefixed(u16, std.mem.span(arg_ptr));
    }
    _ = platform.write(socket.socket.handle, w.written());
}

const EnvBlock = std.process.Environ.Block;

const EnvInfo = struct {
    fingerprint: u64,
    count: u16,
    server_path: ?[]const u8,
    runtime_dir: ?[]const u8,
    xdg_runtime_dir: ?[]const u8,
    home: ?[]const u8,
};

fn scanEnv(block: EnvBlock) EnvInfo {
    var info = EnvInfo{ .fingerprint = 0, .count = 0, .server_path = null, .runtime_dir = null, .xdg_runtime_dir = null, .home = null };
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
        if (std.mem.startsWith(u8, kv, "JULIA_DAEMON_SERVER=")) {
            info.server_path = kv["JULIA_DAEMON_SERVER=".len..];
        } else if (std.mem.startsWith(u8, kv, "JULIA_DAEMON_RUNTIME=")) {
            info.runtime_dir = kv["JULIA_DAEMON_RUNTIME=".len..];
        } else if (std.mem.startsWith(u8, kv, "XDG_RUNTIME_DIR=")) {
            info.xdg_runtime_dir = kv["XDG_RUNTIME_DIR=".len..];
        } else if (std.mem.startsWith(u8, kv, "HOME=")) {
            info.home = kv["HOME=".len..];
        }
    }
    return info;
}

fn sendFullEnv(socket: Io.net.Stream, env: EnvInfo, block: EnvBlock) void {
    var buf: [64 * 1024]u8 = undefined;
    var w = BufWriter{ .buf = &buf };
    w.writeInt(u16, env.count);
    for (block) |entry_opt| {
        const kv = std.mem.span(entry_opt orelse break);
        if (std.mem.startsWith(u8, kv, "HYPERFINE_")) continue;
        const eq = std.mem.indexOfScalar(u8, kv, '=') orelse continue;
        w.writeLenPrefixed(u16, kv[0..eq]);
        w.writeLenPrefixed(u16, kv[eq + 1 ..]);
    }
    _ = platform.write(socket.socket.handle, w.written());
}

fn connectToWorker(allocator: std.mem.Allocator, conductor: Io.net.Stream, env: EnvInfo, block: EnvBlock) !SocketSet {
    var buf: [512]u8 = undefined;
    var sr = conductor.reader(io, &buf);
    const reader = &sr.interface;
    // First byte is either '?' (env request) or low byte of stdio path length
    const first_byte = try reader.takeByte();
    if (first_byte == protocol.client.env_request) {
        sendFullEnv(conductor, env, block);
    }
    // Read length-prefixed socket paths (reconstruct length if we already read first byte)
    const stdio_len = if (first_byte == protocol.client.env_request)
        try reader.takeInt(u16, .little)
    else
        @as(u16, first_byte) | (@as(u16, try reader.takeByte()) << 8);
    const stdio_path = try allocator.alloc(u8, stdio_len);
    defer allocator.free(stdio_path);
    try reader.readSliceAll(stdio_path);
    const signals_len = try reader.takeInt(u16, .little);
    const signals_path = try allocator.alloc(u8, signals_len);
    defer allocator.free(signals_path);
    try reader.readSliceAll(signals_path);
    conductor.close(io);
    // Connect to worker sockets and clean up socket files
    const stdio = connectUnix(stdio_path) catch |e| {
        std.debug.print("Failed to connect to worker stdio socket: {s}: {}\n", .{stdio_path, e});
        std.process.exit(127);
    };
    Io.Dir.deleteFileAbsolute(io, stdio_path) catch {};
    const signals = connectUnix(signals_path) catch |e| {
        std.debug.print("Failed to connect to worker signals socket: {}\n", .{e});
        std.process.exit(127);
    };
    Io.Dir.deleteFileAbsolute(io, signals_path) catch {};
    return .{ .stdio = stdio, .signals = signals };
}

// Signal parser with buffering for fragmented reads.
// Protocol: <id:u8><len:u8><data> (may contain multiple signals)
const SignalParser = struct {
    buf: [256]u8 = undefined,
    len: usize = 0,
    const header_size = 2; // id (1) + len (1)

    pub const Result = union(enum) {
        none,
        exit: u8,
        // Future: resize: struct { w: u16, h: u16 },
    };

    pub fn feed(self: *@This(), input: []const u8, fd: posix.fd_t) Result {
        if (self.len + input.len > self.buf.len) {
            std.debug.print("[client] signal buffer overflow\n", .{});
            return .none;
        }
        @memcpy(self.buf[self.len..][0..input.len], input);
        self.len += input.len;
        return self.process(fd);
    }

    fn process(self: *@This(), fd: posix.fd_t) Result {
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

    fn dispatch(id: u8, data: []const u8, fd: posix.fd_t) Result {
        return switch (id) {
            protocol.signals.exit => .{ .exit = if (data.len == 1) data[0] else unreachable },
            protocol.signals.raw_mode => blk: {
                if (data.len == 1) setTerminalRaw(data[0] != 0);
                _ = platform.write(fd, &[_]u8{ id, 0 }); // ack: id + len:u8=0
                break :blk .none;
            },
            protocol.signals.query_size => blk: {
                const size = getTerminalSize();
                var resp: [6]u8 = undefined;
                resp[0] = id;
                resp[1] = 4; // len:u8 = 4 bytes of data
                std.mem.writeInt(u16, resp[2..4], size.height, .little);
                std.mem.writeInt(u16, resp[4..6], size.width, .little);
                _ = platform.write(fd, &resp);
                break :blk .none;
            },
            else => .none,
        };
    }
};

fn getTerminalSize() struct { height: u16, width: u16 } {
    if (platform.getTerminalSize(posix.STDIN_FILENO)) |size| {
        return .{ .height = size.rows, .width = size.cols };
    }
    return .{ .height = 24, .width = 80 }; // fallback
}

fn setTerminalRaw(raw: bool) void {
    var termios = posix.tcgetattr(posix.STDIN_FILENO) catch return;
    termios.lflag.ECHO = !raw;
    termios.lflag.ICANON = !raw;
    posix.tcsetattr(posix.STDIN_FILENO, .FLUSH, termios) catch {};
}

fn notifyExit() void {
    const addr = Io.net.UnixAddress.init(conductor_path) catch return;
    const stream = addr.connect(io) catch return;
    defer stream.close(io);
    var buf: [9]u8 = undefined;
    std.mem.writeInt(u32, buf[0..4], protocol.notification.magic, .little);
    buf[4] = @intFromEnum(protocol.notification.Type.client_exit);
    std.mem.writeInt(u32, buf[5..9], @intCast(platform.getpid()), .little);
    _ = platform.write(stream.socket.handle, &buf);
}

var signal_parser = SignalParser{};

fn runEventLoop() !void {
    const stdio_fd = sockets.stdio.socket.handle;
    const signals_fd = sockets.signals.socket.handle;
    const exit_code = try eloop.run(stdio_fd, signals_fd, &signal_parser);
    notifyExit();
    std.process.exit(exit_code);
}

pub fn main(init: std.process.Init.Minimal) !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const env = scanEnv(init.environ.block);
    // Set raw mode for TTY to avoid line buffering
    const is_tty = platform.isatty(posix.STDIN_FILENO);
    if (is_tty) {
        var termios = try posix.tcgetattr(posix.STDIN_FILENO);
        termios.lflag.ECHO = false;
        termios.lflag.ICANON = false;
        try posix.tcsetattr(posix.STDIN_FILENO, .FLUSH, termios);
    }
    // Connect to conductor and send client info
    const conductor = try connectToConductor(alloc, env);
    defer notifyExit();
    try sendClientInfo(conductor, env, is_tty, init.args.vector);
    // Get worker socket paths (conductor may request full env on cache miss)
    sockets = try connectToWorker(alloc, conductor, env, init.environ.block);
    // Forward signals to worker instead of terminating
    registerSignalHandlers();
    try runEventLoop();
}
