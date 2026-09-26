// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0
//
// Shared POSIX platform code, over linux.zig or bsd.zig primitives.

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const Io = std.Io;
const protocol = @import("../protocol.zig");
const impl = if (builtin.os.tag == .linux) @import("linux.zig") else @import("bsd.zig");

/// Into an allocator (owned slice) or a `[]u8` buffer (sub-slice).
/// std.debug.print without its stderr locking and terminal handling, which
/// cost the client ~110 KB. Truncates past 1 KiB.
pub fn eprint(comptime fmt: []const u8, args: anytype) void {
    var buf: [1024]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    w.print(fmt, args) catch {};
    _ = posix.system.write(posix.STDERR_FILENO, w.buffered().ptr, w.buffered().len);
}

pub fn print(out: anytype, comptime fmt: []const u8, args: anytype) ![]const u8 {
    if (@TypeOf(out) == std.mem.Allocator)
        return std.fmt.allocPrint(out, fmt, args)
    else
        return std.fmt.bufPrint(out, fmt, args) catch error.NameTooLong;
}

// I/O
pub fn socketWrite(fd: posix.socket_t, buf: []const u8) void { impl.write(fd, buf); }
pub fn close(fd: posix.fd_t) void { impl.rawClose(fd); }
pub fn shutdownWrite(fd: posix.socket_t) void {
    _ = posix.system.shutdown(fd, posix.system.SHUT.WR);
}
/// What the socket takes without waiting, 0 when full; null once its peer is gone.
pub fn sendNonBlocking(fd: posix.socket_t, buf: []const u8) ?usize {
    if (buf.len == 0) return 0;
    while (true) {
        const rc = posix.system.sendto(fd, buf.ptr, buf.len, posix.MSG.DONTWAIT, null, 0);
        switch (posix.errno(rc)) {
            .SUCCESS => return @intCast(rc),
            .INTR => continue,
            .AGAIN => return 0,
            else => return null,
        }
    }
}
/// What the socket holds, without waiting: 0 when nothing; null once it has ended.
pub fn recvNonBlocking(fd: posix.socket_t, buf: []u8) ?usize {
    while (true) {
        const rc = posix.system.recvfrom(fd, buf.ptr, buf.len, posix.MSG.DONTWAIT, null, null);
        switch (posix.errno(rc)) {
            .SUCCESS => return if (rc == 0) null else @intCast(rc),
            .INTR => continue,
            .AGAIN => return 0,
            else => return null,
        }
    }
}
/// Whether `fd` has input, or has ended, within `timeout_ms`.
pub fn waitReadable(fd: posix.fd_t, timeout_ms: u32) bool {
    var pfd = [_]posix.pollfd{.{ .fd = fd, .events = posix.POLL.IN, .revents = 0 }};
    return (posix.poll(&pfd, @intCast(timeout_ms)) catch return true) != 0;
}
pub fn socketRead(fd: posix.socket_t, buf: []u8) usize {
    return posix.read(fd, buf) catch |err| {
        @branchHint(.cold);
        if (err != error.ConnectionResetByPeer)
            eprint("socketRead error: {}\n", .{err});
        return 0;
    };
}

/// Owner-only: the sockets inside run code as us.
pub const runtime_dir_permissions: Io.File.Permissions = .fromMode(0o700);
// Local transport: AF_UNIX sockets in the runtime dir.
pub const max_local_addr = @typeInfo(@FieldType(posix.sockaddr.un, "path")).array.len;
pub fn localSocketDir(out: anytype, runtime_dir: []const u8) ![]const u8 {
    return print(out, "{s}", .{runtime_dir});
}
pub fn localSocketPath(out: anytype, dir: []const u8, comptime name_fmt: []const u8, name_args: anytype) ![]const u8 {
    return print(out, "{s}/" ++ name_fmt, .{dir} ++ name_args);
}
pub fn listenLocal(io: Io, path: []const u8) !Listener {
    if (path.len >= max_local_addr) return error.PathTooLong;
    const ua = try Io.net.UnixAddress.init(path);
    return Listener.fromServer(try ua.listen(io, .{ .kernel_backlog = 128 }), .local, path);
}
/// Raw syscalls only, so usable inside a signal handler.
pub fn connectLocal(path: []const u8, _: u32) !posix.socket_t {
    var addr = std.mem.zeroes(posix.sockaddr.un);
    addr.family = posix.AF.UNIX;
    if (path.len >= addr.path.len) return error.PathTooLong;
    @memcpy(addr.path[0..path.len], path);
    const fd = impl.rawSocket(posix.AF.UNIX, posix.SOCK.STREAM) orelse return error.SocketCreateFailed;
    errdefer impl.rawClose(fd);
    switch (posix.errno(posix.system.connect(fd, @ptrCast(&addr), @sizeOf(posix.sockaddr.un)))) {
        .SUCCESS => return fd,
        else => |e| return connectError(e),
    }
}
/// Retire the single-use address, so nothing else can connect.
pub fn connectLocalOnce(path: []const u8) !posix.socket_t {
    const fd = try connectLocal(path, 0);
    var buf: [max_local_addr]u8 = undefined;
    @memcpy(buf[0..path.len], path);
    buf[path.len] = 0;
    _ = posix.system.unlink(buf[0..path.len :0]);
    return fd;
}
pub const local_transport_name = "unix socket";
/// Bounded, unlike the kernel's minutes of SYN retries.
pub fn connectTcp(ip: Io.net.IpAddress, timeout_ms: u32) !posix.socket_t {
    var storage: Io.Threaded.PosixAddress = undefined;
    const len = Io.Threaded.addressToPosix(&ip, &storage);
    const fd = impl.rawSocket(storage.any.family, posix.SOCK.STREAM) orelse return error.SocketCreateFailed;
    errdefer impl.rawClose(fd);
    _ = try fcntl(fd, posix.F.SETFD, posix.FD_CLOEXEC);
    const flags = try fcntl(fd, posix.F.GETFL, 0);
    const nonblock: u32 = @bitCast(posix.O{ .NONBLOCK = true });
    _ = try fcntl(fd, posix.F.SETFL, flags | nonblock);
    switch (posix.errno(posix.system.connect(fd, &storage.any, len))) {
        .SUCCESS => {},
        .INPROGRESS => {
            var pfd = [_]posix.pollfd{.{ .fd = fd, .events = posix.POLL.OUT, .revents = 0 }};
            if (try posix.poll(&pfd, @intCast(timeout_ms)) == 0) return error.ConnectionTimedOut;
            var err: c_int = 0;
            var err_len: posix.socklen_t = @sizeOf(c_int);
            if (posix.errno(posix.system.getsockopt(fd, posix.SOL.SOCKET, posix.SO.ERROR, @ptrCast(&err), &err_len)) != .SUCCESS)
                return error.Unexpected;
            if (err != 0) return connectError(@enumFromInt(err));
        },
        else => |e| return connectError(e),
    }
    _ = try fcntl(fd, posix.F.SETFL, flags);
    return fd;
}
fn connectError(e: posix.E) anyerror {
    return switch (e) {
        .CONNREFUSED => error.ConnectionRefused,
        .NOENT => error.FileNotFound,
        .TIMEDOUT => error.ConnectionTimedOut,
        .NETUNREACH => error.NetworkUnreachable,
        .HOSTUNREACH => error.HostUnreachable,
        else => posix.unexpectedErrno(e),
    };
}
fn fcntl(fd: posix.fd_t, cmd: anytype, arg: usize) !usize {
    const rc = posix.system.fcntl(fd, cmd, arg);
    if (posix.errno(rc) != .SUCCESS) return error.Unexpected;
    return @intCast(rc);
}

pub const Listener = struct {
    server: Io.net.Server,
    mode: protocol.TransportMode,
    addr_buf: [max_local_addr]u8,
    addr_len: usize,

    pub fn fromServer(server: Io.net.Server, mode: protocol.TransportMode, address: []const u8) !Listener {
        var l = Listener{ .server = server, .mode = mode, .addr_buf = undefined, .addr_len = address.len };
        if (address.len > l.addr_buf.len) return error.PathTooLong;
        @memcpy(l.addr_buf[0..address.len], address);
        return l;
    }
    pub fn addr(self: *const Listener) []const u8 {
        return self.addr_buf[0..self.addr_len];
    }
    pub fn fd(self: *const Listener) posix.socket_t {
        return self.server.socket.handle;
    }
    pub fn accept(self: *Listener, io: Io) !protocol.Connection {
        const stream = try self.server.accept(io);
        return .{ .socket = stream.socket.handle, .peer = if (self.mode == .tcp) stream.socket.address else null };
    }
    /// 0 takes only a connection already waiting.
    pub fn acceptTimeout(self: *Listener, io: Io, timeout_ms: i32) !?posix.socket_t {
        var pfd = [_]posix.pollfd{.{ .fd = self.fd(), .events = posix.POLL.IN, .revents = 0 }};
        if (try posix.poll(&pfd, timeout_ms) == 0) return null;
        return (try self.accept(io)).socket;
    }
    pub fn close(self: *Listener, io: Io) void {
        self.server.deinit(io);
        if (self.mode == .local) Io.Dir.deleteFileAbsolute(io, self.addr()) catch {};
    }
};

// Process helpers
/// Own process group, so a terminal SIGINT reaches only the conductor.
/// Its stderr is a pipe, which the conductor drains (`readAvailable`).
pub fn spawnWorker(io: Io, argv: []const []const u8, environ_map: *const std.process.Environ.Map) !std.process.Child {
    const child = try std.process.spawn(io, .{ .argv = argv, .environ_map = environ_map, .pgid = 0, .stderr = .pipe });
    if (child.stderr) |f| {
        const flags = fcntl(f.handle, posix.F.GETFL, 0) catch return child;
        const nonblock: u32 = @bitCast(posix.O{ .NONBLOCK = true });
        _ = fcntl(f.handle, posix.F.SETFL, flags | nonblock) catch {};
    }
    return child;
}
/// What a non-blocking descriptor holds: 0 when nothing; null once it has ended.
pub fn readAvailable(fd: posix.fd_t, buf: []u8) ?usize {
    while (true) {
        const rc = posix.system.read(fd, buf.ptr, buf.len);
        switch (posix.errno(rc)) {
            .SUCCESS => return if (rc == 0) null else @intCast(rc),
            .INTR => continue,
            .AGAIN => return 0,
            else => return null,
        }
    }
}
pub fn dumpChildStderr(_: Io, _: std.mem.Allocator, _: *std.process.Child, _: u32) void {}
pub fn collectEnviron(allocator: std.mem.Allocator, environ: std.process.Environ) ![]const []const u8 {
    const entries = try allocator.alloc([]const u8, environ.block.slice.len);
    for (environ.block.slice, entries) |entry, *kv| kv.* = std.mem.span(entry.?);
    return entries;
}
/// Signal the conductor whose pid `pid_path` holds (its SIGUSR1 handler).
pub fn requestSocketRecreate(pid_path: []const u8) bool {
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path = std.fmt.bufPrintZ(&path_buf, "{s}", .{pid_path}) catch return false;
    const fd = posix.openatZ(posix.AT.FDCWD, path, .{ .ACCMODE = .RDONLY }, 0) catch return false;
    defer impl.rawClose(fd);
    var buf: [16]u8 = undefined;
    const n = posix.read(fd, &buf) catch return false;
    const pid = std.fmt.parseInt(posix.pid_t, std.mem.trimEnd(u8, buf[0..n], "\n\r "), 10) catch return false;
    // 0 and negatives name process groups, down to everything we may signal.
    return pid > 0 and impl.kill(pid, posix.SIG.USR1) == 0;
}
pub fn sleepMs(ms: u32) void {
    _ = posix.poll(&.{}, @intCast(ms)) catch {};
}
pub const currentDir = impl.currentDir;
pub const lookupHost = impl.lookupHost;
pub fn pidNumber(pid: posix.pid_t) u32 {
    return @intCast(pid);
}
pub const no_socket: posix.socket_t = -1;
pub const no_child = std.process.Child{ .id = null, .thread_handle = {}, .stdin = null, .stdout = null, .stderr = null, .request_resource_usage_statistics = false };
pub fn getChildPid(child: anytype) @TypeOf(child.id orelse 0) {
    return child.id orelse 0;
}
/// Reaps it if so.
pub fn reapIfExited(pid: posix.pid_t) bool {
    // < 0 is ECHILD: already gone.
    return impl.rawWaitpid(pid, false) != 0;
}
/// Blocks, so only for a child already killed.
pub fn waitForExit(pid: posix.pid_t) void {
    _ = impl.rawWaitpid(pid, true);
}

/// `cpu_seconds` is cumulative, not a rate.
pub const ProcessStats = struct { mem_bytes: u64, cpu_seconds: f64 };
pub const getProcessStats = impl.getProcessStats;
pub fn getParentName(pid: u32, buf: []u8) ?[]const u8 {
    return impl.getParentName(@intCast(pid), buf);
}

/// Whether `getProcessStats().mem_bytes` is already the reclaimable figure.
pub const mem_is_reclaimable = impl.mem_is_reclaimable;

/// USS in bytes; null where the OS has no private-page accounting.
pub const processReclaimable = impl.processReclaimable;

pub const MemInfo = impl.MemInfo;
pub const readPsiSomeAvg10 = impl.readPsiSomeAvg10;
pub const readMemInfo = impl.readMemInfo;

// Terminal
pub fn getTerminalSize(fd: posix.fd_t) ?struct { rows: u16, cols: u16 } {
    var ws: posix.winsize = undefined;
    if (impl.rawIoctl(fd, posix.T.IOCGWINSZ, @intFromPtr(&ws)) == 0)
        return .{ .rows = ws.row, .cols = ws.col };
    return null;
}
pub fn isatty(fd: posix.fd_t) bool { return getTerminalSize(fd) != null; }
pub fn setRecvTimeout(socket: posix.fd_t, seconds: u32) void {
    posix.setsockopt(socket, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(
        &impl.Timeval{ .sec = @intCast(seconds), .usec = 0 },
    )) catch {};
}

/// Then probes each second, ten times, as libuv does for the worker's end.
pub fn setTcpKeepalive(socket: posix.fd_t, idle_s: u32) void {
    _ = posix.system.setsockopt(socket, posix.SOL.SOCKET, posix.SO.KEEPALIVE, std.mem.asBytes(&@as(c_int, 1)), @sizeOf(c_int));
    const options = impl.tcp_keepalive_options orelse return;
    for (options, [3]c_int{ @intCast(idle_s), 1, 10 }) |option, value|
        _ = posix.system.setsockopt(socket, 6, option, std.mem.asBytes(&value), @sizeOf(c_int)); // IPPROTO_TCP
}

pub fn setTcpNodelay(socket: posix.fd_t) void {
    // Raw: std's wrapper treats an already-closed socket as unreachable.
    _ = posix.system.setsockopt(socket, 6, 1, std.mem.asBytes(&@as(c_int, 1)), @sizeOf(c_int)); // IPPROTO_TCP, TCP_NODELAY
}

// Terminal raw mode
var saved_termios: ?posix.termios = null;
pub fn setRawMode(raw: bool) void {
    const stdin = impl.STDIN_HANDLE;
    if (raw) {
        var termios = posix.tcgetattr(stdin) catch return;
        if (saved_termios == null) saved_termios = termios;
        termios.lflag.ECHO = false;
        termios.lflag.ICANON = false;
        posix.tcsetattr(stdin, .FLUSH, termios) catch {};
    } else if (saved_termios) |termios| {
        posix.tcsetattr(stdin, .FLUSH, termios) catch {};
        saved_termios = null;
    }
}

// Signal handling
var worker_raw: bool = false;
pub fn setWorkerRawMode(raw: bool) void { worker_raw = raw; }
var worker_executing: bool = false;
pub fn setWorkerExecuting(executing: bool) void { worker_executing = executing; }
pub const SignalHandler = struct {
    sockets_ptr: *anyopaque,
    write_fn: *const fn (*anyopaque, []const u8) void,
    notify_exit_fn: *const fn () void,
    notify_interrupt_fn: *const fn () void,
    pub fn writeStdio(self: SignalHandler, data: []const u8) void {
        self.write_fn(self.sockets_ptr, data);
    }
    pub fn notifyExit(self: SignalHandler) void {
        self.notify_exit_fn();
    }
    pub fn notifyInterrupt(self: SignalHandler) void {
        self.notify_interrupt_fn();
    }
};
var g_signal_handler: ?SignalHandler = null;
fn signalAction(sig: posix.SIG, _: *const posix.siginfo_t, _: ?*anyopaque) callconv(.c) void {
    const handler = g_signal_handler orelse return;
    switch (sig) {
        .INT => {
            // Nothing reads stdin while code runs. Never coalesce: Julia's
            // force-throw for tight loops needs the repeated presses.
            if (worker_raw and !worker_executing)
                handler.writeStdio("\x03")
            else
                handler.notifyInterrupt();
        },
        .TERM, .HUP => {
            handler.notifyExit();
            std.process.exit(128 +% @as(u8, @intCast(@intFromEnum(sig))));
        },
        else => {},
    }
}
pub fn registerSignalHandlers(handler: SignalHandler) void {
    g_signal_handler = handler;
    var mask = std.mem.zeroes(posix.sigset_t);
    posix.sigaddset(&mask, posix.SIG.INT);
    posix.sigaddset(&mask, posix.SIG.TERM);
    posix.sigaddset(&mask, posix.SIG.HUP);
    const sigact = posix.Sigaction{
        .handler = .{ .sigaction = signalAction },
        .mask = mask,
        .flags = 0, // no SA_RESTART, so io_uring_enter returns EINTR promptly
    };
    posix.sigaction(posix.SIG.INT, &sigact, null);
    posix.sigaction(posix.SIG.TERM, &sigact, null);
    posix.sigaction(posix.SIG.HUP, &sigact, null);
    const pipe_act = posix.Sigaction{
        .handler = .{ .handler = posix.SIG.IGN },
        .mask = std.mem.zeroes(posix.sigset_t),
        .flags = 0,
    };
    posix.sigaction(posix.SIG.PIPE, &pipe_act, null);
}
