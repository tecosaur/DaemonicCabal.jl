// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0
//
// Shared POSIX platform code used by both linux.zig and bsd.zig.
// Platform-specific raw syscall wrappers are imported from the active impl.

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const Io = std.Io;
const protocol = @import("../protocol.zig");
const impl = if (builtin.os.tag == .linux) @import("linux.zig") else @import("bsd.zig");

/// Format into either an allocator (returns owned slice) or a `[]u8` buffer (returns sub-slice).
pub fn print(out: anytype, comptime fmt: []const u8, args: anytype) ![]const u8 {
    if (@TypeOf(out) == std.mem.Allocator)
        return std.fmt.allocPrint(out, fmt, args)
    else
        return std.fmt.bufPrint(out, fmt, args) catch error.NameTooLong;
}

// I/O — on POSIX, sockets are fds.
pub fn socketWrite(fd: posix.socket_t, buf: []const u8) void { impl.write(fd, buf); }
pub fn close(fd: posix.fd_t) void { impl.rawClose(fd); }
/// Half-close the sending side; the peer reads EOF once buffered data drains.
pub fn shutdownWrite(fd: posix.socket_t) void {
    _ = posix.system.shutdown(fd, posix.system.SHUT.WR);
}
pub fn socketRead(fd: posix.socket_t, buf: []u8) usize {
    return posix.read(fd, buf) catch |err| {
        @branchHint(.cold);
        if (err != error.ConnectionResetByPeer)
            std.debug.print("socketRead error: {}\n", .{err});
        return 0;
    };
}

// Local transport: AF_UNIX sockets, path-addressed within the socket directory.
// The directory is the runtime dir itself; a path must leave room for sun_path's NUL.
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
pub fn connectLocal(io: Io, path: []const u8) !posix.socket_t {
    if (path.len >= max_local_addr) return error.PathTooLong;
    const ua = try Io.net.UnixAddress.init(path);
    return (try ua.connect(io)).socket.handle;
}
/// Connect to a single-use local address and retire it, so nothing else can.
pub fn connectLocalOnce(io: Io, path: []const u8) !posix.socket_t {
    const fd = try connectLocal(io, path);
    Io.Dir.deleteFileAbsolute(io, path) catch {};
    return fd;
}
/// Connect with raw syscalls only, for use inside a signal handler; null on failure.
pub fn rawConnectLocal(path: []const u8) ?posix.socket_t {
    var addr = std.mem.zeroes(posix.sockaddr.un);
    addr.family = posix.AF.UNIX;
    if (path.len >= addr.path.len) return null;
    @memcpy(addr.path[0..path.len], path);
    const fd = impl.rawSocket(posix.AF.UNIX, posix.SOCK.STREAM) orelse return null;
    if (impl.rawConnect(fd, @ptrCast(&addr), @sizeOf(posix.sockaddr.un))) return fd;
    impl.rawClose(fd);
    return null;
}

/// A listening socket and its address. Accepting yields a plain socket handle;
/// `close` also unlinks a local socket's path.
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
    /// Accept the connection an event loop reported waiting.
    pub fn accept(self: *Listener, io: Io) !posix.socket_t {
        return (try self.server.accept(io)).socket.handle;
    }
    /// Accept a connection arriving within `timeout_ms` (0: one already waiting); null when none does.
    pub fn acceptTimeout(self: *Listener, io: Io, timeout_ms: i32) !?posix.socket_t {
        var pfd = [_]posix.pollfd{.{ .fd = self.fd(), .events = posix.POLL.IN, .revents = 0 }};
        if (try posix.poll(&pfd, timeout_ms) == 0) return null;
        return try self.accept(io);
    }
    pub fn close(self: *Listener, io: Io) void {
        self.server.deinit(io);
        if (self.mode == .local) Io.Dir.deleteFileAbsolute(io, self.addr()) catch {};
    }
};

// Process helpers
/// Start a worker in its own process group, so a terminal SIGINT reaches only
/// the conductor, with stdio inherited (the service manager's fds suit libuv).
pub fn spawnWorker(io: Io, argv: []const []const u8) !std.process.Child {
    return std.process.spawn(io, .{ .argv = argv, .pgid = 0 });
}
pub fn getChildPid(child: anytype) @TypeOf(child.id orelse 0) {
    return child.id orelse 0;
}
pub const WaitPidResult = struct { pid: posix.pid_t, exited: bool };
pub fn waitpidNonBlocking(pid: posix.pid_t) WaitPidResult {
    // ret > 0: reaped now; ret < 0: ECHILD (already gone); ret == 0: still alive.
    const ret = impl.rawWaitpid(pid);
    return .{ .pid = ret, .exited = ret != 0 };
}
// Peer credentials, mount namespaces, pidfds and the detached spawn exist only on
// Linux. Elsewhere they report "unavailable", so no client-spawned worker arises
// and no peer is ever refused.
const linux_only = if (builtin.os.tag == .linux) impl else struct {
    pub fn peerPid(_: posix.socket_t) ?posix.pid_t { return null; }
    pub fn peerForeignMountNs(_: posix.socket_t) ?u64 { return null; }
    pub fn peerMountNs(_: posix.socket_t) ?u64 { return null; }
    pub fn parentPid(_: posix.pid_t) ?posix.pid_t { return null; }
    pub fn pidfdOpen(_: posix.pid_t) ?posix.fd_t { return null; }
    pub fn pidfdSignal(_: posix.fd_t, _: posix.SIG) usize { return 1; }
    pub fn spawnDetached(_: [*:null]const ?[*:0]const u8, _: [*:null]const ?[*:0]const u8) !void { return error.SpawnUnsupported; }
};
/// Pid of a unix-socket peer as this process sees it; null when unavailable.
pub const peerPid = linux_only.peerPid;
/// Inode of the peer's mount namespace when it differs from ours; null when same or unknown.
pub const peerForeignMountNs = linux_only.peerForeignMountNs;
/// Inode of the peer's mount namespace; null when unavailable.
pub const peerMountNs = linux_only.peerMountNs;
/// Parent pid of a process; null when unreadable.
pub const parentPid = linux_only.parentPid;
/// Handle on a process that is not our child, immune to pid reuse; null when unsupported.
pub const pidfdOpen = linux_only.pidfdOpen;
/// Signal a process through its pidfd; 0 on success, like `kill`.
pub const pidfdSignal = linux_only.pidfdSignal;
/// A pidfd turns readable once its process has exited.
pub fn pidfdExited(fd: posix.fd_t) bool {
    var pfd = [_]posix.pollfd{.{ .fd = fd, .events = posix.POLL.IN, .revents = 0 }};
    return (posix.poll(&pfd, 0) catch return true) != 0;
}
/// Exec an absolute command as a daemon: own session, stdio on /dev/null, no
/// inherited fds. Fails before forking when the path is not executable here or
/// /dev/null cannot be opened.
pub const spawnDetached = linux_only.spawnDetached;

/// Per-process memory and cumulative CPU time, for status reporting and eviction
/// sizing. `mem_bytes` is resident set size on Linux, phys_footprint on macOS (the
/// reclaimable private memory — see `mem_is_reclaimable`). `cpu_seconds` is total
/// CPU consumed since the process started (user+system), not a rate.
pub const ProcessStats = struct { mem_bytes: u64, cpu_seconds: f64 };
pub const getProcessStats = impl.getProcessStats;
pub const getParentName = impl.getParentName;

/// True when `getProcessStats().mem_bytes` already reports the reclaimable
/// (USS-equivalent) figure, so eviction needs no separate `processReclaimable`
/// pass. macOS (phys_footprint); false on Linux (RSS, USS needs an smaps walk).
pub const mem_is_reclaimable = impl.mem_is_reclaimable;

/// Reclaimable (private) memory of a process in bytes — what killing it returns
/// to the OS (USS). Null where the OS exposes no private-page accounting, in
/// which case the caller falls back to RSS. Read on demand, never smoothed.
/// Only consulted where `mem_is_reclaimable` is false (Linux).
pub const processReclaimable = impl.processReclaimable;

/// Host memory-pressure sources, resolved per-OS. `readPsiSomeAvg10` is the
/// preferred stall signal (null where PSI is unavailable); `readMemInfo` is the
/// always-available free-memory level. No PSI on macOS/BSD (the level path is used);
/// the level path works on Linux/macOS/FreeBSD, null (inert) on OpenBSD/Windows.
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

pub fn setTcpNodelay(socket: posix.fd_t) void {
    // Raw call: the socket may already be closed (stdin at EOF), which std's
    // wrapper treats as unreachable.
    _ = posix.system.setsockopt(socket, 6, 1, std.mem.asBytes(&@as(c_int, 1)), @sizeOf(c_int)); // IPPROTO_TCP, TCP_NODELAY
}

// Terminal raw mode
var saved_termios: ?posix.termios = null;
pub fn setRawModeStdin(raw: bool) void { setRawMode(impl.STDIN_HANDLE, raw); }
pub fn setRawMode(stdin: posix.fd_t, raw: bool) void {
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
//
// Worker state tracking, reported over the signals socket: whether the client's
// terminal is raw (REPL reading input) or cooked, and whether user code is
// evaluating. The SIGINT handler routes on the latter.
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
            // \x03 only reaches LineEdit at the prompt; while code runs nothing is
            // reading stdin. Never coalesce: Julia's force-throw for tight loops
            // needs the repeated presses to accumulate.
            if (worker_raw and !worker_executing)
                handler.writeStdio("\x03")
            else
                handler.notifyInterrupt();
        },
        // SIGHUP (terminal closed) and SIGTERM both mean "leave now": tell the
        // conductor so it frees the worker, restore the terminal, then exit.
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
        .flags = 0, // No SA_RESTART: let io_uring submit_and_wait return EINTR promptly
    };
    posix.sigaction(posix.SIG.INT, &sigact, null);
    posix.sigaction(posix.SIG.TERM, &sigact, null);
    posix.sigaction(posix.SIG.HUP, &sigact, null);
    // Ignore SIGPIPE so writes to broken sockets return EPIPE instead of killing the process
    const pipe_act = posix.Sigaction{
        .handler = .{ .handler = posix.SIG.IGN },
        .mask = std.mem.zeroes(posix.sigset_t),
        .flags = 0,
    };
    posix.sigaction(posix.SIG.PIPE, &pipe_act, null);
}
