// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0
//
// Shared POSIX platform code used by both linux.zig and bsd.zig.
// Platform-specific raw syscall wrappers are imported from the active impl.

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
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
pub fn socketRead(fd: posix.socket_t, buf: []u8) usize {
    return posix.read(fd, buf) catch |err| {
        @branchHint(.cold);
        if (err != error.ConnectionResetByPeer)
            std.debug.print("socketRead error: {}\n", .{err});
        return 0;
    };
}

// Process helpers
pub fn getChildPid(child: anytype) @TypeOf(child.id orelse 0) {
    return child.id orelse 0;
}
pub const WaitPidResult = struct { pid: posix.pid_t, exited: bool };
pub fn waitpidNonBlocking(pid: posix.pid_t) WaitPidResult {
    const ret = impl.rawWaitpid(pid);
    return .{ .pid = ret, .exited = ret == pid };
}

/// Per-process memory and cumulative CPU time, for status reporting and eviction
/// sizing. `rss_bytes` is resident set size on Linux, but phys_footprint on macOS
/// (the reclaimable private memory — see `mem_is_reclaimable`). `cpu_seconds` is
/// total CPU consumed since the process started (user+system), not a rate.
pub const ProcessStats = struct { rss_bytes: u64, cpu_seconds: f64 };
pub const getProcessStats = impl.getProcessStats;
pub const getParentName = impl.getParentName;

/// True when `getProcessStats().rss_bytes` already reports the reclaimable
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
// Worker raw mode tracking: the worker toggles the client's terminal between
// raw mode (REPL reading input) and cooked mode (code executing) via the
// signals socket. This flag tracks the worker's intent so the SIGINT handler
// can choose the right path — write \x03 to stdin (raw/REPL) or send an
// interrupt notification via the conductor (cooked/executing).
var worker_raw: bool = false;
pub fn setWorkerRawMode(raw: bool) void { worker_raw = raw; }
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
            // In raw mode the REPL is reading input — \x03 triggers LineEdit's ^C binding.
            // In cooked mode code is executing — route through the conductor to deliver
            // InterruptException to the running task.
            if (worker_raw)
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
