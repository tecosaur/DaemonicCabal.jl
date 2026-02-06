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
pub const SignalHandler = struct {
    sockets_ptr: *anyopaque,
    write_fn: *const fn (*anyopaque, []const u8) void,
    notify_exit_fn: *const fn () void,
    pub fn writeStdio(self: SignalHandler, data: []const u8) void {
        self.write_fn(self.sockets_ptr, data);
    }
    pub fn notifyExit(self: SignalHandler) void {
        self.notify_exit_fn();
    }
};
var g_signal_handler: ?SignalHandler = null;
fn signalAction(sig: posix.SIG, _: *const posix.siginfo_t, _: ?*anyopaque) callconv(.c) void {
    const handler = g_signal_handler orelse return;
    switch (sig) {
        .INT => handler.writeStdio("\x03"),
        .TERM => {
            handler.notifyExit();
            std.process.exit(128 + @intFromEnum(posix.SIG.TERM));
        },
        else => {},
    }
}
pub fn registerSignalHandlers(handler: SignalHandler) void {
    g_signal_handler = handler;
    var mask = std.mem.zeroes(posix.sigset_t);
    posix.sigaddset(&mask, posix.SIG.INT);
    posix.sigaddset(&mask, posix.SIG.TERM);
    const sigact = posix.Sigaction{
        .handler = .{ .sigaction = signalAction },
        .mask = mask,
        .flags = 0,
    };
    posix.sigaction(posix.SIG.INT, &sigact, null);
    posix.sigaction(posix.SIG.TERM, &sigact, null);
}
