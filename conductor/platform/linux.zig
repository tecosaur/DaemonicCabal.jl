// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0
//
// Linux platform implementation using direct syscalls (std.os.linux).

const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;

// Types
pub const fd_t = posix.fd_t;
pub const pid_t = linux.pid_t;
pub const uid_t = linux.uid_t;
pub const SIG = posix.SIG;

// Process information
pub const getuid = linux.getuid;
pub const getpid = linux.getpid;
pub const getppid = linux.getppid;

// I/O - write needs a wrapper to take a slice instead of ptr+len
pub fn write(fd: fd_t, buf: []const u8) usize {
    return linux.write(fd, buf.ptr, buf.len);
}

// Process control
pub const kill = linux.kill;

pub const WaitPidResult = struct { pid: pid_t, exited: bool };

pub fn waitpidNonBlocking(pid: pid_t) WaitPidResult {
    var status: u32 = 0;
    const ret = linux.waitpid(pid, &status, linux.W.NOHANG);
    return .{
        .pid = @intCast(@as(isize, @bitCast(ret))),
        .exited = ret == @as(usize, @intCast(pid)),
    };
}

// Socket options
pub fn setRecvTimeout(socket: fd_t, seconds: u32) void {
    const timeout = linux.timeval{ .sec = @intCast(seconds), .usec = 0 };
    const timeout_bytes = std.mem.asBytes(&timeout);
    _ = linux.setsockopt(socket, posix.SOL.SOCKET, posix.SO.RCVTIMEO, timeout_bytes.ptr, timeout_bytes.len);
}

// Terminal
pub fn getTerminalSize(fd: fd_t) ?struct { rows: u16, cols: u16 } {
    var ws: posix.winsize = undefined;
    if (linux.ioctl(fd, posix.T.IOCGWINSZ, @intFromPtr(&ws)) == 0) {
        return .{ .rows = ws.row, .cols = ws.col };
    }
    return null;
}

pub fn isatty(fd: fd_t) bool {
    return getTerminalSize(fd) != null;
}

// Paths
pub fn defaultRuntimeDir(allocator: std.mem.Allocator, xdg_runtime_dir: ?[]const u8, _: ?[]const u8) ![]const u8 {
    if (xdg_runtime_dir) |xdg| {
        return std.fmt.allocPrint(allocator, "{s}/julia-daemon", .{xdg});
    }
    return std.fmt.allocPrint(allocator, "/run/user/{d}/julia-daemon", .{linux.getuid()});
}
