// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0
//
// POSIX platform implementation for BSD/Darwin using libc (std.c).

const std = @import("std");
const builtin = @import("builtin");
const c = std.c;
const posix = std.posix;

// Types
pub const fd_t = posix.fd_t;
pub const pid_t = c.pid_t;
pub const uid_t = c.uid_t;
pub const SIG = posix.SIG;

// Process information
pub const getuid = c.getuid;
pub const getpid = c.getpid;
pub const getppid = c.getppid;

// I/O - write needs wrapper for slice + return type conversion
pub fn write(fd: fd_t, buf: []const u8) usize {
    const ret = c.write(fd, buf.ptr, buf.len);
    return if (ret < 0) 0 else @intCast(ret);
}

// Process control - kill needs wrapper for return type conversion
pub fn kill(pid: pid_t, sig: SIG) usize {
    const ret = c.kill(pid, sig);
    return if (ret < 0) 1 else 0;
}

pub const WaitPidResult = struct { pid: pid_t, exited: bool };

pub fn waitpidNonBlocking(pid: pid_t) WaitPidResult {
    var status: c_int = 0;
    const ret = c.waitpid(pid, &status, 1); // WNOHANG = 1
    return .{ .pid = ret, .exited = ret == pid };
}

// Socket options
pub fn setRecvTimeout(socket: fd_t, seconds: u32) void {
    const timeout = c.timeval{ .sec = @intCast(seconds), .usec = 0 };
    const timeout_bytes = std.mem.asBytes(&timeout);
    _ = c.setsockopt(socket, posix.SOL.SOCKET, posix.SO.RCVTIMEO, timeout_bytes.ptr, @intCast(timeout_bytes.len));
}

// Terminal
pub fn getTerminalSize(fd: fd_t) ?struct { rows: u16, cols: u16 } {
    var ws: posix.winsize = undefined;
    if (c.ioctl(fd, @intCast(posix.T.IOCGWINSZ), @intFromPtr(&ws)) == 0) {
        return .{ .rows = ws.row, .cols = ws.col };
    }
    return null;
}

pub fn isatty(fd: fd_t) bool {
    return getTerminalSize(fd) != null;
}

// Paths
pub fn defaultRuntimeDir(allocator: std.mem.Allocator, xdg_runtime_dir: ?[]const u8, home: ?[]const u8) ![]const u8 {
    if (xdg_runtime_dir) |xdg| {
        return std.fmt.allocPrint(allocator, "{s}/julia-daemon", .{xdg});
    } else if (builtin.os.tag == .macos) {
        const home_dir = home orelse try getHomeDir();
        return std.fmt.allocPrint(allocator, "{s}/Library/Application Support/julia-daemon", .{home_dir});
    } else {
        return std.fmt.allocPrint(allocator, "/run/user/{d}/julia-daemon", .{c.getuid()});
    }
}

fn getHomeDir() ![]const u8 {
    var pwd: c.passwd = undefined;
    var result: ?*c.passwd = null;
    var buf: [1024]u8 = undefined;
    if (c.getpwuid_r(c.getuid(), &pwd, &buf, buf.len, &result) != 0 or result == null) {
        return error.HomeNotSet;
    }
    return std.mem.span(result.?.dir orelse return error.HomeNotSet);
}
