// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0
//
// Linux platform — direct syscalls (std.os.linux).
// Only raw primitives that differ from BSD live here; shared logic is in posix.zig.

const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const shared = @import("posix.zig");

// Constants
pub const SIG = posix.SIG;
pub const STDIN_HANDLE: posix.fd_t = posix.STDIN_FILENO;
pub const STDOUT_HANDLE: posix.fd_t = posix.STDOUT_FILENO;
pub const Timeval = linux.timeval;

// Process info
pub const getpid = linux.getpid;
pub const getppid = linux.getppid;

// I/O — write wraps the raw syscall to take a slice and log errors.
pub fn write(fd: posix.fd_t, buf: []const u8) void {
    const rc = linux.write(fd, buf.ptr, buf.len);
    const signed: isize = @bitCast(rc);
    if (signed < 0) {
        @branchHint(.cold);
        std.debug.print("write error on fd {}: {}\n", .{ fd, @as(linux.E, @enumFromInt(@as(u16, @intCast(-signed)))) });
    }
}

// Raw syscall primitives used by posix.zig shared implementations
pub const kill = linux.kill;
pub fn rawWaitpid(pid: posix.pid_t) posix.pid_t {
    var status: u32 = 0;
    const ret = linux.waitpid(pid, &status, linux.W.NOHANG);
    return @intCast(@as(isize, @bitCast(ret)));
}
pub fn rawIoctl(fd: posix.fd_t, request: anytype, arg: usize) usize {
    return linux.ioctl(fd, request, arg);
}

// Paths — Linux-specific default runtime directory
pub fn defaultRuntimeDir(out: anytype, xdg_runtime_dir: ?[]const u8, _: ?[]const u8) ![]const u8 {
    if (xdg_runtime_dir) |xdg|
        return shared.print(out, "{s}/julia-daemon", .{xdg});
    return shared.print(out, "/run/user/{d}/julia-daemon", .{linux.getuid()});
}
