// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0
//
// BSD/Darwin platform — libc (std.c).
// Only raw primitives that differ from Linux live here; shared logic is in posix.zig.

const std = @import("std");
const builtin = @import("builtin");
const c = std.c;
const posix = std.posix;
const shared = @import("posix.zig");

// Constants
pub const SIG = posix.SIG;
pub const STDIN_HANDLE: posix.fd_t = posix.STDIN_FILENO;
pub const STDOUT_HANDLE: posix.fd_t = posix.STDOUT_FILENO;
pub const STDERR_HANDLE: posix.fd_t = posix.STDERR_FILENO;
pub const Timeval = c.timeval;

// Process info
pub const getpid = c.getpid;
pub const getppid = c.getppid;

// I/O — write wraps the libc call to take a slice and log errors.
pub fn write(fd: posix.fd_t, buf: []const u8) void {
    const ret = c.write(fd, buf.ptr, buf.len);
    if (ret < 0) {
        @branchHint(.cold);
        std.debug.print("write error on fd {}: {}\n", .{ fd, @as(posix.E, @enumFromInt(c._errno().*)) });
    }
}

// Raw syscall primitives used by posix.zig shared implementations
pub fn kill(pid: posix.pid_t, sig: SIG) usize {
    const ret = c.kill(pid, sig);
    return if (ret < 0) 1 else 0;
}
pub fn rawWaitpid(pid: posix.pid_t) posix.pid_t {
    var status: c_int = 0;
    return c.waitpid(pid, &status, 1); // WNOHANG = 1
}
pub fn rawIoctl(fd: posix.fd_t, request: anytype, arg: usize) usize {
    const ret = c.ioctl(fd, @intCast(request), arg);
    return if (ret < 0) 1 else 0;
}

// Network — check if a sockaddr is a loopback address
pub fn isLoopback(addr: *const posix.sockaddr, addr_len: posix.socklen_t) bool {
    if (addr_len >= @sizeOf(posix.sockaddr.in) and addr.family == posix.AF.INET) {
        const in: *const posix.sockaddr.in = @ptrCast(@alignCast(addr));
        const ip_bytes: [4]u8 = @bitCast(in.addr);
        return ip_bytes[0] == 127;
    }
    if (addr_len >= @sizeOf(posix.sockaddr.in6) and addr.family == posix.AF.INET6) {
        const in6: *const posix.sockaddr.in6 = @ptrCast(@alignCast(addr));
        const loopback = [16]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
        const v4mapped_prefix = [12]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };
        if (std.mem.eql(u8, &in6.addr, &loopback)) return true;
        if (std.mem.eql(u8, in6.addr[0..12], &v4mapped_prefix)) return in6.addr[12] == 127;
    }
    return false;
}

// Paths — BSD/macOS-specific default runtime directory
pub fn defaultRuntimeDir(out: anytype, xdg_runtime_dir: ?[]const u8, home: ?[]const u8) ![]const u8 {
    if (xdg_runtime_dir) |xdg|
        return shared.print(out, "{s}/julia-daemon", .{xdg});
    if (builtin.os.tag == .macos) {
        const home_dir = home orelse blk: {
            var pwd: c.passwd = undefined;
            var pw_result: ?*c.passwd = null;
            var pw_buf: [1024]u8 = undefined;
            if (c.getpwuid_r(c.getuid(), &pwd, &pw_buf, pw_buf.len, &pw_result) != 0 or pw_result == null)
                return error.HomeNotSet;
            break :blk std.mem.span(pw_result.?.dir orelse return error.HomeNotSet);
        };
        return shared.print(out, "{s}/Library/Application Support/julia-daemon", .{home_dir});
    }
    return shared.print(out, "/tmp/julia-daemon-{d}", .{c.getuid()});
}
