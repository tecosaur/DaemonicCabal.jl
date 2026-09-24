// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0
//
// BSD/Darwin platform primitives, over libc; shared logic is in posix.zig.

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

// I/O
pub fn write(fd: posix.fd_t, buf: []const u8) void {
    var written: usize = 0;
    while (written < buf.len) {
        const ret = c.write(fd, buf.ptr + written, buf.len - written);
        if (ret < 0) {
            @branchHint(.cold);
            const e = @as(posix.E, @enumFromInt(c._errno().*));
            if (e == .INTR) continue;
            shared.eprint("write error on fd {d}: errno {d}\n", .{ fd, @intFromEnum(e) });
            return;
        }
        if (ret == 0) return; // no progress; avoid spinning
        written += @intCast(ret);
    }
}

// Raw primitives
pub fn kill(pid: posix.pid_t, sig: SIG) usize {
    const ret = c.kill(pid, sig);
    return if (ret < 0) 1 else 0;
}

pub fn rawWaitpid(pid: posix.pid_t, block: bool) posix.pid_t {
    var status: c_int = 0;
    return c.waitpid(pid, &status, if (block) 0 else 1); // WNOHANG = 1
}
// Width varies by sysctl, so read into the widest and zero-extend.
fn sysctlUint(comptime name: [:0]const u8) ?u64 {
    var val: u64 = 0;
    var len: usize = @sizeOf(u64);
    if (c.sysctlbyname(name, &val, &len, null, 0) != 0) return null;
    return switch (len) {
        8 => val,
        4 => @as(u32, @truncate(val)),
        else => null,
    };
}

// macOS phys_footprint is already the reclaimable figure.
pub const mem_is_reclaimable = builtin.os.tag == .macos;

// proc_pid_rusage, as task_for_pid is denied to unprivileged callers.
// phys_footprint excludes the shared sysimage pages every worker maps.
// FreeBSD/OpenBSD: null, their kinfo_proc ABI being unverifiable.
pub fn getProcessStats(pid: posix.pid_t) ?shared.ProcessStats {
    if (builtin.os.tag != .macos) return null;
    const ru = darwinRusage(pid) orelse return null;
    const cpu_ns: f64 = @floatFromInt(machToNanos(ru.ri_user_time + ru.ri_system_time));
    return .{ .mem_bytes = ru.ri_phys_footprint, .cpu_seconds = cpu_ns / 1_000_000_000.0 };
}

// Mach time units: 1:1 with ns on Intel, 125:3 on Apple Silicon.
var timebase: ?c.mach_timebase_info_data = null;
fn machToNanos(ticks: u64) u64 {
    const tb = timebase orelse blk: {
        var info: c.mach_timebase_info_data = .{ .numer = 1, .denom = 1 };
        _ = c.mach_timebase_info(&info);
        if (info.denom == 0) info = .{ .numer = 1, .denom = 1 };
        timebase = info;
        break :blk info;
    };
    return ticks * tb.numer / tb.denom;
}

pub fn processReclaimable(pid: posix.pid_t) ?u64 {
    if (builtin.os.tag != .macos) return null;
    const ru = darwinRusage(pid) orelse return null;
    return ru.ri_phys_footprint;
}

// rusage_info_v0 from <libproc.h>; the kernel fills it by offset.
const RUSAGE_INFO_V0: c_int = 0;
const rusage_info_v0 = extern struct {
    ri_uuid: [16]u8,
    ri_user_time: u64,
    ri_system_time: u64,
    ri_pkg_idle_wkups: u64,
    ri_interrupt_wkups: u64,
    ri_pageins: u64,
    ri_wired_size: u64,
    ri_resident_size: u64,
    ri_phys_footprint: u64,
    ri_proc_start_abstime: u64,
    ri_proc_exit_abstime: u64,
};
extern "c" fn proc_pid_rusage(pid: c_int, flavor: c_int, buffer: *anyopaque) c_int;

fn darwinRusage(pid: posix.pid_t) ?rusage_info_v0 {
    if (builtin.os.tag != .macos) return null;
    var info: rusage_info_v0 = undefined;
    if (proc_pid_rusage(@intCast(pid), RUSAGE_INFO_V0, @ptrCast(&info)) != 0) return null;
    return info;
}

pub const MemInfo = struct { available: u64, total: u64 };

pub fn readPsiSomeAvg10() ?f64 {
    return null;
}

pub fn readMemInfo() ?MemInfo {
    return switch (builtin.os.tag) {
        .macos => darwinMemInfo(),
        .freebsd => blk: {
            const page = shared_page_size();
            const free = sysctlUint("vm.stats.vm.v_free_count") orelse break :blk null;
            const inactive = sysctlUint("vm.stats.vm.v_inactive_count") orelse 0;
            const cache = sysctlUint("vm.stats.vm.v_cache_count") orelse 0;
            const total = sysctlUint("hw.physmem") orelse break :blk null;
            break :blk MemInfo{ .available = (free + inactive + cache) * page, .total = total };
        },
        else => null, // OpenBSD/NetBSD: uvmexp not name-addressable
    };
}

const shared_page_size = std.heap.pageSize;

// macOS keeps little truly free, so count inactive, purgeable and external too.
const HOST_VM_INFO64: c_int = 4;
// <mach/vm_statistics.h>; @sizeOf/4 must equal HOST_VM_INFO64_COUNT (38).
const vm_statistics64 = extern struct {
    free_count: u32,
    active_count: u32,
    inactive_count: u32,
    wire_count: u32,
    zero_fill_count: u64,
    reactivations: u64,
    pageins: u64,
    pageouts: u64,
    faults: u64,
    cow_faults: u64,
    lookups: u64,
    hits: u64,
    purges: u64,
    purgeable_count: u32,
    speculative_count: u32,
    decompressions: u64,
    compressions: u64,
    swapins: u64,
    swapouts: u64,
    compressor_page_count: u32,
    throttled_count: u32,
    external_page_count: u32,
    internal_page_count: u32,
    total_uncompressed_pages_in_compressor: u64,
};

extern "c" fn host_statistics64(host: c.mach_port_t, flavor: c_int, info: *anyopaque, count: *c.mach_msg_type_number_t) c.kern_return_t;

fn darwinMemInfo() ?MemInfo {
    if (builtin.os.tag != .macos) return null;
    var vm: vm_statistics64 = undefined;
    var count: c.mach_msg_type_number_t = @sizeOf(vm_statistics64) / @sizeOf(u32);
    if (host_statistics64(c.mach_host_self(), HOST_VM_INFO64, @ptrCast(&vm), &count) != 0) return null;
    const total = sysctlUint("hw.memsize") orelse return null;
    const page = shared_page_size();
    const reclaimable = @as(u64, vm.free_count) + vm.inactive_count + vm.purgeable_count + vm.external_page_count;
    return .{ .available = reclaimable * page, .total = total };
}
pub fn getParentName(_: posix.pid_t, _: []u8) ?[]const u8 {
    return null;
}
pub fn rawIoctl(fd: posix.fd_t, request: anytype, arg: usize) usize {
    const ret = c.ioctl(fd, @intCast(request), arg);
    return if (ret < 0) 1 else 0;
}
pub fn rawClose(fd: posix.fd_t) void {
    _ = c.close(fd);
}
pub fn rawSocket(family: u32, sock_type: u32) ?posix.fd_t {
    const rc = c.socket(@intCast(family), @intCast(sock_type), 0);
    return if (rc >= 0) rc else null;
}
pub fn rawConnect(fd: posix.fd_t, addr: *const posix.sockaddr, len: posix.socklen_t) bool {
    return c.connect(fd, addr, len) == 0;
}


// Paths
pub fn defaultRuntimeDir(out: anytype, xdg_runtime_dir: ?[]const u8, home: ?[]const u8) ![]const u8 {
    if (builtin.os.tag == .macos) {
        // A macOS XDG_RUNTIME_DIR is often a sandbox-private path other
        // processes can't reach.
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
    if (xdg_runtime_dir) |xdg|
        return shared.print(out, "{s}/julia-daemon", .{xdg});
    return shared.print(out, "/tmp/julia-daemon-{d}", .{c.getuid()});
}

pub fn currentDir(buf: []u8) ![]const u8 {
    const cwd = c.getcwd(buf.ptr, buf.len) orelse return error.CurrentDirUnavailable;
    return std.mem.sliceTo(@as([*:0]u8, @ptrCast(cwd)), 0);
}

const IpAddress = std.Io.net.IpAddress;

pub fn lookupHost(name: []const u8, port: u16, buf: []IpAddress) ![]IpAddress {
    var name_buf: [256]u8 = undefined;
    const name_z = std.fmt.bufPrintZ(&name_buf, "{s}", .{name}) catch return error.InvalidAddress;
    const hints = std.mem.zeroInit(c.addrinfo, .{ .socktype = posix.SOCK.STREAM });
    var res: ?*c.addrinfo = null;
    const rc = c.getaddrinfo(name_z, null, &hints, &res);
    if (@intFromEnum(rc) != 0) return if (rc == .NONAME) error.UnknownHostName else error.LookupFailed;
    defer c.freeaddrinfo(res.?);
    var n: usize = 0;
    var next = res;
    while (next) |ai| : (next = ai.next) {
        const sa = ai.addr orelse continue;
        if (sa.family != posix.AF.INET and sa.family != posix.AF.INET6) continue;
        var storage: std.Io.Threaded.PosixAddress = undefined;
        @memcpy(std.mem.asBytes(&storage)[0..ai.addrlen], @as([*]const u8, @ptrCast(sa))[0..ai.addrlen]);
        var ip = std.Io.Threaded.addressFromPosix(&storage);
        ip.setPort(port);
        if (n < buf.len) {
            buf[n] = ip;
            n += 1;
        }
    }
    return if (n == 0) error.UnknownHostName else buf[0..n];
}
