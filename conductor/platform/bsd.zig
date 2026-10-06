// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0
//
// BSD/Darwin platform primitives, over libc; shared logic is in posix.zig.

const std = @import("std");
const builtin = @import("builtin");
const c = std.c;
const posix = std.posix;
const shared = @import("posix.zig");

/// OpenBSD sets these only system-wide.
pub const tcp_keepalive_options: ?[3]u32 = switch (builtin.target.os.tag) {
    .macos => .{ c.TCP.KEEPALIVE, c.TCP.KEEPINTVL, c.TCP.KEEPCNT },
    .freebsd => .{ 256, 512, 1024 }, // netinet/tcp.h
    else => null,
};

// Constants
pub const SIG = posix.SIG;
/// Asks a Julia process for its stacks and a profile (`Profile.peek_report`).
pub const peek_signal: ?SIG = .INFO;
pub const STDIN_HANDLE: posix.fd_t = posix.STDIN_FILENO;
pub const STDOUT_HANDLE: posix.fd_t = posix.STDOUT_FILENO;
pub const STDERR_HANDLE: posix.fd_t = posix.STDERR_FILENO;

// Process info
pub const getpid = c.getpid;
pub const getppid = c.getppid;
pub const geteuid = c.geteuid;

// I/O
pub fn write(fd: posix.fd_t, buf: []const u8) void {
    if (!writeAll(fd, buf)) shared.eprint("write error on fd {d}\n", .{fd});
}

/// Whether all of `buf` was written: false once `fd` refuses it, its reader
/// gone, say. Waits out a non-blocking `fd` that is full.
pub fn writeAll(fd: posix.fd_t, buf: []const u8) bool {
    var written: usize = 0;
    while (written < buf.len) {
        const ret = c.write(fd, buf.ptr + written, buf.len - written);
        if (ret < 0) {
            @branchHint(.cold);
            switch (@as(posix.E, @enumFromInt(c._errno().*))) {
                .INTR => continue,
                .AGAIN => {
                    var pfd = [_]posix.pollfd{.{ .fd = fd, .events = posix.POLL.OUT, .revents = 0 }};
                    _ = posix.poll(&pfd, -1) catch return false;
                    continue;
                },
                else => return false,
            }
        }
        if (ret == 0) return false; // no progress; avoid spinning
        written += @intCast(ret);
    }
    return true;
}

// kqueue, for the event loops
// Some BSDs lack these in Zig's bindings.
pub const EV_EOF: u16 = if (@hasDecl(c.EV, "EOF")) c.EV.EOF else 0x8000;
pub const EV_ERROR: u16 = if (@hasDecl(c.EV, "ERROR")) c.EV.ERROR else 0x4000;

pub fn makeKevent(ident: usize, filter: i16, flags: u16, fflags: u32, data: isize, udata: usize) c.Kevent {
    return .{ .ident = ident, .filter = filter, .flags = flags, .fflags = fflags, .data = data, .udata = udata };
}

/// -1 on error; a null `timeout` waits indefinitely.
pub fn keventCall(kq: posix.fd_t, changelist: []const c.Kevent, eventlist: []c.Kevent, timeout: ?*const c.timespec) c_int {
    return c.kevent(kq, changelist.ptr, @intCast(changelist.len), eventlist.ptr, @intCast(eventlist.len), timeout);
}

// Raw primitives
pub fn kill(pid: posix.pid_t, sig: SIG) usize {
    const ret = c.kill(pid, sig);
    return if (ret < 0) 1 else 0;
}

pub fn rawWaitpid(pid: posix.pid_t, block: bool) posix.pid_t {
    var status: u32 = 0;
    return rawWaitpidStatus(pid, block, &status);
}
pub fn rawWaitpidStatus(pid: posix.pid_t, block: bool, status: *u32) posix.pid_t {
    return c.waitpid(pid, @ptrCast(status), if (block) 0 else 1); // WNOHANG = 1
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
pub const mem_is_reclaimable = builtin.target.os.tag == .macos;

// proc_pid_rusage, as task_for_pid is denied to unprivileged callers.
// phys_footprint excludes the shared sysimage pages every worker maps.
// FreeBSD/OpenBSD: null, their kinfo_proc ABI being unverifiable.
pub fn getProcessStats(pid: posix.pid_t) ?shared.ProcessStats {
    if (builtin.target.os.tag != .macos) return null;
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
    if (builtin.target.os.tag != .macos) return null;
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
    if (builtin.target.os.tag != .macos) return null;
    var info: rusage_info_v0 = undefined;
    if (proc_pid_rusage(@intCast(pid), RUSAGE_INFO_V0, @ptrCast(&info)) != 0) return null;
    return info;
}

pub const MemInfo = struct { available: u64, total: u64 };

pub fn readPsiSomeAvg10() ?f64 {
    return null;
}

pub fn readMemInfo() ?MemInfo {
    return switch (builtin.target.os.tag) {
        // The kernel's own free-memory percentage, as `memory_pressure` reports it:
        // page counts double-count file-backed pages sitting inactive.
        .macos => blk: {
            const level = sysctlUint("kern.memorystatus_level") orelse break :blk null;
            const total = sysctlUint("hw.memsize") orelse break :blk null;
            break :blk MemInfo{ .available = total / 100 * @min(level, 100), .total = total };
        },
        .freebsd => blk: {
            const page = std.heap.pageSize();
            const free = sysctlUint("vm.stats.vm.v_free_count") orelse break :blk null;
            const inactive = sysctlUint("vm.stats.vm.v_inactive_count") orelse 0;
            const cache = sysctlUint("vm.stats.vm.v_cache_count") orelse 0;
            const total = sysctlUint("hw.physmem") orelse break :blk null;
            break :blk MemInfo{ .available = (free + inactive + cache) * page, .total = total };
        },
        else => null, // OpenBSD/NetBSD: uvmexp not name-addressable
    };
}

pub fn ephemeralPorts() ?[2]u16 {
    return switch (builtin.target.os.tag) {
        .macos, .freebsd => .{
            std.math.cast(u16, sysctlUint("net.inet.ip.portrange.first") orelse return null) orelse return null,
            std.math.cast(u16, sysctlUint("net.inet.ip.portrange.last") orelse return null) orelse return null,
        },
        else => null, // OpenBSD's are under a MIB with no name to look it up by
    };
}

pub fn getParentName(pid: posix.pid_t, out: []u8) ?[]const u8 {
    if (builtin.target.os.tag != .macos) return null;
    const ppid = (darwinBsdInfo(pid) orelse return null).pbi_ppid;
    if (ppid == 0) return null;
    const parent = darwinBsdInfo(@intCast(ppid)) orelse return null;
    // The full name, where the command is cut at MAXCOMLEN.
    const field = if (parent.pbi_name[0] != 0) &parent.pbi_name else &parent.pbi_comm;
    const name = std.mem.sliceTo(field, 0);
    const n = @min(name.len, out.len);
    @memcpy(out[0..n], name[0..n]);
    return out[0..n];
}

// <sys/proc_info.h>; PROC_PIDTBSDINFO_SIZE is 136.
const PROC_PIDTBSDINFO: c_int = 3;
const proc_bsdinfo = extern struct {
    pbi_flags: u32,
    pbi_status: u32,
    pbi_xstatus: u32,
    pbi_pid: u32,
    pbi_ppid: u32,
    pbi_uid: u32,
    pbi_gid: u32,
    pbi_ruid: u32,
    pbi_rgid: u32,
    pbi_svuid: u32,
    pbi_svgid: u32,
    rfu_1: u32,
    pbi_comm: [16]u8,
    pbi_name: [32]u8,
    pbi_nfiles: u32,
    pbi_pgid: u32,
    pbi_pjobc: u32,
    e_tdev: u32,
    e_tpgid: u32,
    pbi_nice: i32,
    pbi_start_tvsec: u64,
    pbi_start_tvusec: u64,
};

comptime {
    std.debug.assert(@sizeOf(proc_bsdinfo) == 136);
}

extern "c" fn proc_pidinfo(pid: c_int, flavor: c_int, arg: u64, buffer: *anyopaque, buffersize: c_int) c_int;

fn darwinBsdInfo(pid: posix.pid_t) ?proc_bsdinfo {
    var info: proc_bsdinfo = undefined;
    if (proc_pidinfo(@intCast(pid), PROC_PIDTBSDINFO, 0, @ptrCast(&info), @sizeOf(proc_bsdinfo)) != @sizeOf(proc_bsdinfo)) return null;
    return info;
}
pub fn rawIoctl(fd: posix.fd_t, request: anytype, arg: usize) usize {
    const ret = c.ioctl(fd, @intCast(request), arg);
    return if (ret < 0) 1 else 0;
}
pub fn rawClose(fd: posix.fd_t) void {
    _ = c.close(fd);
}
/// Close-on-exec: macOS takes no SOCK_CLOEXEC, so it is set after. Zig
/// declares one there for its own wrappers' shim, which libc's socket() refuses.
pub fn rawSocket(family: u32, sock_type: u32) ?posix.fd_t {
    const cloexec_flag: u32 = if (@hasDecl(posix.SOCK, "CLOEXEC") and !builtin.target.os.tag.isDarwin()) posix.SOCK.CLOEXEC else 0;
    const rc = c.socket(@intCast(family), @intCast(sock_type | cloexec_flag), 0);
    if (rc < 0) return null;
    if (cloexec_flag == 0 and c.fcntl(rc, posix.F.SETFD, @as(c_int, posix.FD_CLOEXEC)) < 0) {
        _ = c.close(rc);
        return null;
    }
    return rc;
}
pub fn fileOwner(fd: posix.fd_t) ?struct { uid: posix.uid_t, mode: u32 } {
    var st: c.Stat = undefined;
    if (c.fstat(fd, &st) != 0) return null;
    return .{ .uid = st.uid, .mode = @intCast(st.mode) };
}


/// Past `max_bytes`, the log a launchd agent's stderr names (macOS gives an
/// fd's path) moves to `<path>.1`, and stdout and stderr go on in a new one.
pub fn rotateLog(max_bytes: u64) void {
    if (builtin.target.os.tag != .macos) return;
    var err_st: c.Stat = undefined;
    if (c.fstat(posix.STDERR_FILENO, &err_st) != 0 or !posix.S.ISREG(err_st.mode) or err_st.size <= max_bytes) return;
    var path_buf: [std.Io.Dir.max_path_bytes:0]u8 = @splat(0);
    if (c.fcntl(posix.STDERR_FILENO, c.F.GETPATH, &path_buf) == -1) return;
    var old_buf: [std.Io.Dir.max_path_bytes + 2:0]u8 = undefined;
    const old = std.mem.printSentinel(&old_buf, "{s}.1", .{std.mem.sliceTo(&path_buf, 0)}, 0) catch return;
    var out_st: c.Stat = undefined;
    const shares_stdout = c.fstat(posix.STDOUT_FILENO, &out_st) == 0 and out_st.dev == err_st.dev and out_st.ino == err_st.ino;
    if (c.rename(&path_buf, old) != 0) return;
    const fd = c.open(&path_buf, .{ .ACCMODE = .WRONLY, .CREAT = true, .APPEND = true, .CLOEXEC = true }, @as(c_uint, @intCast(err_st.mode & 0o777)));
    if (fd < 0) return;
    if (shares_stdout) _ = c.dup2(fd, posix.STDOUT_FILENO);
    _ = c.dup2(fd, posix.STDERR_FILENO);
    _ = c.close(fd);
}


// Paths
pub fn defaultRuntimeDir(out: anytype, xdg_runtime_dir: ?[]const u8, home: ?[]const u8) ![]const u8 {
    if (builtin.target.os.tag == .macos) {
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
    const name_z = std.mem.printSentinel(&name_buf, "{s}", .{name}, 0) catch return error.InvalidAddress;
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
