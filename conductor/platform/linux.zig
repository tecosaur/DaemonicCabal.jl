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
pub const STDERR_HANDLE: posix.fd_t = posix.STDERR_FILENO;
pub const Timeval = linux.timeval;

// Process info
pub const getpid = linux.getpid;
pub const getppid = linux.getppid;

// I/O — write wraps the raw syscall to take a slice and log errors.
// Loops until the whole buffer is written, as a single write() can be short.
pub fn write(fd: posix.fd_t, buf: []const u8) void {
    var written: usize = 0;
    while (written < buf.len) {
        const rc = linux.write(fd, buf.ptr + written, buf.len - written);
        const signed: isize = @bitCast(rc);
        if (signed < 0) {
            @branchHint(.cold);
            const e = @as(linux.E, @enumFromInt(@as(u16, @intCast(-signed))));
            if (e == .INTR) continue;
            std.debug.print("write error on fd {}: {}\n", .{ fd, e });
            return;
        }
        if (signed == 0) return; // no progress; avoid spinning
        written += @intCast(signed);
    }
}

// Raw syscall primitives used by posix.zig shared implementations
pub const kill = linux.kill;

/// A pidfd turns readable once its process has exited.
pub fn pidfdExited(fd: posix.fd_t) bool {
    var pfd = [_]posix.pollfd{.{ .fd = fd, .events = posix.POLL.IN, .revents = 0 }};
    return (posix.poll(&pfd, 0) catch return true) != 0;
}
pub fn pidfdOpen(pid: posix.pid_t) ?posix.fd_t {
    const rc = linux.pidfd_open(pid, 0);
    return if (linux.errno(rc) == .SUCCESS) @intCast(rc) else null;
}

pub fn pidfdSignal(fd: posix.fd_t, sig: SIG) usize {
    return linux.pidfd_send_signal(fd, sig, null, 0);
}

fn canExec(path: [*:0]const u8) bool {
    return linux.faccessat(linux.AT.FDCWD, path, linux.X_OK, 0) == 0;
}

pub fn peerPid(socket: posix.socket_t) ?posix.pid_t {
    var cred: extern struct { pid: posix.pid_t, uid: posix.uid_t, gid: posix.gid_t } = undefined;
    var len: posix.socklen_t = @sizeOf(@TypeOf(cred));
    if (linux.getsockopt(socket, linux.SOL.SOCKET, linux.SO.PEERCRED, @ptrCast(&cred), &len) != 0) return null;
    return if (cred.pid != 0) cred.pid else null; // zeros on a TCP socket
}

var own_mount_ns: ?u64 = null; // ours never changes; read once
pub fn peerMountNs(socket: posix.socket_t) ?u64 {
    return mountNsInode(peerPid(socket) orelse return null);
}

pub fn peerForeignMountNs(socket: posix.socket_t) ?u64 {
    const peer = peerMountNs(socket) orelse return null;
    const own = own_mount_ns orelse (mountNsInode(linux.getpid()) orelse return null);
    own_mount_ns = own;
    return if (peer == own) null else peer;
}

/// Forked twice so the parent is init, not the caller: the worker's parent-death
/// signal then means "die with the sandbox".
pub fn spawnDetached(argv: [*:null]const ?[*:0]const u8, envp: [*:null]const ?[*:0]const u8) !void {
    // Checked here: a missing executable or /dev/null in the grandchild would die unwatched.
    const exe = argv[0].?;
    if (!canExec(exe)) return error.ExecutableNotFound;
    const devnull_rc = linux.open("/dev/null", .{ .ACCMODE = .RDWR }, 0);
    if (linux.errno(devnull_rc) != .SUCCESS) return error.DevNullUnavailable;
    const devnull: i32 = @intCast(devnull_rc);
    defer _ = linux.close(devnull);
    const pid = linux.fork();
    if (linux.errno(pid) != .SUCCESS) return error.ForkFailed;
    if (pid != 0) {
        var status: u32 = 0;
        _ = linux.waitpid(@intCast(pid), &status, 0); // the intermediate exits at once
        return;
    }
    _ = linux.setsid();
    const grandchild = linux.fork();
    if (linux.errno(grandchild) != .SUCCESS) linux.exit_group(1);
    if (grandchild != 0) linux.exit_group(0);
    for (0..3) |fd| _ = linux.dup2(devnull, @intCast(fd));
    _ = linux.close_range(3, std.math.maxInt(i32), .{ .UNSHARE = false, .CLOEXEC = false });
    _ = linux.execve(exe, argv, envp);
    linux.exit_group(127);
}

// The link reads "mnt:[4026531841]".
fn mountNsInode(pid: posix.pid_t) ?u64 {
    var path_buf: [64]u8 = undefined;
    var link_buf: [64]u8 = undefined;
    const path = std.fmt.bufPrintZ(&path_buf, "/proc/{d}/ns/mnt", .{pid}) catch return null;
    const n = linux.readlink(path, &link_buf, link_buf.len);
    if (n == 0 or n > link_buf.len) return null;
    const link = link_buf[0..n];
    const open = std.mem.indexOfScalar(u8, link, '[') orelse return null;
    const close = std.mem.indexOfScalar(u8, link, ']') orelse return null;
    return std.fmt.parseInt(u64, link[open + 1 .. close], 10) catch null;
}
pub fn rawWaitpid(pid: posix.pid_t) posix.pid_t {
    var status: u32 = 0;
    const ret = linux.waitpid(pid, &status, linux.W.NOHANG);
    return @intCast(@as(isize, @bitCast(ret)));
}
pub fn rawIoctl(fd: posix.fd_t, request: anytype, arg: usize) usize {
    return linux.ioctl(fd, request, arg);
}
pub fn rawClose(fd: posix.fd_t) void {
    _ = linux.close(fd);
}
pub fn rawSocket(family: u32, sock_type: u32) ?posix.fd_t {
    const rc = linux.socket(family, sock_type | linux.SOCK.CLOEXEC, 0);
    const signed: isize = @bitCast(rc);
    return if (signed >= 0) @intCast(signed) else null;
}
pub fn rawConnect(fd: posix.fd_t, addr: *const posix.sockaddr, len: posix.socklen_t) bool {
    return @as(isize, @bitCast(linux.connect(fd, addr, len))) == 0;
}

// Network — check if a sockaddr is a loopback address
pub fn isLoopback(addr: *const posix.sockaddr, addr_len: posix.socklen_t) bool {
    if (addr_len >= @sizeOf(posix.sockaddr.in) and addr.family == posix.AF.INET) {
        const in: *const posix.sockaddr.in = @ptrCast(@alignCast(addr));
        // 127.0.0.0/8 in network byte order: first byte is 127
        const ip_bytes: [4]u8 = @bitCast(in.addr);
        return ip_bytes[0] == 127;
    }
    if (addr_len >= @sizeOf(posix.sockaddr.in6) and addr.family == posix.AF.INET6) {
        const in6: *const posix.sockaddr.in6 = @ptrCast(@alignCast(addr));
        // ::1 in network byte order
        const loopback = [16]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
        // Also check IPv4-mapped ::ffff:127.x.x.x
        const v4mapped_prefix = [12]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };
        if (std.mem.eql(u8, &in6.addr, &loopback)) return true;
        if (std.mem.eql(u8, in6.addr[0..12], &v4mapped_prefix)) return in6.addr[12] == 127;
    }
    return false;
}

// Read a file into `buf`, returning the bytes read (null if unopenable).
fn readFile(path: [*:0]const u8, buf: []u8) ?[]const u8 {
    const fd_rc = linux.openat(linux.AT.FDCWD, path, .{ .ACCMODE = .RDONLY }, 0);
    const fd_signed: isize = @bitCast(fd_rc);
    if (fd_signed < 0) return null;
    const fd: posix.fd_t = @intCast(fd_signed);
    defer _ = linux.close(fd);
    var total: usize = 0;
    while (total < buf.len) {
        const n: isize = @bitCast(linux.read(fd, buf[total..].ptr, buf[total..].len));
        if (n <= 0) break;
        total += @intCast(n);
    }
    return buf[0..total];
}

fn readProc(comptime fmt: []const u8, pid: posix.pid_t, buf: []u8) ?[]const u8 {
    var path_buf: [64]u8 = undefined;
    const path = std.fmt.bufPrintZ(&path_buf, fmt, .{pid}) catch return null;
    return readFile(path.ptr, buf);
}

// The command name of `pid`'s parent process, copied into `out`. Resolves the
// parent pid from /proc/<pid>/stat (field 4), then reads /proc/<ppid>/comm.
// Returns null if either step fails (e.g. a remote client with no local /proc).
pub fn getParentName(pid: posix.pid_t, out: []u8) ?[]const u8 {
    const ppid = parentPid(pid) orelse return null;
    const comm = readProc("/proc/{d}/comm", ppid, out) orelse return null;
    return std.mem.trimEnd(u8, comm, "\n");
}

// Field 4 of /proc/<pid>/stat, parsed from after the final ')' so a comm string
// containing spaces or parens is skipped.
pub fn parentPid(pid: posix.pid_t) ?posix.pid_t {
    var buf: [256]u8 = undefined;
    const content = readProc("/proc/{d}/stat", pid, &buf) orelse return null;
    const close_paren = std.mem.lastIndexOfScalar(u8, content, ')') orelse return null;
    var fields = std.mem.tokenizeScalar(u8, content[close_paren + 1 ..], ' ');
    _ = fields.next() orelse return null; // field 3: state
    const ppid = std.fmt.parseInt(posix.pid_t, fields.next() orelse return null, 10) catch return null;
    return if (ppid > 0) ppid else null;
}

// False: getProcessStats returns RSS (cheap, from /proc/<pid>/stat), but true USS
// requires an smaps walk (processReclaimable), so eviction refines candidates with
// a second pass. See runEvictionEpisode and bsd.zig's mem_is_reclaimable.
pub const mem_is_reclaimable = false;

// Process stats — read resident memory and CPU time from /proc/<pid>/stat.
// Returns null if the process is gone or /proc is unreadable. Fields are parsed
// from after the final ')' so a comm string containing spaces/parens is skipped.
pub fn getProcessStats(pid: posix.pid_t) ?shared.ProcessStats {
    var buf: [4096]u8 = undefined;
    const content = readProc("/proc/{d}/stat", pid, &buf) orelse return null;
    const close_paren = std.mem.lastIndexOfScalar(u8, content, ')') orelse return null;
    var fields = std.mem.tokenizeScalar(u8, content[close_paren + 1 ..], ' ');
    var vals: [22]u64 = undefined; // state(field 3) .. rss(field 24)
    var count: usize = 0;
    while (count < vals.len) : (count += 1) {
        const tok = fields.next() orelse break;
        vals[count] = std.fmt.parseInt(u64, tok, 10) catch 0;
    }
    if (count <= 21) return null;
    const utime = vals[11]; // field 14
    const stime = vals[12]; // field 15
    const rss_pages = vals[21]; // field 24
    // USER_HZ (_SC_CLK_TCK) is 100 on every mainstream Linux config; reading it
    // exactly needs libc, which the conductor deliberately doesn't link.
    const ticks_per_sec: f64 = 100;
    return .{
        .mem_bytes = rss_pages * std.heap.pageSize(),
        .cpu_seconds = @as(f64, @floatFromInt(utime + stime)) / ticks_per_sec,
    };
}

// Reclaimable (USS) bytes from /proc/<pid>/smaps_rollup: Private_Clean +
// Private_Dirty — the private pages freed when this process dies. Null if the
// file is absent (very old kernels) or unparseable.
pub fn processReclaimable(pid: posix.pid_t) ?u64 {
    var buf: [4096]u8 = undefined;
    const content = readProc("/proc/{d}/smaps_rollup", pid, &buf) orelse return null;
    const clean = fieldKb(content, "Private_Clean:") orelse return null;
    const dirty = fieldKb(content, "Private_Dirty:") orelse return null;
    return (clean + dirty) * 1024;
}

// First numeric token after `field` in a "Field:  <n> kB"-style file, or null.
fn fieldKb(content: []const u8, field: []const u8) ?u64 {
    const start = std.mem.indexOf(u8, content, field) orelse return null;
    var toks = std.mem.tokenizeAny(u8, content[start + field.len ..], " \n");
    return std.fmt.parseInt(u64, toks.next() orelse return null, 10) catch null;
}

// --- Memory pressure sources ---

// PSI "some avg10" %, or null if PSI is compiled out (common on stock distros).
pub fn readPsiSomeAvg10() ?f64 {
    var buf: [256]u8 = undefined;
    const content = readFile("/proc/pressure/memory", &buf) orelse return null;
    const some = std.mem.indexOf(u8, content, "some avg10=") orelse return null;
    var toks = std.mem.tokenizeAny(u8, content[some + "some avg10=".len ..], " \n");
    return std.fmt.parseFloat(f64, toks.next() orelse return null) catch null;
}

pub const MemInfo = struct { available: u64, total: u64 };

// MemAvailable (excludes reclaimable cache) vs MemTotal. Always present on Linux.
pub fn readMemInfo() ?MemInfo {
    var buf: [2048]u8 = undefined;
    const content = readFile("/proc/meminfo", &buf) orelse return null;
    const total = fieldKb(content, "MemTotal:") orelse return null;
    const avail = fieldKb(content, "MemAvailable:") orelse return null;
    return .{ .available = avail * 1024, .total = total * 1024 };
}

// Paths — Linux-specific default runtime directory
pub fn defaultRuntimeDir(out: anytype, xdg_runtime_dir: ?[]const u8, _: ?[]const u8) ![]const u8 {
    if (xdg_runtime_dir) |xdg|
        return shared.print(out, "{s}/julia-daemon", .{xdg});
    return shared.print(out, "/run/user/{d}/julia-daemon", .{linux.getuid()});
}
