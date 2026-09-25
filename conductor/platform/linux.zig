// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0
//
// Linux platform primitives, over raw syscalls; shared logic is in posix.zig.

const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const shared = @import("posix.zig");

pub const tcp_keepalive_options: ?[3]u32 = .{ linux.TCP.KEEPIDLE, linux.TCP.KEEPINTVL, linux.TCP.KEEPCNT };

// Constants
pub const SIG = posix.SIG;
/// Asks a Julia process for its stacks and a profile (`Profile.peek_report`).
pub const peek_signal: ?SIG = .USR1;
pub const STDIN_HANDLE: posix.fd_t = posix.STDIN_FILENO;
pub const STDOUT_HANDLE: posix.fd_t = posix.STDOUT_FILENO;
pub const STDERR_HANDLE: posix.fd_t = posix.STDERR_FILENO;
pub const Timeval = linux.timeval;

// Process info
pub const getpid = linux.getpid;
pub const getppid = linux.getppid;

// I/O
pub fn write(fd: posix.fd_t, buf: []const u8) void {
    var written: usize = 0;
    while (written < buf.len) {
        const rc = linux.write(fd, buf.ptr + written, buf.len - written);
        const signed: isize = @bitCast(rc);
        if (signed < 0) {
            @branchHint(.cold);
            const e = @as(linux.E, @enumFromInt(@as(u16, @intCast(-signed))));
            if (e == .INTR) continue;
            shared.eprint("write error on fd {d}: errno {d}\n", .{ fd, @intFromEnum(e) });
            return;
        }
        if (signed == 0) return; // no progress; avoid spinning
        written += @intCast(signed);
    }
}

// Raw primitives
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

var own_mount_ns: ?u64 = null;
pub fn peerMountNs(socket: posix.socket_t) ?u64 {
    return processMountNs(peerPid(socket) orelse return null);
}

pub fn peerForeignMountNs(socket: posix.socket_t) ?u64 {
    const peer = peerMountNs(socket) orelse return null;
    const own = own_mount_ns orelse (processMountNs(linux.getpid()) orelse return null);
    own_mount_ns = own;
    return if (peer == own) null else peer;
}

/// Forked twice so the parent is init: the worker's parent-death signal then
/// means "die with the sandbox".
pub fn spawnDetached(argv: [*:null]const ?[*:0]const u8, envp: [*:null]const ?[*:0]const u8) !void {
    // Checked here, as the grandchild would fail unwatched.
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
        _ = linux.waitpid(@intCast(pid), &status, 0);
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

pub fn childMountNs(child: std.process.Child) ?u64 {
    return processMountNs(child.id orelse return null);
}

// The link reads "mnt:[4026531841]".
fn processMountNs(pid: posix.pid_t) ?u64 {
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
pub fn rawWaitpid(pid: posix.pid_t, block: bool) posix.pid_t {
    var status: u32 = 0;
    const ret = linux.waitpid(pid, &status, if (block) 0 else linux.W.NOHANG);
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

pub fn getParentName(pid: posix.pid_t, out: []u8) ?[]const u8 {
    const ppid = parentPid(pid) orelse return null;
    const comm = readProc("/proc/{d}/comm", ppid, out) orelse return null;
    return std.mem.trimEnd(u8, comm, "\n");
}

// Parsed after the final ')', as comm may contain spaces or parens.
pub fn parentPid(pid: posix.pid_t) ?posix.pid_t {
    var buf: [256]u8 = undefined;
    const content = readProc("/proc/{d}/stat", pid, &buf) orelse return null;
    const close_paren = std.mem.lastIndexOfScalar(u8, content, ')') orelse return null;
    var fields = std.mem.tokenizeScalar(u8, content[close_paren + 1 ..], ' ');
    _ = fields.next() orelse return null; // field 3: state
    const ppid = std.fmt.parseInt(posix.pid_t, fields.next() orelse return null, 10) catch return null;
    return if (ppid > 0) ppid else null;
}

// RSS; USS needs the smaps walk in processReclaimable.
pub const mem_is_reclaimable = false;

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
    // USER_HZ is 100 on every mainstream config; reading it needs libc.
    const ticks_per_sec: f64 = 100;
    return .{
        .mem_bytes = rss_pages * std.heap.pageSize(),
        .cpu_seconds = @as(f64, @floatFromInt(utime + stime)) / ticks_per_sec,
    };
}

pub fn processReclaimable(pid: posix.pid_t) ?u64 {
    var buf: [4096]u8 = undefined;
    const content = readProc("/proc/{d}/smaps_rollup", pid, &buf) orelse return null;
    const clean = fieldKb(content, "Private_Clean:") orelse return null;
    const dirty = fieldKb(content, "Private_Dirty:") orelse return null;
    return (clean + dirty) * 1024;
}

fn fieldKb(content: []const u8, field: []const u8) ?u64 {
    const start = std.mem.indexOf(u8, content, field) orelse return null;
    var toks = std.mem.tokenizeAny(u8, content[start + field.len ..], " \n");
    return std.fmt.parseInt(u64, toks.next() orelse return null, 10) catch null;
}

// --- Memory pressure sources ---

// Null where PSI is compiled out, common on stock distros.
pub fn readPsiSomeAvg10() ?f64 {
    var buf: [256]u8 = undefined;
    const content = readFile("/proc/pressure/memory", &buf) orelse return null;
    const some = std.mem.indexOf(u8, content, "some avg10=") orelse return null;
    var toks = std.mem.tokenizeAny(u8, content[some + "some avg10=".len ..], " \n");
    return std.fmt.parseFloat(f64, toks.next() orelse return null) catch null;
}

pub const MemInfo = struct { available: u64, total: u64 };

pub fn readMemInfo() ?MemInfo {
    var buf: [2048]u8 = undefined;
    const content = readFile("/proc/meminfo", &buf) orelse return null;
    const total = fieldKb(content, "MemTotal:") orelse return null;
    const avail = fieldKb(content, "MemAvailable:") orelse return null;
    return .{ .available = avail * 1024, .total = total * 1024 };
}

// Paths
pub fn defaultRuntimeDir(out: anytype, xdg_runtime_dir: ?[]const u8, _: ?[]const u8) ![]const u8 {
    if (xdg_runtime_dir) |xdg|
        return shared.print(out, "{s}/julia-daemon", .{xdg});
    return shared.print(out, "/run/user/{d}/julia-daemon", .{linux.getuid()});
}

pub fn currentDir(buf: []u8) ![]const u8 {
    const rc = linux.getcwd(buf.ptr, buf.len);
    if (linux.errno(rc) != .SUCCESS) return error.CurrentDirUnavailable;
    return buf[0 .. rc - 1]; // the length counts the NUL
}

// Name lookup. A static binary links no libc, so `getent` runs the system's
// own getaddrinfo, NSS included; std's resolver would cost the client ~100 KB.

const IpAddress = std.Io.net.IpAddress;
const lookup_timeout_ms = 5000;

pub fn lookupHost(name: []const u8, port: u16, buf: []IpAddress) ![]IpAddress {
    for ([_][*:0]const u8{ "ahosts", "hosts" }) |database| {
        var out: [8192]u8 = undefined;
        const run = try getent(database, name, &out);
        switch (run.status) {
            0 => return parseHosts(run.output, port, buf),
            1 => continue, // this getent lacks the database
            2 => return error.UnknownHostName,
            127 => {
                shared.eprint("Resolving host names needs `getent` (from glibc or musl-utils), which is not installed.\n", .{});
                return error.LookupFailed;
            },
            else => return error.LookupFailed,
        }
    }
    return error.LookupFailed;
}

fn getent(database: [*:0]const u8, name: []const u8, out: []u8) !struct { status: u8, output: []const u8 } {
    var name_buf: [256]u8 = undefined;
    if (name.len >= name_buf.len) return error.InvalidAddress;
    @memcpy(name_buf[0..name.len], name);
    name_buf[name.len] = 0;
    var fds: [2]i32 = undefined;
    if (linux.errno(linux.pipe2(&fds, .{ .CLOEXEC = true })) != .SUCCESS) return error.LookupFailed;
    const fork_rc = linux.fork();
    if (linux.errno(fork_rc) != .SUCCESS) {
        _ = linux.close(fds[0]);
        _ = linux.close(fds[1]);
        return error.LookupFailed;
    }
    if (fork_rc == 0) {
        _ = linux.dup2(fds[1], 1);
        const argv = [_:null]?[*:0]const u8{ "getent", database, name_buf[0..name.len :0] };
        const envp = [_:null]?[*:0]const u8{};
        for ([_][*:0]const u8{ "/usr/bin/getent", "/bin/getent" }) |exe| _ = linux.execve(exe, &argv, &envp);
        linux.exit_group(127);
    }
    const pid: posix.pid_t = @intCast(fork_rc);
    _ = linux.close(fds[1]);
    defer _ = linux.close(fds[0]);
    var n: usize = 0;
    const finished = while (n < out.len) {
        var pfd = [_]posix.pollfd{.{ .fd = fds[0], .events = posix.POLL.IN, .revents = 0 }};
        if ((posix.poll(&pfd, lookup_timeout_ms) catch 0) == 0) break false;
        const rc: isize = @bitCast(linux.read(fds[0], out[n..].ptr, out.len - n));
        if (rc <= 0) break true;
        n += @intCast(rc);
    } else false;
    if (!finished) _ = linux.kill(pid, .KILL);
    var status: u32 = 0;
    _ = linux.waitpid(pid, &status, 0);
    const exited = status & 0x7f == 0;
    return .{ .status = if (finished and exited) @intCast((status >> 8) & 0xff) else 255, .output = out[0..n] };
}

/// Each line opens with an address; `ahosts` lists one per socket type.
fn parseHosts(output: []const u8, port: u16, buf: []IpAddress) ![]IpAddress {
    var n: usize = 0;
    var lines = std.mem.tokenizeScalar(u8, output, '\n');
    while (lines.next()) |line| {
        var words = std.mem.tokenizeAny(u8, line, " \t");
        const ip = IpAddress.parse(words.next() orelse continue, port) catch continue;
        for (buf[0..n]) |*seen| {
            if (seen.eql(&ip)) break;
        } else if (n < buf.len) {
            buf[n] = ip;
            n += 1;
        }
    }
    return if (n == 0) error.UnknownHostName else buf[0..n];
}
