// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0
//
// Linux sandbox for untrusted Julia workers, built on unprivileged user
// namespaces: read-only host system dirs, an ephemeral overlay on the depot,
// and no access to the host home.

const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const Allocator = std.mem.Allocator;

// --- Constants ---

const MS_RDONLY: u32 = 0x0001;
const MS_NOSUID: u32 = 0x0002;
const MS_NODEV: u32 = 0x0004;
const MS_NOEXEC: u32 = 0x0008;
const MS_REMOUNT: u32 = 0x0020;
const MS_NOATIME: u32 = 0x0400;
const MS_NODIRATIME: u32 = 0x0800;
const MS_RELATIME: u32 = 0x200000;
const MS_STRICTATIME: u32 = 0x1000000;
const MS_SILENT: u32 = 0x8000;
const MS_BIND: u32 = 0x1000;
const MS_REC: u32 = 0x4000;
const MS_SLAVE: u32 = 0x80000;
const MS_PRIVATE: u32 = 0x40000;
const MNT_DETACH: u32 = 0x00000002;
const CLONE_NEWNS: usize = 0x00020000;
const CLONE_NEWPID: usize = 0x20000000;
const CLONE_NEWUSER: usize = 0x10000000;

// --- Public types ---

pub const SandboxConfig = struct {
    julia_executable: []const u8,
    julia_channel: ?[]const u8,
    threads_arg: ?[]const u8,
    worker_project: []const u8,
    worker_args: []const u8,
    eval_expr: []const u8,
    host_environ: *const std.process.Environ.Map,
    setup_socket_path: []const u8, // its parent dir is bound rw
    worker_id: u32,
    host_home: []const u8,
    depot_env: ?[]const u8 = null, // host JULIA_DEPOT_PATH, null when unset
    extra_ro_binds: []const []const u8 = &.{},
    extra_rw_binds: []const []const u8 = &.{},
    max_memory: ?[]const u8,
    max_cpu: ?u32,
};

pub const max_depots: usize = 8;

pub const DepotMount = struct {
    path: []const u8,
    /// Also set on any ancestor of the written depot, which a read-only mount
    /// would otherwise cover.
    writable: bool,
};

/// Ordered shallowest-first, so a nested depot mounts over its ancestors.
pub const DepotTargets = struct {
    entries: [max_depots]DepotMount = undefined,
    len: usize = 0,
    writable_at: usize = 0,

    pub fn slice(self: *const DepotTargets) []const DepotMount {
        return self.entries[0..self.len];
    }

    pub fn writablePath(self: *const DepotTargets) []const u8 {
        return if (self.len == 0) "" else self.entries[self.writable_at].path;
    }

    /// First occurrence wins, so a duplicate cannot displace the writable depot.
    fn push(self: *DepotTargets, path: []const u8) void {
        if (path.len == 0) return;
        for (self.entries[0..self.len]) |e|
            if (std.mem.eql(u8, e.path, path)) return;
        if (self.len >= max_depots) {
            std.debug.print("Sandbox: >{d} depot entries, ignoring {s}\n", .{ max_depots, path });
            return;
        }
        self.entries[self.len] = .{ .path = path, .writable = self.len == 0 };
        self.len += 1;
    }

    /// Required before mounting: a mount over an ancestor shadows its descendants.
    fn arrange(self: *DepotTargets) void {
        if (self.len == 0) return;
        const writable = self.entries[0].path;
        for (self.entries[1..self.len]) |*e|
            e.writable = isStrictAncestor(e.path, writable);
        // Stable, so unrelated depots at equal depth keep their written order.
        std.mem.sort(DepotMount, self.entries[0..self.len], {}, struct {
            fn lessThan(_: void, a: DepotMount, b: DepotMount) bool {
                return pathDepth(a.path) < pathDepth(b.path);
            }
        }.lessThan);
        // Ancestors sort before the depot they contain, so the last wins.
        for (self.slice(), 0..) |e, i|
            if (e.writable) { self.writable_at = i; };
    }
};

/// Follows the Julia manual's empty-entry rules. Bundled depots are left out:
/// they live under the install root, mounted separately.
pub fn resolveDepots(depot_env: ?[]const u8, host_home: []const u8) DepotTargets {
    var out: DepotTargets = .{};
    // An empty string is a zero-element list, not a one-element empty list.
    const env = depot_env orelse "";
    if (depot_env != null and env.len == 0) return out;
    // ":" is equivalent to unset: both put the user depot first.
    const explicit = std.mem.indexOfNone(u8, env, ":") != null;
    if (!explicit or env[0] == ':') out.push(homeDepotPath(host_home));
    var it = std.mem.splitScalar(u8, env, ':');
    while (it.next()) |entry| {
        if (entry.len > 0) out.push(entry); // empties add bundled paths, not mounts
    }
    out.arrange();
    return out;
}

pub const InstallRoot = union(enum) {
    /// Contains `share/julia/base`.
    install_root: []const u8,
    /// Contains `juliaup.json`, with every channel.
    launcher_home: []const u8,
    unrecognised,
};

fn isDangerousRoot(path: []const u8, host_home: []const u8) bool {
    if (path.len == 0) return true;
    if (std.mem.eql(u8, path, "/")) return true;
    if (std.mem.eql(u8, path, "/home")) return true;
    if (std.mem.eql(u8, path, "/root")) return true;
    return host_home.len > 0 and std.mem.eql(u8, path, host_home);
}

/// Raw syscall: also runs in the post-fork sandbox child.
fn pathExists(path: [*:0]const u8) bool {
    return errnoFromRc(linux.access(path, 0)) == null;
}

/// Recognises the root by content within two levels, never by shape:
/// `dirname(dirname("/home/user/julia"))` is `/home`. `exe_path` must not be
/// canonicalised, as the juliaup launcher may exec any channel. `prefix` is
/// used only for probing (the host sits under `/oldroot` after pivot_root).
pub fn classifyInstallPrefixed(exe_path: []const u8, host_home: []const u8, prefix: []const u8) InstallRoot {
    if (exe_path.len == 0 or exe_path[0] != '/') return .unrecognised;
    var dir = std.fs.path.dirname(exe_path) orelse return .unrecognised;
    var level: usize = 0;
    while (level < 2) : (level += 1) {
        if (isDangerousRoot(dir, host_home)) return .unrecognised;
        var buf: [512]u8 = undefined;
        if (fmtPath(&buf, "{s}{s}/share/julia/base", .{ prefix, dir })) |marker|
            if (pathExists(marker)) return .{ .install_root = dir };
        if (fmtPath(&buf, "{s}{s}/juliaup.json", .{ prefix, dir })) |marker|
            if (pathExists(marker)) return .{ .launcher_home = dir };
        dir = std.fs.path.dirname(dir) orelse return .unrecognised;
    }
    return .unrecognised;
}

pub const SandboxError = error{
    ForkFailed,
    UnshareFailed,
    UidMapFailed,
    GidMapFailed,
    SetgroupsFailed,
    MountFailed,
    MkdirFailed,
    PivotRootFailed,
    ChdirFailed,
    ExecFailed,
    CgroupSetupFailed,
    PathTooLong,
};

// --- Public API ---

pub fn spawnSandboxed(allocator: Allocator, config: *const SandboxConfig) SandboxError!posix.pid_t {
    const argv = buildArgv(allocator, config) catch return SandboxError.ExecFailed;
    defer freeNullTermList(allocator, argv);
    const envp = buildEnvp(allocator, config) catch return SandboxError.ExecFailed;
    defer freeNullTermList(allocator, envp);
    return execInSandbox(argv, envp, config);
}

pub fn execInSandbox(
    argv: [*:null]const ?[*:0]const u8,
    envp: [*:null]const ?[*:0]const u8,
    config: *const SandboxConfig,
) SandboxError!posix.pid_t {
    const orig_uid = linux.getuid();
    const orig_gid = linux.getgid();
    var cgroup_buf: [std.fs.max_path_bytes]u8 = undefined;
    const cgroup = try createCgroup(&cgroup_buf, config);
    const pid1 = callFork() orelse {
        removeCgroup(config.worker_id);
        return SandboxError.ForkFailed;
    };
    if (pid1 != 0) return pid1;
    // Joined while the host's cgroup tree is still in view; the worker inherits it.
    if (cgroup) |cg| cgroupWrite(cg, "cgroup.procs", "0") catch |err|
        fatalChild("joining the sandbox cgroup", err);
    // Child 1 holds the signals it relays until there is a worker to take them.
    var relayed = posix.sigemptyset();
    posix.sigaddset(&relayed, .INT);
    posix.sigaddset(&relayed, .TERM);
    posix.sigprocmask(posix.SIG.BLOCK, &relayed, null);
    setupNamespaces(orig_uid, orig_gid) catch |err|
        fatalChild("namespace setup", err);
    const pid2 = callFork() orelse
        fatalChild("inner fork", SandboxError.ForkFailed);
    if (pid2 != 0) {
        relay_target = pid2;
        const relay = posix.Sigaction{ .handler = .{ .handler = relaySignal }, .mask = std.mem.zeroes(posix.sigset_t), .flags = 0 };
        posix.sigaction(.INT, &relay, null);
        posix.sigaction(.TERM, &relay, null);
        // Inherited from the conductor, whose signal pipe it writes into.
        const ignore = posix.Sigaction{ .handler = .{ .handler = posix.SIG.IGN }, .mask = std.mem.zeroes(posix.sigset_t), .flags = 0 };
        posix.sigaction(.USR1, &ignore, null);
        posix.sigprocmask(posix.SIG.UNBLOCK, &relayed, null);
        var status: u32 = 0;
        while (errnoFromRc(linux.waitpid(@intCast(pid2), &status, 0))) |e| {
            if (e != .INTR) break;
        }
        linux.exit_group(@intCast(status >> 8));
    }
    // Child 2, PID 1 inside: the signal mask survives exec.
    posix.sigprocmask(posix.SIG.UNBLOCK, &relayed, null);
    setupFilesystem(config) catch |err|
        fatalChild("filesystem setup", err);
    const exe = argv[0].?;
    std.debug.print("Sandbox: execve {s}\n", .{std.mem.span(exe)});
    const rc = linux.execve(exe, argv, envp);
    if (errnoFromRc(rc)) |e|
        std.debug.print("Sandbox: execve failed: {s}\n", .{@tagName(e)});
    linux.exit_group(127);
}

// Child 1 relays rather than dies, which would kill the worker through its
// parent-death signal.
var relay_target: posix.pid_t = 0;
fn relaySignal(sig: posix.SIG) callconv(.c) void {
    _ = linux.kill(relay_target, sig);
}

pub fn envAllowed(key: []const u8) bool {
    if (std.mem.startsWith(u8, key, "JULIA_")) return true;
    for (env_allowlist) |allowed|
        if (std.mem.eql(u8, key, allowed)) return true;
    return false;
}

// --- Namespace setup ---

fn setupNamespaces(orig_uid: linux.uid_t, orig_gid: linux.gid_t) SandboxError!void {
    if (errnoFromRc(linux.unshare(CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWUSER))) |e| {
        logErrno("unshare", e);
        return SandboxError.UnshareFailed;
    }
    // setgroups must be denied before an unprivileged gid_map write.
    writeFile("/proc/self/setgroups", "deny") catch return SandboxError.SetgroupsFailed;
    var uid_buf: [64]u8 = undefined;
    const uid_map = std.fmt.bufPrint(&uid_buf, "0 {d} 1\n", .{orig_uid}) catch
        return SandboxError.UidMapFailed;
    writeFile("/proc/self/uid_map", uid_map) catch return SandboxError.UidMapFailed;
    var gid_buf: [64]u8 = undefined;
    const gid_map = std.fmt.bufPrint(&gid_buf, "0 {d} 1\n", .{orig_gid}) catch
        return SandboxError.GidMapFailed;
    writeFile("/proc/self/gid_map", gid_map) catch return SandboxError.GidMapFailed;
}

// --- Filesystem construction ---

fn setupFilesystem(config: *const SandboxConfig) SandboxError!void {
    const home = config.host_home;
    try mountStaging();
    try mountSystemDirs();
    try mountHome(config, home);
    try mountJuliaInstall(config.julia_executable, home);
    for (config.extra_ro_binds) |path| {
        if (path.len == 0) continue;
        var src_buf: [512]u8 = undefined;
        var dst_buf: [512]u8 = undefined;
        const src = fmtPath(&src_buf, "/oldroot{s}", .{path}) orelse continue;
        const dst = fmtPath(&dst_buf, "/newroot{s}", .{path}) orelse continue;
        mkdirp(dst);
        try robindOptional(src, dst);
    }
    for (config.extra_rw_binds) |path| {
        if (path.len == 0) continue;
        var src_buf: [512]u8 = undefined;
        var dst_buf: [512]u8 = undefined;
        const src = fmtPath(&src_buf, "/oldroot{s}", .{path}) orelse continue;
        const dst = fmtPath(&dst_buf, "/newroot{s}", .{path}) orelse continue;
        mkdirp(dst);
        try mountBind(src, dst);
    }
    // Only the per-worker socket subdirectory is exposed, not the runtime dir.
    if (config.setup_socket_path.len > 0) {
        if (std.mem.lastIndexOfScalar(u8, config.setup_socket_path, '/')) |sep| {
            const runtime_dir = config.setup_socket_path[0..sep];
            var src_buf: [512]u8 = undefined;
            var dst_buf: [512]u8 = undefined;
            if (fmtPath(&src_buf, "/oldroot{s}", .{runtime_dir})) |src| {
                if (fmtPath(&dst_buf, "/newroot{s}", .{runtime_dir})) |dst| {
                    mkdirp(dst);
                    mountBind(src, dst) catch {};
                }
            }
        }
    }
    mountFlags("oldroot", MS_REC | MS_PRIVATE) catch {};
    if (errnoFromRc(linux.chdir("/newroot"))) |_| return SandboxError.ChdirFailed;
    if (errnoFromRc(linux.pivot_root(".", "."))) |e| {
        logErrno("pivot_root final", e);
        return SandboxError.PivotRootFailed;
    }
    if (errnoFromRc(linux.chdir("/"))) |_| return SandboxError.ChdirFailed;
    _ = linux.umount2(".", MNT_DETACH);
    _ = linux.chdir("/home/sandbox");
}

fn mountStaging() SandboxError!void {
    // No mount propagation back to the host.
    mountFlags("/", MS_SLAVE | MS_REC) catch return SandboxError.MountFailed;
    mountTmpfs("/tmp", MS_NOSUID | MS_NODEV, null) catch return SandboxError.MountFailed;
    if (errnoFromRc(linux.chdir("/tmp"))) |_| return SandboxError.ChdirFailed;
    try mkdirE("newroot");
    mountBind("newroot", "newroot") catch return SandboxError.MountFailed;
    try mkdirE("oldroot");
    try mkdirE("ovl-upper");
    try mkdirE("ovl-work");
    if (errnoFromRc(linux.pivot_root("/tmp", "oldroot"))) |e| {
        logErrno("pivot_root staging", e);
        return SandboxError.PivotRootFailed;
    }
    if (errnoFromRc(linux.chdir("/"))) |_| return SandboxError.ChdirFailed;
}

fn mountSystemDirs() SandboxError!void {
    try mkdirE("/newroot/dev");
    mountTmpfs("/newroot/dev", MS_NOSUID | MS_NODEV, "mode=0755") catch
        return SandboxError.MountFailed;
    for ([_][:0]const u8{ "null", "zero", "full", "random", "urandom", "tty" }) |name| {
        var src: [48]u8 = undefined;
        var dst: [48]u8 = undefined;
        const s = fmtPath(&src, "/oldroot/dev/{s}", .{name}) orelse continue;
        const d = fmtPath(&dst, "/newroot/dev/{s}", .{name}) orelse continue;
        touchFile(d) catch continue;
        mountBind(s, d) catch continue;
    }
    _ = linux.symlink("/proc/self/fd/0", "/newroot/dev/stdin");
    _ = linux.symlink("/proc/self/fd/1", "/newroot/dev/stdout");
    _ = linux.symlink("/proc/self/fd/2", "/newroot/dev/stderr");
    _ = linux.symlink("/proc/self/fd", "/newroot/dev/fd");
    _ = linux.symlink("/proc/kcore", "/newroot/dev/core");
    mkdirE("/newroot/dev/shm") catch {};
    try mkdirE("/newroot/dev/pts");
    mountOrFail("devpts", "/newroot/dev/pts", "devpts", MS_NOSUID | MS_NOEXEC, "newinstance,ptmxmode=0666,mode=620") catch {};
    _ = linux.symlink("pts/ptmx", "/newroot/dev/ptmx");
    try mkdirE("/newroot/proc");
    mountOrFail("proc", "/newroot/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, "") catch
        return SandboxError.MountFailed;
    try mkdirE("/newroot/tmp");
    mountTmpfs("/newroot/tmp", MS_NOSUID | MS_NODEV, "mode=1777") catch
        return SandboxError.MountFailed;
    try robind("/oldroot/usr", "/newroot/usr");
    try robind("/oldroot/etc", "/newroot/etc");
    // nss-systemd can leak the host user through the uid mapping.
    try overrideEtcFile("/newroot/etc/passwd",
        "root:x:0:0:root:/root:/bin/sh\nsandbox:x:0:0:sandbox:/home/sandbox:/bin/sh\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n");
    try overrideEtcFile("/newroot/etc/group",
        "root:x:0:\nsandbox:x:0:\nnogroup:x:65534:\n");
    try overrideEtcFile("/newroot/etc/nsswitch.conf",
        "passwd: files\ngroup:  files\nshadow: files\nhosts:  files dns\nnetworks: files\nprotocols: files\nservices: files\n");
    // /lib, /lib64 and /bin are often symlinks into /usr.
    try robindOptional("/oldroot/usr/lib", "/newroot/lib");
    try robindOptional("/oldroot/usr/lib64", "/newroot/lib64");
    try robindOptional("/oldroot/usr/bin", "/newroot/bin");
    try robindOptional("/oldroot/opt", "/newroot/opt");
}

/// A juliaup launcher looks for its home under `$HOME`, which is
/// `/home/sandbox` here, so it is bound there too.
fn mountJuliaInstall(exe_path: []const u8, home: []const u8) SandboxError!void {
    const install = classifyInstallPrefixed(exe_path, home, "/oldroot");
    const root = switch (install) {
        .install_root, .launcher_home => |r| r,
        .unrecognised => {
            std.debug.print("Sandbox: cannot place Julia install for {s} — no share/julia or juliaup.json within two levels; the worker will likely fail to load Base\n", .{exe_path});
            return;
        },
    };
    var src_buf: [512]u8 = undefined;
    const src = fmtPath(&src_buf, "/oldroot{s}", .{root}) orelse return SandboxError.PathTooLong;
    if (!isWithin(root, "/usr") and !isWithin(root, "/opt")) {
        var dst_buf: [512]u8 = undefined;
        if (fmtPath(&dst_buf, "/newroot{s}", .{root})) |dst| {
            mkdirp(dst);
            try robindOptional(src, dst);
        }
    }
    if (install == .launcher_home) {
        mkdirp("/newroot/home/sandbox/.julia/juliaup");
        try robindOptional(src, "/newroot/home/sandbox/.julia/juliaup");
    }
}

/// Static buffer: callers consume the slice before resolving again.
var home_depot_buf: [384]u8 = undefined;
fn homeDepotPath(home: []const u8) []const u8 {
    if (home.len == 0) return "";
    return std.fmt.bufPrint(&home_depot_buf, "{s}/.julia", .{home}) catch "";
}

fn mountHome(config: *const SandboxConfig, home: []const u8) SandboxError!void {
    try mkdirE("/newroot/home");
    mountTmpfs("/newroot/home", MS_NOSUID | MS_NODEV, "mode=0755") catch
        return SandboxError.MountFailed;
    if (home.len == 0) return;
    const depots = resolveDepots(config.depot_env, home);
    if (depots.len == 0) return;
    // Mounted at their host paths, since precompile caches embed absolute paths.
    for (depots.slice()) |depot| {
        var dst_buf: [384]u8 = undefined;
        const dst = fmtPath(&dst_buf, "/newroot{s}", .{depot.path}) orelse continue;
        mkdirp(dst);
        if (depot.writable) {
            try mountDepotOverlay(depot.path, dst);
        } else {
            var src_buf: [384]u8 = undefined;
            const src = fmtPath(&src_buf, "/oldroot{s}", .{depot.path}) orelse continue;
            try robindOptional(src, dst);
        }
    }
    try linkSandboxDepot(depots.writablePath(), home);
}

/// A relocated depot is bound rather than linked, as the juliaup bind lives
/// under it. It sources from `/newroot` to keep writes on the overlay, so it
/// must run after every depot mount.
fn linkSandboxDepot(depot: []const u8, home: []const u8) SandboxError!void {
    mkdirE("/newroot/home/sandbox") catch {};
    var buf: [384]u8 = undefined;
    if (std.mem.eql(u8, depot, homeDepotPath(home))) {
        if (fmtPath(&buf, "{s}", .{depot})) |target|
            _ = linux.symlink(target, "/newroot/home/sandbox/.julia");
    } else {
        mkdirp("/newroot/home/sandbox/.julia");
        if (fmtPath(&buf, "/newroot{s}", .{depot})) |src|
            mountBind(src, "/newroot/home/sandbox/.julia") catch {};
    }
}

fn pathDepth(path: []const u8) usize {
    return std.mem.count(u8, path, "/");
}

/// Component-wise: `/usrlocal` is not within `/usr`.
pub fn isWithin(path: []const u8, dir: []const u8) bool {
    return std.mem.eql(u8, path, dir) or isStrictAncestor(dir, path);
}

pub fn isStrictAncestor(ancestor: []const u8, descendant: []const u8) bool {
    if (ancestor.len >= descendant.len) return false;
    if (!std.mem.startsWith(u8, descendant, ancestor)) return false;
    return descendant[ancestor.len] == '/';
}

/// `environments` is bound read-only over the overlay, so named environments
/// resolve but no manifest can change.
fn mountDepotOverlay(depot_src: []const u8, depot_dst: [*:0]const u8) SandboxError!void {
    var opts_buf: [512]u8 = undefined;
    const opts = fmtPath(&opts_buf,
        "upperdir=/ovl-upper,workdir=/ovl-work,lowerdir=/oldroot{s},userxattr",
        .{depot_src}) orelse return;
    mountOrFail("overlay", depot_dst, "overlay", 0, opts) catch {
        std.debug.print("Sandbox: overlay on {s} failed, falling back to bind mount\n", .{depot_src});
        var src_buf: [384]u8 = undefined;
        if (fmtPath(&src_buf, "/oldroot{s}", .{depot_src})) |src|
            try robindOptional(src, depot_dst);
        return;
    };
    var src_buf: [384]u8 = undefined;
    var dst_buf: [384]u8 = undefined;
    const src = fmtPath(&src_buf, "/oldroot{s}/environments", .{depot_src}) orelse return;
    const dst = fmtPath(&dst_buf, "/newroot{s}/environments", .{depot_src}) orelse return;
    try robindOptional(src, dst);
}

// --- Cgroup v2 resource limits ---

var cgroup_root_buf: [std.fs.max_path_bytes]u8 = undefined;
/// The conductor's own cgroup, where each limited sandbox gets `sandbox-N`.
var cgroup_root: ?[]const u8 = null;

/// Ready the conductor's cgroup to hold limited sandboxes. It must be delegated
/// to us (systemd `Delegate=yes`), and cgroup v2 hands controllers down only
/// from a cgroup with no processes of its own, so the conductor first moves
/// into a `conductor` leaf. Call before any child is spawned.
pub fn delegateCgroups(max_memory: ?[]const u8, max_cpu: ?u32) SandboxError!void {
    var self_buf: [1024]u8 = undefined;
    const self_len = readFile("/proc/self/cgroup", &self_buf) orelse return cgroupFailed("read /proc/self/cgroup");
    const own = cgroupV2Path(self_buf[0..self_len]) orelse return cgroupFailed("find a cgroup v2 hierarchy");
    const root = std.fmt.bufPrint(&cgroup_root_buf, "/sys/fs/cgroup{s}", .{std.mem.trimEnd(u8, own, "/")}) catch
        return SandboxError.PathTooLong;
    var leaf_buf: [std.fs.max_path_bytes]u8 = undefined;
    const leaf = fmtPath(&leaf_buf, "{s}/conductor", .{root}) orelse return SandboxError.PathTooLong;
    try cgroupMkdir(leaf);
    try cgroupWrite(leaf, "cgroup.procs", "0");
    const controllers = if (max_cpu == null) "+memory" else if (max_memory == null) "+cpu" else "+memory +cpu";
    try cgroupWrite(root, "cgroup.subtree_control", controllers);
    cgroup_root = root;
}

pub fn removeCgroup(worker_id: u32) void {
    const root = cgroup_root orelse return;
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const cg = fmtPath(&buf, "{s}/sandbox-{d}", .{ root, worker_id }) orelse return;
    _ = linux.unlinkat(linux.AT.FDCWD, cg, linux.AT.REMOVEDIR);
}

/// Null when no limits are configured.
fn createCgroup(buf: []u8, config: *const SandboxConfig) SandboxError!?[:0]const u8 {
    const root = cgroup_root orelse return null;
    const cg = fmtPath(buf, "{s}/sandbox-{d}", .{ root, config.worker_id }) orelse return SandboxError.PathTooLong;
    try cgroupMkdir(cg);
    errdefer removeCgroup(config.worker_id);
    if (config.max_memory) |mem| try cgroupWrite(cg, "memory.max", mem);
    if (config.max_cpu) |cpu| {
        var val_buf: [32]u8 = undefined;
        const quota = std.fmt.bufPrint(&val_buf, "{d} 100000", .{@as(u64, cpu) * 1000}) catch return SandboxError.CgroupSetupFailed;
        try cgroupWrite(cg, "cpu.max", quota);
    }
    return cg;
}

/// The path on the `0::` line of /proc/self/cgroup.
fn cgroupV2Path(self_cgroup: []const u8) ?[]const u8 {
    var it = std.mem.splitScalar(u8, self_cgroup, '\n');
    while (it.next()) |line| if (std.mem.startsWith(u8, line, "0::")) return line[3..];
    return null;
}

fn cgroupMkdir(path: [:0]const u8) SandboxError!void {
    if (errnoFromRc(linux.mkdir(path, 0o755))) |e| if (e != .EXIST) {
        std.debug.print("Sandbox: cannot create cgroup {s}: {s}\n", .{ path, @tagName(e) });
        return SandboxError.CgroupSetupFailed;
    };
}

fn cgroupWrite(dir: []const u8, file: []const u8, data: []const u8) SandboxError!void {
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const path = fmtPath(&buf, "{s}/{s}", .{ dir, file }) orelse return SandboxError.PathTooLong;
    const fd_rc = linux.openat(linux.AT.FDCWD, path, .{ .ACCMODE = .WRONLY }, 0);
    const e = errnoFromRc(fd_rc) orelse blk: {
        defer _ = linux.close(@intCast(fd_rc));
        break :blk errnoFromRc(linux.write(@intCast(fd_rc), data.ptr, data.len)) orelse return;
    };
    std.debug.print("Sandbox: cannot write \"{s}\" to {s}: {s}\n", .{ data, path, @tagName(e) });
    return SandboxError.CgroupSetupFailed;
}

fn cgroupFailed(step: []const u8) SandboxError {
    std.debug.print("Sandbox: cannot {s}\n", .{step});
    return SandboxError.CgroupSetupFailed;
}

// --- Argv/envp construction ---

fn buildArgv(allocator: Allocator, config: *const SandboxConfig) ![:null]?[*:0]const u8 {
    var list = std.array_list.AlignedManaged([*:0]const u8, null).init(allocator);
    defer list.deinit();
    errdefer for (list.items) |s| allocator.free(std.mem.span(s));
    try list.append(try allocator.dupeZ(u8, config.julia_executable));
    if (config.julia_channel) |ch|
        try list.append(try allocator.dupeZ(u8, ch));
    if (config.worker_project.len > 0)
        try list.append(try std.fmt.allocPrintSentinel(allocator, "--project={s}", .{config.worker_project}, 0));
    // Args containing spaces are not supported.
    var it = std.mem.tokenizeScalar(u8, config.worker_args, ' ');
    while (it.next()) |arg|
        try list.append(try allocator.dupeZ(u8, arg));
    if (config.threads_arg) |t|
        try list.append(try allocator.dupeZ(u8, t));
    try list.append(try allocator.dupeZ(u8, "--eval"));
    try list.append(try allocator.dupeZ(u8, config.eval_expr));
    const argv = try allocator.allocSentinel(?[*:0]const u8, list.items.len, null);
    for (list.items, 0..) |s, i| argv[i] = s;
    return argv;
}

/// Besides JULIA_*.
const env_allowlist = [_][]const u8{
    "LANG",  "LC_CTYPE",  "LC_ALL",
    "TERM",  "COLORTERM",
    "PATH",  "XDG_DATA_HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME",
    "OPENBLAS_MAIN_FREE", "OPENBLAS_DEFAULT_NUM_THREADS",
    "CUDA_CACHE_PATH",
};

/// `JULIA_DEPOT_PATH` passes through, so Julia's expansion matches the mounts.
const env_managed = [_][]const u8{
    "HOME", "USER", "LOGNAME", "PATH",
};

fn buildEnvp(allocator: Allocator, config: *const SandboxConfig) ![:null]?[*:0]const u8 {
    var list = std.array_list.AlignedManaged([*:0]const u8, null).init(allocator);
    defer list.deinit();
    errdefer for (list.items) |s| allocator.free(std.mem.span(s));
    const env = config.host_environ;
    for (env.array_hash_map.keys(), env.array_hash_map.values()) |key, value| {
        var managed = false;
        for (env_managed) |mk| if (std.mem.eql(u8, key, mk)) { managed = true; };
        if (!managed and envAllowed(key))
            try list.append(try std.fmt.allocPrintSentinel(allocator, "{s}={s}", .{ key, value }, 0));
    }
    try list.append(try allocator.dupeZ(u8, "HOME=/home/sandbox"));
    try list.append(try allocator.dupeZ(u8, "USER=sandbox"));
    try list.append(try allocator.dupeZ(u8, "LOGNAME=sandbox"));
    if (std.fs.path.dirname(config.julia_executable)) |bindir| {
        try list.append(try std.fmt.allocPrintSentinel(allocator,
            "PATH={s}:/usr/local/bin:/usr/bin:/bin", .{bindir}, 0));
    } else {
        try list.append(try allocator.dupeZ(u8, "PATH=/usr/local/bin:/usr/bin:/bin"));
    }
    const envp = try allocator.allocSentinel(?[*:0]const u8, list.items.len, null);
    for (list.items, 0..) |s, i| envp[i] = s;
    return envp;
}

fn freeNullTermList(allocator: Allocator, list: [:null]?[*:0]const u8) void {
    for (list) |maybe_s| if (maybe_s) |s| allocator.free(std.mem.span(s));
    allocator.free(list);
}

// --- Mount primitives ---

fn mountOrFail(source: [*:0]const u8, target: [*:0]const u8, fstype: [*:0]const u8, flags: u32, data: [*:0]const u8) SandboxError!void {
    if (errnoFromRc(linux.mount(source, target, fstype, flags, @intFromPtr(data)))) |e| {
        logMountError(source, target, e);
        return SandboxError.MountFailed;
    }
}

fn mountFlags(target: [*:0]const u8, flags: u32) SandboxError!void {
    if (errnoFromRc(linux.mount(null, target, null, flags, 0))) |e| {
        logErrno("mount flags", e);
        return SandboxError.MountFailed;
    }
}

fn mountBind(source: [*:0]const u8, target: [*:0]const u8) SandboxError!void {
    if (errnoFromRc(linux.mount(source, target, null, MS_BIND | MS_REC | MS_SILENT, 0))) |e| {
        logMountError(source, target, e);
        return SandboxError.MountFailed;
    }
}

fn mountTmpfs(target: [*:0]const u8, flags: u32, opts: ?[*:0]const u8) SandboxError!void {
    if (errnoFromRc(linux.mount("tmpfs", target, "tmpfs", flags, @intFromPtr(opts orelse @as([*:0]const u8, ""))))) |e| {
        logMountError("tmpfs", target, e);
        return SandboxError.MountFailed;
    }
}

var etc_override_counter: u8 = 0;
fn overrideEtcFile(target: [*:0]const u8, content: []const u8) SandboxError!void {
    var src_buf: [64]u8 = undefined;
    const src = fmtPath(&src_buf, "/etc-override-{d}", .{etc_override_counter}) orelse return SandboxError.PathTooLong;
    etc_override_counter += 1;
    createFile(src, content) catch return SandboxError.MountFailed;
    try mountBind(src, target);
    try remountTreeReadonly(target);
}

fn robind(source: [*:0]const u8, target: [*:0]const u8) SandboxError!void {
    try mkdirE(target);
    try mountBind(source, target);
    try remountTreeReadonly(target);
}

/// A source that cannot be bound is skipped; one that is bound ends up read-only.
fn robindOptional(source: [*:0]const u8, target: [*:0]const u8) SandboxError!void {
    mkdirE(target) catch return;
    mountBind(source, target) catch return;
    try remountTreeReadonly(target);
}

/// Remount `target` and every mount beneath it read-only. In a user namespace a
/// bind remount must keep the flags its source was locked with, or it fails.
/// Runs in the staging root, whose own `/proc` is the sandbox's at /newroot/proc.
fn remountTreeReadonly(target: [*:0]const u8) SandboxError!void {
    const prefix = std.mem.span(target);
    var info_buf: [16384]u8 = undefined;
    const info_len = readFile("/newroot/proc/self/mountinfo", &info_buf) orelse return SandboxError.MountFailed;
    if (info_len == info_buf.len) return SandboxError.MountFailed;
    const info = info_buf[0..info_len];
    var it = std.mem.splitScalar(u8, info, '\n');
    while (it.next()) |line| {
        const entry = parseMountEntry(line) orelse continue;
        var path_buf: [std.fs.max_path_bytes]u8 = undefined;
        const path = unescapeMountPath(&path_buf, entry.point) orelse return SandboxError.PathTooLong;
        if (!isWithin(path, prefix)) continue;
        // Only the topmost mount at a point is reached through its path.
        if (laterMountAt(it.rest(), entry.point)) continue;
        const flags = MS_RDONLY | MS_NOSUID | MS_NODEV | MS_REMOUNT | MS_BIND | MS_SILENT | lockedFlags(entry.options);
        if (errnoFromRc(linux.mount("none", path, null, flags, 0))) |e| {
            std.debug.print("Sandbox: read-only remount of {s} failed: {s}\n", .{ path, @tagName(e) });
            return SandboxError.MountFailed;
        }
    }
}

const MountEntry = struct { point: []const u8, options: []const u8 };

/// Fields 5 and 6 of a mountinfo line.
fn parseMountEntry(line: []const u8) ?MountEntry {
    var fields = std.mem.splitScalar(u8, line, ' ');
    for (0..4) |_| _ = fields.next() orelse return null;
    const point = fields.next() orelse return null;
    const options = fields.next() orelse return null;
    if (point.len == 0) return null;
    return .{ .point = point, .options = options };
}

fn laterMountAt(rest: []const u8, point: []const u8) bool {
    var it = std.mem.splitScalar(u8, rest, '\n');
    while (it.next()) |line| {
        const entry = parseMountEntry(line) orelse continue;
        if (std.mem.eql(u8, entry.point, point)) return true;
    }
    return false;
}

/// mountinfo writes space, tab, newline and backslash as `\ooo` octal.
fn unescapeMountPath(buf: []u8, escaped: []const u8) ?[:0]const u8 {
    var n: usize = 0;
    var i: usize = 0;
    while (i < escaped.len) : (n += 1) {
        if (n + 1 >= buf.len) return null;
        if (escaped[i] == '\\' and i + 4 <= escaped.len) {
            buf[n] = std.fmt.parseInt(u8, escaped[i + 1 .. i + 4], 8) catch return null;
            i += 4;
        } else {
            buf[n] = escaped[i];
            i += 1;
        }
    }
    buf[n] = 0;
    return buf[0..n :0];
}

const locked_options = [_]struct { name: []const u8, flag: u32 }{
    .{ .name = "noexec", .flag = MS_NOEXEC },
    .{ .name = "noatime", .flag = MS_NOATIME },
    .{ .name = "nodiratime", .flag = MS_NODIRATIME },
    .{ .name = "relatime", .flag = MS_RELATIME },
};

fn lockedFlags(options: []const u8) u32 {
    var flags: u32 = 0;
    var it = std.mem.splitScalar(u8, options, ',');
    while (it.next()) |option| for (locked_options) |locked| {
        if (std.mem.eql(u8, option, locked.name)) flags |= locked.flag;
    };
    // Neither noatime nor relatime: strictatime, which is locked too.
    if (flags & (MS_NOATIME | MS_RELATIME) == 0) flags |= MS_STRICTATIME;
    return flags;
}

// --- Low-level helpers ---

fn fmtPath(buf: []u8, comptime fmt: []const u8, args: anytype) ?[:0]const u8 {
    const result = std.fmt.bufPrint(buf[0 .. buf.len - 1], fmt, args) catch return null;
    buf[result.len] = 0;
    return buf[0..result.len :0];
}

fn callFork() ?posix.pid_t {
    const rc = linux.fork();
    const pid: isize = @bitCast(rc);
    return if (pid < 0) null else @intCast(pid);
}

fn errnoFromRc(rc: usize) ?linux.E {
    const signed: isize = @bitCast(rc);
    return if (signed < 0) @enumFromInt(@as(u16, @intCast(-signed))) else null;
}

fn mkdirE(path: [*:0]const u8) SandboxError!void {
    if (errnoFromRc(linux.mkdir(path, 0o755))) |e|
        if (e != .EXIST) return SandboxError.MkdirFailed;
}

fn mkdirp(path: [*:0]const u8) void {
    const span = std.mem.span(path);
    if (span.len == 0) return;
    var buf: [512]u8 = undefined;
    if (span.len >= buf.len) return;
    @memcpy(buf[0..span.len], span);
    var i: usize = 1;
    while (i < span.len) : (i += 1) {
        if (buf[i] == '/') {
            buf[i] = 0;
            _ = linux.mkdir(buf[0..i :0], 0o755);
            buf[i] = '/';
        }
    }
    buf[span.len] = 0;
    _ = linux.mkdir(buf[0..span.len :0], 0o755);
}

fn touchFile(path: [*:0]const u8) !void {
    const fd_rc = linux.openat(linux.AT.FDCWD, path, .{ .ACCMODE = .WRONLY, .CREAT = true }, 0o644);
    if (errnoFromRc(fd_rc)) |_| return error.OpenFailed;
    _ = linux.close(@intCast(fd_rc));
}

fn writeFile(path: [*:0]const u8, data: []const u8) !void {
    const fd_rc = linux.openat(linux.AT.FDCWD, path, .{ .ACCMODE = .WRONLY }, 0);
    if (errnoFromRc(fd_rc)) |_| return error.OpenFailed;
    const fd: posix.fd_t = @intCast(fd_rc);
    defer _ = linux.close(fd);
    if (errnoFromRc(linux.write(fd, data.ptr, data.len))) |_| return error.WriteFailed;
}

fn createFile(path: [*:0]const u8, data: []const u8) !void {
    const fd_rc = linux.openat(linux.AT.FDCWD, path, .{ .ACCMODE = .WRONLY, .CREAT = true }, 0o644);
    if (errnoFromRc(fd_rc)) |_| return error.OpenFailed;
    const fd: posix.fd_t = @intCast(fd_rc);
    defer _ = linux.close(fd);
    if (errnoFromRc(linux.write(fd, data.ptr, data.len))) |_| return error.WriteFailed;
}

fn readFile(path: [*:0]const u8, buf: []u8) ?usize {
    const fd_rc = linux.openat(linux.AT.FDCWD, path, .{ .ACCMODE = .RDONLY }, 0);
    if (errnoFromRc(fd_rc)) |_| return null;
    const fd: posix.fd_t = @intCast(fd_rc);
    defer _ = linux.close(fd);
    var total: usize = 0;
    while (total < buf.len) {
        const n: isize = @bitCast(linux.read(fd, buf[total..].ptr, buf[total..].len));
        if (n <= 0) break;
        total += @intCast(n);
    }
    return total;
}

fn logErrno(op: []const u8, e: linux.E) void {
    std.debug.print("Sandbox: {s} failed: {s}\n", .{ op, @tagName(e) });
}

fn logMountError(source: [*:0]const u8, target: [*:0]const u8, e: linux.E) void {
    std.debug.print("Sandbox: mount {s} → {s} failed: {s}\n", .{
        std.mem.span(source), std.mem.span(target), @tagName(e),
    });
}

fn fatalChild(context: []const u8, err: anyerror) noreturn {
    std.debug.print("Sandbox fatal ({s}): {}\n", .{ context, err });
    linux.exit_group(126);
}
