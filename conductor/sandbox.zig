// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0
//
// Linux sandbox for untrusted Julia worker processes.
//
// Uses unprivileged user namespaces (no root required) to isolate a
// child process with its own uid mapping, PID namespace, and filesystem.
// The child sees a minimal root built from read-only bind mounts of host
// system directories plus an overlayfs on ~/.julia (so writes are
// ephemeral). The host home directory is not accessible.
//
// Public API:
//   spawnSandboxed  — build argv/envp from config, fork+exec in sandbox
//   execInSandbox   — fork+exec pre-built argv/envp in sandbox
//   envAllowed      — test whether an env var passes the sandbox allowlist
//   cleanupCgroup   — remove a sandbox's cgroup directory by worker ID

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
    // Process execution
    julia_executable: []const u8,
    julia_channel: ?[]const u8,
    worker_project: []const u8,
    worker_args: []const u8,
    eval_expr: []const u8,
    host_environ: *const std.process.Environ.Map,
    setup_socket_path: []const u8, // host path to wsetup-*.sock (bind-mounted individually)
    worker_id: u32, // conductor-assigned worker ID (unique, used for cgroup naming)
    // Isolation
    host_home: []const u8,
    extra_ro_binds: []const []const u8 = &.{},
    empty_environment: bool = true,
    max_memory: ?[]const u8,
    max_cpu: ?u32,
};

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

/// Build argv/envp from config, then fork+exec inside a sandboxed namespace.
/// Returns the child PID on success.
pub fn spawnSandboxed(allocator: Allocator, config: *const SandboxConfig) SandboxError!posix.pid_t {
    const argv = buildArgv(allocator, config) catch return SandboxError.ExecFailed;
    defer freeNullTermList(allocator, argv);
    const envp = buildEnvp(allocator, config) catch return SandboxError.ExecFailed;
    defer freeNullTermList(allocator, envp);
    return execInSandbox(argv, envp, config);
}

/// Fork+exec pre-built argv/envp inside a sandboxed namespace.
/// Returns the child PID on success.
pub fn execInSandbox(
    argv: [*:null]const ?[*:0]const u8,
    envp: [*:null]const ?[*:0]const u8,
    config: *const SandboxConfig,
) SandboxError!posix.pid_t {
    const orig_uid = linux.getuid();
    const orig_gid = linux.getgid();
    // First fork: parent gets child PID back
    const pid1 = callFork() orelse return SandboxError.ForkFailed;
    if (pid1 != 0) return pid1;
    // Child 1: create new user/mount/PID namespaces
    setupNamespaces(orig_uid, orig_gid) catch |err|
        fatalChild("namespace setup", err);
    // Second fork: enter the PID namespace (child becomes PID 1 inside)
    const pid2 = callFork() orelse
        fatalChild("inner fork", SandboxError.ForkFailed);
    if (pid2 != 0) {
        var status: u32 = 0;
        _ = linux.waitpid(@intCast(pid2), &status, 0);
        linux.exit_group(@intCast(status >> 8));
    }
    // Child 2 (PID 1 inside): build filesystem and exec
    setupFilesystem(config) catch |err|
        fatalChild("filesystem setup", err);
    if (config.max_memory != null or config.max_cpu != null)
        setupCgroup(config) catch {};
    const exe = argv[0].?;
    std.debug.print("Sandbox: execve {s}\n", .{std.mem.span(exe)});
    const rc = linux.execve(exe, argv, envp);
    if (errnoFromRc(rc)) |e|
        std.debug.print("Sandbox: execve failed: {s}\n", .{@tagName(e)});
    linux.exit_group(127);
}

/// Test whether an environment variable key passes the sandbox allowlist.
pub fn envAllowed(key: []const u8) bool {
    if (std.mem.startsWith(u8, key, "JULIA_")) return true;
    for (env_allowlist) |allowed|
        if (std.mem.eql(u8, key, allowed)) return true;
    return false;
}

/// Remove a sandbox's cgroup directory after the worker exits. Best-effort.
pub fn cleanupCgroup(worker_id: u32) void {
    var buf: [128]u8 = undefined;
    const path = fmtPath(&buf, "/sys/fs/cgroup/julia-sandbox-{d}", .{worker_id}) orelse return;
    _ = linux.unlinkat(linux.AT.FDCWD, path, linux.AT.REMOVEDIR);
}

// --- Namespace setup ---

fn setupNamespaces(orig_uid: linux.uid_t, orig_gid: linux.gid_t) SandboxError!void {
    if (errnoFromRc(linux.unshare(CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWUSER))) |e| {
        logErrno("unshare", e);
        return SandboxError.UnshareFailed;
    }
    // Deny setgroups, then map uid/gid: 0 inside → real uid/gid outside
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
//
// Build a new root from scratch:
//   1. mountStaging    — tmpfs staging area, overlay dirs, first pivot_root
//   2. mountSystemDirs — /dev, /proc, /tmp, system ro-binds
//   3. mountHome       — /home tmpfs, juliaup config, depot overlay, sandbox symlink
//   4. extra ro-binds  — caller-specified paths (e.g. worker project)
//   5. final pivot     — pivot_root into /newroot, detach staging

fn setupFilesystem(config: *const SandboxConfig) SandboxError!void {
    const home = config.host_home;
    try mountStaging();
    try mountSystemDirs();
    try mountHome(config, home);
    // Extra read-only bind mounts
    for (config.extra_ro_binds) |path| {
        if (path.len == 0) continue;
        var src_buf: [512]u8 = undefined;
        var dst_buf: [512]u8 = undefined;
        const src = fmtPath(&src_buf, "/oldroot{s}", .{path}) orelse continue;
        const dst = fmtPath(&dst_buf, "/newroot{s}", .{path}) orelse continue;
        mkdirp(dst);
        robindOptional(src, dst);
    }
    // Setup socket: bind-mount only the specific socket file the worker
    // needs to connect back to the conductor. This avoids exposing the
    // entire runtime dir (which contains conductor.sock, pid files, etc.).
    if (config.setup_socket_path.len > 0) {
        var sock_src: [512]u8 = undefined;
        var sock_dst: [512]u8 = undefined;
        if (fmtPath(&sock_src, "/oldroot{s}", .{config.setup_socket_path})) |src| {
            if (fmtPath(&sock_dst, "/newroot{s}", .{config.setup_socket_path})) |dst| {
                mkdirp(dst);
                touchFile(dst) catch {};
                mountBind(src, dst) catch {};
            }
        }
    }
    // Final pivot: enter /newroot, detach staging
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

/// Create tmpfs staging area, prepare overlay dirs, pivot_root into staging.
fn mountStaging() SandboxError!void {
    // Prevent mount propagation back to host
    mountFlags("/", MS_SLAVE | MS_REC) catch return SandboxError.MountFailed;
    mountTmpfs("/tmp", MS_NOSUID | MS_NODEV, null) catch return SandboxError.MountFailed;
    if (errnoFromRc(linux.chdir("/tmp"))) |_| return SandboxError.ChdirFailed;
    // Staging layout
    try mkdirE("newroot");
    mountBind("newroot", "newroot") catch return SandboxError.MountFailed;
    try mkdirE("oldroot");
    // Overlay upper/work on the staging tmpfs — ephemeral, per-sandbox
    try mkdirE("ovl-upper");
    try mkdirE("ovl-work");
    // Pivot into staging
    if (errnoFromRc(linux.pivot_root("/tmp", "oldroot"))) |e| {
        logErrno("pivot_root staging", e);
        return SandboxError.PivotRootFailed;
    }
    if (errnoFromRc(linux.chdir("/"))) |_| return SandboxError.ChdirFailed;
}

/// Mount /dev, /proc, /tmp, and read-only system directories into /newroot.
fn mountSystemDirs() SandboxError!void {
    // /dev — tmpfs with bind-mounted device nodes and devpts
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
    // /proc — fresh procfs scoped to PID namespace
    try mkdirE("/newroot/proc");
    mountOrFail("proc", "/newroot/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, "") catch
        return SandboxError.MountFailed;
    // /tmp — private tmpfs
    try mkdirE("/newroot/tmp");
    mountTmpfs("/newroot/tmp", MS_NOSUID | MS_NODEV, "mode=1777") catch
        return SandboxError.MountFailed;
    // System directories — read-only from host
    try robind("/oldroot/usr", "/newroot/usr");
    try robind("/oldroot/etc", "/newroot/etc");
    // Override identity files: the host /etc/passwd maps uid 0 → root,
    // and nss-systemd can leak the real host user through the namespace
    // uid mapping. Write synthetic files and bind-mount them over the
    // host originals so getpwuid(0) returns "sandbox".
    overrideEtcFile("/newroot/etc/passwd",
        "root:x:0:0:root:/root:/bin/sh\nsandbox:x:0:0:sandbox:/home/sandbox:/bin/sh\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n");
    overrideEtcFile("/newroot/etc/group",
        "root:x:0:\nsandbox:x:0:\nnogroup:x:65534:\n");
    overrideEtcFile("/newroot/etc/nsswitch.conf",
        "passwd: files\ngroup:  files\nshadow: files\nhosts:  files dns\nnetworks: files\nprotocols: files\nservices: files\n");
    // /lib, /lib64, /bin are often symlinks to /usr/* — bind resolved paths
    robindOptional("/oldroot/usr/lib", "/newroot/lib");
    robindOptional("/oldroot/usr/lib64", "/newroot/lib64");
    robindOptional("/oldroot/usr/bin", "/newroot/bin");
    robindOptional("/oldroot/opt", "/newroot/opt");
}

/// Mount /home tmpfs, juliaup config bind, depot overlay, and sandbox symlink.
fn mountHome(config: *const SandboxConfig, home: []const u8) SandboxError!void {
    try mkdirE("/newroot/home");
    mountTmpfs("/newroot/home", MS_NOSUID | MS_NODEV, "mode=0755") catch
        return SandboxError.MountFailed;
    if (home.len == 0) return;
    // Juliaup config: sandbox runs as uid 0, so juliaup looks at
    // /root/.julia/juliaup/. Bind the real user's dir there (rw for lockfile).
    var juliaup_buf: [384]u8 = undefined;
    if (fmtPath(&juliaup_buf, "/oldroot{s}/.julia/juliaup", .{home})) |src| {
        mkdirp("/newroot/root/.julia/juliaup");
        mountBind(src, "/newroot/root/.julia/juliaup") catch {};
    }
    // Depot overlay at the host path (precompile caches embed absolute paths)
    var depot_buf: [384]u8 = undefined;
    const depot = fmtPath(&depot_buf, "/newroot{s}/.julia", .{home}) orelse
        return SandboxError.PathTooLong;
    mkdirp(depot);
    mountDepotOverlay(config, home, depot);
    // /home/sandbox with symlink to depot
    mkdirE("/newroot/home/sandbox") catch {};
    var link_buf: [384]u8 = undefined;
    if (fmtPath(&link_buf, "{s}/.julia", .{home})) |target|
        _ = linux.symlink(target, "/newroot/home/sandbox/.julia");
}

/// Mount overlayfs on the depot directory, with fallback to read-only bind.
fn mountDepotOverlay(config: *const SandboxConfig, home: []const u8, depot: [*:0]const u8) void {
    var opts_buf: [512]u8 = undefined;
    const opts = fmtPath(&opts_buf,
        "upperdir=/ovl-upper,workdir=/ovl-work,lowerdir=/oldroot{s}/.julia,userxattr",
        .{home}) orelse return;
    mountOrFail("overlay", depot, "overlay", 0, opts) catch {
        std.debug.print("Sandbox: overlay on ~/.julia failed, falling back to bind mount\n", .{});
        var src_buf: [384]u8 = undefined;
        if (fmtPath(&src_buf, "/oldroot{s}/.julia", .{home})) |src|
            robindOptional(src, depot);
        return;
    };
    // Mask ~/.julia/environments so the sandbox can't see or modify host environments
    if (config.empty_environment) {
        var env_buf: [384]u8 = undefined;
        if (fmtPath(&env_buf, "/newroot{s}/.julia/environments", .{home})) |env_path| {
            mkdirE(env_path) catch {};
            mountTmpfs(env_path, MS_NOSUID | MS_NODEV, "mode=0755") catch {};
        }
    }
}

// --- Cgroup v2 resource limits ---

/// Set up cgroup v2 resource limits. Uses worker_id (not PID) for the
/// cgroup name, since the in-namespace PID is always 1 after double-fork
/// and would collide across sandbox instances.
fn setupCgroup(config: *const SandboxConfig) !void {
    var cg_buf: [128]u8 = undefined;
    const cg = fmtPath(&cg_buf, "/sys/fs/cgroup/julia-sandbox-{d}", .{config.worker_id}) orelse
        return SandboxError.CgroupSetupFailed;
    mkdirE(cg) catch return SandboxError.CgroupSetupFailed;
    if (config.max_memory) |mem| {
        var buf: [192]u8 = undefined;
        const path = fmtPath(&buf, "{s}/memory.max", .{cg}) orelse return SandboxError.CgroupSetupFailed;
        writeFile(path, mem) catch return SandboxError.CgroupSetupFailed;
    }
    if (config.max_cpu) |cpu| {
        var path_buf: [192]u8 = undefined;
        const path = fmtPath(&path_buf, "{s}/cpu.max", .{cg}) orelse return SandboxError.CgroupSetupFailed;
        var val_buf: [32]u8 = undefined;
        const val = std.fmt.bufPrint(&val_buf, "{d} 100000", .{@as(u64, cpu) * 1000}) catch
            return SandboxError.CgroupSetupFailed;
        writeFile(path, val) catch return SandboxError.CgroupSetupFailed;
    }
    // Move self into the cgroup
    var procs_buf: [192]u8 = undefined;
    const procs = fmtPath(&procs_buf, "{s}/cgroup.procs", .{cg}) orelse return SandboxError.CgroupSetupFailed;
    writeFile(procs, "0") catch return SandboxError.CgroupSetupFailed;
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
    // Split on spaces; individual args containing spaces are not supported.
    var it = std.mem.tokenizeScalar(u8, config.worker_args, ' ');
    while (it.next()) |arg|
        try list.append(try allocator.dupeZ(u8, arg));
    try list.append(try allocator.dupeZ(u8, "--eval"));
    try list.append(try allocator.dupeZ(u8, config.eval_expr));
    const argv = try allocator.allocSentinel(?[*:0]const u8, list.items.len, null);
    for (list.items, 0..) |s, i| argv[i] = s;
    return argv;
}

/// Environment variables allowed through from the host (in addition to JULIA_*).
const env_allowlist = [_][]const u8{
    "LANG",  "LC_CTYPE",  "LC_ALL",
    "TERM",  "COLORTERM",
    "PATH",  "XDG_DATA_HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME",
    "OPENBLAS_MAIN_FREE", "OPENBLAS_DEFAULT_NUM_THREADS",
    "CUDA_CACHE_PATH",
};

/// Keys always overridden rather than passed through from the host.
const env_managed = [_][]const u8{
    "HOME", "USER", "LOGNAME", "PATH",
    "JULIA_DEPOT_PATH", "JULIA_DAEMON_REVISE",
};

fn buildEnvp(allocator: Allocator, config: *const SandboxConfig) ![:null]?[*:0]const u8 {
    var list = std.array_list.AlignedManaged([*:0]const u8, null).init(allocator);
    defer list.deinit();
    errdefer for (list.items) |s| allocator.free(std.mem.span(s));
    // Pass through allowlisted host vars, skipping managed keys
    const env = config.host_environ;
    for (env.array_hash_map.keys(), env.array_hash_map.values()) |key, value| {
        var managed = false;
        for (env_managed) |mk| if (std.mem.eql(u8, key, mk)) { managed = true; };
        if (!managed and envAllowed(key))
            try list.append(try std.fmt.allocPrintSentinel(allocator, "{s}={s}", .{ key, value }, 0));
    }
    // Sandbox identity and paths
    try list.append(try allocator.dupeZ(u8, "HOME=/home/sandbox"));
    try list.append(try allocator.dupeZ(u8, "USER=sandbox"));
    try list.append(try allocator.dupeZ(u8, "LOGNAME=sandbox"));
    if (config.host_home.len > 0) {
        try list.append(try std.fmt.allocPrintSentinel(allocator,
            "PATH={s}/.julia/juliaup/bin:/usr/local/bin:/usr/bin:/bin", .{config.host_home}, 0));
        try list.append(try std.fmt.allocPrintSentinel(allocator,
            "JULIA_DEPOT_PATH={s}/.julia", .{config.host_home}, 0));
    } else {
        try list.append(try allocator.dupeZ(u8, "PATH=/usr/local/bin:/usr/bin:/bin"));
    }
    try list.append(try allocator.dupeZ(u8, "JULIA_DAEMON_REVISE=no"));
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

/// Write content to a staging tmpfs file and bind-mount it over target.
/// Used to override individual files inside a read-only /etc bind mount.
var etc_override_counter: u8 = 0;
fn overrideEtcFile(target: [*:0]const u8, content: []const u8) void {
    var src_buf: [64]u8 = undefined;
    const src = fmtPath(&src_buf, "/etc-override-{d}", .{etc_override_counter}) orelse return;
    etc_override_counter += 1;
    createFile(src, content) catch return;
    mountBind(src, target) catch return;
    remountReadonly(target);
}

/// Bind-mount source to target read-only, remounting all submounts rdonly.
fn robind(source: [*:0]const u8, target: [*:0]const u8) SandboxError!void {
    try mkdirE(target);
    mountBind(source, target) catch return SandboxError.MountFailed;
    remountReadonly(target);
    remountSubmountsReadonly(target);
}

/// Like robind but silently skips if source doesn't exist.
fn robindOptional(source: [*:0]const u8, target: [*:0]const u8) void {
    mkdirE(target) catch return;
    mountBind(source, target) catch return;
    remountReadonly(target);
    remountSubmountsReadonly(target);
}

fn remountReadonly(target: [*:0]const u8) void {
    _ = linux.mount("none", target, null, MS_RDONLY | MS_NOSUID | MS_NODEV | MS_REMOUNT | MS_BIND | MS_SILENT, 0);
}

/// Read /proc/self/mountinfo and remount any mounts strictly under target as rdonly.
/// Aborts the sandbox if mountinfo is truncated or a mount path overflows,
/// since silently skipping mounts would leave them writable.
fn remountSubmountsReadonly(target: [*:0]const u8) void {
    const prefix = std.mem.span(target);
    var info_buf: [16384]u8 = undefined;
    const info_len = readFile("/proc/self/mountinfo", &info_buf) orelse return;
    if (info_len == info_buf.len)
        fatalChild("remountSubmountsReadonly", SandboxError.MountFailed);
    var it = std.mem.splitScalar(u8, info_buf[0..info_len], '\n');
    while (it.next()) |line| {
        if (line.len == 0) continue;
        const mp = parseMountPoint(line) orelse continue;
        if (mp.len <= prefix.len or !std.mem.startsWith(u8, mp, prefix) or mp[prefix.len] != '/')
            continue;
        var buf: [std.fs.max_path_bytes]u8 = undefined;
        if (mp.len >= buf.len)
            fatalChild("remountSubmountsReadonly: path too long", SandboxError.PathTooLong);
        @memcpy(buf[0..mp.len], mp);
        buf[mp.len] = 0;
        _ = linux.mount("none", buf[0..mp.len :0], null,
            MS_RDONLY | MS_NOSUID | MS_NODEV | MS_REMOUNT | MS_BIND | MS_SILENT, 0);
    }
}

/// Extract mount point (field 5) from a /proc/self/mountinfo line.
fn parseMountPoint(line: []const u8) ?[]const u8 {
    var pos: usize = 0;
    var field: u8 = 0;
    while (field < 4) : (field += 1) {
        while (pos < line.len and line[pos] != ' ') pos += 1;
        if (pos >= line.len) return null;
        pos += 1;
    }
    const start = pos;
    while (pos < line.len and line[pos] != ' ') pos += 1;
    return if (pos == start) null else line[start..pos];
}

// --- Low-level helpers ---

/// Format a null-terminated path into a stack buffer. Returns null on overflow.
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

/// Create all directories along a path (like mkdir -p). Best-effort.
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
