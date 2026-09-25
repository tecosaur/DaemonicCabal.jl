// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const Io = std.Io;
const Allocator = std.mem.Allocator;
const platform = @import("platform/main.zig");
const protocol = @import("protocol.zig");
const config = @import("config.zig");
const args = @import("args.zig");
pub const sandbox = if (builtin.os.tag == .linux) @import("sandbox.zig") else struct {};

const BufWriter = protocol.BufWriter;
const readExact = protocol.readExact;

const max_recent_ppids = 32;
const daemon_env_prefix = "JULIA_DAEMON_";

// --- Activity signals (see WORKER_CACHE.md) ---

fn decay(dt_s: i64, half_life_s: u64) f64 {
    if (half_life_s == 0) return 0;
    return std.math.exp2(-@as(f64, @floatFromInt(dt_s)) / @as(f64, @floatFromInt(half_life_s)));
}

/// `value` is the LRFU score; `srtt`/`rttvar` estimate the inter-summon
/// interval as RFC 6298 does round trips.
pub const Crf = struct {
    value: f64 = 0,
    last_update: i64 = 0,
    srtt: f64 = 0, // seconds; 0 until the second summon
    rttvar: f64 = 0,

    pub fn summon(self: *Crf, now: i64, half_life_s: u64) void {
        const gap = now - self.last_update;
        if (self.value > 0 and gap > 0) {
            const g: f64 = @floatFromInt(gap);
            if (self.srtt == 0) {
                self.srtt = g;
                self.rttvar = g / 2;
            } else {
                self.rttvar = 0.75 * self.rttvar + 0.25 * @abs(self.srtt - g);
                self.srtt = 0.875 * self.srtt + 0.125 * g;
            }
        }
        self.value = 1 + self.value * decay(gap, half_life_s);
        self.last_update = now;
    }

    /// RFC 6298's RTO.
    pub fn intervalBudget(self: *const Crf) f64 {
        return self.srtt + 4 * self.rttvar;
    }

    pub fn read(self: *const Crf, now: i64, half_life_s: u64) f64 {
        return self.value * decay(now - self.last_update, half_life_s);
    }

    /// Into [0,1), comparable with occupancy; monotone, so ranking is kept.
    pub fn normalize(value: f64) f64 {
        return value / (value + 2.0);
    }
};

/// PELT-style decayed busy-fraction; folding is exact, as the EWMA composes.
pub const Occupancy = struct {
    value: f64 = 0,
    last_update: i64 = 0,
    busy: bool = false,

    fn fold(self: *Occupancy, now: i64, half_life_s: u64) void {
        const dt = now - self.last_update;
        if (dt <= 0) return;
        const d = decay(dt, half_life_s);
        self.value = (if (self.busy) 1 - d else 0) + self.value * d;
        self.last_update = now;
    }

    pub fn attach(self: *Occupancy, now: i64, half_life_s: u64) void {
        self.fold(now, half_life_s);
        self.busy = true;
    }

    pub fn detach(self: *Occupancy, now: i64, half_life_s: u64) void {
        self.fold(now, half_life_s);
        self.busy = false;
    }

    pub fn read(self: *const Occupancy, now: i64, half_life_s: u64) f64 {
        const d = decay(now - self.last_update, half_life_s);
        return (if (self.busy) 1 - d else 0) + self.value * d;
    }
};

/// The fast signal ranks under pressure; the slow one scales the idle-cull budget.
pub const Occupancies = struct {
    fast: Occupancy = .{},
    slow: Occupancy = .{},

    pub fn attach(self: *Occupancies, now: i64, fast_hl: u64, slow_hl: u64) void {
        self.fast.attach(now, fast_hl);
        self.slow.attach(now, slow_hl);
    }

    pub fn detach(self: *Occupancies, now: i64, fast_hl: u64, slow_hl: u64) void {
        self.fast.detach(now, fast_hl);
        self.slow.detach(now, slow_hl);
    }
};

/// Busy cores, as an EWMA over real elapsed time.
pub const CpuMeter = struct {
    util: f64 = 0,
    last_cpu_s: f64 = 0,
    last_ns: i64 = 0,
    primed: bool = false,

    // A null `half_life_s` sets util to the raw rate since the last reading.
    pub fn update(self: *CpuMeter, now_ns: i64, cpu_s: f64, half_life_s: ?f64) void {
        const dt = @as(f64, @floatFromInt(now_ns - self.last_ns)) / 1_000_000_000.0;
        if (self.primed and dt > 0) {
            const rate = @max(0, cpu_s - self.last_cpu_s) / dt;
            self.util = if (half_life_s) |h| blk: {
                const d = std.math.exp2(-dt / h);
                break :blk rate * (1 - d) + self.util * d;
            } else rate;
        }
        self.last_cpu_s = cpu_s;
        self.last_ns = now_ns;
        self.primed = true;
    }
};

pub const Worker = struct {
    allocator: Allocator,
    id: u32,
    process: std.process.Child,
    socket: posix.socket_t,
    project: ?[]const u8,
    julia_channel: ?[]const u8,
    threads: args.Threads,
    session_label: ?[]const u8,
    created_at: i64,
    last_active: i64,
    last_pinged: i64,
    ping_pending: bool = false,
    /// Set once an unanswered ping has been met with `forceInterrupt`.
    unresponsive_interrupted: bool = false,
    /// Echoed in the pong, which tells a late pong for an earlier ping from this one's.
    ping_seq: u8 = 0,
    pong_buf: [protocol.worker.pong_size]u8 = undefined,
    active_clients: u32,
    occupancy: Occupancies = .{},
    cpu: CpuMeter = .{},
    mem: u64 = 0, // bytes: RSS on Linux, phys_footprint on macOS
    mem_at: i64 = 0, // seconds
    launch: LaunchKind = .direct,
    interactive: bool = false,
    pidfd: ?posix.fd_t = null, // for a client-spawned worker, which is not our child
    recent_ppids: [max_recent_ppids]u32 = .{0} ** max_recent_ppids,
    recent_ppids_next: usize = 0,

    pub const Launch = union(enum) {
        direct,
        sandboxed: struct {
            environ: *const std.process.Environ.Map,
            ro_binds: []const []const u8,
            rw_binds: []const []const u8,
        },
        /// Started by the client, in a mount namespace we cannot see into.
        client: struct { socket: posix.socket_t, environ: *const std.process.Environ.Map, ns: u64 },
    };
    pub const LaunchKind = std.meta.Tag(Launch);

    pub fn begin(
        allocator: Allocator,
        io: Io,
        cfg: *const config.Config,
        id: u32,
        julia_channel: ?[]const u8,
        threads: args.Threads,
        interactive: bool,
        launch: Launch,
    ) !Spawn {
        // A sandbox binds only this subdirectory; the worker puts its stdio
        // sockets beside its setup socket.
        var subdir_buf: [std.fs.max_path_bytes]u8 = undefined;
        const socket_dir = if (launch == .sandboxed) blk: {
            const subdir = std.fmt.bufPrint(&subdir_buf, "{s}/sandbox-{d}", .{ cfg.socket_dir, id }) catch
                return error.PathTooLong;
            Io.Dir.createDirAbsolute(io, subdir, .default_dir) catch {};
            break :blk subdir;
        } else cfg.socket_dir;
        var setup = try protocol.createListener(io, .local, socket_dir, "wsetup.sock", "");
        errdefer setup.close(io);
        const channel_copy: ?[]const u8 = if (julia_channel) |ch| try allocator.dupe(u8, ch) else null;
        errdefer if (channel_copy) |ch| allocator.free(ch);
        const eval_expr = try std.fmt.allocPrint(
            allocator,
            "using DaemonWorker; DaemonWorker.runworker({f}, {f})",
            .{ juliaString(setup.addr()), juliaString(cfg.socket_path) },
        );
        defer allocator.free(eval_expr);
        // Passed after worker_args so a client's request wins.
        const threads_arg: ?[]const u8 = if (try args.renderThreads(allocator, threads)) |v| blk: {
            defer allocator.free(v);
            break :blk try std.fmt.allocPrint(allocator, "--threads={s}", .{v});
        } else null;
        defer if (threads_arg) |a| allocator.free(a);
        const environ: ?*const std.process.Environ.Map = switch (launch) {
            .direct => null,
            .sandboxed => |s| s.environ,
            .client => |c| c.environ,
        };
        // Raw execve (sandbox, client spawn) needs an absolute path.
        const bare = std.mem.indexOfScalar(u8, cfg.worker_executable, '/') == null;
        const resolved: ?[]const u8 = if (!bare) cfg.worker_executable else if (environ) |env|
            (if (env.get("PATH")) |p| resolveInPath(io, cfg.worker_executable, p) else null)
        else
            null;
        const child: std.process.Child = switch (launch) {
            .sandboxed => |s| if (comptime builtin.os.tag != .linux) return error.SandboxUnsupported else blk: {
                const exe_path = resolved orelse cfg.worker_executable;
                var ro_binds: [8][]const u8 = undefined;
                var n_ro: usize = 0;
                ro_binds[n_ro] = cfg.worker_project;
                n_ro += 1;
                if (s.ro_binds.len > ro_binds.len - n_ro) {
                    std.debug.print("Worker: too many ro binds ({d}), max {d}\n", .{ s.ro_binds.len + 1, ro_binds.len });
                    return error.TooManyBinds;
                }
                for (s.ro_binds) |b| {
                    ro_binds[n_ro] = b;
                    n_ro += 1;
                }
                const sandbox_cfg = sandbox.SandboxConfig{
                    .julia_executable = exe_path,
                    .julia_channel = julia_channel,
                    .threads_arg = threads_arg,
                    .worker_project = cfg.worker_project,
                    .worker_args = cfg.worker_args,
                    .eval_expr = eval_expr,
                    .host_environ = s.environ,
                    .setup_socket_path = setup.addr(),
                    .worker_id = id,
                    .host_home = cfg.host_home,
                    .depot_env = s.environ.get("JULIA_DEPOT_PATH"),
                    .extra_ro_binds = ro_binds[0..n_ro],
                    .extra_rw_binds = s.rw_binds,
                    .max_memory = cfg.sandbox_max_memory,
                    .max_cpu = cfg.sandbox_max_cpu,
                };
                std.debug.print("Spawning sandboxed worker\n", .{});
                const sandbox_pid = try sandbox.spawnSandboxed(allocator, &sandbox_cfg);
                // Child 1, the waiter: killing it ends the whole sandbox.
                break :blk .{ .id = sandbox_pid, .thread_handle = {}, .stdin = null, .stdout = null, .stderr = null, .request_resource_usage_statistics = false };
            },
            .direct, .client => blk: {
                var argv = std.array_list.AlignedManaged([]const u8, null).init(allocator);
                defer argv.deinit();
                try argv.append(if (launch == .client) resolved orelse {
                    std.debug.print("Worker {d}: cannot resolve '{s}' on the daemon's PATH to name it to the client's sandbox; set JULIA_DAEMON_WORKER_EXECUTABLE to an absolute path\n", .{ id, cfg.worker_executable });
                    return error.ExecutableNotFound;
                } else cfg.worker_executable);
                if (julia_channel) |ch| try argv.append(ch);
                const project_arg: ?[]const u8 = if (cfg.worker_project.len > 0)
                    try std.fmt.allocPrint(allocator, "--project={s}", .{cfg.worker_project})
                else
                    null;
                defer if (project_arg) |p| allocator.free(p);
                if (project_arg) |p| try argv.append(p);
                {
                    // Args containing spaces are not supported.
                    var it = std.mem.tokenizeScalar(u8, cfg.worker_args, ' ');
                    while (it.next()) |arg| try argv.append(arg);
                }
                if (threads_arg) |a| try argv.append(a);
                if (interactive) try argv.append("-i");
                try argv.append("--eval");
                try argv.append(eval_expr);
                break :blk switch (launch) {
                    .client => |c| handed: {
                        try sendSpawnRequest(c.socket, argv.items, c.environ);
                        break :handed platform.no_child;
                    },
                    else => try platform.spawnWorker(io, argv.items),
                };
            },
        };
        const now = Io.Clock.now(.awake, io).toSeconds();
        const pending = Spawn{
            .worker = .{
                .allocator = allocator,
                .id = id,
                .process = child,
                .socket = platform.no_socket,
                .project = null,
                .julia_channel = channel_copy,
                .threads = threads,
                .session_label = null,
                .created_at = now,
                .last_active = now,
                .last_pinged = now,
                .active_clients = 0,
                .launch = launch,
                .interactive = interactive,
            },
            .client_ns = if (launch == .client) launch.client.ns else null,
            .listener = setup,
            .deadline = now + @as(i64, @intCast(cfg.spawn_timeout)),
        };
        return pending;
    }

    /// Escapes `"`, `\` and `$` for embedding in `--eval` source.
    fn juliaString(bytes: []const u8) std.fmt.Alt([]const u8, formatJuliaString) {
        return .{ .data = bytes };
    }
    fn formatJuliaString(bytes: []const u8, w: *std.Io.Writer) std.Io.Writer.Error!void {
        try w.writeByte('"');
        for (bytes) |b| {
            if (b == '"' or b == '\\' or b == '$') try w.writeByte('\\');
            try w.writeByte(b);
        }
        try w.writeByte('"');
    }

    /// A launched worker not yet connected. The deadline is fixed at launch, so
    /// dropped connections cannot extend it.
    pub const Spawn = struct {
        worker: Worker, // socket, pidfd and a client launch's pid arrive with the connection
        client_ns: ?u64,
        listener: protocol.Listener,
        deadline: i64,

        pub fn listenerFd(self: *const Spawn) posix.socket_t {
            return self.listener.fd();
        }

        /// Null when nothing was waiting or an unexpected process connected:
        /// anything reaching the runtime directory could pose as the worker.
        pub fn accept(self: *Spawn, io: Io, cfg: *const config.Config) !?Worker {
            const socket = (try self.listener.acceptTimeout(io, 0)) orelse return null;
            var w = self.worker;
            if (!isExpectedWorker(socket, w.launch, self.client_ns, w.process.id)) {
                std.debug.print("Worker {d}: dropped a setup connection from an unexpected process\n", .{w.id});
                platform.close(socket);
                return null;
            }
            errdefer platform.close(socket);
            // Not our child: only a pidfd taken now survives pid reuse.
            if (w.launch == .client) {
                w.process.id = platform.peerPid(socket) orelse {
                    std.debug.print("Worker {d}: no peer credentials on the setup connection, so the client-spawned worker cannot be tracked\n", .{w.id});
                    return error.UnknownWorkerPid;
                };
                w.pidfd = platform.pidfdOpen(w.process.id.?) orelse {
                    std.debug.print("Worker {d}: pidfd_open failed for pid {d}; client-spawned workers need Linux 5.3+\n", .{ w.id, platform.pidNumber(w.process.id.?) });
                    return error.PidfdUnsupported;
                };
            }
            platform.setRecvTimeout(socket, @intCast(cfg.ping_timeout));
            var magic_buf: [4]u8 = undefined;
            std.mem.writeInt(u32, &magic_buf, protocol.worker.magic, .little);
            platform.write(socket, &magic_buf);
            self.listener.close(io);
            self.worker.julia_channel = null; // moved into `w`
            w.socket = socket;
            w.created_at = Io.Clock.now(.awake, io).toSeconds();
            w.last_active = w.created_at;
            w.last_pinged = w.created_at;
            return w;
        }

        /// A client-launched worker is not our child; its client's socket turning
        /// readable signals failure instead.
        pub fn check(self: *Spawn, io: Io, cfg: *const config.Config) !void {
            if (platform.timeSeconds(io) >= self.deadline) {
                std.debug.print("Worker {d}: no connection from the new worker within {d}s (JULIA_DAEMON_SPAWN_TIMEOUT)\n", .{ self.worker.id, cfg.spawn_timeout });
                return error.WorkerSpawnTimeout;
            }
            if (self.worker.process.id) |pid| if (platform.reapIfExited(pid)) {
                self.worker.process.id = null; // reaped; the pid may be reused
                std.debug.print("Worker {d}: process exited before connecting; its output is above\n", .{self.worker.id});
                return error.WorkerExitedEarly;
            };
        }

        pub fn abandon(self: *Spawn, io: Io) void {
            if (self.worker.launch != .client) if (self.worker.process.id) |pid| {
                _ = platform.kill(pid, platform.SIG.KILL);
                // A nonblocking reap would race the kill, and its stderr is read to EOF next.
                platform.waitForExit(pid);
            };
            platform.dumpChildStderr(io, self.worker.allocator, &self.worker.process, self.worker.id);
            self.listener.close(io);
            if (self.worker.julia_channel) |ch| self.worker.allocator.free(ch);
        }
    };

    fn sendSpawnRequest(client_socket: posix.socket_t, argv: []const []const u8, environ: *const std.process.Environ.Map) !void {
        var buf: [4096]u8 = undefined;
        var w = protocol.BufWriter{ .buf = &buf };
        var needed: usize = 5;
        var nenv: u16 = 0;
        for (argv) |arg| needed += 2 + arg.len;
        var it = environ.iterator();
        while (it.next()) |e| if (std.mem.startsWith(u8, e.key_ptr.*, daemon_env_prefix)) {
            needed += 3 + e.key_ptr.len + e.value_ptr.len;
            nenv += 1;
        };
        if (needed > buf.len) return error.SpawnRequestTooLong;
        w.writeInt(u8, protocol.client.spawn_request);
        w.writeInt(u16, @intCast(argv.len));
        for (argv) |arg| w.writeLenPrefixed(u16, arg);
        w.writeInt(u16, nenv);
        it = environ.iterator();
        while (it.next()) |e| if (std.mem.startsWith(u8, e.key_ptr.*, daemon_env_prefix)) {
            w.writeInt(u16, @intCast(e.key_ptr.len + 1 + e.value_ptr.len));
            w.writeSlice(e.key_ptr.*);
            w.writeSlice("=");
            w.writeSlice(e.value_ptr.*);
        };
        platform.write(client_socket, w.written());
    }

    fn isExpectedWorker(socket: posix.socket_t, kind: LaunchKind, client_ns: ?u64, child_pid: ?posix.pid_t) bool {
        const peer = platform.peerPid(socket) orelse return true;
        return switch (kind) {
            .direct, .sandboxed => peer == child_pid or platform.parentPid(peer) == child_pid,
            .client => platform.peerMountNs(socket) == client_ns,
        };
    }

    /// Reaps a child of ours as a side effect.
    pub fn exited(self: *const Worker) bool {
        if (self.pidfd) |fd| return platform.pidfdExited(fd);
        const pid = self.process.id orelse return true;
        return platform.reapIfExited(pid);
    }

    /// Null once a pidfd-backed worker has exited: its pid may be reused.
    pub fn livePid(self: *const Worker) ?posix.pid_t {
        if (self.pidfd) |fd| if (platform.pidfdExited(fd)) return null;
        return self.process.id;
    }

    /// Through the pidfd where held: a pid init reaps can be recycled unnoticed.
    pub fn signal(self: *const Worker, sig: platform.SIG) void {
        if (self.pidfd) |fd| {
            _ = platform.pidfdSignal(fd, sig);
        } else if (self.process.id) |pid| {
            _ = platform.kill(pid, sig);
        }
    }

    /// For session affinity; 0 marks an empty slot.
    pub fn recordPpid(self: *Worker, ppid: u32, max_history: u32) void {
        const cap = if (max_history == 0) max_recent_ppids else @min(max_history, max_recent_ppids);
        self.recent_ppids[self.recent_ppids_next] = ppid;
        self.recent_ppids_next = (self.recent_ppids_next + 1) % cap;
    }

    pub fn deinit(self: *Worker) void {
        if (self.project) |p| self.allocator.free(p);
        if (self.julia_channel) |ch| self.allocator.free(ch);
        if (self.session_label) |l| self.allocator.free(l);
        if (self.pidfd) |fd| platform.close(fd);
        platform.close(self.socket);
    }

    fn writeHeader(self: *Worker, msg_type: protocol.worker.MessageType, payload_len: u16) void {
        var buf: [3]u8 = undefined;
        buf[0] = @intFromEnum(msg_type);
        std.mem.writeInt(u16, buf[1..3], payload_len, .little);
        platform.write(self.socket, &buf);
    }

    const Header = struct {
        msg_type: protocol.worker.MessageType,
        payload_len: u16,
        raw: [3]u8,
    };

    fn readHeader(self: *Worker) !Header {
        var buf: [3]u8 = undefined;
        try readExact(self.socket, &buf);
        return .{
            .msg_type = @enumFromInt(buf[0]),
            .payload_len = std.mem.readInt(u16, buf[1..3], .little),
            .raw = buf,
        };
    }

    /// The reply to a request, past any pong still owed for a ping whose
    /// timeout was let pass (a busy worker answers late).
    fn readReply(self: *Worker) !Header {
        while (true) {
            const header = try self.readHeader();
            if (header.msg_type != .pong) return header;
            var payload: [protocol.worker.pong_size - 3]u8 = undefined;
            try readExact(self.socket, &payload);
        }
    }

    pub fn ping(self: *Worker) !void {
        self.sendPing();
        const header = try self.readHeader();
        if (header.msg_type != .pong) {
            std.debug.print("Worker {d}: ping expected pong, got {s} ({s})\n", .{
                self.id, @tagName(header.msg_type), &std.fmt.bytesToHex(header.raw, .lower),
            });
            return error.UnexpectedResponse;
        }
        var payload: [protocol.worker.pong_size - 3]u8 = undefined;
        try readExact(self.socket, &payload);
        if (payload[0] != self.ping_seq) return error.UnexpectedResponse;
    }

    // A busy worker's ping only reconciles counts, so it runs slower.
    const busy_ping_factor = 4;
    pub fn shouldPing(self: *const Worker, now: i64, ping_interval: u64) bool {
        if (self.ping_pending) return false;
        const interval: u64 = if (self.active_clients == 0) ping_interval else ping_interval * busy_ping_factor;
        return now - self.last_pinged >= @as(i64, @intCast(interval));
    }

    pub fn sendPing(self: *Worker) void {
        self.ping_seq +%= 1;
        self.writeHeader(.ping, 1);
        platform.write(self.socket, &.{self.ping_seq});
    }

    /// Julia force-throws past a tight loop from the fifth SIGINT in quick
    /// succession (one more is sent to spare), and a signal still pending when
    /// the next is sent merges with it.
    pub fn forceInterrupt(self: *const Worker) void {
        for (0..6) |i| {
            if (i > 0) platform.sleepMs(50);
            self.signal(.INT);
        }
    }

    /// Takes ownership of `project` on success.
    pub fn setProject(self: *Worker, project: []const u8) !void {
        self.writeHeader(.set_project, @intCast(2 + project.len));
        var len_buf: [2]u8 = undefined;
        std.mem.writeInt(u16, &len_buf, @intCast(project.len), .little);
        platform.write(self.socket, &len_buf);
        platform.write(self.socket, project);
        const header = try self.readReply();
        if (header.msg_type == .err) {
            std.debug.print("Worker {d}: setProject got {s} ({s})\n", .{
                self.id, @tagName(header.msg_type), &std.fmt.bytesToHex(header.raw, .lower),
            });
            return error.ProjectError;
        }
        if (header.msg_type != .project_ok) {
            std.debug.print("Worker {d}: setProject expected project_ok, got {s} ({s})\n", .{
                self.id, @tagName(header.msg_type), &std.fmt.bytesToHex(header.raw, .lower),
            });
            return error.UnexpectedResponse;
        }
        self.project = project;
    }

    pub fn softExit(self: *Worker) void {
        self.writeHeader(.soft_exit, 0);
    }

    pub fn dropSession(self: *Worker, label: []const u8) void {
        self.writeHeader(.drop_session, @intCast(2 + label.len));
        var len_buf: [2]u8 = undefined;
        std.mem.writeInt(u16, &len_buf, @intCast(label.len), .little);
        platform.write(self.socket, &len_buf);
        platform.write(self.socket, label);
    }

    /// The worker drops clients not in `pids`; returns its remaining count.
    /// Returns the worker's count of clients still running.
    pub fn syncClients(self: *Worker, ids: []const u32) !u16 {
        const payload_len: u16 = 2 + @as(u16, @intCast(ids.len)) * 4;
        self.writeHeader(.sync_clients, payload_len);
        var len_buf: [2]u8 = undefined;
        std.mem.writeInt(u16, &len_buf, @intCast(ids.len), .little);
        platform.write(self.socket, &len_buf);
        for (ids) |id| {
            var id_buf: [4]u8 = undefined;
            std.mem.writeInt(u32, &id_buf, id, .little);
            platform.write(self.socket, &id_buf);
        }
        const header = try self.readReply();
        if (header.msg_type != .ack) {
            std.debug.print("Worker {d}: syncClients expected ack, got {s} ({s})\n", .{
                self.id, @tagName(header.msg_type), &std.fmt.bytesToHex(header.raw, .lower),
            });
            return error.UnexpectedResponse;
        }
        var count_buf: [2]u8 = undefined;
        try readExact(self.socket, &count_buf);
        return std.mem.readInt(u16, &count_buf, .little);
    }

    /// `error.TooManyClients` when `buf` overflows: a partial list would look
    /// like exited clients.
    pub fn queryClients(self: *Worker, buf: []u32) ![]u32 {
        self.writeHeader(.query_clients, 0);
        const header = try self.readReply();
        if (header.msg_type != .clients) {
            std.debug.print("Worker {d}: queryClients expected clients, got {s} ({s})\n", .{
                self.id, @tagName(header.msg_type), &std.fmt.bytesToHex(header.raw, .lower),
            });
            return error.UnexpectedResponse;
        }
        var count_buf: [2]u8 = undefined;
        try readExact(self.socket, &count_buf);
        const count = std.mem.readInt(u16, &count_buf, .little);
        // Drain the full list even when over capacity, or the stream desyncs.
        var n: usize = 0;
        for (0..count) |_| {
            var pid_buf: [4]u8 = undefined;
            try readExact(self.socket, &pid_buf);
            if (n < buf.len) {
                buf[n] = std.mem.readInt(u32, &pid_buf, .little);
                n += 1;
            }
        }
        if (count > buf.len) return error.TooManyClients;
        return buf[0..n];
    }

    pub const SocketPaths = struct {
        stdin: []const u8,
        stdout: []const u8,
        stderr: []const u8,
        signals: []const u8,
    };

    pub fn runClient(
        self: *Worker,
        allocator: Allocator,
        client_info: *const ClientInfo,
    ) !SocketPaths {
        const pf_len: usize = if (client_info.programfile) |pf| pf.len + 2 else 0;
        var payload_size: usize = 1 + 4 + 4 + 2 + client_info.cwd.len + 2 + 2 + 1 + pf_len + 2 + 2;
        for (client_info.env) |e| payload_size += 4 + e.key.len + e.value.len;
        for (client_info.switches) |sw| payload_size += 4 + sw.name.len + sw.value.len;
        for (client_info.args) |arg| payload_size += 2 + arg.len;
        const send_buf = try allocator.alloc(u8, payload_size);
        defer allocator.free(send_buf);
        var w = BufWriter{ .buf = send_buf };
        w.writeInt(u8, @bitCast(protocol.worker.Flags{ .tty = client_info.tty, .color = client_info.color, .force = client_info.force }));
        w.writeInt(u32, client_info.id);
        // The pid as the worker will see it: a client-launched worker shares
        // the client's pid namespace.
        w.writeInt(u32, if (self.launch == .client) client_info.pid else (client_info.host_pid orelse client_info.pid));
        w.writeLenPrefixed(u16, client_info.cwd);
        w.writeInt(u16, @intCast(client_info.env.len));
        for (client_info.env) |e| {
            w.writeLenPrefixed(u16, e.key);
            w.writeLenPrefixed(u16, e.value);
        }
        w.writeInt(u16, @intCast(client_info.switches.len));
        for (client_info.switches) |sw| {
            w.writeLenPrefixed(u16, sw.name);
            w.writeLenPrefixed(u16, sw.value);
        }
        if (client_info.programfile) |pf| {
            w.writeInt(u8, 1);
            w.writeLenPrefixed(u16, pf);
        } else {
            w.writeInt(u8, 0);
        }
        w.writeInt(u16, @intCast(client_info.args.len));
        for (client_info.args) |arg| {
            w.writeLenPrefixed(u16, arg);
        }
        w.writeInt(u16, client_info.port_set);
        std.debug.print("Worker {d}: sending client_run ({d} bytes)\n", .{ self.id, payload_size });
        self.writeHeader(.client_run, @intCast(payload_size));
        platform.write(self.socket, send_buf);
        std.debug.print("Worker {d}: waiting for response...\n", .{self.id});
        const header = try self.readReply();
        std.debug.print("Worker {d}: got response: {s} ({d} bytes payload)\n", .{ self.id, @tagName(header.msg_type), header.payload_len });
        if (header.msg_type == .err) {
            std.debug.print("Worker {d}: runClient got {s} ({s})\n", .{
                self.id, @tagName(header.msg_type), &std.fmt.bytesToHex(header.raw, .lower),
            });
            if (header.payload_len > 0 and header.payload_len < 4096) {
                const err_payload = allocator.alloc(u8, header.payload_len) catch {
                    return error.WorkerError;
                };
                defer allocator.free(err_payload);
                readExact(self.socket, err_payload) catch {
                    return error.WorkerError;
                };
                if (header.payload_len >= 4) {
                    const err_code = std.mem.readInt(u16, err_payload[0..2], .little);
                    const msg_len = std.mem.readInt(u16, err_payload[2..4], .little);
                    if (4 + msg_len <= header.payload_len) {
                        const err_msg = err_payload[4..][0..msg_len];
                        std.debug.print("Worker {d}: error (code {d}): {s}\n", .{ self.id, err_code, err_msg });
                    }
                }
            }
            return error.WorkerError;
        }
        if (header.msg_type != .sockets) {
            std.debug.print("Worker {d}: runClient expected sockets, got {s} ({s})\n", .{
                self.id, @tagName(header.msg_type), &std.fmt.bytesToHex(header.raw, .lower),
            });
            return error.UnexpectedResponse;
        }
        const payload = try allocator.alloc(u8, header.payload_len);
        defer allocator.free(payload);
        try readExact(self.socket, payload);
        var rpos: usize = 0;
        self.active_clients = std.mem.readInt(u32, payload[rpos..][0..4], .little);
        rpos += 4;
        const stdin_len = std.mem.readInt(u16, payload[rpos..][0..2], .little);
        rpos += 2;
        // An empty stdin path means the worker is at capacity.
        if (stdin_len == 0) return error.WorkerBusy;
        const stdin_path = try allocator.dupe(u8, payload[rpos..][0..stdin_len]);
        errdefer allocator.free(stdin_path);
        rpos += stdin_len;
        const stdout_len = std.mem.readInt(u16, payload[rpos..][0..2], .little);
        rpos += 2;
        const stdout_path = try allocator.dupe(u8, payload[rpos..][0..stdout_len]);
        errdefer allocator.free(stdout_path);
        rpos += stdout_len;
        const stderr_len = std.mem.readInt(u16, payload[rpos..][0..2], .little);
        rpos += 2;
        const stderr_path = try allocator.dupe(u8, payload[rpos..][0..stderr_len]);
        errdefer allocator.free(stderr_path);
        rpos += stderr_len;
        const signals_len = std.mem.readInt(u16, payload[rpos..][0..2], .little);
        rpos += 2;
        const signals_path = try allocator.dupe(u8, payload[rpos..][0..signals_len]);
        return .{ .stdin = stdin_path, .stdout = stdout_path, .stderr = stderr_path, .signals = signals_path };
    }
};

pub const ClientInfo = struct {
    tty: bool,
    color: bool,
    force: bool, // bypass the worker's capacity check
    id: u32, // conductor-assigned
    pid: u32, // self-reported
    host_pid: ?u32, // from peer credentials
    ppid: u32,
    cwd: []const u8,
    env: []const EnvVar,
    switches: []const args.Switch,
    programfile: ?[]const u8,
    args: []const []const u8,
    port_set: u16, // PortPool index, or PortPool.none when unmanaged
};

pub const EnvVar = struct {
    key: []const u8,
    value: []const u8,
};

var resolve_buf: [std.fs.max_path_bytes]u8 = undefined;
fn resolveInPath(io: Io, name: []const u8, path_env: []const u8) ?[]const u8 {
    var it = std.mem.splitScalar(u8, path_env, ':');
    while (it.next()) |dir| {
        if (dir.len == 0) continue;
        const candidate = std.fmt.bufPrint(&resolve_buf, "{s}/{s}", .{ dir, name }) catch continue;
        Io.Dir.accessAbsolute(io, candidate, .{}) catch continue;
        return candidate;
    }
    return null;
}
