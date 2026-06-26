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
const sandbox = if (builtin.os.tag == .linux) @import("sandbox.zig") else struct {};

const BufWriter = protocol.BufWriter;
const readExact = protocol.readExact;
const randomSocketPath = protocol.randomSocketPath;
const createListener = protocol.createListener;

const max_recent_ppids = 32;

// --- Activity signals ---
// Lazily-decayed eviction-warmth predictors, combined as max(crf_norm, occupancy).
// Both decay 2^(-Δt/half_life) over real elapsed time, so sampling can be irregular.

fn decay(dt_s: i64, half_life_s: u64) f64 {
    if (half_life_s == 0) return 0;
    return std.math.exp2(-@as(f64, @floatFromInt(dt_s)) / @as(f64, @floatFromInt(half_life_s)));
}

/// Per-pool-key summon history. `value` is the LRFU recency-frequency score (decayed
/// summon count). `srtt`/`rttvar` are a Jacobson inter-summon interval estimator
/// (RFC 6298). Together they set the idle keep-alive budget; `value` alone ranks
/// workers for pressure eviction.
pub const Crf = struct {
    value: f64 = 0,
    last_update: i64 = 0,
    srtt: f64 = 0, // smoothed inter-summon interval (s); 0 until the 2nd summon
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

    /// RFC 6298 RTO: the cadence's expected next-summon time at a ~99.99% tail.
    pub fn intervalBudget(self: *const Crf) f64 {
        return self.srtt + 4 * self.rttvar;
    }

    /// Pure read for ranking — does not advance last_update.
    pub fn read(self: *const Crf, now: i64, half_life_s: u64) f64 {
        return self.value * decay(now - self.last_update, half_life_s);
    }

    /// Squash unbounded crf into [0,1) to compare with occupancy. Monotone, so
    /// ranking order is unchanged.
    pub fn normalize(value: f64) f64 {
        return value / (value + 2.0);
    }
};

/// PELT-style decayed busy-fraction for one worker. Folding on attach/detach is
/// exact (not approximate) because the geometric EWMA is composable.
pub const Occupancy = struct {
    value: f64 = 0,
    last_update: i64 = 0,
    busy: bool = false,

    // EWMA of the [last_update, now] interval: 1 if held during it, else 0
    // (clamped OR, so overlapping clients never exceed 1).
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

    /// Current occupancy in [0,1], projecting the interval since last_update
    /// forward — rising toward 1 while busy, decaying toward 0 while idle.
    pub fn read(self: *const Occupancy, now: i64, half_life_s: u64) f64 {
        const d = decay(now - self.last_update, half_life_s);
        return (if (self.busy) 1 - d else 0) + self.value * d;
    }
};

/// The fast signal (~min_ttl) drives pressure ranking + status; the slow one (longer
/// half-life) scales the idle-cull budget. Transitions touch both so they can't drift.
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

/// Smoothed CPU utilisation (busy cores) from cumulative-CPU readings, as an EWMA
/// over real elapsed time, so sampling can be irregular and opportunistic.
pub const CpuMeter = struct {
    util: f64 = 0,
    last_cpu_s: f64 = 0,
    last_ns: i64 = 0,
    primed: bool = false,

    // Fold a cumulative-CPU reading at ns timestamp `now_ns` into util as busy
    // cores. `half_life_s` blends the rate into the EWMA (live view); null sets
    // util to the raw rate (one-shot, two reads a beat apart bracket the window).
    // ns timestamps give finer dt than the conductor's seconds clock.
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
    pong_buf: [5]u8 = undefined,
    active_clients: u32,
    occupancy: Occupancies = .{},
    cpu: CpuMeter = .{},
    // Cached footprint in bytes (RSS on Linux, phys_footprint on macOS), written by
    // Conductor.refreshOne for status + eviction sizing.
    mem: u64 = 0,
    mem_at: i64 = 0, // seconds: last sample time, gating the idle-ping refresh
    sandboxed: bool = false,
    interactive: bool = false,
    recent_ppids: [max_recent_ppids]u32 = .{0} ** max_recent_ppids,
    recent_ppids_next: usize = 0,

    pub fn spawn(
        allocator: Allocator,
        io: Io,
        cfg: *const config.Config,
        id: u32,
        runtime_dir: []const u8,
        julia_channel: ?[]const u8,
        threads: args.Threads,
        interactive: bool,
    ) !Worker {
        return spawnImpl(allocator, io, cfg, id, runtime_dir, julia_channel, threads, interactive, false, null, &.{}, &.{});
    }

    pub fn spawnSandboxed(
        allocator: Allocator,
        io: Io,
        cfg: *const config.Config,
        id: u32,
        runtime_dir: []const u8,
        julia_channel: ?[]const u8,
        threads: args.Threads,
        environ_map: *const std.process.Environ.Map,
        extra_ro_binds: []const []const u8,
        extra_rw_binds: []const []const u8,
    ) !Worker {
        return spawnImpl(allocator, io, cfg, id, runtime_dir, julia_channel, threads, false, true, environ_map, extra_ro_binds, extra_rw_binds);
    }

    fn spawnImpl(
        allocator: Allocator,
        io: Io,
        cfg: *const config.Config,
        id: u32,
        runtime_dir: []const u8,
        julia_channel: ?[]const u8,
        threads: args.Threads,
        interactive: bool,
        sandboxed: bool,
        environ_map: ?*const std.process.Environ.Map,
        extra_ro_binds: []const []const u8,
        extra_rw_binds: []const []const u8,
    ) !Worker {
        var path_buf: [std.fs.max_path_bytes]u8 = undefined;
        // Sandboxed workers use a per-worker subdirectory so the sandbox
        // can bind-mount it rw without exposing the rest of the runtime dir.
        // The worker derives its RUNTIME_DIR from dirname(setup_socket_path),
        // so placing the setup socket here makes the worker create its
        // stdio sockets in the same isolated subdirectory.
        var subdir_buf: [std.fs.max_path_bytes]u8 = undefined;
        const effective_runtime_dir = if (sandboxed and builtin.os.tag == .linux) blk: {
            const subdir = std.fmt.bufPrint(&subdir_buf, "{s}/sandbox-{d}", .{ runtime_dir, id }) catch
                return error.PathTooLong;
            Io.Dir.createDirAbsolute(io, subdir, .default_dir) catch {};
            break :blk subdir;
        } else runtime_dir;
        // Conductor and worker are always on the same machine, so use a
        // Unix socket regardless of the client-facing transport mode.
        var setup = try createListener(io, .unix, effective_runtime_dir, "wsetup.sock", "", &path_buf);
        defer setup.server.deinit(io);
        defer Io.Dir.deleteFileAbsolute(io, setup.addr) catch {};
        const eval_expr = try std.fmt.allocPrint(
            allocator,
            "using DaemonWorker; DaemonWorker.runworker(\"{s}\", {d}, \"{s}\")",
            .{ setup.addr, id, cfg.socket_path },
        );
        defer allocator.free(eval_expr);
        // Rendered once for both spawn paths. Passed after worker_args so a
        // client request overrides any thread count in JULIA_DAEMON_WORKER_ARGS.
        const threads_arg: ?[]const u8 = if (try args.renderThreads(allocator, threads)) |v| blk: {
            defer allocator.free(v);
            break :blk try std.fmt.allocPrint(allocator, "--threads={s}", .{v});
        } else null;
        defer if (threads_arg) |a| allocator.free(a);
        // Sandboxed spawn: fork+namespace+bind-mounts+exec (Linux only)
        var child: std.process.Child = undefined;
        if (sandboxed and builtin.os.tag == .linux) {
            // execve(2) requires an absolute path — resolve bare command via PATH.
            // std.process.spawn does this internally, but sandbox uses raw execve.
            const exe_path = if (std.mem.indexOfScalar(u8, cfg.worker_executable, '/') != null)
                cfg.worker_executable
            else if (environ_map.?.get("PATH")) |p|
                resolveInPath(io, cfg.worker_executable, p) orelse cfg.worker_executable
            else
                cfg.worker_executable;
            // Merge caller-provided ro binds with the worker project dir
            var ro_binds: [8][]const u8 = undefined;
            var n_ro: usize = 0;
            ro_binds[n_ro] = cfg.worker_project;
            n_ro += 1;
            if (extra_ro_binds.len > ro_binds.len - n_ro) {
                std.debug.print("Worker: too many ro binds ({d}), max {d}\n", .{ extra_ro_binds.len + 1, ro_binds.len });
                return error.TooManyBinds;
            }
            for (extra_ro_binds) |b| {
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
                .host_environ = environ_map.?,
                .setup_socket_path = setup.addr,
                .worker_id = id,
                .host_home = cfg.host_home,
                .extra_ro_binds = ro_binds[0..n_ro],
                .extra_rw_binds = extra_rw_binds,
                .empty_environment = cfg.sandbox_empty_environment,
                .max_memory = cfg.sandbox_max_memory,
                .max_cpu = cfg.sandbox_max_cpu,
            };
            std.debug.print("Spawning sandboxed worker\n", .{});
            const sandbox_pid = try sandbox.spawnSandboxed(allocator, &sandbox_cfg);
            // The host-visible PID is the intermediate process (child 1)
            // which waits on the Julia process inside the PID namespace —
            // killing it terminates the whole sandbox.
            child = .{ .id = sandbox_pid, .thread_handle = {}, .stdin = null, .stdout = null, .stderr = null, .request_resource_usage_statistics = false };
        } else {
            // Normal spawn via std.process
            var argv = std.array_list.AlignedManaged([]const u8, null).init(allocator);
            defer argv.deinit();
            try argv.append(cfg.worker_executable);
            if (julia_channel) |ch| try argv.append(ch);
            const project_arg: ?[]const u8 = if (cfg.worker_project.len > 0)
                try std.fmt.allocPrint(allocator, "--project={s}", .{cfg.worker_project})
            else
                null;
            defer if (project_arg) |p| allocator.free(p);
            if (project_arg) |p| try argv.append(p);
            {
                // Split on spaces; individual args containing spaces are not supported.
                var it = std.mem.tokenizeScalar(u8, cfg.worker_args, ' ');
                while (it.next()) |arg| try argv.append(arg);
            }
            if (threads_arg) |a| try argv.append(a);
            if (interactive) try argv.append("-i");
            try argv.append("--eval");
            try argv.append(eval_expr);
            // Spawn in separate process group so terminal SIGINT only goes to conductor
            child = try std.process.spawn(io, .{
                .argv = argv.items,
                .pgid = if (builtin.os.tag == .windows) null else 0,
            });
        }
        const worker_stream = try setup.server.accept(io);
        const socket = worker_stream.socket.handle;
        // Set read timeout to avoid blocking conductor if worker becomes unresponsive
        platform.setRecvTimeout(socket, @intCast(cfg.ping_timeout));
        var magic_buf: [4]u8 = undefined;
        std.mem.writeInt(u32, &magic_buf, protocol.worker.magic, .little);
        platform.write(socket, &magic_buf);
        const now = Io.Clock.now(.awake, io).toSeconds();
        return .{
            .allocator = allocator,
            .id = id,
            .process = child,
            .socket = socket,
            .project = null,
            .julia_channel = julia_channel,
            .threads = threads,
            .session_label = null,
            .created_at = now,
            .last_active = now,
            .last_pinged = now,
            .active_clients = 0,
            .sandboxed = sandboxed,
            .interactive = interactive,
        };
    }

    /// Record a PPID for session affinity tracking (circular buffer, 0 = empty)
    pub fn recordPpid(self: *Worker, ppid: u32, max_history: u32) void {
        const cap = if (max_history == 0) max_recent_ppids else @min(max_history, max_recent_ppids);
        self.recent_ppids[self.recent_ppids_next] = ppid;
        self.recent_ppids_next = (self.recent_ppids_next + 1) % cap;
    }

    pub fn deinit(self: *Worker) void {
        if (self.project) |p| self.allocator.free(p);
        if (self.session_label) |l| self.allocator.free(l);
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

    pub fn ping(self: *Worker) !void {
        self.writeHeader(.ping, 0);
        const header = try self.readHeader();
        if (header.msg_type != .pong) {
            std.debug.print("Worker {d}: ping expected pong, got {s} ({s})\n", .{
                self.id, @tagName(header.msg_type), &std.fmt.bytesToHex(header.raw, .lower),
            });
            return error.UnexpectedResponse;
        }
        // Drain the 2-byte client count payload
        var payload: [2]u8 = undefined;
        try readExact(self.socket, &payload);
    }

    // Idle: liveness ping. Busy: slower count-reconcile ping (miss tolerated).
    const busy_ping_factor = 4;
    pub fn shouldPing(self: *const Worker, now: i64, ping_interval: u64) bool {
        if (self.ping_pending) return false;
        const interval: u64 = if (self.active_clients == 0) ping_interval else ping_interval * busy_ping_factor;
        return now - self.last_pinged >= @as(i64, @intCast(interval));
    }

    /// Send ping without waiting for response (for async ping via event loop)
    pub fn sendPing(self: *Worker) void {
        self.writeHeader(.ping, 0);
        self.ping_pending = true;
    }

    /// Takes ownership of project slice (caller must not free on success)
    pub fn setProject(self: *Worker, project: []const u8) !void {
        self.writeHeader(.set_project, @intCast(2 + project.len));
        var len_buf: [2]u8 = undefined;
        std.mem.writeInt(u16, &len_buf, @intCast(project.len), .little);
        platform.write(self.socket, &len_buf);
        platform.write(self.socket, project);
        const header = try self.readHeader();
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

    /// Tell the worker to tear down an expired session's REPL. Fire-and-forget.
    pub fn dropSession(self: *Worker, label: []const u8) void {
        self.writeHeader(.drop_session, @intCast(2 + label.len));
        var len_buf: [2]u8 = undefined;
        std.mem.writeInt(u16, &len_buf, @intCast(label.len), .little);
        platform.write(self.socket, &len_buf);
        platform.write(self.socket, label);
    }

    /// Send list of active PIDs to worker; worker kills any clients not in list.
    /// Returns the worker's reported remaining client count.
    pub fn syncClients(self: *Worker, pids: []const u32) !u16 {
        const payload_len: u16 = 2 + @as(u16, @intCast(pids.len)) * 4;
        self.writeHeader(.sync_clients, payload_len);
        var len_buf: [2]u8 = undefined;
        std.mem.writeInt(u16, &len_buf, @intCast(pids.len), .little);
        platform.write(self.socket, &len_buf);
        for (pids) |pid| {
            var pid_buf: [4]u8 = undefined;
            std.mem.writeInt(u32, &pid_buf, pid, .little);
            platform.write(self.socket, &pid_buf);
        }
        // Wait for ack with remaining client count
        const header = try self.readHeader();
        if (header.msg_type != .ack) {
            std.debug.print("Worker {d}: syncClients expected ack, got {s} ({s})\n", .{
                self.id, @tagName(header.msg_type), &std.fmt.bytesToHex(header.raw, .lower),
            });
            return error.UnexpectedResponse;
        }
        // Read 2-byte payload: remaining client count
        var count_buf: [2]u8 = undefined;
        try readExact(self.socket, &count_buf);
        return std.mem.readInt(u16, &count_buf, .little);
    }

    /// Read-only query of the worker's live client PIDs into `buf` (excess dropped).
    pub fn queryClients(self: *Worker, buf: []u32) ![]u32 {
        self.writeHeader(.query_clients, 0);
        const header = try self.readHeader();
        if (header.msg_type != .clients) {
            std.debug.print("Worker {d}: queryClients expected clients, got {s} ({s})\n", .{
                self.id, @tagName(header.msg_type), &std.fmt.bytesToHex(header.raw, .lower),
            });
            return error.UnexpectedResponse;
        }
        var count_buf: [2]u8 = undefined;
        try readExact(self.socket, &count_buf);
        const count = std.mem.readInt(u16, &count_buf, .little);
        var n: usize = 0;
        for (0..count) |_| {
            var pid_buf: [4]u8 = undefined;
            try readExact(self.socket, &pid_buf);
            if (n < buf.len) {
                buf[n] = std.mem.readInt(u32, &pid_buf, .little);
                n += 1;
            }
        }
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
        // Calculate payload size
        const pf_len: usize = if (client_info.programfile) |pf| pf.len + 2 else 0;
        var payload_size: usize = 1 + 4 + 2 + client_info.cwd.len + 2 + 2 + 1 + pf_len + 2 + 2;
        for (client_info.env) |e| payload_size += 4 + e.key.len + e.value.len;
        for (client_info.switches) |sw| payload_size += 4 + sw.name.len + sw.value.len;
        for (client_info.args) |arg| payload_size += 2 + arg.len;
        // Build message
        const send_buf = try allocator.alloc(u8, payload_size);
        defer allocator.free(send_buf);
        var w = BufWriter{ .buf = send_buf };
        w.writeInt(u8, @bitCast(protocol.worker.Flags{ .tty = client_info.tty, .force = client_info.force }));
        w.writeInt(u32, client_info.pid);
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
        // Send header + payload
        std.debug.print("Worker {d}: sending client_run ({d} bytes)\n", .{ self.id, payload_size });
        self.writeHeader(.client_run, @intCast(payload_size));
        platform.write(self.socket, send_buf);
        // Read response
        std.debug.print("Worker {d}: waiting for response...\n", .{self.id});
        const header = try self.readHeader();
        std.debug.print("Worker {d}: got response: {s} ({d} bytes payload)\n", .{ self.id, @tagName(header.msg_type), header.payload_len });
        if (header.msg_type == .err) {
            std.debug.print("Worker {d}: runClient got {s} ({s})\n", .{
                self.id, @tagName(header.msg_type), &std.fmt.bytesToHex(header.raw, .lower),
            });
            // Try to read and print error details if payload is reasonable size
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
        // Read payload
        const payload = try allocator.alloc(u8, header.payload_len);
        defer allocator.free(payload);
        try readExact(self.socket, payload);
        // Parse: active_clients (u32) + stdin path + stdout path + stderr path + signals path
        var rpos: usize = 0;
        self.active_clients = std.mem.readInt(u32, payload[rpos..][0..4], .little);
        rpos += 4;
        const stdin_len = std.mem.readInt(u16, payload[rpos..][0..2], .little);
        rpos += 2;
        // Empty stdin path means worker rejected (at capacity)
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
    force: bool, // Bypass worker capacity check
    pid: u32,
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

/// Search PATH for a bare command name, returning the first existing candidate.
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
