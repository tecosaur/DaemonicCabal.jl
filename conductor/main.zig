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
const project = @import("project.zig");
const env_cache = @import("env_cache.zig");
const status = @import("status.zig");
const pal = @import("palette.zig");
const pressure = @import("pressure.zig");
pub const worker = @import("worker.zig");

pub const PeerInfo = struct {
    /// Null for a local peer, or a TCP peer of unknown address (remote).
    address: ?Io.net.IpAddress = null,

    pub fn fromSockaddr(storage: *const Io.Threaded.PosixAddress) PeerInfo {
        // std maps any other family to loopback, which must not pass as local.
        return .{ .address = switch (storage.any.family) {
            posix.AF.INET, posix.AF.INET6 => Io.Threaded.addressFromPosix(storage),
            else => null,
        } };
    }

    pub fn isRemote(self: *const PeerInfo, transport: protocol.TransportMode) bool {
        if (transport != .tcp) return false;
        return !isLoopback(self.address orelse return true);
    }

    fn isLoopback(address: Io.net.IpAddress) bool {
        const v4_mapped = [12]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };
        return switch (address) {
            .ip4 => |a| a.bytes[0] == 127,
            .ip6 => |a| std.mem.eql(u8, &a.bytes, &Io.net.Ip6Address.loopback(0).bytes) or
                (std.mem.eql(u8, a.bytes[0..12], &v4_mapped) and a.bytes[12] == 127),
        };
    }
};

pub const eventLoopImpl = if (builtin.os.tag == .linux)
    @import("eloop/linux.zig")
else if (builtin.os.tag.isBSD())
    @import("eloop/kqueue.zig")
else if (builtin.os.tag == .windows)
    @import("eloop/windows.zig")
else
    @compileError("unsupported OS");

const readExact = protocol.readExact;
const EventLocation = protocol.EventLocation;


// --- Constants ---

/// Grace per retirement stage; SIGTERM/SIGKILL fire only for a wedged worker.
const retire_grace_s: i64 = 5;

/// Bounds runaway culling under sustained pressure (WORKER_CACHE.md §Bounding).
const max_evict_per_episode: usize = 4;

/// Episodes beyond this rank only the first `episode_capacity`, logged.
const episode_capacity: usize = 256;

/// Flattens the occupancy term's early climb (smaller → steeper near 0). See idleBudget.
const idle_budget_bias: f64 = 0.25;
const idle_budget_log_span: f64 = @log2((1 + idle_budget_bias) / idle_budget_bias);
/// k in the cadence multiplier 1+log2(1+(crf-1)/k): smaller → frequency earns longevity faster.
const cadence_mult_divisor: f64 = 2;

/// Per-worker client PIDs a single reconciliation pass can hold.
const max_tracked_clients = 256;

// --- Global state for cleanup ---

pub var g_socket_path: [:0]const u8 = "";
pub var g_pid_path: [:0]const u8 = "";

// --- Types ---

pub const WorkerList = std.array_list.Aligned(*worker.Worker, null);

pub const ActiveClientInfo = struct {
    worker: *worker.Worker,
    pid: u32, // host-view where peer credentials exist, else self-reported; for display

    start_time_us: i64,
    port_set: u16, // PortPool index, or PortPool.none when unmanaged
};

pub const ActiveClientMap = std.AutoHashMap(u32, ActiveClientInfo);
pub const PendingSpawnList = std.array_list.Aligned(*Conductor.PendingSpawn, null);
pub const PendingConnectionList = std.array_list.Aligned(*Conductor.PendingConnection, null);

/// Owns the `Worker` until reaped.
pub const PendingKill = struct {
    w: *worker.Worker,
    stage: enum { soft, term },
    deadline: i64,
};

pub const PendingKillList = std.array_list.Aligned(PendingKill, null);

const AssignReason = enum {
    session_label,
    ppid_affinity,
    recent_worker,
    new_worker,
};

const WorkerAssignment = struct {
    paths: worker.Worker.SocketPaths,
    w: *worker.Worker,
    reason: AssignReason,
};

// --- Conductor ---

pub const Conductor = struct {
    io: Io,
    allocator: Allocator,
    cfg: config.Config,
    environ_map: *std.process.Environ.Map,
    cache: env_cache.EnvCache,
    workers: std.StringHashMap(WorkerList),
    active_clients: ActiveClientMap,
    port_pool: ?protocol.PortPool,
    reserve: ?*worker.Worker,
    next_worker_id: u32,
    client_counter: u32,
    pending_spawns: PendingSpawnList,
    /// Read only once readable, so a silent peer costs nothing.
    pending_connections: PendingConnectionList,
    pending_kills: PendingKillList,
    /// LRFU, keyed like `workers`; survives every death but a max-TTL cull.
    crf: std.StringHashMap(worker.Crf),
    pressure_monitor: pressure.Monitor,
    event_loop: eventLoopImpl.EventLoop,
    live_clients: std.ArrayList(LiveClient),
    live_armed: bool,
    dirty: bool,

    const LiveClient = struct {
        streams: ClientStreams, // held open across repaints
        palette: ?pal.Palette, // probed once at subscribe
        id: u32, // matched for teardown on exit/interrupt
        lines_last_printed: usize, // for the cursor-up redraw
        oneshot: bool, // draw one CPU-resolved frame, then disconnect
    };

    // --- Lifecycle ---

    pub fn init(io: Io, allocator: Allocator, cfg: config.Config, environ_map: *std.process.Environ.Map) !Conductor {
        return .{
            .io = io,
            .allocator = allocator,
            .cfg = cfg,
            .environ_map = environ_map,
            .cache = env_cache.EnvCache.init(allocator),
            .workers = std.StringHashMap(WorkerList).init(allocator),
            .active_clients = ActiveClientMap.init(allocator),
            .port_pool = if (cfg.port_range) |r| protocol.PortPool.init(r.base, r.count) else null,
            .reserve = null,
            .next_worker_id = 1,
            .client_counter = 0,
            .pending_kills = .empty,
            .pending_spawns = .empty,
            .pending_connections = .empty,
            .crf = std.StringHashMap(worker.Crf).init(allocator),
            .pressure_monitor = pressure.Monitor.init(&cfg),
            .event_loop = try eventLoopImpl.EventLoop.init(64),
            .live_clients = .empty,
            .live_armed = false,
            .dirty = false,
        };
    }

    pub fn deinit(self: *Conductor) void {
        self.abandonSpawns();
        self.pending_spawns.deinit(self.allocator);
        while (self.pending_connections.pop()) |pc| {
            platform.close(pc.socket);
            self.allocator.destroy(pc);
        }
        self.pending_connections.deinit(self.allocator);
        self.event_loop.deinit();
        for (self.live_clients.items) |*lc| {
            platform.write(lc.streams.fd(.stdout), "\r\n" ++ live_cursor_show);
            lc.streams.deinit();
        }
        self.live_clients.deinit(self.allocator);
        self.cache.deinit();
        self.active_clients.deinit();
        for (self.pending_kills.items) |pk| {
            pk.w.signal(platform.SIG.KILL);
            self.cleanupWorker(pk.w);
        }
        self.pending_kills.deinit(self.allocator);
        var crf_it = self.crf.keyIterator();
        while (crf_it.next()) |k| self.allocator.free(k.*);
        self.crf.deinit();
        if (self.reserve) |r| self.cleanupWorker(r);
        var it = self.workers.iterator();
        while (it.next()) |entry| {
            for (entry.value_ptr.items) |w| self.cleanupWorker(w);
            entry.value_ptr.deinit(self.allocator);
            self.allocator.free(entry.key_ptr.*);
        }
        self.workers.deinit();
        if (g_socket_path.len > 0) self.allocator.free(g_socket_path);
        if (g_pid_path.len > 0) self.allocator.free(g_pid_path);
        self.cfg.deinit();
    }

    // Event loops drop completions for workers retired (and maybe freed) since.
    pub fn isLiveWorker(self: *Conductor, w: *const worker.Worker) bool {
        if (self.reserve == w) return true;
        var it = self.workers.iterator();
        while (it.next()) |entry| {
            for (entry.value_ptr.items) |item| if (item == w) return true;
        }
        return false;
    }

    fn cleanupWorker(self: *Conductor, w: *worker.Worker) void {
        if (w.exited()) platform.dumpChildStderr(self.io, self.allocator, &w.process, w.id);
        if (w.launch == .sandboxed) {
            self.removeSandboxDir(w.id);
            if (builtin.os.tag == .linux) worker.sandbox.removeCgroup(w.id);
        }
        w.deinit();
        self.allocator.destroy(w);
    }

    fn removeSandboxDir(self: *Conductor, worker_id: u32) void {
        var buf: [std.fs.max_path_bytes]u8 = undefined;
        const name = std.fmt.bufPrint(&buf, "sandbox-{d}", .{worker_id}) catch return;
        var dir = Io.Dir.openDirAbsolute(self.io, self.cfg.socket_dir, .{}) catch return;
        defer dir.close(self.io);
        dir.deleteTree(self.io, name) catch {};
    }

    pub fn run(self: *Conductor) !void {
        g_socket_path = try self.allocator.dupeZ(u8, self.cfg.socket_path);
        try eventLoopImpl.installSignalHandlers();
        defer eventLoopImpl.cleanupSignalHandlers();
        if (self.cfg.transport == .local) {
            const pid_path = try std.fmt.allocPrint(self.allocator, "{s}/conductor.pid", .{self.cfg.runtime_dir});
            g_pid_path = try self.allocator.dupeZ(u8, pid_path);
            self.allocator.free(pid_path);
            self.writePidFile();
        }
        defer if (self.cfg.transport == .local) {
            Io.Dir.deleteFileAbsolute(self.io, g_pid_path) catch {};
        };
        var listener = try self.createServer();
        defer listener.close(self.io);
        std.debug.print("Conductor listening on {s}\n", .{self.cfg.socket_path});
        if (self.cfg.reserve_worker) self.beginReserveSpawn() catch |err| {
            std.debug.print("Failed to start a reserve worker: {}\n", .{err});
        };
        eventLoopImpl.run(self, &listener);
    }

    fn cleanupRuntimeDir(self: *Conductor) void {
        var dir = Io.Dir.openDirAbsolute(self.io, self.cfg.runtime_dir, .{ .iterate = true }) catch |err| {
            std.debug.print("Warning: cannot open runtime dir for cleanup: {}\n", .{err});
            return;
        };
        defer dir.close(self.io);
        var iter = dir.iterate();
        while (iter.next(self.io) catch null) |entry| {
            if (entry.kind == .directory)
                dir.deleteTree(self.io, entry.name) catch {}
            else
                dir.deleteFile(self.io, entry.name) catch {};
        }
    }

    // --- Connection handling ---

    /// `held`: the socket stays open for a client waiting on a starting worker.
    pub const Outcome = enum { done, held };

    pub const PendingConnection = struct { socket: posix.socket_t, peer: PeerInfo, deadline: i64 };

    // Event tags: a pending record's pointer, its low bits naming what turned readable.
    const tag_spawn_listener: usize = 2;
    const tag_spawn_client: usize = 3;
    const tag_connection: usize = 4;

    /// Read once readable, or dropped after `request_timeout_s`.
    pub fn admitConnection(self: *Conductor, socket: posix.socket_t, peer: *const PeerInfo) void {
        if (self.cfg.transport == .tcp) platform.setTcpNodelay(socket);
        const pc = self.allocator.create(PendingConnection) catch return platform.close(socket);
        pc.* = .{ .socket = socket, .peer = peer.*, .deadline = self.currentTime() + request_timeout_s };
        self.pending_connections.append(self.allocator, pc) catch {
            self.allocator.destroy(pc);
            return platform.close(socket);
        };
        self.event_loop.watchFd(@intFromPtr(pc) | tag_connection, socket);
    }

    /// A tag whose record is no longer pending is stale.
    pub fn onReadable(self: *Conductor, tag: usize) void {
        if (tag & tag_connection != 0) {
            const pc: *PendingConnection = @ptrFromInt(tag & ~@as(usize, 7));
            if (!removePending(&self.pending_connections, pc)) return;
            defer self.allocator.destroy(pc);
            const outcome = self.handleConnectionFd(pc.socket, &pc.peer) catch |err| blk: {
                std.debug.print("Client handling failed: {}\n", .{err});
                break :blk .done;
            };
            if (outcome == .done) platform.close(pc.socket);
        } else {
            const p: *PendingSpawn = @ptrFromInt(tag & ~@as(usize, 7));
            if (!isPending(&self.pending_spawns, p)) return;
            if (tag & 1 == 0) self.onSpawnReadable(p) else self.onSpawnClientGone(p);
        }
    }

    /// Runs each second while anything is pending; returns whether anything still is.
    pub fn tick(self: *Conductor) bool {
        const now = self.currentTime();
        var i: usize = 0;
        while (i < self.pending_connections.items.len) {
            const pc = self.pending_connections.items[i];
            if (now < pc.deadline) {
                i += 1;
                continue;
            }
            std.debug.print("Connection sent no request within {d}s; dropped\n", .{request_timeout_s});
            _ = self.pending_connections.swapRemove(i);
            self.event_loop.unwatchFd(@intFromPtr(pc) | tag_connection, pc.socket);
            platform.close(pc.socket);
            self.allocator.destroy(pc);
        }
        i = 0;
        while (i < self.pending_spawns.items.len) {
            const p = self.pending_spawns.items[i];
            if (p.spawn.check(self.io, &self.cfg)) i += 1 else |err| self.failSpawn(p, err); // failSpawn removes p
        }
        return self.pending_spawns.items.len > 0 or self.pending_connections.items.len > 0;
    }

    fn isPending(list: anytype, item: anytype) bool {
        for (list.items) |q| if (q == item) return true;
        return false;
    }

    fn removePending(list: anytype, item: anytype) bool {
        for (list.items, 0..) |q, i| if (q == item) {
            _ = list.swapRemove(i);
            return true;
        };
        return false;
    }

    pub fn handleConnectionFd(self: *Conductor, socket: posix.socket_t, peer: *const PeerInfo) !Outcome {
        // Bounds a peer stalling midway; one that never sends is dropped by tickConnections.
        platform.setRecvTimeout(socket, request_timeout_s);
        var magic_buf: [4]u8 = undefined;
        // A silent close is `juliaclient --version` probing.
        const first = platform.socketRead(socket, &magic_buf);
        if (first == 0) return .done;
        readExact(socket, magic_buf[first..]) catch |err| {
            std.debug.print("Connection sent no request within {d}s ({})\n", .{ request_timeout_s, err });
            return err;
        };
        const magic = std.mem.readInt(u32, &magic_buf, .little);
        if (magic == protocol.client.magic) {
            return self.handleClient(socket, peer);
        } else if (magic == protocol.notification.magic) {
            self.handleNotification(socket);
        } else if (magic >> 8 == protocol.client.magic_prefix) {
            try self.rejectClientVersion(socket, peer, @intCast(magic & 0xFF));
        } else {
            std.debug.print("Invalid magic: {x}\n", .{magic});
            return error.InvalidMagic;
        }
        return .done;
    }

    // The body is drained first so the reply isn't lost to a reset; a client too
    // old for this framing still fails at once.
    fn rejectClientVersion(self: *Conductor, socket: posix.socket_t, peer: *const PeerInfo, theirs: u8) !void {
        const ours = protocol.client.version;
        std.debug.print("Client speaks protocol v{d}, this daemon v{d}; rejecting\n", .{ theirs, ours });
        var request = try self.readClientRequest(socket, peer.isRemote(self.cfg.transport));
        defer request.deinit(self.allocator);
        var buf: [256]u8 = undefined;
        const msg = try std.fmt.bufPrint(&buf, "This juliaclient speaks protocol v{d} but the daemon speaks v{d}: {s}.\n", .{
            theirs, ours, if (theirs < ours) "rebuild or reinstall juliaclient to match the daemon" else "restart the daemon so it runs the newly installed version",
        });
        try self.serveString(socket, msg, 1);
    }

    fn handleNotification(self: *Conductor, socket: posix.socket_t) void {
        var buf: [5]u8 = undefined;
        readExact(socket, &buf) catch |err| {
            std.debug.print("Notification read error: {}\n", .{err});
            return;
        };
        const subject = std.mem.readInt(u32, buf[1..5], .little); // client id, or worker pid/id
        const ntype = @as(protocol.notification.Type, @enumFromInt(buf[0]));
        // A live-status subscriber was never assigned a worker.
        if ((ntype == .client_exit or ntype == .client_interrupt) and self.dropLiveClient(subject)) return;
        switch (ntype) {
            .client_done => _ = self.clientDone(subject),
            .client_exit => {
                if (self.clientDone(subject)) |w| {
                    if (!w.ping_pending) self.event_loop.scheduleHealthCheck(w);
                }
            },
            .client_interrupt => {
                // Untargeted, but the common worker serves one client.
                if (self.active_clients.get(subject)) |info| info.worker.signal(platform.SIG.INT);
            },
            .worker_unresponsive => std.debug.print("Worker unresponsive notification for pid {d}\n", .{subject}),
            .worker_exit => {
                if (self.findWorkerByPid(subject)) |w| {
                    std.debug.print("Worker {d} exiting (TTL expired)\n", .{w.id});
                    self.retireWorker(w);
                } else {
                    std.debug.print("Worker (pid {d}) exiting (TTL expired)\n", .{subject});
                }
            },
        }
    }

    fn handleClient(self: *Conductor, socket: posix.socket_t, peer: *const PeerInfo) !Outcome {
        const is_remote = peer.isRemote(self.cfg.transport);
        var request = try self.readClientRequest(socket, is_remote);
        var request_held = false; // moved into a HeldClient while its worker starts
        defer if (!request_held) request.deinit(self.allocator);
        self.client_counter += 1;
        if (request.parsed.hasSwitch("--status")) {
            try self.serveStatus(socket, request.parsed.getSwitch("--status"), request.flags.tty);
            return .done;
        }
        const project_path = request.project orelse "";
        const julia_channel = request.parsed.julia_channel;
        // Thread count is fixed at worker startup, so it's part of pool identity.
        const threads = resolveThreads(&request);
        // A client in another mount namespace is sandboxed by something we cannot
        // see into, so it spawns its own worker there.
        const foreign_ns = if (is_remote) null else platform.peerForeignMountNs(socket);
        const sandbox: SandboxKind = if (is_remote and (self.cfg.sandbox_remote_clients or request.parsed.hasSwitch("--sandbox")))
            .remote
        else if (foreign_ns) |ns| blk: {
            // Refused, not downgraded: we can neither see into nor nest in the client's sandbox.
            if (request.parsed.hasSwitch("--sandbox")) {
                std.debug.print("Client {d}: --sandbox from inside a sandbox, rejecting\n", .{self.client_counter});
                try self.serveString(socket,
                    "--sandbox: this client is already inside a sandbox (its mount namespace differs from the\n" ++
                        "daemon's), and the daemon cannot nest another in it. Drop --sandbox: the worker runs\n" ++
                        "inside this sandbox as it is.\n", 1);
                return .done;
            }
            break :blk .{ .client = .{ .socket = socket, .ns = ns } };
        } else if (request.parsed.hasSwitch("--sandbox")) blk: {
            const cwd = trimTrailingSlashes(request.cwd);
            const proj = trimTrailingSlashes(project_path);
            const has_local_project = proj.len > 0 and proj[0] != '@';
            break :blk .{ .local = if (has_local_project and pathCoveredBy(cwd, &.{proj})) proj else cwd };
        } else .none;
        if (sandbox != .none) {
            if (comptime builtin.os.tag != .linux) {
                const msg = if (sandbox == .remote)
                    "Sandboxed workers are only available on Linux. " ++
                        "Remote TCP clients from non-loopback addresses are rejected.\n"
                else
                    "--sandbox requires Linux (user namespaces).\n";
                std.debug.print("Client {d}: sandbox rejected (Linux only)\n", .{self.client_counter});
                try self.serveString(socket, msg, 1);
                return .done;
            }
            std.debug.print("Client {d}: {s} sandbox\n", .{
                self.client_counter, @tagName(sandbox),
            });
        }
        // Session bypass
        if (sandbox == .remote) {
            const session_label = request.parsed.getSwitch("--session");
            if (session_label != null and session_label.?.len > 0 and self.cfg.sandbox_session_bypass) {
                if (self.findWorkerByLabelGlobal(session_label.?)) |w| {
                    std.debug.print("Client {d}: session bypass — joining local worker {d} (label '{s}')\n", .{
                        self.client_counter, w.id, session_label.?,
                    });
                    if (try self.assignClientToExistingWorker(socket, &request, w)) return .done;
                }
            }
        }
        const tkey = args.packThreads(threads);
        const ch = julia_channel orelse "";
        const worker_key = switch (sandbox) {
            .none => try std.fmt.allocPrint(self.allocator, "{s}\x00{s}\x00{d}", .{ project_path, ch, tkey }),
            .remote => try std.fmt.allocPrint(self.allocator, "__sandbox__\x00{s}\x00{d}", .{ ch, tkey }),
            // Keyed by mount namespace: a worker never serves another sandbox or the host.
            .client => |c| try std.fmt.allocPrint(self.allocator, "__ns{d}__\x00{s}\x00{s}\x00{d}", .{ c.ns, project_path, ch, tkey }),
            // Workers share only when their mounts match.
            .local => |rw| try std.fmt.allocPrint(self.allocator, "__lsandbox__\x00{s}\x00{s}\x00{s}\x00{d}", .{ rw, trimTrailingSlashes(project_path), ch, tkey }),
        };
        defer self.allocator.free(worker_key);
        if (request.parsed.hasSwitch("--sync")) {
            const session = request.parsed.getSwitch("--session");
            if (session == null or session.?.len == 0) {
                std.debug.print("Client {d}: --sync without --session label, rejecting\n", .{self.client_counter});
                try self.serveString(socket, "--sync requires --session=<label>\n", 1);
                return .done;
            }
            std.debug.print("Client {d}: sync mode, session='{s}'\n", .{ self.client_counter, session.? });
        }
        if (request.parsed.hasSwitch("--restart")) {
            const nkilled = self.killWorkersForProject(worker_key);
            std.debug.print("Restart: killed {d} worker(s) for {s}{s}{s}\n", .{
                nkilled,
                project_path,
                if (julia_channel != null) " " else "",
                julia_channel orelse "",
            });
            const msg = try std.fmt.allocPrint(self.allocator, "Reset: killed {d} worker(s) for project\n", .{nkilled});
            defer self.allocator.free(msg);
            try self.serveString(socket, msg, 0);
            return .done;
        }
        const outcome = self.assignClientToWorker(socket, &request, worker_key, sandbox, null, null) catch |err| {
            self.reportNoWorker(socket, err, sandbox);
            return .done;
        };
        request_held = outcome == .held;
        return outcome;
    }

    fn reportNoWorker(self: *Conductor, socket: posix.socket_t, err: anyerror, sandbox: SandboxKind) void {
        std.debug.print("Client {d}: no worker: {}\n", .{ self.client_counter, err });
        if (err == error.ClientGone) return;
        var msg_buf: [1024]u8 = undefined;
        const msg = std.fmt.bufPrint(&msg_buf, "Could not run a Julia worker for this session ({s}).\n{s}", .{
            @errorName(err), self.spawnFailureHint(err, sandbox),
        }) catch return;
        self.serveString(socket, msg, 1) catch |e| std.debug.print("Client {d}: could not report the failure: {}\n", .{ self.client_counter, e });
    }

    fn spawnFailureHint(self: *Conductor, err: anyerror, sandbox: SandboxKind) []const u8 {
        return switch (err) {
            error.WorkerSpawnTimeout => if (sandbox == .client)
                "The worker started inside your sandbox never connected to the daemon. Julia, the DaemonWorker project\n" ++
                    "and the Julia depot must all be visible inside the sandbox; a fresh depot precompiles first, which\n" ++
                    "JULIA_DAEMON_SPAWN_TIMEOUT bounds.\n"
            else
                "The worker never connected to the daemon within JULIA_DAEMON_SPAWN_TIMEOUT.\n",
            error.WorkerExitedEarly => "The worker exited while starting up; its output is in the daemon log.\n",
            error.ExecutableNotFound => if (self.cfg.worker_executable.len > 0)
                "The daemon cannot resolve its worker executable to an absolute path to hand to your sandbox;\n" ++
                    "set JULIA_DAEMON_WORKER_EXECUTABLE to one.\n"
            else
                "",
            else => "See the daemon log for details.\n",
        };
    }

    const ClientRequest = struct {
        flags: protocol.client.Flags,
        pid: u32, // self-reported, meaningful only in the client's pid namespace
        host_pid: ?u32, // from peer credentials; null on TCP
        ppid: u32,
        cwd: []const u8,
        env: []const worker.EnvVar,
        parsed: args.ParsedArgs,
        project: ?[]const u8,
        raw_args: []const []const u8, // Backing storage for parsed.switches slices

        fn deinit(self: *ClientRequest, allocator: Allocator) void {
            allocator.free(self.cwd);
            if (self.project) |p| allocator.free(p);
            self.parsed.deinit();
            for (self.raw_args) |arg| allocator.free(arg);
            allocator.free(self.raw_args);
        }
    };

    fn readClientRequest(self: *Conductor, socket: posix.socket_t, is_remote: bool) !ClientRequest {
        var r = protocol.BufReader{ .fd = socket };
        // Fixed header: flags(1) + reserved(3) + pid(4) + ppid(4) = 12 bytes
        var hdr: [12]u8 = undefined;
        try r.readSlice(&hdr);
        const flags: protocol.client.Flags = @bitCast(hdr[0]);
        const pid = std.mem.readInt(u32, hdr[4..8], .little);
        const ppid = std.mem.readInt(u32, hdr[8..12], .little);
        const cwd = try r.readLenPrefixed(u16, self.allocator);
        errdefer self.allocator.free(cwd);
        const fingerprint = try r.readInt(u64);
        const client_args = try self.readClientArgs(&r);
        // Switches slice into client_args; request.deinit() frees them.
        errdefer {
            for (client_args) |a| self.allocator.free(a);
            self.allocator.free(client_args);
        }
        // The fingerprint cache is per-machine.
        const cached = if (is_remote) blk: {
            platform.write(socket, &[_]u8{protocol.client.env_request});
            const full_env = try self.readFullEnv(&r);
            break :blk self.cache.insert(fingerprint, full_env);
        } else (self.cache.lookup(fingerprint) orelse blk: {
            platform.write(socket, &[_]u8{protocol.client.env_request});
            const full_env = try self.readFullEnv(&r);
            break :blk self.cache.insert(fingerprint, full_env);
        });
        var parsed = try args.parse(self.allocator, client_args);
        errdefer parsed.deinit();
        // A remote client's filesystem isn't ours.
        const proj = if (is_remote) null else blk: {
            const home_dir = self.environ_map.get("HOME") orelse "";
            break :blk try project.resolve(self.allocator, self.io, &parsed, cached.julia_project, home_dir, cwd);
        };
        return .{
            .flags = flags,
            .pid = pid,
            .host_pid = if (platform.peerPid(socket)) |p| platform.pidNumber(p) else null,
            .ppid = ppid,
            .cwd = cwd,
            .env = cached.env,
            .parsed = parsed,
            .project = proj,
            .raw_args = client_args,
        };
    }

    fn readClientArgs(self: *Conductor, r: *protocol.BufReader) ![][]const u8 {
        const arg_count = try r.readInt(u16);
        const client_args = try self.allocator.alloc([]const u8, arg_count);
        errdefer self.allocator.free(client_args);
        var allocated: usize = 0;
        errdefer for (client_args[0..allocated]) |arg| self.allocator.free(arg);
        for (0..arg_count) |i| {
            client_args[i] = try r.readLenPrefixed(u16, self.allocator);
            allocated += 1;
        }
        return client_args;
    }

    fn readFullEnv(self: *Conductor, r: *protocol.BufReader) ![]worker.EnvVar {
        const count = try r.readInt(u16);
        const env = try self.allocator.alloc(worker.EnvVar, count);
        errdefer self.allocator.free(env);
        var allocated: usize = 0;
        errdefer for (env[0..allocated]) |e| {
            self.allocator.free(e.key);
            self.allocator.free(e.value);
        };
        for (0..count) |i| {
            const key = try r.readLenPrefixed(u16, self.allocator);
            errdefer self.allocator.free(key);
            const val = try r.readLenPrefixed(u16, self.allocator);
            env[i] = .{ .key = key, .value = val };
            allocated += 1;
        }
        return env;
    }

    pub const SandboxKind = union(enum) {
        none,
        remote,
        local: []const u8, // the one rw bind mount: the project, or just cwd
        client: struct { socket: posix.socket_t, ns: u64 }, // the client spawns the worker inside its own sandbox
    };

    pub const HeldClient = struct {
        socket: posix.socket_t,
        request: ClientRequest, // its env is an owned copy: the cache entry may be evicted meanwhile
        worker_key: []const u8,
        sandbox: SandboxKind,
        id: u32,
    };

    /// Clients for the same pool key queue as waiters, re-selected once it is up.
    pub const PendingSpawn = struct {
        spawn: worker.Worker.Spawn,
        purpose: union(enum) { reserve, client: *HeldClient },
        waiters: std.array_list.Aligned(*HeldClient, null) = .empty,
    };

    const PreparedClient = struct {
        port_set: u16,
        sandbox_env: ?[]const worker.EnvVar,
        info: worker.ClientInfo,
    };

    fn prepareClient(self: *Conductor, request: *const ClientRequest, sandbox: SandboxKind) !PreparedClient {
        const session_label = request.parsed.getSwitch("--session");
        const is_labeled_session = session_label != null and session_label.?.len > 0;
        const port_set = if (self.port_pool) |*pool| blk: {
            break :blk pool.allocate() orelse {
                std.debug.print("Client {d}: port pool exhausted\n", .{self.client_counter});
                return error.PortPoolExhausted;
            };
        } else protocol.PortPool.none;
        errdefer self.releasePortSet(port_set);
        // So withenv(client.env...) doesn't leak the remote HOME etc.
        const sandbox_env = if (sandbox == .remote) try self.buildSandboxClientEnv(request.env) else null;
        return .{ .port_set = port_set, .sandbox_env = sandbox_env, .info = .{
            .tty = request.flags.tty,
            .color = request.flags.color,
            .force = is_labeled_session,
            .id = self.client_counter,
            .pid = request.pid,
            .host_pid = request.host_pid,
            .ppid = request.ppid,
            .cwd = if (sandbox == .remote) "/home/sandbox" else request.cwd,
            .env = sandbox_env orelse request.env,
            .switches = request.parsed.switches.items,
            .programfile = request.parsed.program_file,
            .args = request.parsed.program_args,
            .port_set = port_set,
        } };
    }

    /// `direct` is the worker started for the client; `existing_hold` resumes a hold.
    fn assignClientToWorker(self: *Conductor, socket: posix.socket_t, request: *ClientRequest, worker_key: []const u8, sandbox: SandboxKind, existing_hold: ?*HeldClient, direct: ?*worker.Worker) !Outcome {
        const list = try self.getWorkerList(worker_key);
        const session_label = request.parsed.getSwitch("--session");
        std.debug.print("Client {d}; pid: {d}{s}{s}{s}{s}, project: {s}{s}\n", .{
            self.client_counter,
            request.pid,
            if (request.parsed.julia_channel != null) ", julia: " else "",
            request.parsed.julia_channel orelse "",
            if (session_label != null) ", session: " else "",
            if (session_label) |l| (if (l.len > 0) l else ".") else "",
            request.project orelse "(default)",
            if (sandbox != .none) " [sandboxed]" else "",
        });
        // Queue behind a starting worker so a labelled session can't end up with two.
        if (direct == null) if (self.findPendingSpawn(worker_key)) |p| {
            const hold = existing_hold orelse try self.holdClient(socket, request, worker_key, sandbox);
            errdefer if (existing_hold == null) self.unholdClient(hold);
            try p.waiters.append(self.allocator, hold);
            std.debug.print("Client {d}: waiting for worker {d}\n", .{ self.client_counter, p.spawn.worker.id });
            return .held;
        };
        var prepared = try self.prepareClient(request, sandbox);
        defer if (prepared.sandbox_env) |e| self.allocator.free(e);
        var port_set_held = true;
        errdefer if (port_set_held) self.releasePortSet(prepared.port_set);
        const assignment: ?WorkerAssignment = if (direct) |w|
            self.tryAssignWorker(w, &prepared.info, .new_worker) orelse return error.WorkerUnavailable
        else
            try self.selectWorker(list, &prepared.info, session_label, labelOf(request) != null, request.project orelse "", request.parsed.julia_channel, resolveThreads(request), self.currentTime(), sandbox);
        if (assignment) |a| {
            self.finishAssignment(socket, request, worker_key, a, prepared.port_set);
            return .done;
        }
        self.releasePortSet(prepared.port_set);
        port_set_held = false;
        const hold = existing_hold orelse try self.holdClient(socket, request, worker_key, sandbox);
        errdefer if (existing_hold == null) self.unholdClient(hold);
        try self.beginClientSpawn(hold);
        return .held;
    }

    fn labelOf(request: *const ClientRequest) ?[]const u8 {
        const label = request.parsed.getSwitch("--session") orelse return null;
        return if (label.len > 0) label else null;
    }

    fn finishAssignment(self: *Conductor, socket: posix.socket_t, request: *const ClientRequest, worker_key: []const u8, assignment: WorkerAssignment, port_set: u16) void {
        std.debug.print("Assigned client {d} to worker {d}: {s}\n", .{ self.client_counter, assignment.w.id, @tagName(assignment.reason) });
        defer self.allocator.free(assignment.paths.stdin);
        defer self.allocator.free(assignment.paths.stdout);
        defer self.allocator.free(assignment.paths.stderr);
        defer self.allocator.free(assignment.paths.signals);
        const now = self.currentTime();
        assignment.w.last_pinged = now;
        assignment.w.recordPpid(request.ppid, self.cfg.worker_maxclients);
        self.registerClient(self.client_counter, request.host_pid orelse request.pid, assignment.w, port_set) catch |err| {
            std.debug.print("Client {d}: cannot track: {}\n", .{ self.client_counter, err });
        };
        self.bumpCrf(worker_key, now); // count the summons only once the client is tracked
        std.debug.print("Client {d}: sending socket paths to client\n", .{self.client_counter});
        self.sendSocketPaths(socket, assignment.paths);
        std.debug.print("Client {d}: done\n", .{self.client_counter});
        if (self.cfg.reserve_worker) self.beginReserveSpawn() catch |err| {
            std.debug.print("Warning: failed to start a reserve worker: {}\n", .{err});
        };
    }

    // --- Held clients ---

    // The request changes hands: the caller must not deinit it while held.
    fn holdClient(self: *Conductor, socket: posix.socket_t, request: *const ClientRequest, worker_key: []const u8, sandbox: SandboxKind) !*HeldClient {
        const hold = try self.allocator.create(HeldClient);
        errdefer self.allocator.destroy(hold);
        const env = try self.allocator.alloc(worker.EnvVar, request.env.len);
        var copied: usize = 0;
        errdefer self.freeEnv(env[0..copied], env);
        for (request.env, env) |src, *dst| {
            dst.key = try self.allocator.dupe(u8, src.key);
            errdefer self.allocator.free(dst.key);
            dst.value = try self.allocator.dupe(u8, src.value);
            copied += 1;
        }
        const key = try self.allocator.dupe(u8, worker_key);
        hold.* = .{ .socket = socket, .request = request.*, .worker_key = key, .sandbox = sandbox, .id = self.client_counter };
        hold.request.env = env;
        return hold;
    }

    fn freeEnv(self: *Conductor, filled: []const worker.EnvVar, storage: []const worker.EnvVar) void {
        for (filled) |e| {
            self.allocator.free(e.key);
            self.allocator.free(e.value);
        }
        self.allocator.free(storage);
    }

    // Undo holdClient while the caller still owns the request.
    fn unholdClient(self: *Conductor, hold: *HeldClient) void {
        self.freeEnv(hold.request.env, hold.request.env);
        self.allocator.free(hold.worker_key);
        self.allocator.destroy(hold);
    }

    fn discardHold(self: *Conductor, hold: *HeldClient) void {
        platform.close(hold.socket);
        hold.request.deinit(self.allocator);
        self.unholdClient(hold);
    }

    const Resumption = union(enum) { select, on: *worker.Worker, refuse: anyerror };

    fn resumeHeld(self: *Conductor, hold: *HeldClient, how: Resumption) void {
        self.client_counter = hold.id;
        const attempt: anyerror!Outcome = switch (how) {
            .refuse => |err| err,
            .select => self.assignClientToWorker(hold.socket, &hold.request, hold.worker_key, hold.sandbox, hold, null),
            .on => |w| self.assignClientToWorker(hold.socket, &hold.request, hold.worker_key, hold.sandbox, hold, w),
        };
        const outcome = attempt catch |err| blk: {
            self.reportNoWorker(hold.socket, err, hold.sandbox);
            break :blk Outcome.done;
        };
        if (outcome == .done) self.discardHold(hold);
    }

    /// False when the worker already died; the caller falls back to selection.
    fn assignClientToExistingWorker(self: *Conductor, socket: posix.socket_t, request: *const ClientRequest, w: *worker.Worker) !bool {
        const port_set = if (self.port_pool) |*pool| blk: {
            break :blk pool.allocate() orelse {
                std.debug.print("Client {d}: port pool exhausted\n", .{self.client_counter});
                return error.PortPoolExhausted;
            };
        } else protocol.PortPool.none;
        errdefer self.releasePortSet(port_set);
        const session_label = request.parsed.getSwitch("--session");
        const is_labeled_session = session_label != null and session_label.?.len > 0;
        // The remote cwd doesn't exist here.
        const client_info = worker.ClientInfo{
            .tty = request.flags.tty,
            .color = request.flags.color,
            .force = is_labeled_session,
            .id = self.client_counter,
            .pid = request.pid,
            .host_pid = request.host_pid,
            .ppid = request.ppid,
            .cwd = if (self.cfg.host_home.len > 0) self.cfg.host_home else "/",
            .env = request.env,
            .switches = request.parsed.switches.items,
            .programfile = request.parsed.program_file,
            .args = request.parsed.program_args,
            .port_set = port_set,
        };
        self.event_loop.cancelPendingPing(w);
        const paths = w.runClient(self.allocator, &client_info) catch |err| {
            if (!self.handleRunClientError(w, err)) return err;
            self.releasePortSet(port_set);
            return false;
        };
        defer self.allocator.free(paths.stdin);
        defer self.allocator.free(paths.stdout);
        defer self.allocator.free(paths.stderr);
        defer self.allocator.free(paths.signals);
        const now = self.currentTime();
        w.last_pinged = now;
        w.recordPpid(request.ppid, self.cfg.worker_maxclients);
        try self.registerClient(self.client_counter, request.host_pid orelse request.pid, w, port_set);
        self.sendSocketPaths(socket, paths);
        return true;
    }

    // --- Worker selection ---

    fn selectWorker(
        self: *Conductor,
        list: *WorkerList,
        client_info: *const worker.ClientInfo,
        session_label: ?[]const u8,
        is_labeled_session: bool,
        project_path: []const u8,
        julia_channel: ?[]const u8,
        threads: args.Threads,
        now: i64,
        sandbox: SandboxKind,
    ) !?WorkerAssignment {
        const want_interactive = for (client_info.switches) |sw| {
            if (std.mem.eql(u8, sw.name, "-i")) break true;
        } else false;
        // 1. Labeled session: join its worker (global, or scoped to an explicit --project)
        if (is_labeled_session) {
            const explicit_project = for (client_info.switches) |sw| {
                if (std.mem.eql(u8, sw.name, "--project")) break true;
            } else false;
            // A sandboxed client's label stays in its pool: joining a host worker would escape.
            const found = if (explicit_project or sandbox != .none)
                findWorkerByLabel(list, session_label.?)
            else
                self.findWorkerByLabelGlobal(session_label.?);
            if (found) |w| {
                if (self.tryAssignWorker(w, client_info, .session_label)) |a| return a;
            }
        }
        // Skip ppid/recency reuse for remote clients (isolation) and labeled
        // sessions (their identity is the label, handled above and below).
        if (sandbox != .remote and !is_labeled_session) {
            // 2. PPID-affinity (interactive flag must match)
            if (self.findWorkerByPpid(list, client_info.ppid, want_interactive, now)) |w| {
                if (self.tryAssignWorker(w, client_info, .ppid_affinity)) |a| return a;
            }
            // 3. Lightest available worker, sparing the most-recent for ppid reuse
            if (self.tryExistingWorkers(list, client_info, want_interactive, now)) |a| return a;
        }
        // 3b. New labeled session: claim an idle worker and tag it, else spawn.
        if (is_labeled_session and sandbox == .none) {
            if (self.findClaimableWorker(list, want_interactive, now)) |w| {
                if (w.session_label != null) self.clearLabel(w); // expired
                w.session_label = try self.allocator.dupe(u8, session_label.?);
                if (self.tryAssignWorker(w, client_info, .session_label)) |a| return a;
            }
        }
        // 4. The warm reserve, for a plain non-interactive request it matches.
        if (sandbox == .none and !want_interactive) {
            if (try self.claimReserve(list, project_path, julia_channel, threads, if (is_labeled_session) session_label else null)) |w| {
                if (self.tryAssignWorker(w, client_info, .new_worker)) |a| return a;
            }
        }
        return null; // nothing to be had: the caller starts a worker
    }

    fn isWorkerAvailable(self: *Conductor, w: *worker.Worker, interactive: bool, now: i64) bool {
        const max = self.cfg.worker_maxclients;
        if (max != 0 and w.active_clients >= max) return false;
        if (w.session_label != null and !self.isLabelExpired(w, now)) return false;
        if (w.interactive != interactive) return false;
        return true;
    }

    fn tryAssignWorker(self: *Conductor, w: *worker.Worker, client_info: *const worker.ClientInfo, reason: AssignReason) ?WorkerAssignment {
        self.event_loop.cancelPendingPing(w);
        const paths = w.runClient(self.allocator, client_info) catch |err| {
            _ = self.handleRunClientError(w, err);
            return null;
        };
        return .{ .paths = paths, .w = w, .reason = reason };
    }

    fn findWorkerByPpid(self: *Conductor, list: *WorkerList, ppid: u32, interactive: bool, now: i64) ?*worker.Worker {
        for (list.items) |w| {
            if (!self.isWorkerAvailable(w, interactive, now)) continue;
            if (std.mem.indexOfScalar(u32, &w.recent_ppids, ppid) != null) {
                if (self.isLabelExpired(w, now)) self.clearLabel(w);
                return w;
            }
        }
        return null;
    }

    fn findWorkerByLabel(list: *WorkerList, label: []const u8) ?*worker.Worker {
        for (list.items) |w| {
            if (w.session_label) |wl| {
                if (std.mem.eql(u8, wl, label)) return w;
            }
        }
        return null;
    }

    // Warmest first; null → spawn.
    fn findClaimableWorker(self: *Conductor, list: *WorkerList, interactive: bool, now: i64) ?*worker.Worker {
        var best: ?*worker.Worker = null;
        for (list.items) |w| {
            if (w.active_clients != 0) continue;
            if (w.session_label != null and !self.isLabelExpired(w, now)) continue;
            if (w.interactive != interactive) continue;
            if (best == null or w.last_active > best.?.last_active) best = w;
        }
        return best;
    }

    // Spare the most recent for its ppid owner; the lightest goes, so heavy workers age out.
    fn tryExistingWorkers(self: *Conductor, list: *WorkerList, client_info: *const worker.ClientInfo, interactive: bool, now: i64) ?WorkerAssignment {
        var newest: ?*worker.Worker = null;
        for (list.items) |w| {
            if (!self.isWorkerAvailable(w, interactive, now)) continue;
            if (newest == null or w.last_active > newest.?.last_active) newest = w;
        }
        if (newest == null) return null;

        var pick: ?*worker.Worker = null;
        var pick_mem: u64 = 0;
        for (list.items) |w| {
            if (w == newest.? or !self.isWorkerAvailable(w, interactive, now)) continue;
            // Unmeasured ranks heaviest; an idle candidate's mem is current.
            const mem = if (w.mem > 0) w.mem else std.math.maxInt(u64);
            if (pick == null or mem < pick_mem or (mem == pick_mem and w.last_active > pick.?.last_active)) {
                pick = w;
                pick_mem = mem;
            }
        }
        const chosen = pick orelse newest.?;
        if (self.isLabelExpired(chosen, now)) self.clearLabel(chosen);
        return self.tryAssignWorker(chosen, client_info, .recent_worker);
    }

    fn handleRunClientError(self: *Conductor, w: *worker.Worker, err: anyerror) bool {
        switch (err) {
            error.WorkerBusy => {
                std.debug.print("Worker {d}: busy (likely has stuck client), syncing\n", .{w.id});
                self.syncWorkerClients(w);
                return true;
            },
            error.WouldBlock, error.EndOfStream, error.BrokenPipe, error.ConnectionResetByPeer,
            error.UnexpectedResponse, error.WorkerError => {
                self.retireWorker(w);
                return true;
            },
            else => return false,
        }
    }

    // --- Worker pool management ---

    pub fn beginReserveSpawn(self: *Conductor) !void {
        if (self.reserve != null) return;
        for (self.pending_spawns.items) |p| if (p.purpose == .reserve) return;
        // Clients usually inherit JULIA_NUM_THREADS, and reuse needs an exact match.
        const reserve_threads = if (self.environ_map.get("JULIA_NUM_THREADS")) |v|
            args.parseThreads(v)
        else
            args.threads_none;
        const p = try self.beginSpawn(.reserve, null, reserve_threads, false, .direct);
        std.debug.print("Spawning reserve worker {d} (pid {d})\n", .{ p.spawn.worker.id, platform.getChildPid(p.spawn.worker.process) });
    }

    // Seated in `list` (and labelled) on return.
    fn claimReserve(self: *Conductor, list: *WorkerList, proj: []const u8, julia_channel: ?[]const u8, threads: args.Threads, label: ?[]const u8) !?*worker.Worker {
        const r = self.reserve orelse return null;
        if (!std.meta.eql(threads, r.threads)) return null;
        const channel_matches = if (julia_channel == null and r.julia_channel == null)
            true
        else if (julia_channel != null and r.julia_channel != null)
            std.mem.eql(u8, julia_channel.?, r.julia_channel.?)
        else
            false;
        if (!channel_matches) return null;
        self.reserve = null;
        std.debug.print("Assigning reserve worker {d} to project {s}{s}{s}\n", .{
            r.id, proj, if (julia_channel != null) " " else "", julia_channel orelse "",
        });
        try self.seatWorker(list, r, proj, label);
        return r;
    }

    // Killed if seating fails, else it would orphan.
    fn seatWorker(self: *Conductor, list: *WorkerList, w: *worker.Worker, proj: []const u8, label: ?[]const u8) !void {
        self.event_loop.cancelPendingPing(w);
        errdefer self.enqueueKill(w);
        if (w.launch != .sandboxed or proj.len > 0) {
            const proj_copy = try self.allocator.dupe(u8, proj);
            w.setProject(proj_copy) catch |err| {
                self.allocator.free(proj_copy);
                return err;
            };
        }
        if (label) |l| if (w.session_label == null) {
            std.debug.print("Worker {d}: assigning label '{s}'\n", .{ w.id, l });
            w.session_label = try self.allocator.dupe(u8, l);
        };
        try list.append(self.allocator, w);
    }

    fn beginClientSpawn(self: *Conductor, hold: *HeldClient) !void {
        const proj = hold.request.project orelse "";
        // Conductor-built sandboxes are never interactive.
        const interactive = (hold.sandbox == .none or hold.sandbox == .client) and hold.request.parsed.hasSwitch("-i");
        var rw_bind: [1][]const u8 = undefined;
        var ro_bind: [1][]const u8 = undefined;
        const launch: worker.Worker.Launch = switch (hold.sandbox) {
            .none => .direct,
            .client => |c| .{ .client = .{ .socket = c.socket, .environ = self.environ_map, .ns = c.ns } },
            .remote => .{ .sandboxed = .{ .environ = self.environ_map, .ro_binds = projectRoBind(proj, &.{}, &ro_bind), .rw_binds = &.{} } },
            .local => |rw| blk: {
                rw_bind = .{rw};
                break :blk .{ .sandboxed = .{ .environ = self.environ_map, .ro_binds = projectRoBind(proj, &rw_bind, &ro_bind), .rw_binds = &rw_bind } };
            },
        };
        const p = try self.beginSpawn(.{ .client = hold }, hold.request.parsed.julia_channel, resolveThreads(&hold.request), interactive, launch);
        std.debug.print("Spawning {s}worker {d} (pid {d}) for project {s}{s}{s}\n", .{
            switch (hold.sandbox) {
                .client => "client-spawned ",
                .remote, .local => "sandboxed ",
                .none => if (interactive) "interactive " else "",
            },
            p.spawn.worker.id,
            platform.getChildPid(p.spawn.worker.process),
            proj,
            if (hold.request.parsed.julia_channel != null) " " else "",
            hold.request.parsed.julia_channel orelse "",
        });
    }

    // The project dir is mounted ro when no rw bind already covers it.
    fn projectRoBind(proj: []const u8, rw_binds: []const []const u8, buf: *[1][]const u8) []const []const u8 {
        if (proj.len == 0 or pathCoveredBy(proj, rw_binds)) return &.{};
        buf[0] = proj;
        return buf[0..1];
    }

    fn beginSpawn(self: *Conductor, purpose: @FieldType(PendingSpawn, "purpose"), julia_channel: ?[]const u8, threads: args.Threads, interactive: bool, launch: worker.Worker.Launch) !*PendingSpawn {
        const p = try self.allocator.create(PendingSpawn);
        errdefer self.allocator.destroy(p);
        p.* = .{
            .spawn = try worker.Worker.begin(self.allocator, self.io, &self.cfg, self.next_worker_id, julia_channel, threads, interactive, launch),
            .purpose = purpose,
        };
        errdefer p.spawn.abandon(self.io);
        try self.pending_spawns.append(self.allocator, p);
        self.next_worker_id += 1;
        self.event_loop.watchFd(@intFromPtr(p) | tag_spawn_listener, p.spawn.listenerFd());
        // It sends nothing until it has its paths, so readable means it hung up.
        if (p.purpose == .client) self.event_loop.watchFd(@intFromPtr(p) | tag_spawn_client, p.purpose.client.socket);
        self.event_loop.armTick();
        return p;
    }

    // --- Pending spawns ---

    fn findPendingSpawn(self: *Conductor, key: []const u8) ?*PendingSpawn {
        for (self.pending_spawns.items) |p| switch (p.purpose) {
            .reserve => {},
            .client => |hold| if (std.mem.eql(u8, hold.worker_key, key)) return p,
        };
        return null;
    }

    // The setup listener turned readable: the worker, or an impostor, connected.
    fn onSpawnReadable(self: *Conductor, p: *PendingSpawn) void {
        const connected = p.spawn.accept(self.io, &self.cfg) catch |err| return self.failSpawn(p, err);
        if (connected) |w| self.completeSpawn(p, w) else self.event_loop.watchFd(@intFromPtr(p) | tag_spawn_listener, p.spawn.listenerFd());
    }

    // Waiters select again; the worker underway is not worth keeping.
    fn onSpawnClientGone(self: *Conductor, p: *PendingSpawn) void {
        std.debug.print("Client {d}: left while worker {d} was starting\n", .{ p.purpose.client.id, p.spawn.worker.id });
        self.failSpawn(p, error.ClientGone);
    }

    fn detachSpawn(self: *Conductor, p: *PendingSpawn) void {
        _ = removePending(&self.pending_spawns, p);
        self.event_loop.unwatchFd(@intFromPtr(p) | tag_spawn_listener, p.spawn.listenerFd());
        if (p.purpose == .client) self.event_loop.unwatchFd(@intFromPtr(p) | tag_spawn_client, p.purpose.client.socket);
    }

    fn failSpawn(self: *Conductor, p: *PendingSpawn, err: anyerror) void {
        if (err != error.ClientGone) std.debug.print("Worker {d}: spawn failed: {}\n", .{ p.spawn.worker.id, err });
        self.detachSpawn(p);
        p.spawn.abandon(self.io);
        self.settleSpawn(p, .{ .refuse = err });
    }

    fn completeSpawn(self: *Conductor, p: *PendingSpawn, connected: worker.Worker) void {
        self.detachSpawn(p);
        const w = self.allocator.create(worker.Worker) catch |err| {
            var lost = connected;
            lost.signal(platform.SIG.KILL);
            lost.deinit();
            return self.settleSpawn(p, .{ .refuse = err });
        };
        w.* = connected;
        std.debug.print("Worker {d} (pid {d}) connected\n", .{ w.id, platform.getChildPid(w.process) });
        switch (p.purpose) {
            .reserve => if (w.ping()) {
                self.reserve = w;
            } else |err| {
                std.debug.print("Reserve worker {d}: first ping failed: {}\n", .{ w.id, err });
                self.enqueueKill(w);
            },
            .client => |hold| {
                const list = self.getWorkerList(hold.worker_key) catch |err| return self.settleSpawn(p, .{ .refuse = err });
                self.seatWorker(list, w, hold.request.project orelse "", labelOf(&hold.request)) catch |err| return self.settleSpawn(p, .{ .refuse = err });
                return self.settleSpawn(p, .{ .on = w });
            },
        }
        self.settleSpawn(p, .select);
    }

    fn settleSpawn(self: *Conductor, p: *PendingSpawn, how: Resumption) void {
        if (p.purpose == .client) self.resumeHeld(p.purpose.client, how);
        for (p.waiters.items) |hold| self.resumeHeld(hold, .select);
        p.waiters.deinit(self.allocator);
        self.allocator.destroy(p);
    }

    fn abandonSpawns(self: *Conductor) void {
        while (self.pending_spawns.pop()) |p| {
            self.detachSpawn(p);
            p.spawn.abandon(self.io);
            for (p.waiters.items) |hold| self.resumeHeld(hold, .{ .refuse = error.DaemonShuttingDown });
            p.waiters.clearRetainingCapacity();
            self.settleSpawn(p, .{ .refuse = error.DaemonShuttingDown });
        }
    }

    fn findWorkerByLabelGlobal(self: *Conductor, label: []const u8) ?*worker.Worker {
        var it = self.workers.iterator();
        while (it.next()) |entry| {
            // A sandboxed pool never serves a caller outside its sandbox.
            const pool = entry.value_ptr.items;
            if (pool.len > 0 and pool[0].launch != .direct) continue;
            if (findWorkerByLabel(entry.value_ptr, label)) |w| return w;
        }
        return null;
    }

    fn trimTrailingSlashes(path: []const u8) []const u8 {
        var end = path.len;
        while (end > 1 and path[end - 1] == '/') end -= 1;
        return path[0..end];
    }

    fn pathCoveredBy(path: []const u8, dirs: []const []const u8) bool {
        const p = trimTrailingSlashes(path);
        for (dirs) |raw_d| {
            const d = trimTrailingSlashes(raw_d);
            if (std.mem.eql(u8, d, p)) return true;
            if (p.len > d.len and
                std.mem.startsWith(u8, p, d) and
                p[d.len] == '/') return true;
        }
        return false;
    }

    fn killWorkersForProject(self: *Conductor, proj: []const u8) usize {
        // Starting workers count too; their clients are told to try again.
        var starting: [16]*PendingSpawn = undefined;
        var n_starting: usize = 0;
        for (self.pending_spawns.items) |p| switch (p.purpose) {
            .reserve => {},
            .client => |hold| if (n_starting < starting.len and std.mem.eql(u8, hold.worker_key, proj)) {
                starting[n_starting] = p;
                n_starting += 1;
            },
        };
        for (starting[0..n_starting]) |p| self.failSpawn(p, error.Restarted);
        if (self.workers.getPtr(proj)) |list| {
            const count = list.items.len + n_starting;
            for (list.items) |w| {
                self.event_loop.cancelPendingPing(w);
                if (self.reserve == w) self.reserve = null;
                self.removeActiveClientsForWorker(w);
                self.enqueueKill(w);
            }
            // crf history is kept: --restart is a non-TTL death (may come back hot).
            self.dropPoolEntry(proj);
            return count;
        }
        return n_starting;
    }

    // Returns at once; the sweep escalates soft -> SIGTERM -> SIGKILL and reaps.
    pub fn retireWorker(self: *Conductor, w: *worker.Worker) void {
        self.event_loop.cancelPendingPing(w);
        if (self.reserve == w) self.reserve = null;
        self.removeActiveClientsForWorker(w);
        var it = self.workers.iterator();
        while (it.next()) |entry| {
            for (entry.value_ptr.items, 0..) |item, i| {
                if (item == w) {
                    _ = entry.value_ptr.swapRemove(i);
                    break;
                }
            }
        }
        self.enqueueKill(w);
    }

    // Precondition: `w` is already detached from the pool.
    fn enqueueKill(self: *Conductor, w: *worker.Worker) void {
        if (w.process.id == null) {
            self.cleanupWorker(w);
            return;
        }
        w.softExit();
        self.pending_kills.append(self.allocator, .{
            .w = w, .stage = .soft, .deadline = self.currentTime() + retire_grace_s,
        }) catch {
            w.signal(platform.SIG.KILL);
            self.cleanupWorker(w);
        };
    }

    // --- Activity signals ---

    fn activityHalfLife(self: *const Conductor) u64 {
        return self.cfg.min_ttl;
    }

    // Slow half-lives: occupancy over half the budget span, crf a quarter (it compounds).
    fn budgetOccHalfLife(self: *const Conductor) u64 {
        return (self.cfg.max_ttl - self.cfg.min_ttl) / 2;
    }
    fn crfHalfLife(self: *const Conductor) u64 {
        return (self.cfg.max_ttl - self.cfg.min_ttl) / 4;
    }

    fn bumpCrf(self: *Conductor, key: []const u8, now: i64) void {
        if (self.crf.getPtr(key)) |e| return e.summon(now, self.crfHalfLife());
        const key_copy = self.allocator.dupe(u8, key) catch return;
        self.crf.put(key_copy, .{ .last_update = now }) catch return self.allocator.free(key_copy);
        self.crf.getPtr(key_copy).?.summon(now, self.crfHalfLife());
    }

    fn readCrf(self: *Conductor, key: []const u8, now: i64) f64 {
        const e = self.crf.getPtr(key) orelse return 0;
        return e.read(now, self.crfHalfLife());
    }

    // Discounts the first summon: only reuse counts as warmth.
    fn crfWarmth(self: *Conductor, key: ?[]const u8, now: i64) f64 {
        const k = key orelse return 0;
        return worker.Crf.normalize(@max(0, self.readCrf(k, now) - 1));
    }

    // Pure, so safe from the status renderer.
    pub fn workerActivity(self: *Conductor, w: *const worker.Worker, key: ?[]const u8, now: i64) f64 {
        return @max(self.crfWarmth(key, now), w.occupancy.fast.read(now, self.activityHalfLife()));
    }

    // Caches mem and folds cpu into the meter, so the status render stays clock-free.
    // Null `half_life_s` sets util to the raw rate (one-shot); a value blends the EWMA.
    pub fn refreshStats(self: *Conductor, half_life_s: ?f64) void {
        const now_ns = self.nowNs();
        var it = self.workers.iterator();
        while (it.next()) |entry| {
            for (entry.value_ptr.items) |w| refreshOne(w, now_ns, half_life_s);
        }
        if (self.reserve) |r| refreshOne(r, now_ns, half_life_s);
    }

    fn refreshOne(w: *worker.Worker, now_ns: i64, half_life_s: ?f64) void {
        const pid = w.livePid() orelse return;
        const s = platform.getProcessStats(pid) orelse return;
        w.mem = s.mem_bytes;
        w.mem_at = @divTrunc(now_ns, 1_000_000_000);
        w.cpu.update(now_ns, s.cpu_seconds, half_life_s);
    }

    // Once per ping interval, so sizing tracks idle drift without an extra wakeup.
    pub fn refreshIdleMemIfStale(self: *Conductor, w: *worker.Worker, now_s: i64) void {
        if (w.active_clients != 0) return;
        if (now_s - w.mem_at < @as(i64, @intCast(self.cfg.ping_interval))) return;
        refreshOne(w, self.nowNs(), null);
    }

    // Only for a TTL-culled key; cleanupWorker has no handle on the crf map, enforcing this.
    fn dropColdKey(self: *Conductor, key: []const u8) void {
        if (self.crf.fetchRemove(key)) |kv| self.allocator.free(kv.key);
    }

    pub fn enforceMaxTtl(self: *Conductor) void {
        if (self.cfg.max_ttl == 0) return;
        const now = self.currentTime();
        // Re-scan from the top after each cull: retireWorker mutates the pool.
        while (self.findExpired(now)) |hit| {
            std.debug.print("Worker {d}: idle {d}s past activity-scaled budget (max TTL {d}s), retiring\n", .{ hit.w.id, now - hit.w.last_active, self.cfg.max_ttl });
            self.retireWorker(hit.w);
            // dropColdKey reads hit.key, which dropPoolEntry frees.
            if (self.workers.getPtr(hit.key)) |list| {
                if (list.items.len == 0) {
                    self.dropColdKey(hit.key);
                    self.dropPoolEntry(hit.key);
                }
            }
        }
    }

    // Callers own the list's workers first; `key` dangles afterward.
    fn dropPoolEntry(self: *Conductor, key: []const u8) void {
        if (self.workers.fetchRemove(key)) |kv| {
            var list = kv.value;
            list.deinit(self.allocator);
            self.allocator.free(kv.key);
        }
    }

    const Expired = struct { w: *worker.Worker, key: []const u8 };

    // One at a time: the caller mutates the pool between calls. The reserve is
    // exempt from TTL, though not from pressure.
    fn findExpired(self: *Conductor, now: i64) ?Expired {
        var it = self.workers.iterator();
        while (it.next()) |entry| {
            for (entry.value_ptr.items) |w| {
                if (self.isExpired(w, entry.key_ptr.*, now)) return .{ .w = w, .key = entry.key_ptr.* };
            }
        }
        return null;
    }

    // --- Pressure-reactive eviction ---

    const Candidate = struct { w: *worker.Worker, key: []const u8, size: u64, value: f64 };

    // Under pressure: rank idle in-band workers by value() on cheap RSS, validate
    // the lowest band with true USS, retire the lowest up to the cap.
    pub fn runEvictionEpisode(self: *Conductor) void {
        if (!self.pressure_monitor.poll(&self.cfg)) return;
        const now = self.currentTime();
        var buf: [episode_capacity]Candidate = undefined;
        const cands = self.collectDiscretionary(&buf, now);
        if (cands.len == 0) return;
        // An unreadable footprint (size 0) ranks by activity alone.
        const now_ns = self.nowNs();
        const half_life: f64 = @floatFromInt(self.cfg.ping_interval);
        for (cands) |*c| {
            refreshOne(c.w, now_ns, half_life);
            c.size = c.w.mem;
            c.value = self.workerValue(c.w, c.key, now, c.size);
        }
        std.sort.pdq(Candidate, cands, {}, lessByValue);
        // Where selection used RSS, refine the bottom 2*cap band with true USS.
        const band = @min(2 * max_evict_per_episode, cands.len);
        if (!platform.mem_is_reclaimable) {
            for (cands[0..band]) |*c| {
                if (c.w.livePid()) |pid| {
                    if (platform.processReclaimable(pid)) |uss| c.size = uss;
                }
                c.value = self.workerValue(c.w, c.key, now, c.size);
            }
            std.sort.pdq(Candidate, cands[0..band], {}, lessByValue);
        }
        // Re-check each: the ranking may predate an assignment.
        var evicted: usize = 0;
        for (cands[0..band]) |c| {
            if (evicted >= max_evict_per_episode) break;
            if (!self.inPressureBand(c.w, c.key, now)) continue;
            if (c.size == 0)
                std.debug.print("Worker {d}: evicting under memory pressure (value={d:.5}, size n/a)\n", .{ c.w.id, c.value })
            else
                std.debug.print("Worker {d}: evicting under memory pressure (value={d:.5}, {d}MB)\n", .{ c.w.id, c.value, c.size >> 20 });
            self.retireWorker(c.w);
            evicted += 1;
        }
    }

    fn collectDiscretionary(self: *Conductor, buf: []Candidate, now: i64) []Candidate {
        var n: usize = 0;
        var it = self.workers.iterator();
        while (it.next()) |entry| {
            for (entry.value_ptr.items) |w| {
                if (n >= buf.len) {
                    std.debug.print("Eviction episode: discretionary set exceeds cap; ranking first {d} only\n", .{buf.len});
                    return buf[0..n];
                }
                if (self.inPressureBand(w, entry.key_ptr.*, now)) {
                    buf[n] = .{ .w = w, .key = entry.key_ptr.*, .size = 0, .value = 0 };
                    n += 1;
                }
            }
        }
        // The keyless reserve (crf=0) is the cheapest thing to drop under pressure.
        if (self.reserve) |r| {
            if (n < buf.len and self.inPressureBand(r, "", now)) {
                buf[n] = .{ .w = r, .key = "", .size = 0, .value = 0 };
                n += 1;
            }
        }
        return buf[0..n];
    }

    fn cullableAge(self: *Conductor, w: *worker.Worker, now: i64) ?u64 {
        if (w.active_clients > 0) return null;
        if (w.session_label != null and !self.isLabelExpired(w, now)) return null;
        return @intCast(@max(0, now - w.last_active));
    }
    // Past budget is expired instead: enforceMaxTtl culls it regardless.
    fn inPressureBand(self: *Conductor, w: *worker.Worker, key: []const u8, now: i64) bool {
        const age = self.cullableAge(w, now) orelse return false;
        return age >= self.cfg.min_ttl and age < self.idleBudget(w, key);
    }
    // Idle seconds before TTL culls a worker, the larger of two earned terms:
    //  • cadence: the key's expected next-summon time (RFC 6298 RTO), scaled by a
    //    log multiplier of crf so established frequency earns more headroom.
    //  • occupancy: sustained busy-time, so a long single session earns budget too.
    pub fn idleBudget(self: *Conductor, w: *const worker.Worker, key: []const u8) u64 {
        const max_ttl: f64 = @floatFromInt(self.cfg.max_ttl);
        // A session worker's floor is the geomean of min/max_ttl.
        const min_ttl: f64 = if (w.session_label != null)
            @sqrt(@as(f64, @floatFromInt(self.cfg.min_ttl)) * max_ttl)
        else
            @floatFromInt(self.cfg.min_ttl);
        var cadence: f64 = 0;
        if (key.len > 0) if (self.crf.getPtr(key)) |e| {
            const mult = 1 + @log2(1 + @max(0, e.read(w.last_active, self.crfHalfLife()) - 1) / cadence_mult_divisor);
            cadence = mult * @max(min_ttl, e.intervalBudget());
        };
        const occ = w.occupancy.slow.read(w.last_active, self.budgetOccHalfLife());
        const occ_budget = min_ttl + (max_ttl - min_ttl) * @log2((occ + idle_budget_bias) / idle_budget_bias) / idle_budget_log_span;
        return @intFromFloat(std.math.clamp(@max(cadence, occ_budget), min_ttl, max_ttl));
    }
    fn isExpired(self: *Conductor, w: *worker.Worker, key: []const u8, now: i64) bool {
        const age = self.cullableAge(w, now) orelse return false;
        return age >= self.idleBudget(w, key);
    }

    // value = activity / size_MiB, lowest evicted first. An unmeasured footprint
    // (size 0) ranks by activity alone, spared rather than evicted on a made-up size.
    fn workerValue(self: *Conductor, w: *worker.Worker, key: []const u8, now: i64, size_bytes: u64) f64 {
        const activity_val = self.workerActivity(w, key, now);
        if (size_bytes == 0) return activity_val;
        return activity_val / (@as(f64, @floatFromInt(size_bytes)) / (1 << 20));
    }

    fn lessByValue(_: void, a: Candidate, b: Candidate) bool {
        return a.value < b.value;
    }

    pub fn sweepPendingKills(self: *Conductor) void {
        const now = self.currentTime();
        var i: usize = 0;
        while (i < self.pending_kills.items.len) {
            var pk = &self.pending_kills.items[i];
            if (pk.w.exited()) {
                self.cleanupWorker(pk.w);
                _ = self.pending_kills.swapRemove(i);
                continue;
            }
            if (now >= pk.deadline) switch (pk.stage) {
                .soft => {
                    pk.w.signal(platform.SIG.TERM);
                    pk.stage = .term;
                    pk.deadline = now + retire_grace_s;
                },
                .term => {
                    pk.w.signal(platform.SIG.KILL);
                    self.cleanupWorker(pk.w);
                    _ = self.pending_kills.swapRemove(i);
                    continue;
                },
            };
            i += 1;
        }
    }

    fn removeActiveClientsForWorker(self: *Conductor, w: *worker.Worker) void {
        // Repeat: the fixed buffer may not hold every match in one pass.
        var to_remove: [64]u32 = undefined;
        while (true) {
            var remove_count: usize = 0;
            var it = self.active_clients.iterator();
            while (it.next()) |entry| {
                if (entry.value_ptr.worker == w) {
                    self.releasePortSet(entry.value_ptr.port_set);
                    to_remove[remove_count] = entry.key_ptr.*;
                    remove_count += 1;
                    if (remove_count >= to_remove.len) break;
                }
            }
            for (to_remove[0..remove_count]) |id| {
                _ = self.active_clients.remove(id);
            }
            if (remove_count < to_remove.len) break;
        }
    }

    fn resolveThreads(request: *const ClientRequest) args.Threads {
        const sw = request.parsed.threadSwitch();
        if (!std.meta.eql(sw, args.threads_none)) return sw;
        for (request.env) |e| {
            if (std.mem.eql(u8, e.key, "JULIA_NUM_THREADS")) return args.parseThreads(e.value);
        }
        return args.threads_none;
    }

    fn getWorkerList(self: *Conductor, key: []const u8) !*WorkerList {
        if (!self.workers.contains(key)) {
            const key_copy = try self.allocator.dupe(u8, key);
            errdefer self.allocator.free(key_copy);
            try self.workers.put(key_copy, .empty);
        }
        return self.workers.getPtr(key).?;
    }

    fn findWorkerByPid(self: *Conductor, pid: u32) ?*worker.Worker {
        var it = self.workers.iterator();
        while (it.next()) |entry| {
            for (entry.value_ptr.items) |w| {
                if (platform.getChildPid(w.process) == pid) return w;
            }
        }
        if (self.reserve) |r| {
            if (platform.getChildPid(r.process) == pid) return r;
        }
        return null;
    }

    // --- Session labels ---

    fn isLabelExpired(self: *Conductor, w: *worker.Worker, now: i64) bool {
        if (w.session_label == null or w.active_clients > 0) return false;
        const idle_time: u64 = @intCast(@max(0, now - w.last_active));
        return idle_time >= self.cfg.label_ttl;
    }

    fn clearLabel(self: *Conductor, w: *worker.Worker) void {
        if (w.session_label) |label| {
            std.debug.print("Worker {d}: clearing label '{s}'\n", .{ w.id, label });
            w.dropSession(label); // tear down the now-orphaned session REPL before reuse
            self.allocator.free(label);
            w.session_label = null;
        }
    }

    // --- Sandbox env filtering ---

    const sandbox_identity_keys = [_][]const u8{ "HOME", "USER", "LOGNAME" };
    const sandbox_identity_vars = [_]worker.EnvVar{
        .{ .key = "HOME", .value = "/home/sandbox" },
        .{ .key = "USER", .value = "sandbox" },
        .{ .key = "LOGNAME", .value = "sandbox" },
    };

    /// Free only the slice: its EnvVars point into `env` or static strings.
    fn buildSandboxClientEnv(self: *Conductor, env: []const worker.EnvVar) ![]const worker.EnvVar {
        const result = try self.allocator.alloc(worker.EnvVar, env.len + sandbox_identity_vars.len);
        errdefer self.allocator.free(result);
        var n: usize = 0;
        for (env) |e| {
            var is_identity = false;
            for (sandbox_identity_keys) |k|
                if (std.mem.eql(u8, e.key, k)) { is_identity = true; };
            if (!is_identity) { result[n] = e; n += 1; }
        }
        for (sandbox_identity_vars) |e| { result[n] = e; n += 1; }
        // Callers free the whole allocation.
        return self.allocator.realloc(result, n);
    }

    // --- Port pool ---

    fn releasePortSet(self: *Conductor, port_set: u16) void {
        if (port_set != protocol.PortPool.none) {
            if (self.port_pool) |*pool| pool.release(port_set);
        }
    }

    // --- Client tracking ---

    fn registerClient(self: *Conductor, id: u32, pid: u32, w: *worker.Worker, port_set: u16) !void {
        const now_us = @divTrunc(self.nowNs(), 1000);
        const now_s = @divTrunc(now_us, 1_000_000);
        if (!w.occupancy.fast.busy) w.occupancy.attach(now_s, self.activityHalfLife(), self.budgetOccHalfLife());
        try self.active_clients.put(id, .{ .worker = w, .pid = pid, .start_time_us = now_us, .port_set = port_set });
    }

    fn clientDone(self: *Conductor, id: u32) ?*worker.Worker {
        if (self.active_clients.fetchRemove(id)) |entry| {
            const info = entry.value;
            self.releasePortSet(info.port_set);
            if (info.worker.active_clients > 0) {
                info.worker.active_clients -= 1;
            } else {
                std.debug.print("Worker {d}: clientDone underflow (map/count drift)\n", .{info.worker.id});
            }
            const now_ns = self.nowNs();
            const now_us = @divTrunc(now_ns, 1000);
            const now_s = @divTrunc(now_us, 1_000_000);
            info.worker.last_active = now_s;
            if (info.worker.active_clients == 0) {
                info.worker.occupancy.detach(now_s, self.activityHalfLife(), self.budgetOccHalfLife());
                refreshOne(info.worker, now_ns, null);
            }
            const duration_us = now_us - info.start_time_us;
            const duration_s: u64 = @intCast(@divTrunc(duration_us, 1_000_000));
            const duration_ms: u64 = @intCast(@divTrunc(@mod(duration_us, 1_000_000), 1_000));
            std.debug.print("Client {d} disconnected; worker: {d}, duration: {d}.{d:0>3}s\n", .{
                entry.key,
                info.worker.id,
                duration_s,
                duration_ms,
            });
            if (info.worker.active_clients == 0) return info.worker;
        }
        return null;
    }

    pub fn syncWorkerClients(self: *Conductor, w: *worker.Worker) void {
        // The worker kills every client not listed, so a partial list is never sent.
        var ids: [max_tracked_clients]u32 = undefined;
        var count: usize = 0;
        var it = self.active_clients.iterator();
        while (it.next()) |entry| if (entry.value_ptr.worker == w) {
            if (count == ids.len) {
                std.debug.print("Worker {d}: over {d} clients, skipping sync\n", .{ w.id, ids.len });
                return;
            }
            ids[count] = entry.key_ptr.*;
            count += 1;
        };
        w.syncClients(ids[0..count]) catch |err| {
            std.debug.print("Worker {d}: sync_clients failed: {}\n", .{ w.id, err });
            self.retireWorker(w);
            return;
        };
        self.reconcileClientMap(w);
        // Count from our map, not the worker's report: a task stuck on a dead socket
        // over-counts, leaking a phantom client no later sync clears.
        const remaining = self.countMapClients(w);
        w.active_clients = remaining;
        const now = self.currentTime();
        if (remaining == 0 and w.occupancy.fast.busy) {
            w.occupancy.detach(now, self.activityHalfLife(), self.budgetOccHalfLife());
        } else if (remaining > 0 and !w.occupancy.fast.busy) {
            w.occupancy.attach(now, self.activityHalfLife(), self.budgetOccHalfLife());
        }
        std.debug.print("Worker {d}: sync complete, {d} active clients\n", .{ w.id, remaining });
    }

    fn countMapClients(self: *Conductor, w: *worker.Worker) u32 {
        var count: u32 = 0;
        var it = self.active_clients.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.worker == w) count += 1;
        }
        return count;
    }

    // Repairs a lost client_done, which the count-only sync can't.
    fn reconcileClientMap(self: *Conductor, w: *worker.Worker) void {
        var live_buf: [max_tracked_clients]u32 = undefined;
        const live = w.queryClients(&live_buf) catch |err| {
            std.debug.print("Worker {d}: queryClients failed: {}\n", .{ w.id, err });
            return;
        };
        var stale: [max_tracked_clients]u32 = undefined;
        var n: usize = 0;
        var it = self.active_clients.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.worker != w) continue;
            if (std.mem.indexOfScalar(u32, live, entry.key_ptr.*) != null) continue;
            if (n < stale.len) {
                stale[n] = entry.key_ptr.*;
                n += 1;
            }
        }
        for (stale[0..n]) |id| {
            if (self.active_clients.fetchRemove(id)) |e| self.releasePortSet(e.value.port_set);
        }
    }

    // --- Shutdown ---

    pub fn gracefulShutdown(self: *Conductor) void {
        self.abandonSpawns();
        var it = self.workers.iterator();
        while (it.next()) |entry| {
            for (entry.value_ptr.items) |w| w.softExit();
        }
        if (self.reserve) |r| r.softExit();
        if (self.waitForWorkers(1000)) return;
        std.debug.print("Timeout waiting for soft exit, sending SIGTERM\n", .{});
        self.signalAllWorkers(platform.SIG.TERM);
        if (self.waitForWorkers(1000)) return;
        std.debug.print("Timeout waiting for SIGTERM, sending SIGKILL\n", .{});
        self.signalAllWorkers(platform.SIG.KILL);
    }

    fn waitForWorkers(self: *Conductor, timeout_ms: u32) bool {
        var elapsed: u32 = 0;
        while (elapsed < timeout_ms) : (elapsed += 100) {
            Io.sleep(self.io, Io.Duration.fromMilliseconds(100), .awake) catch {};
            if (!self.anyWorkerAlive()) return true;
        }
        return false;
    }

    fn signalAllWorkers(self: *Conductor, sig: platform.SIG) void {
        var it = self.workers.iterator();
        while (it.next()) |entry| {
            for (entry.value_ptr.items) |w| w.signal(sig);
        }
        if (self.reserve) |r| r.signal(sig);
        // Workers mid-retirement are no longer in the pool but still dying.
        for (self.pending_kills.items) |pk| pk.w.signal(sig);
    }

    fn anyWorkerAlive(self: *Conductor) bool {
        var it = self.workers.iterator();
        while (it.next()) |entry| {
            for (entry.value_ptr.items) |w| if (!w.exited()) return true;
        }
        for (self.pending_kills.items) |pk| if (!pk.w.exited()) return true;
        if (self.reserve) |r| return !r.exited();
        return false;
    }

    // --- Health checks ---
    // Policy only: each event loop supplies `queuePing`, arming a pong read
    // and a timeout, and reports back through the handlers below.

    pub fn pressureIntervalS(self: *const Conductor) u64 {
        return @min(@as(u64, 5), self.cfg.ping_interval);
    }

    pub fn onPingTimer(self: *Conductor) void {
        if (!self.pressure_monitor.active()) self.sweepPendingKills();
        self.enforceMaxTtl();
        const now = self.currentTime();
        var it = self.workers.iterator();
        while (it.next()) |entry| for (entry.value_ptr.items) |w| self.pingIfDue(w, now);
        if (self.reserve) |r| self.pingIfDue(r, now);
    }

    pub fn onPressureTimer(self: *Conductor) void {
        self.sweepPendingKills();
        self.runEvictionEpisode();
    }

    /// Scheduled after a client leaves, so an idle worker is checked promptly.
    pub fn onHealthCheck(self: *Conductor, w: *worker.Worker) void {
        const now = self.currentTime();
        self.refreshIdleMemIfStale(w, now);
        if (w.active_clients == 0 and !w.ping_pending and now - w.last_pinged >= 2)
            self.event_loop.queuePing(w, self.cfg.ping_timeout * 1000);
    }

    /// `read`: pong bytes the loop already read into `w.pong_buf` (0 at EOF or
    /// error), or null for a readiness loop, whose socket is read here.
    pub fn onPong(self: *Conductor, w: *worker.Worker, read: ?usize) void {
        // A timeout in the same batch may have settled this ping already.
        if (!w.ping_pending) return;
        w.ping_pending = false;
        const n = read orelse platform.socketRead(w.socket, &w.pong_buf);
        if (n == 0) {
            std.debug.print("Worker {d}: connection closed\n", .{w.id});
            return self.retireWorker(w);
        }
        if (n < w.pong_buf.len) readExact(w.socket, w.pong_buf[n..]) catch {
            std.debug.print("Worker {d}: pong short read\n", .{w.id});
            return self.retireWorker(w);
        };
        self.processPong(w, &w.pong_buf);
    }

    pub fn onPongTimeout(self: *Conductor, w: *worker.Worker) void {
        if (!w.ping_pending) return;
        w.ping_pending = false;
        if (w.active_clients > 0) {
            w.last_pinged = self.currentTime(); // hold the slow cadence
            std.debug.print("Worker {d}: ping slow while busy (ignored)\n", .{w.id});
            return;
        }
        std.debug.print("Worker {d}: ping timed out\n", .{w.id});
        self.retireWorker(w);
    }

    fn pingIfDue(self: *Conductor, w: *worker.Worker, now: i64) void {
        self.refreshIdleMemIfStale(w, now);
        if (w.shouldPing(now, self.cfg.ping_interval)) self.event_loop.queuePing(w, self.cfg.ping_timeout * 1000);
    }

    fn processPong(self: *Conductor, w: *worker.Worker, pong_buf: *const [5]u8) void {
        w.last_pinged = self.currentTime();
        const worker_count = std.mem.readInt(u16, pong_buf[3..5], .little);
        if (worker_count != w.active_clients) {
            std.debug.print("Worker {d}: client count mismatch (worker={d}, conductor={d}), syncing\n", .{
                w.id, worker_count, w.active_clients,
            });
            self.syncWorkerClients(w);
        }
    }

    // --- Utilities ---

    pub fn currentTime(self: *Conductor) i64 {
        return platform.timeSeconds(self.io);
    }

    fn nowNs(self: *Conductor) i64 {
        return @intCast(Io.Clock.now(.awake, self.io).nanoseconds);
    }

    pub fn createServer(self: *Conductor) !protocol.Listener {
        return protocol.listenAddress(self.io, self.cfg.transport, self.cfg.socket_path);
    }

    fn writePidFile(self: *Conductor) void {
        var buf: [16]u8 = undefined;
        const pid_str = std.fmt.bufPrint(&buf, "{d}", .{platform.getpid()}) catch unreachable;
        var file = Io.Dir.createFileAbsolute(self.io, g_pid_path, .{}) catch |err| {
            std.debug.print("Warning: failed to create PID file: {}\n", .{err});
            return;
        };
        defer file.close(self.io);
        file.writePositionalAll(self.io, pid_str, 0) catch |err| {
            std.debug.print("Warning: failed to write PID file: {}\n", .{err});
        };
    }

    const Stream = enum(usize) { stdin, stdout, stderr, signals };
    const reply_accept_timeout_ms = 5000;
    const request_timeout_s = 10; // a client sends its whole request at once

    const ClientStreams = struct {
        c: *Conductor,
        listeners: [4]protocol.Listener,
        conns: [4]posix.socket_t,
        port_set_idx: u16,

        fn fd(self: *const ClientStreams, s: Stream) posix.socket_t {
            return self.conns[@intFromEnum(s)];
        }

        fn finish(self: *const ClientStreams, content: []const u8, exit_code: u8) void {
            platform.write(self.fd(.stdout), content);
            self.closeForExit(exit_code);
        }

        fn closeForExit(self: *const ClientStreams, exit_code: u8) void {
            platform.shutdownWrite(self.fd(.stdout));
            platform.shutdownWrite(self.fd(.stderr));
            platform.write(self.fd(.signals), &[_]u8{ protocol.signals.exit, 0x01, exit_code });
            platform.shutdownWrite(self.fd(.signals));
        }

        fn deinit(self: *ClientStreams) void {
            for (self.conns) |conn| platform.close(conn);
            for (&self.listeners) |*l| l.close(self.c.io);
            self.c.releasePortSet(self.port_set_idx);
        }
    };

    // On failure everything partial is released first.
    fn openClientStreams(self: *Conductor, client_socket: posix.socket_t) !ClientStreams {
        const mode = self.cfg.transport;
        const bind = self.cfg.bind_address;
        var port_set_idx: u16 = protocol.PortPool.none;
        var ports: ?[4]u16 = null;
        if (self.port_pool) |*pool| {
            if (pool.allocate()) |idx| {
                port_set_idx = idx;
                ports = pool.portsForIndex(idx);
            }
        }
        errdefer self.releasePortSet(port_set_idx);
        const suffixes = [_][]const u8{ "stdin.sock", "stdout.sock", "stderr.sock", "signals.sock" };
        var listeners: [4]protocol.Listener = undefined;
        var created: usize = 0;
        errdefer for (listeners[0..created]) |*l| l.close(self.io);
        for (0..4) |i| {
            listeners[i] = if (ports) |p|
                try protocol.listenTcp(self.io, bind, p[i])
            else
                try protocol.createListener(self.io, mode, self.cfg.socket_dir, suffixes[i], bind);
            created += 1;
        }
        self.sendSocketPaths(client_socket, .{
            .stdin = listeners[0].addr(), .stdout = listeners[1].addr(),
            .stderr = listeners[2].addr(), .signals = listeners[3].addr(),
        });
        var conns: [4]posix.socket_t = undefined;
        var accepted: usize = 0;
        errdefer for (conns[0..accepted]) |c| platform.close(c);
        for (0..4) |i| {
            // A client that gave up waiting must not wedge us in a bare accept.
            conns[i] = (try listeners[i].acceptTimeout(self.io, reply_accept_timeout_ms)) orelse return error.ClientGone;
            accepted += 1;
        }
        return .{ .c = self, .listeners = listeners, .conns = conns, .port_set_idx = port_set_idx };
    }

    fn serveString(self: *Conductor, client_socket: posix.socket_t, content: []const u8, exit_code: u8) !void {
        var streams = try self.openClientStreams(client_socket);
        defer streams.deinit();
        streams.finish(content, exit_code);
    }

    fn isLiveStatus(format: ?[]const u8) bool {
        return format != null and std.mem.eql(u8, format.?, "live");
    }

    // A TTY client is colour-probed first; a non-answering terminal gets the flat report.
    fn serveStatus(self: *Conductor, client_socket: posix.socket_t, format: ?[]const u8, tty: bool) !void {
        var streams = try self.openClientStreams(client_socket);
        var held = false;
        defer if (!held) streams.deinit();
        const live = tty and isLiveStatus(format);
        const palette: ?pal.Palette = if (tty and (format == null or live)) probePalette(&streams) else null;
        // A styled TTY one-shot waits a beat so its CPU meter resolves.
        if (tty and format == null) {
            try self.subscribeOneshot(streams, palette);
            held = true;
            return;
        }
        const report = self.renderStatus(format, tty, palette) catch |err| {
            std.debug.print("Status: render failed: {}\n", .{err});
            streams.finish("Failed to generate status report.\n", 1);
            return;
        };
        defer self.allocator.free(report.bytes);
        platform.write(streams.fd(.stdout), report.bytes);
        if (live) {
            try self.subscribeLive(streams, palette, report.lines);
            held = true; // ownership moved into live_clients
        } else {
            streams.closeForExit(0);
        }
    }

    fn renderStatus(self: *Conductor, format: ?[]const u8, tty: bool, palette: ?pal.Palette) !status.Report {
        return status.render(self, .{
            .format = format,
            .tty = tty,
            .palette = if (palette) |*p| p else null,
        });
    }

    // --- Live repaint scheduling ---
    //
    // A change with no timer armed repaints at once; a burst only sets `dirty`.
    // Each fire re-arms fast if dirty, else at the heartbeat, until no clients remain.
    const live_debounce_ms = 100;
    const live_heartbeat_ms = 1000;
    const live_cursor_hide = "\x1b[?25l";
    const live_cursor_show = "\x1b[?25h";
    // ~1.4s tracks the 1s heartbeat.
    const live_cpu_half_life: f64 = 1.4;
    const palette_probe_timeout_s = 2;

    // serveStatus sent the first frame, so `dirty` stays false.
    fn subscribeLive(self: *Conductor, streams: ClientStreams, palette: ?pal.Palette, lines: usize) !void {
        try self.live_clients.append(self.allocator, .{
            .streams = streams,
            .palette = palette,
            .id = self.client_counter,
            .lines_last_printed = lines,
            .oneshot = false,
        });
        // Cooked (the probe left it raw) so ^C/^D become SIGINT/EOF and tear down.
        platform.write(streams.fd(.signals), &[_]u8{ protocol.signals.raw_mode, 0x01, 0x00 });
        platform.write(streams.fd(.stdout), live_cursor_hide);
        if (!self.live_armed) {
            self.event_loop.armLiveTimer(live_heartbeat_ms);
            self.live_armed = true;
        }
    }

    // fireLive's refreshStats takes the second reading, so util is the busy-cores
    // rate over the beat. The cursor is left alone: the frame is a static report.
    fn subscribeOneshot(self: *Conductor, streams: ClientStreams, palette: ?pal.Palette) !void {
        self.refreshStats(null); // first reading; the deferred fire takes the second
        try self.live_clients.append(self.allocator, .{
            .streams = streams,
            .palette = palette,
            .id = self.client_counter,
            .lines_last_printed = 0,
            .oneshot = true,
        });
        self.event_loop.armLiveTimer(live_debounce_ms);
        self.live_armed = true;
    }

    pub fn noteLiveChange(self: *Conductor) void {
        if (self.live_clients.items.len == 0) return;
        self.dirty = true;
        if (!self.live_armed) self.fireLive();
    }

    pub fn onLiveTimer(self: *Conductor) void {
        self.live_armed = false;
        self.fireLive();
    }

    // A one-shot disconnects itself after its frame, so an all-one-shot fire stops the timer.
    fn fireLive(self: *Conductor) void {
        if (self.live_clients.items.len == 0) return;
        const had_change = self.dirty;
        self.dirty = false;
        // Pure one-shots set util to the raw rate; any live watcher uses the EWMA.
        const all_oneshot = for (self.live_clients.items) |lc| {
            if (!lc.oneshot) break false;
        } else true;
        self.refreshStats(if (all_oneshot) null else live_cpu_half_life);
        var i: usize = 0;
        while (i < self.live_clients.items.len) {
            if (self.repaintOne(&self.live_clients.items[i])) i += 1 else _ = self.live_clients.swapRemove(i);
        }
        if (self.live_clients.items.len == 0) return;
        self.event_loop.armLiveTimer(if (had_change) live_debounce_ms else live_heartbeat_ms);
        self.live_armed = true;
    }

    // Returns whether the client stays subscribed.
    fn repaintOne(self: *Conductor, lc: *LiveClient) bool {
        const report = self.renderStatus("live", true, lc.palette) catch return !lc.oneshot;
        defer self.allocator.free(report.bytes);
        const fd = lc.streams.fd(.stdout);
        // DEC 2026 synchronized update, so no tearing; ESC[<n>F returns to the frame's
        // top and ESC[0J clears any tail.
        var hdr: [32]u8 = undefined;
        const prefix = if (lc.lines_last_printed > 0)
            std.fmt.bufPrint(&hdr, "\x1b[?2026h\x1b[{d}F\x1b[0J", .{lc.lines_last_printed}) catch unreachable
        else
            "\x1b[?2026h";
        platform.write(fd, prefix);
        platform.write(fd, report.bytes);
        platform.write(fd, "\x1b[?2026l");
        lc.lines_last_printed = report.lines;
        if (!lc.oneshot) return true;
        lc.streams.closeForExit(0);
        lc.streams.deinit();
        return false;
    }

    fn dropLiveClient(self: *Conductor, id: u32) bool {
        for (self.live_clients.items, 0..) |*lc, i| {
            if (lc.id != id) continue;
            var removed = self.live_clients.swapRemove(i);
            // So the shell prompt lands under the frozen snapshot.
            platform.write(removed.streams.fd(.stdout), "\r\n" ++ live_cursor_show);
            removed.streams.deinit();
            return true;
        }
        return false;
    }

    // Read raw until the CSI 5n sentinel or a byte cap; the client's exit restores
    // cooked mode.
    fn probePalette(streams: *ClientStreams) ?pal.Palette {
        const stdin = streams.fd(.stdin);
        const signals = streams.fd(.signals);
        platform.write(signals, &[_]u8{ protocol.signals.raw_mode, 0x01, 0x01 });
        platform.write(streams.fd(.stdout), pal.queries);
        // This read blocks the event loop.
        platform.setRecvTimeout(stdin, palette_probe_timeout_s);
        defer platform.setRecvTimeout(stdin, 0);
        var buf: [4096]u8 = undefined;
        var len: usize = 0;
        while (len < buf.len) {
            const n = platform.socketRead(stdin, buf[len..]);
            if (n == 0) break;
            len += n;
            if (std.mem.indexOf(u8, buf[0..len], pal.sentinel) != null) break;
        }
        var palette: pal.Palette = .{};
        pal.parse(buf[0..len], &palette);
        return if (palette.isPopulated()) palette else null;
    }

    fn sendSocketPaths(self: *Conductor, socket: posix.socket_t, paths: worker.Worker.SocketPaths) void {
        var buf: [1024]u8 = undefined;
        var w = protocol.BufWriter{ .buf = &buf };
        w.writeInt(u8, protocol.client.socket_paths);
        w.writeInt(u32, self.client_counter);
        // TCP: the client pairs the port with the conductor's host.
        const all = [_][]const u8{ paths.stdin, paths.stdout, paths.stderr, paths.signals };
        for (all) |path| {
            if (self.cfg.transport == .tcp) {
                const colon = std.mem.lastIndexOfScalar(u8, path, ':') orelse path.len;
                w.writeLenPrefixed(u16, path[colon..]);
            } else {
                w.writeLenPrefixed(u16, path);
            }
        }
        platform.write(socket, w.written());
    }
};

// --- Entry point ---

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const allocator = init.gpa;
    const cfg = try config.Config.load(allocator, init.environ_map);
    var conductor = try Conductor.init(io, allocator, cfg, init.environ_map);
    defer conductor.deinit();
    std.debug.print("Starting Julia Daemon Conductor. Configuration:\n", .{});
    std.debug.print(" - Worker executable: {s}\n", .{cfg.worker_executable});
    std.debug.print(" - Worker args: {s}\n", .{cfg.worker_args});
    std.debug.print(" - Max clients per worker: {d}\n", .{cfg.worker_maxclients});
    std.debug.print(" - Idle TTL: {d}s (min {d}s), orphan failsafe {d}s\n", .{ cfg.max_ttl, cfg.min_ttl, cfg.max_ttl * 4 });
    conductor.pressure_monitor.logResolution(&conductor.cfg);
    std.debug.print(" - Transport: {s}\n", .{@tagName(cfg.transport)});
    std.debug.print(" - Address: {s}\n", .{cfg.socket_path});
    if (cfg.port_range) |r| {
        std.debug.print(" - Port range: {d}-{d} ({d} port sets, {d} ports used)\n", .{ r.base, r.base + r.count * 4 - 1, r.count, @as(u32, r.count) * 4 });
    }
    if (cfg.sandbox_max_memory) |m|
        std.debug.print(" - Sandbox memory limit: {s}\n", .{m});
    if (cfg.sandbox_max_cpu) |c|
        std.debug.print(" - Sandbox CPU limit: {d}%\n", .{c});
    if (builtin.os.tag == .linux and (cfg.sandbox_max_memory != null or cfg.sandbox_max_cpu != null)) {
        worker.sandbox.delegateCgroups(cfg.sandbox_max_memory, cfg.sandbox_max_cpu) catch |err| {
            std.debug.print("Sandbox limits need a cgroup delegated to the conductor (systemd Delegate=yes); " ++
                "unset JULIA_DAEMON_SANDBOX_MAX_MEMORY and _MAX_CPU to run without them.\n", .{});
            return err;
        };
    }
    if (!cfg.sandbox_remote_clients)
        std.debug.print(" - Sandbox remote clients: disabled\n", .{});
    if (cfg.sandbox_session_bypass)
        std.debug.print(" - Sandbox session bypass: enabled\n", .{});
    // Needed even in TCP mode: the worker setup socket is always local.
    try Io.Dir.cwd().createDirPath(io, cfg.runtime_dir);
    conductor.cleanupRuntimeDir();
    try conductor.run();
}
