// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0
//
// The conductor's state, the events its loop delivers, and its entry point.
// The rest is by concern: requests.zig reads and routes a client's request,
// assign.zig finds it a worker, spawns.zig starts one, tracking.zig keeps
// count of the clients each runs, retire.zig and eviction.zig end them, and
// replies.zig answers a client itself.

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const Io = std.Io;
const Allocator = std.mem.Allocator;

const platform = @import("platform/main.zig");
const protocol = @import("protocol.zig");
const config = @import("config.zig");
const args = @import("args.zig");
const env_cache = @import("env_cache.zig");
const live = @import("live.zig");
const reconfigure = @import("reconfigure.zig");
const terminal = @import("terminal.zig");
const pressure = @import("pressure.zig");
pub const worker = @import("worker.zig");

// The conductor's work, by concern; each takes the `Conductor` it acts for.
const requests = @import("requests.zig");
const assign = @import("assign.zig");
const tracking = @import("tracking.zig");
const spawns = @import("spawns.zig");
const retire = @import("retire.zig");
const eviction = @import("eviction.zig");

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
        return !protocol.isLoopback(self.address orelse return true);
    }
};

pub const eventLoopImpl = switch (builtin.target.os.tag) {
    .linux => @import("eloop/linux.zig"),
    .macos, .freebsd, .openbsd, .netbsd, .dragonfly => @import("eloop/kqueue.zig"),
    .windows => @import("eloop/windows.zig"),
    else => @compileError("unsupported OS"),
};

// --- Constants ---

/// How long a worker may take to answer as a client is ended, a forced
/// interrupt included.
pub const end_probe_ms = 1000;

// --- Global state for cleanup ---

pub var g_socket_path: [:0]const u8 = "";
pub var g_pid_path: [:0]const u8 = "";

// --- Types ---

pub const WorkerList = std.array_list.Aligned(*worker.Worker, null);

pub const ActiveClientInfo = struct {
    worker: *worker.Worker,
    pid: u32, // host-view where peer credentials exist, else self-reported; for display

    start_time_us: i64 = 0, // set when tracked
    port_set: u16, // PortPool index, or PortPool.none when unmanaged
    watcher: bool = false, // `--watch`, which is no use of the session
    internal: bool = false, // the conductor's own watcher, for a live view
    session: bool = false, // `--session`: its runs are the session's
    sync: bool = false,
};

pub const ActiveClientMap = std.AutoHashMap(u32, ActiveClientInfo);
pub const PendingSpawnList = std.array_list.Aligned(*Conductor.PendingSpawn, null);
pub const PendingConnectionList = std.array_list.Aligned(*Conductor.PendingConnection, null);

/// Owns the `Worker` until reaped.
pub const PendingKill = struct {
    w: *worker.Worker,
    stage: enum { soft, term, kill },
    deadline: i64,
};

pub const PendingKillList = std.array_list.Aligned(PendingKill, null);

/// What a retired worker's code left running, its process group sent SIGTERM
/// as the worker was reaped, and SIGKILL at `deadline`.
pub const OrphanGroup = struct { pgid: posix.pid_t, deadline: i64 };

pub const AssignReason = enum {
    session_label,
    ppid_affinity,
    recent_worker,
    new_worker,
};

pub const WorkerAssignment = struct {
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
    /// The last id given out; ids are never reused.
    client_counter: u32,
    /// The client being served.
    client_id: u32,
    pending_spawns: PendingSpawnList,
    /// Read only once readable, so a silent peer costs nothing.
    pending_connections: PendingConnectionList,
    pending_kills: PendingKillList,
    /// Sandboxes' cgroups their processes still held as they were removed.
    cgroups_left: std.ArrayList(u32) = .empty,
    orphan_groups: std.ArrayList(OrphanGroup) = .empty,
    /// LRFU, keyed like `workers`; survives every death but a max-TTL cull.
    crf: std.StringHashMap(worker.Crf),
    pressure_monitor: pressure.Monitor,
    event_loop: eventLoopImpl.EventLoop,
    live: live.Subscribers,
    settings: reconfigure.Settings,
    /// Keys clients and workers by their ids (`protocol.keyFor`).
    secret: [16]u8,
    /// Kept in the runtime dir, which no sandbox sees.
    host_key: protocol.client.HostKey,
    /// Accepts are failing for want of descriptors or memory, until one succeeds.
    accept_starved: bool = false,

    // --- Lifecycle ---

    pub fn init(io: Io, allocator: Allocator, cfg: config.Config, environ_map: *std.process.Environ.Map) !Conductor {
        var c: Conductor = .{
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
            .client_id = 0,
            .pending_kills = .empty,
            .pending_spawns = .empty,
            .pending_connections = .empty,
            .crf = std.StringHashMap(worker.Crf).init(allocator),
            .pressure_monitor = pressure.Monitor.init(&cfg),
            .event_loop = try eventLoopImpl.EventLoop.init(64),
            .live = .{},
            .settings = try reconfigure.Settings.init(allocator, io, environ_map),
            .secret = undefined,
            .host_key = undefined,
        };
        io.random(&c.secret);
        io.random(&c.host_key);
        return c;
    }

    pub fn keyFor(self: *const Conductor, kind: protocol.KeyKind, id: u32) u64 {
        return protocol.keyFor(&self.secret, kind, id);
    }

    pub fn deinit(self: *Conductor) void {
        spawns.abandonSpawns(self);
        self.pending_spawns.deinit(self.allocator);
        while (self.pending_connections.pop()) |pc| requests.discardConnection(self, pc);
        self.pending_connections.deinit(self.allocator);
        live.deinit(self);
        reconfigure.deinit(self);
        self.cache.deinit();
        self.active_clients.deinit();
        for (self.pending_kills.items) |pk| {
            pk.w.killAndReap();
            retire.cleanupWorker(self, pk.w);
        }
        self.pending_kills.deinit(self.allocator);
        retire.retryCgroups(self);
        self.cgroups_left.deinit(self.allocator);
        self.orphan_groups.deinit(self.allocator);
        var crf_it = self.crf.keyIterator();
        while (crf_it.next()) |k| self.allocator.free(k.*);
        self.crf.deinit();
        if (self.reserve) |r| retire.cleanupWorker(self, r);
        var it = self.workers.iterator();
        while (it.next()) |entry| {
            for (entry.value_ptr.items) |w| retire.cleanupWorker(self, w);
            entry.value_ptr.deinit(self.allocator);
            self.allocator.free(entry.key_ptr.*);
        }
        self.workers.deinit();
        self.event_loop.deinit(); // last: cleaning a worker up unwatches its stderr
        if (g_socket_path.len > 0) self.allocator.free(g_socket_path);
        if (g_pid_path.len > 0) self.allocator.free(g_pid_path);
        self.cfg.deinit();
    }

    // Event loops drop completions for workers retired (and maybe freed) since.
    pub fn isLiveWorker(self: *Conductor, w: *const worker.Worker) bool {
        var it = self.liveWorkers();
        while (it.next()) |item| if (item == w) return true;
        return false;
    }

    /// Every pooled worker, then the reserve.
    pub fn liveWorkers(self: *Conductor) LiveWorkers {
        return .{ .pools = self.workers.valueIterator(), .reserve = self.reserve };
    }

    const LiveWorkers = struct {
        pools: std.StringHashMap(WorkerList).ValueIterator,
        pool: []const *worker.Worker = &.{},
        reserve: ?*worker.Worker,

        pub fn next(self: *LiveWorkers) ?*worker.Worker {
            while (self.pool.len == 0) {
                const list = self.pools.next() orelse {
                    defer self.reserve = null;
                    return self.reserve;
                };
                self.pool = list.items;
            }
            defer self.pool = self.pool[1..];
            return self.pool[0];
        }
    };

    pub fn run(self: *Conductor) !void {
        g_socket_path = try self.allocator.dupeSentinel(u8, self.cfg.socket_path, 0);
        try eventLoopImpl.installSignalHandlers();
        defer eventLoopImpl.cleanupSignalHandlers();
        // Over TCP too, for `refuseIfRunning`: only a local client signals it.
        g_pid_path = try self.allocator.printSentinel("{s}/conductor.pid", .{self.cfg.runtime_dir}, 0);
        const pid_file = self.writePidFile();
        defer if (pid_file) |file| {
            file.close(self.io);
            Io.Dir.deleteFileAbsolute(self.io, g_pid_path) catch {};
        };
        if (self.cfg.transport == .tcp) try self.writeHostKey();
        var listener = try self.createServer();
        defer if (listener.fd() != platform.no_socket) listener.close(self.io); // a failed recreate closed it
        const port_file = self.writePortFile(&listener) catch |err| blk: {
            std.debug.print("Warning: failed to write the port file: {}\n", .{err});
            break :blk null;
        };
        defer if (port_file) |file| file.close(self.io);
        std.debug.print("Conductor listening on {s}\n", .{self.cfg.socket_path});
        if (self.cfg.reserve_worker) spawns.beginReserveSpawn(self) catch |err| {
            std.debug.print("Failed to start a reserve worker: {}\n", .{err});
        };
        eventLoopImpl.run(self, &listener);
    }

    /// Removes what a conductor before this one left, and only that: the
    /// runtime directory is a setting, and may hold anything else.
    fn cleanupRuntimeDir(self: *Conductor) void {
        var dir = Io.Dir.openDirAbsolute(self.io, self.cfg.runtime_dir, .{ .iterate = true }) catch |err| {
            std.debug.print("Warning: cannot open runtime dir for cleanup: {}\n", .{err});
            return;
        };
        defer dir.close(self.io);
        var iter = dir.iterate();
        while (iter.next(self.io) catch null) |entry| {
            if (entry.kind == .directory) {
                const id = std.mem.cutPrefix(u8, entry.name, "sandbox-") orelse continue;
                _ = std.fmt.parseInt(u32, id, 10) catch continue;
                dir.deleteTree(self.io, entry.name) catch {};
            } else if (std.mem.endsWith(u8, entry.name, ".sock") or std.mem.eql(u8, entry.name, "conductor.pid") or
                std.mem.eql(u8, entry.name, protocol.client.host_key_file) or std.mem.startsWith(u8, entry.name, protocol.client.port_file))
            {
                dir.deleteFile(self.io, entry.name) catch {};
            }
        }
    }

    // --- Connection handling ---

    /// `held`: the socket stays open for a client waiting on a starting worker.
    pub const Outcome = enum { done, held };

    /// Read as it arrives, however slowly, all within `request_timeout_s`.
    pub const PendingConnection = struct {
        socket: posix.socket_t,
        peer: PeerInfo,
        deadline: i64,
        received: std.ArrayList(u8) = .empty,
        /// Where the client's environment begins, once it was asked for.
        env_at: ?usize = null,
        /// The strings of a list checked so far, so each chunk walks only what is new.
        walk: ?struct { list_at: usize, at: usize, left: usize } = null,

        /// Where the list at `list_at` ends, once all of it has arrived: a
        /// count of entries, each `strings_per_entry` length-prefixed strings.
        pub fn listEnd(pc: *PendingConnection, list_at: usize, comptime strings_per_entry: usize) !usize {
            var r = protocol.SliceReader{ .bytes = pc.received.items, .pos = list_at };
            if (pc.walk == null or pc.walk.?.list_at != list_at) {
                const count = try r.int(u32);
                if (count > (max_message_bytes - r.pos) / (4 * strings_per_entry)) return error.MessageTooLarge;
                pc.walk = .{ .list_at = list_at, .at = r.pos, .left = count * strings_per_entry };
            }
            const walk = &pc.walk.?;
            r.pos = walk.at;
            while (walk.left > 0) : (walk.left -= 1) {
                _ = try r.lenPrefixed(u32);
                walk.at = r.pos;
            }
            return walk.at;
        }
    };

    /// Whatever a peer may send: a request with its arguments and
    /// environment, or a notification with a profile report.
    pub const max_message_bytes = 64 << 20;

    // Event tags: a pending record's pointer, its low bits naming what turned readable.
    pub const tag_spawn_listener: usize = 2;
    pub const tag_spawn_client: usize = 3;
    const tag_connection: usize = 4;
    pub const tag_worker_stderr: usize = 6;
    pub const tag_spawn_stderr: usize = 7;

    /// Read once readable, or dropped after `request_timeout_s`.
    pub fn admitConnection(self: *Conductor, socket: posix.socket_t, peer: *const PeerInfo) void {
        if (self.accept_starved) std.debug.print("Accepting connections again\n", .{});
        self.accept_starved = false;
        if (self.cfg.transport == .tcp) platform.setTcpNodelay(socket);
        const pc = self.allocator.create(PendingConnection) catch return platform.close(socket);
        pc.* = .{ .socket = socket, .peer = peer.*, .deadline = self.currentTime() + request_timeout_s };
        self.pending_connections.append(self.allocator, pc) catch {
            self.allocator.destroy(pc);
            return platform.close(socket);
        };
        self.event_loop.watchFd(@intFromPtr(pc) | tag_connection, socket);
        self.event_loop.armTick();
    }

    /// Logs the first failure of a run, and arms the tick on which the loop
    /// resumes accepting.
    pub fn onAcceptStarved(self: *Conductor, err: anytype) void {
        if (!self.accept_starved) std.debug.print("Accept error: {t}; retrying each second until one succeeds\n", .{err});
        self.accept_starved = true;
        self.event_loop.armTick();
    }

    /// A tag whose record is no longer pending is stale.
    pub fn onReadable(self: *Conductor, tag: usize) void {
        const addr = tag & ~@as(usize, 7);
        switch (tag & 7) {
            // Each view takes only its own, found by address.
            terminal.tag => {
                live.onReadable(self, @ptrFromInt(addr));
                reconfigure.onReadable(self, @ptrFromInt(addr));
            },
            tag_connection => {
                const pc: *PendingConnection = @ptrFromInt(addr);
                if (!isPending(&self.pending_connections, pc)) return;
                const outcome = requests.receive(self, pc) catch |err| blk: {
                    std.debug.print("Connection dropped: {}\n", .{err});
                    break :blk .done;
                } orelse return self.event_loop.watchFd(tag, pc.socket);
                _ = removePending(&self.pending_connections, pc);
                if (outcome == .held) pc.socket = platform.no_socket;
                requests.discardConnection(self, pc);
            },
            tag_worker_stderr => {
                const w: *worker.Worker = @ptrFromInt(addr);
                if (!self.holdsWorker(w)) return;
                if (self.drainStderr(w, true)) self.event_loop.watchFd(tag, w.stderrFd().?);
                if (w.stderr_scan.take(self.allocator)) |stacks| live.onStacks(self, w, stacks);
            },
            tag_spawn_stderr => {
                const p: *PendingSpawn = @ptrFromInt(addr);
                if (!isPending(&self.pending_spawns, p)) return;
                const w = &p.spawn.worker;
                if (self.drainStderr(w, false)) self.event_loop.watchFd(tag, w.stderrFd().?);
            },
            tag_spawn_listener => {
                const p: *PendingSpawn = @ptrFromInt(addr);
                if (isPending(&self.pending_spawns, p)) spawns.onSpawnReadable(self, p);
            },
            tag_spawn_client => spawns.onHeldClientGone(self, @ptrFromInt(addr)),
            else => {},
        }
    }

    /// Passes a worker's stderr to ours, keeping it among the worker's recent
    /// lines, and through its stack scanner when `scan`; returns whether there
    /// may be more. At its end the pipe is closed.
    pub fn drainStderr(self: *Conductor, w: *worker.Worker, scan: bool) bool {
        const file = w.process.stderr orelse return false;
        var buf: [16 << 10]u8 = undefined;
        while (true) {
            const n = platform.readAvailable(file.handle, &buf) orelse {
                file.close(self.io);
                w.process.stderr = null;
                w.log("stderr closed", .{});
                return false;
            };
            if (n == 0) return true;
            platform.writeFile(platform.getStderrHandle(), buf[0..n]);
            w.noteStderr(buf[0..n]);
            if (scan) w.stderr_scan.feed(self.allocator, buf[0..n]);
        }
    }

    // Pooled, the reserve, or being retired: its record still stands.
    fn holdsWorker(self: *Conductor, w: *const worker.Worker) bool {
        if (self.isLiveWorker(w)) return true;
        for (self.pending_kills.items) |pk| if (pk.w == w) return true;
        return false;
    }

    pub fn findWorkerById(self: *Conductor, id: u32) ?*worker.Worker {
        var it = self.liveWorkers();
        while (it.next()) |w| if (w.id == id) return w;
        return null;
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
            std.debug.print("Connection sent no whole message within {d}s; dropped\n", .{request_timeout_s});
            _ = self.pending_connections.swapRemove(i);
            self.event_loop.unwatchFd(@intFromPtr(pc) | tag_connection, pc.socket);
            requests.discardConnection(self, pc);
        }
        i = 0;
        while (i < self.pending_spawns.items.len) {
            const p = self.pending_spawns.items[i];
            if (p.spawn.check(self.io, &self.cfg)) i += 1 else |err| spawns.failSpawn(self, p, err); // failSpawn removes p
        }
        const settling = reconfigure.onTick(self);
        return self.pending_spawns.items.len > 0 or self.pending_connections.items.len > 0 or settling;
    }

    fn isPending(list: anytype, item: anytype) bool {
        for (list.items) |q| if (q == item) return true;
        return false;
    }

    pub fn removePending(list: anytype, item: anytype) bool {
        for (list.items, 0..) |q, i| if (q == item) {
            _ = list.swapRemove(i);
            return true;
        };
        return false;
    }

    pub const ClientRequest = struct {
        flags: protocol.client.Flags,
        size: protocol.TerminalSize, // zeros without a terminal
        pid: u32, // self-reported, meaningful only in the client's pid namespace
        host_pid: ?u32, // from peer credentials; null on TCP
        ppid: u32,
        cwd: []const u8,
        env: []const worker.EnvVar,
        parsed: args.ParsedArgs,
        project: ?[]const u8,
        raw_args: []const []const u8, // what `parsed` reads
        owned_env: ?[]worker.EnvVar = null, // a remote client's, kept out of the cache

        pub fn deinit(self: *ClientRequest, allocator: Allocator) void {
            if (self.owned_env) |env| worker.freeEnv(allocator, env);
            allocator.free(self.cwd);
            if (self.project) |p| allocator.free(p);
            for (self.raw_args) |arg| allocator.free(arg);
            allocator.free(self.raw_args);
        }
    };

    pub const SandboxKind = union(enum) {
        none,
        remote: ?Io.net.IpAddress, // the client's host, port zeroed; null if unknown
        local: []const u8, // the one rw bind mount: the project, or just cwd
        client: struct { socket: posix.socket_t, ns: u64 }, // the client spawns the worker inside its own sandbox
    };

    pub const HeldClient = struct {
        socket: posix.socket_t,
        request: ClientRequest, // its env is an owned copy: the cache entry may be evicted meanwhile
        worker_key: []const u8,
        sandbox: SandboxKind,
        id: u32,
        /// Hung up while its worker was starting, which others wait on.
        gone: bool = false,
    };

    /// Clients for the same pool key queue as waiters, re-selected once it is up.
    pub const PendingSpawn = struct {
        spawn: worker.Worker.Spawn,
        purpose: union(enum) { reserve, client: *HeldClient },
        waiters: std.array_list.Aligned(*HeldClient, null) = .empty,
    };

    // --- Health checks ---
    // Policy only: each event loop supplies `awaitPong`, arming a pong read
    // and a timeout, and reports back through the handlers below.

    pub fn pressureIntervalS(self: *const Conductor) u64 {
        return @min(@as(u64, 5), self.cfg.ping_interval);
    }

    pub fn onPingTimer(self: *Conductor) void {
        platform.rotateLog(10 << 20);
        if (!self.pressure_monitor.active()) retire.sweepPendingKills(self);
        eviction.enforceMaxTtl(self);
        const now = self.currentTime();
        var it = self.liveWorkers();
        while (it.next()) |w| self.pingIfDue(w, now);
    }

    pub fn onPressureTimer(self: *Conductor) void {
        retire.sweepPendingKills(self);
        eviction.runEvictionEpisode(self);
    }

    /// Scheduled after a client leaves, so an idle worker is checked promptly.
    pub fn onHealthCheck(self: *Conductor, w: *worker.Worker) void {
        const now = self.currentTime();
        eviction.refreshIdleMemIfStale(self, w, now);
        if (w.busyClients() == 0 and !w.ping_pending and now - w.last_pinged >= 2)
            self.queuePing(w);
    }

    /// The worker's socket turned readable while its ping was pending.
    pub fn onPong(self: *Conductor, w: *worker.Worker) void {
        // A timeout in the same batch may have settled this ping already.
        if (!w.ping_pending) return;
        w.ping_pending = false;
        const pong = w.readPong() catch |err| {
            w.log("no pong read: {}", .{err});
            return retire.retireWorker(self, w);
        };
        // Late for a ping whose timeout was let pass; this one's is still to come.
        if (pong.seq != w.ping_seq) return self.event_loop.awaitPong(w, self.cfg.ping_timeout * 1000);
        w.last_pinged = self.currentTime();
        w.unresponsive_interrupted = false;
        if (pong.clients != w.active_clients) {
            w.log("client count mismatch (worker={d}, conductor={d}), syncing", .{ pong.clients, w.active_clients });
            tracking.syncWorkerClients(self, w);
        }
    }

    pub fn onPongTimeout(self: *Conductor, w: *worker.Worker) void {
        if (!w.ping_pending) return;
        w.ping_pending = false;
        if (w.busyClients() > 0) {
            w.last_pinged = self.currentTime(); // hold the slow cadence
            w.log("ping slow while busy (ignored)", .{});
            return;
        }
        // An idle worker's thread 0 may still be spinning in a departed client's code.
        if (!w.unresponsive_interrupted) {
            w.log("ping timed out, interrupting", .{});
            w.unresponsive_interrupted = true;
            w.forceInterrupt();
            return self.event_loop.awaitPong(w, self.cfg.ping_timeout * 1000);
        }
        w.log("ping timed out", .{});
        retire.retireWorker(self, w);
    }

    fn pingIfDue(self: *Conductor, w: *worker.Worker, now: i64) void {
        eviction.refreshIdleMemIfStale(self, w, now);
        if (w.shouldPing(now, self.cfg.ping_interval)) self.queuePing(w);
    }

    fn queuePing(self: *Conductor, w: *worker.Worker) void {
        w.sendPing();
        self.event_loop.awaitPong(w, self.cfg.ping_timeout * 1000);
    }

    // --- Utilities ---

    pub fn currentTime(self: *Conductor) i64 {
        return platform.timeSeconds(self.io);
    }

    pub fn nowNs(self: *Conductor) i64 {
        return @intCast(Io.Clock.now(.awake, self.io).nanoseconds);
    }

    pub fn createServer(self: *Conductor) !protocol.Listener {
        return protocol.listenAddress(self.io, self.cfg.transport, self.cfg.socket_path);
    }

    fn writeHostKey(self: *Conductor) !void {
        var dir = try Io.Dir.openDirAbsolute(self.io, self.cfg.runtime_dir, .{});
        defer dir.close(self.io);
        var file = try dir.createFile(self.io, protocol.client.host_key_file, .{ .permissions = platform.private_file_permissions });
        defer file.close(self.io);
        try file.writeStreamingAll(self.io, &self.host_key);
    }

    /// Only where a client here reaches the listener at 127.0.0.1. Renamed into
    /// place, so none reads it half written, and held under a shared lock, as
    /// on Windows an exclusive one would bar reading it.
    fn writePortFile(self: *Conductor, listener: *const protocol.Listener) !?Io.File {
        const ip = switch (listener.bound() orelse return null) {
            .ip4 => |a| a,
            .ip6 => return null,
        };
        if (!std.mem.eql(u8, &ip.bytes, &.{ 127, 0, 0, 1 }) and !std.mem.allEqual(u8, &ip.bytes, 0)) return null;
        const staging = protocol.client.port_file ++ ".new";
        var dir = try Io.Dir.openDirAbsolute(self.io, self.cfg.runtime_dir, .{});
        defer dir.close(self.io);
        const file = try dir.createFile(self.io, staging, .{ .permissions = platform.private_file_permissions, .lock = .shared, .lock_nonblocking = true });
        errdefer file.close(self.io);
        var buf: [5]u8 = undefined;
        try file.writeStreamingAll(self.io, std.mem.print(&buf, "{d}", .{ip.port}) catch unreachable);
        try dir.rename(staging, dir, protocol.client.port_file, self.io);
        return file;
    }

    /// Held locked while the conductor lives, so a client signals no stale pid.
    fn writePidFile(self: *Conductor) ?Io.File {
        var buf: [16]u8 = undefined;
        const pid_str = std.mem.print(&buf, "{d}", .{platform.getpid()}) catch unreachable;
        const file = Io.Dir.createFileAbsolute(self.io, g_pid_path, .{ .lock = .exclusive, .lock_nonblocking = true }) catch |err| {
            std.debug.print("Warning: failed to create PID file: {}\n", .{err});
            return null;
        };
        file.writePositionalAll(self.io, pid_str, 0) catch |err| {
            std.debug.print("Warning: failed to write PID file: {}\n", .{err});
        };
        return file;
    }

    pub const Stream = enum(usize) { stdin, stdout, stderr, signals };
    pub const reply_accept_timeout_ms = 5000;
    const request_timeout_s = 10; // a client sends its whole request at once

    pub const ClientStreams = struct {
        c: *Conductor,
        listeners: [4]protocol.Listener,
        conns: [4]posix.socket_t,
        port_set_idx: u16,

        pub fn fd(self: *const ClientStreams, s: Stream) posix.socket_t {
            return self.conns[@intFromEnum(s)];
        }

        pub fn finish(self: *const ClientStreams, content: []const u8, exit_code: u8) void {
            platform.write(self.fd(.stdout), content);
            self.closeForExit(exit_code);
        }

        // `deinit` closes right after, which is the EOF; a half-close first would
        // wait, on Windows, on this client, itself waiting for that EOF.
        pub fn closeForExit(self: *const ClientStreams, exit_code: u8) void {
            platform.write(self.fd(.signals), &[_]u8{ protocol.signals.exit, 0x01, exit_code });
        }

        pub fn deinit(self: *ClientStreams) void {
            for (self.conns) |conn| platform.close(conn);
            for (&self.listeners) |*l| l.close(self.c.io);
            assign.releasePortSet(self.c, self.port_set_idx);
        }
    };

    pub const palette_probe_timeout_s = 2;

    pub fn noteLiveChange(self: *Conductor) void {
        live.noteChange(self);
    }

    pub fn onLiveTimer(self: *Conductor) void {
        live.onTimer(self);
    }
};

// --- Entry point ---

/// What a conductor exits with when another already runs in its runtime
/// directory (sysexits' EX_TEMPFAIL), which the systemd unit doesn't restart.
const exit_already_running = 75;

/// Exits when a conductor holds the pid file in `cfg`'s runtime directory:
/// starting would clear its sockets from under it.
fn refuseIfRunning(cfg: *const config.Config) void {
    var path_buf: [Io.Dir.max_path_bytes]u8 = undefined;
    const path = std.mem.print(&path_buf, "{s}/conductor.pid", .{cfg.runtime_dir}) catch return;
    var pid_buf: [16]u8 = undefined;
    const held = platform.readSmallFile(path, &pid_buf, true) orelse return;
    std.debug.print(
        \\Not starting: a conductor (pid {s}) is already running, holding {s}.
        \\Stop it first, or give this one a JULIA_DAEMON_RUNTIME of its own.
        \\
    , .{ std.mem.trim(u8, held, " \r\n"), path });
    std.process.exit(exit_already_running);
}

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const allocator = init.gpa;
    // The log is UTF-8, which a console shows as such only in its code page.
    const console = platform.setupConsoleIo(platform.getStderrHandle(), platform.getStderrHandle());
    defer platform.restoreConsoleIo(console);
    const cfg = try config.Config.load(allocator, init.environ_map);
    refuseIfRunning(&cfg);
    var conductor = try Conductor.init(io, allocator, cfg, init.environ_map);
    defer conductor.deinit();
    std.debug.print("Starting Julia Daemon Conductor. Configuration:\n", .{});
    std.debug.print(" - Worker executable: {s}\n", .{cfg.worker_executable});
    std.debug.print(" - Worker args: {s}\n", .{cfg.worker_args});
    std.debug.print(" - Max clients per worker: {d}\n", .{cfg.worker_maxclients});
    std.debug.print(" - Idle TTL: {d}s (min {d}s), orphan failsafe {d}s\n", .{ cfg.max_ttl, cfg.min_ttl, cfg.max_ttl * 4 });
    conductor.pressure_monitor.logResolution(&conductor.cfg);
    conductor.event_loop.logResolution();
    std.debug.print(" - Transport: {s}\n", .{@tagName(cfg.transport)});
    std.debug.print(" - Address: {s}\n", .{cfg.socket_path});
    if (cfg.port_range) |r| {
        const used = @as(u32, r.count) * 4;
        std.debug.print(" - Port range: {d}-{d} ({d} port sets, {d} ports used)\n", .{ r.base, r.base + used - 1, r.count, used });
    }
    if (cfg.sandbox_max_memory) |m|
        std.debug.print(" - Sandbox memory limit: {s}\n", .{m});
    if (cfg.sandbox_max_cpu) |c|
        std.debug.print(" - Sandbox CPU limit: {d}%\n", .{c});
    if (builtin.target.os.tag == .linux and (cfg.sandbox_max_memory != null or cfg.sandbox_max_cpu != null)) {
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
    if (!cfg.sandbox_reuse)
        std.debug.print(" - Sandbox reuse per host: disabled\n", .{});
    if (!cfg.sandbox_isolate_hosts)
        std.debug.print(" - Sandbox host isolation: disabled\n", .{});
    if (!cfg.sandbox_hide_secrets)
        std.debug.print(" - Sandbox depot secrets: visible\n", .{});
    // Needed even in TCP mode: the worker setup socket is always local.
    _ = try Io.Dir.cwd().createDirPathStatus(io, cfg.runtime_dir, platform.runtime_dir_permissions);
    try platform.secureRuntimeDir(cfg.runtime_dir);
    conductor.cleanupRuntimeDir();
    retire.cleanupCgroups(&conductor);
    try conductor.run();
}
