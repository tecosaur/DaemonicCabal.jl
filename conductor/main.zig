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
const live = @import("live.zig");
const reconfigure = @import("reconfigure.zig");
const terminal = @import("terminal.zig");
const peek = @import("peek.zig");
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

/// Grace per retirement stage; SIGTERM/SIGKILL fire only for a wedged worker.
const retire_grace_s: i64 = 5;

/// Bounds runaway culling under sustained pressure.
const max_evict_per_episode: usize = 4;

/// Episodes beyond this rank only the first `episode_capacity`, logged.
const episode_capacity: usize = 256;

/// Flattens the occupancy term's early climb (smaller → steeper near 0). See idleBudget.
const idle_budget_bias: f64 = 0.25;
const idle_budget_log_span: f64 = @log2((1 + idle_budget_bias) / idle_budget_bias);
/// k in the cadence multiplier 1+log2(1+(crf-1)/k): smaller → frequency earns longevity faster.
const cadence_mult_divisor: f64 = 2;

/// Per-worker client ids a single reconciliation pass can hold.
const max_tracked_clients = 256;
const max_peek_report_bytes = 1 << 20;
/// How long a worker may take to answer as a client is ended, a forced
/// interrupt included.
const end_probe_ms = 1000;

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
    /// The last id given out; ids are never reused.
    client_counter: u32,
    /// The client being served.
    client_id: u32,
    pending_spawns: PendingSpawnList,
    /// Read only once readable, so a silent peer costs nothing.
    pending_connections: PendingConnectionList,
    pending_kills: PendingKillList,
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
        self.abandonSpawns();
        self.pending_spawns.deinit(self.allocator);
        while (self.pending_connections.pop()) |pc| self.discardConnection(pc);
        self.pending_connections.deinit(self.allocator);
        live.deinit(self);
        reconfigure.deinit(self);
        self.cache.deinit();
        self.active_clients.deinit();
        for (self.pending_kills.items) |pk| {
            pk.w.killAndReap();
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
    fn liveWorkers(self: *Conductor) LiveWorkers {
        return .{ .pools = self.workers.valueIterator(), .reserve = self.reserve };
    }

    const LiveWorkers = struct {
        pools: std.StringHashMap(WorkerList).ValueIterator,
        pool: []const *worker.Worker = &.{},
        reserve: ?*worker.Worker,

        fn next(self: *LiveWorkers) ?*worker.Worker {
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

    fn cleanupWorker(self: *Conductor, w: *worker.Worker) void {
        if (w.exited()) platform.dumpChildStderr(self.io, self.allocator, &w.process, w.id);
        if (w.stderrFd()) |fd| {
            self.event_loop.unwatchFd(@intFromPtr(w) | tag_worker_stderr, fd);
            _ = self.drainStderr(w, false);
            if (w.process.stderr) |f| f.close(self.io);
            w.process.stderr = null;
        }
        if (w.launch == .sandboxed) {
            self.removeSandboxDir(w.id);
            if (builtin.target.os.tag == .linux) worker.sandbox.removeCgroup(w.id);
        }
        w.deinit();
        self.allocator.destroy(w);
    }

    fn removeSandboxDir(self: *Conductor, worker_id: u32) void {
        var buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
        const name = std.mem.print(&buf, "sandbox-{d}", .{worker_id}) catch return;
        var dir = Io.Dir.openDirAbsolute(self.io, self.cfg.socket_dir, .{}) catch return;
        defer dir.close(self.io);
        dir.deleteTree(self.io, name) catch {};
    }

    pub fn run(self: *Conductor) !void {
        g_socket_path = try self.allocator.dupeSentinel(u8, self.cfg.socket_path, 0);
        try eventLoopImpl.installSignalHandlers();
        defer eventLoopImpl.cleanupSignalHandlers();
        if (self.cfg.transport == .local) {
            g_pid_path = try self.allocator.printSentinel("{s}/conductor.pid", .{self.cfg.runtime_dir}, 0);
        }
        const pid_file = if (self.cfg.transport == .local) self.writePidFile() else null;
        defer if (pid_file) |file| {
            file.close(self.io);
            Io.Dir.deleteFileAbsolute(self.io, g_pid_path) catch {};
        };
        if (self.cfg.transport == .tcp) try self.writeHostKey();
        var listener = try self.createServer();
        defer if (listener.fd() != platform.no_socket) listener.close(self.io); // a failed recreate closed it
        std.debug.print("Conductor listening on {s}\n", .{self.cfg.socket_path});
        if (self.cfg.reserve_worker) self.beginReserveSpawn() catch |err| {
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
                std.mem.eql(u8, entry.name, protocol.client.host_key_file))
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
    const max_message_bytes = 64 << 20;

    // Event tags: a pending record's pointer, its low bits naming what turned readable.
    const tag_spawn_listener: usize = 2;
    const tag_spawn_client: usize = 3;
    const tag_connection: usize = 4;
    const tag_worker_stderr: usize = 6;
    const tag_spawn_stderr: usize = 7;

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
                const outcome = self.receive(pc) catch |err| blk: {
                    std.debug.print("Connection dropped: {}\n", .{err});
                    break :blk .done;
                } orelse return self.event_loop.watchFd(tag, pc.socket);
                _ = removePending(&self.pending_connections, pc);
                if (outcome == .held) pc.socket = platform.no_socket;
                self.discardConnection(pc);
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
                if (isPending(&self.pending_spawns, p)) self.onSpawnReadable(p);
            },
            tag_spawn_client => self.onHeldClientGone(@ptrFromInt(addr)),
            else => {},
        }
    }

    /// Passes a worker's stderr to ours, keeping it among the worker's recent
    /// lines, and through its stack scanner when `scan`; returns whether there
    /// may be more. At its end the pipe is closed.
    fn drainStderr(self: *Conductor, w: *worker.Worker, scan: bool) bool {
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
            self.discardConnection(pc);
        }
        i = 0;
        while (i < self.pending_spawns.items.len) {
            const p = self.pending_spawns.items[i];
            if (p.spawn.check(self.io, &self.cfg)) i += 1 else |err| self.failSpawn(p, err); // failSpawn removes p
        }
        const settling = reconfigure.onTick(self);
        return self.pending_spawns.items.len > 0 or self.pending_connections.items.len > 0 or settling;
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

    fn discardConnection(self: *Conductor, pc: *PendingConnection) void {
        if (pc.socket != platform.no_socket) platform.close(pc.socket);
        pc.received.deinit(self.allocator);
        self.allocator.destroy(pc);
    }

    /// Takes what has arrived; null while the message is still incomplete.
    fn receive(self: *Conductor, pc: *PendingConnection) !?Outcome {
        var chunk: [16 << 10]u8 = undefined;
        const n = platform.recvNonBlocking(pc.socket, &chunk) orelse {
            // A silent close is `juliaclient --version` probing.
            if (pc.received.items.len == 0) return .done;
            return error.EndOfStream;
        };
        if (n == 0) return null;
        if (pc.received.items.len + n > max_message_bytes) return error.MessageTooLarge;
        try pc.received.appendSlice(self.allocator, chunk[0..n]);
        var r = protocol.SliceReader{ .bytes = pc.received.items };
        const magic = r.int(u32) catch return null;
        if (magic == protocol.client.magic) return self.receiveRequest(pc, &r);
        if (magic == protocol.notification.magic) {
            const note = parseNotification(&r) catch |err| return if (err == error.Truncated) null else err;
            self.handleNotification(note);
            return .done;
        }
        if (magic >> 8 == protocol.client.magic_prefix) {
            try self.rejectClientVersion(pc.socket, @intCast(magic & 0xFF));
            return .done;
        }
        std.debug.print("Invalid magic: {x}\n", .{magic});
        return error.InvalidMagic;
    }

    // Its request is left unread: however it is framed, the reply's opening
    // (a socket_paths frame) is the same.
    fn rejectClientVersion(self: *Conductor, socket: posix.socket_t, theirs: u8) !void {
        const ours = protocol.client.version;
        std.debug.print("Client speaks protocol v{d}, this daemon v{d}; rejecting\n", .{ theirs, ours });
        var buf: [256]u8 = undefined;
        const msg = try std.mem.print(&buf, "This juliaclient speaks protocol v{d} but the daemon speaks v{d}: {s}.\n", .{
            theirs, ours, if (theirs < ours) "rebuild or reinstall juliaclient to match the daemon" else "restart the daemon so it runs the newly installed version",
        });
        // Its streams come without a key: it knows of none. Id 0 is no
        // client's, so neither is the key it is sent.
        self.client_id = 0;
        var streams = try self.openClientStreams(socket, false);
        defer streams.deinit();
        streams.finish(msg, 1);
    }

    const Notification = struct {
        kind: protocol.notification.Type,
        subject: u32, // client id, or a peek's worker id
        key: u64, // its sender's
        evaluation: u32 = 0, // an interrupt's
        report: []const u8 = "", // a peek's, in the connection's buffer
    };

    fn parseNotification(r: *protocol.SliceReader) !Notification {
        var note = Notification{
            .kind = std.enums.fromInt(protocol.notification.Type, try r.int(u8)) orelse return error.UnknownNotification,
            .subject = try r.int(u32),
            .key = try r.int(u64),
        };
        switch (note.kind) {
            .client_interrupt => note.evaluation = try r.int(u32),
            .peek_report => {
                const len = try r.int(u32);
                if (len > max_peek_report_bytes) return error.ReportTooLarge;
                note.report = try r.take(len);
            },
            else => {},
        }
        return note;
    }

    /// Whether the notification's key is its sender's: the client it names,
    /// or the worker that client is on, or whose peek it is.
    fn isGenuine(self: *Conductor, note: Notification) bool {
        const worker_id = switch (note.kind) {
            .client_exit, .client_interrupt => return note.key == self.keyFor(.client, note.subject),
            // Of a client gone already, it can do nothing.
            .client_done => (self.active_clients.get(note.subject) orelse return true).worker.id,
            .peek_report => note.subject,
        };
        return note.key == self.keyFor(.worker, worker_id);
    }

    fn handleNotification(self: *Conductor, note: Notification) void {
        if (!self.isGenuine(note)) return std.debug.print("Dropped a {s} notification with a wrong key\n", .{@tagName(note.kind)});
        const subject = note.subject;
        // A view's client was never assigned a worker.
        if ((note.kind == .client_exit or note.kind == .client_interrupt) and
            (live.dropById(self, subject) or reconfigure.dropById(self, subject))) return;
        switch (note.kind) {
            .client_done => _ = self.clientDone(subject),
            .client_exit => {
                if (self.clientDone(subject)) |w| {
                    if (!w.ping_pending) self.event_loop.scheduleHealthCheck(w);
                }
            },
            .client_interrupt => if (self.active_clients.get(subject)) |info| {
                // From Julia 1.14 the message cancels exactly the client's code,
                // and the SIGINT finds nothing to cancel; before, the SIGINT
                // interrupts whichever client's code thread 0 runs.
                info.worker.cancelClient(subject, note.evaluation);
                info.worker.signal(platform.SIG.INT);
            },
            .peek_report => {
                const w = self.findWorkerById(subject) orelse return;
                live.onProfile(self, w, self.allocator.dupe(u8, note.report) catch return);
            },
        }
    }

    /// A request's fixed part, its lengths checked against what has arrived.
    const RequestHead = struct {
        flags: protocol.client.Flags,
        pid: u32, // self-reported
        ppid: u32,
        host_key: *const protocol.client.HostKey,
        cwd: []const u8,
        fingerprint: u64,
        args_at: usize, // their count
    };

    fn parseRequestHead(r: *protocol.SliceReader) !RequestHead {
        // flags(1) + reserved(3) + pid(4) + ppid(4) + host key(16)
        const fixed = try r.take(28);
        const cwd = try r.lenPrefixed(u32);
        const fingerprint = try r.int(u64);
        return .{
            .flags = @bitCast(fixed[0]),
            .pid = std.mem.readInt(u32, fixed[4..8], .little),
            .ppid = std.mem.readInt(u32, fixed[8..12], .little),
            .host_key = fixed[12..28],
            .cwd = cwd,
            .fingerprint = fingerprint,
            .args_at = r.pos,
        };
    }

    /// Over TCP, a loopback peer is the host's only with the host key: a
    /// sandbox shares the host's network, but not its runtime dir.
    fn isRemote(self: *const Conductor, peer: *const PeerInfo, host_key: *const protocol.client.HostKey) bool {
        if (peer.isRemote(self.cfg.transport)) return true;
        return self.cfg.transport == .tcp and !std.crypto.timing_safe.eql(protocol.client.HostKey, host_key.*, self.host_key);
    }

    /// A local client's environment comes from the cache, where its first
    /// request leaves it; the rest are asked for theirs.
    fn receiveRequest(self: *Conductor, pc: *PendingConnection, r: *protocol.SliceReader) !?Outcome {
        const head = parseRequestHead(r) catch |err| return if (err == error.Truncated) null else err;
        const args_end = pc.env_at orelse pc.listEnd(head.args_at, 1) catch |err| return if (err == error.Truncated) null else err;
        const is_remote = self.isRemote(&pc.peer, head.host_key);
        // The cache is this machine's: a remote client's environment would
        // only evict local ones.
        const cached = if (is_remote or pc.env_at != null) null else self.cache.lookup(head.fingerprint);
        if (cached == null and pc.env_at == null) {
            pc.env_at = args_end;
            platform.write(pc.socket, &[_]u8{protocol.client.env_request});
            return null;
        }
        var owned_env: ?[]worker.EnvVar = null;
        const env = cached orelse blk: {
            _ = pc.listEnd(pc.env_at.?, 2) catch |err| return if (err == error.Truncated) null else err;
            var er = protocol.SliceReader{ .bytes = r.bytes, .pos = pc.env_at.? };
            const full = try self.copyEnv(&er);
            if (!is_remote) break :blk self.cache.insert(head.fingerprint, full);
            owned_env = full;
            break :blk env_cache.EnvCache.LookupResult{ .env = full, .julia_project = null };
        };
        // Its parts are freed here only until handleClient owns them.
        const request: ClientRequest = request: {
            errdefer if (owned_env) |e| worker.freeEnv(self.allocator, e);
            var args_reader = protocol.SliceReader{ .bytes = r.bytes, .pos = head.args_at };
            const raw_args = try self.copyArgs(&args_reader);
            errdefer {
                for (raw_args) |a| self.allocator.free(a);
                self.allocator.free(raw_args);
            }
            var problem: args.Problem = undefined;
            const parsed = args.parseReporting([]const u8, raw_args, &problem) catch |err| {
                var buf: [512]u8 = undefined;
                self.client_id = 0;
                try self.serveString(pc.socket, std.mem.print(&buf, "ERROR: {f}\n", .{problem}) catch "ERROR: invalid command line\n", 1);
                return err;
            };
            // A remote client's filesystem isn't ours: it names a project of ours
            // only by --project, and starts in its directory, else in our home.
            const home = if (self.cfg.host_home.len > 0) self.cfg.host_home else "/";
            const proj = project.resolve(self.allocator, self.io, &parsed, if (is_remote) null else env.julia_project, self.cfg.host_home, if (is_remote) home else head.cwd) catch |err| {
                if (err == error.CurrentDirUnavailable) {
                    self.client_id = 0;
                    try self.serveString(pc.socket, "The project is named relative to the working directory, which no longer exists.\n", 1);
                }
                return err;
            };
            errdefer if (proj) |p| self.allocator.free(p);
            const project_dir = if (proj) |p| (if (p[0] == '@') home else if (std.mem.endsWith(u8, p, ".toml")) std.Io.Dir.path.dirname(p) orelse home else p) else home;
            const cwd = try self.allocator.dupe(u8, if (is_remote) project_dir else head.cwd);
            errdefer self.allocator.free(cwd);
            break :request .{
                .flags = head.flags,
                .pid = head.pid,
                .host_pid = if (platform.peerPid(pc.socket)) |p| platform.pidNumber(p) else null,
                .ppid = head.ppid,
                .cwd = cwd,
                .env = env.env,
                .parsed = parsed,
                .project = proj,
                .raw_args = raw_args,
                .owned_env = owned_env,
            };
        };
        return try self.handleClient(pc.socket, is_remote, request);
    }

    // `r`'s lengths are already checked.
    fn copyArgs(self: *Conductor, r: *protocol.SliceReader) ![][]const u8 {
        const client_args = try self.allocator.alloc([]const u8, try r.int(u32));
        errdefer self.allocator.free(client_args);
        var copied: usize = 0;
        errdefer for (client_args[0..copied]) |arg| self.allocator.free(arg);
        for (client_args) |*arg| {
            arg.* = try self.allocator.dupe(u8, try r.lenPrefixed(u32));
            copied += 1;
        }
        return client_args;
    }

    // `r`'s lengths are already checked.
    fn copyEnv(self: *Conductor, r: *protocol.SliceReader) ![]worker.EnvVar {
        const env = try self.allocator.alloc(worker.EnvVar, try r.int(u32));
        defer self.allocator.free(env);
        for (env) |*e| e.* = .{ .key = try r.lenPrefixed(u32), .value = try r.lenPrefixed(u32) };
        return worker.dupeEnv(self.allocator, env);
    }

    fn handleClient(self: *Conductor, socket: posix.socket_t, is_remote: bool, received: ClientRequest) !Outcome {
        var request = received;
        var request_held = false; // moved into a HeldClient while its worker starts
        defer if (!request_held) request.deinit(self.allocator);
        self.client_counter += 1;
        self.client_id = self.client_counter;
        const sandbox = try self.sandboxFor(socket, is_remote, &request) orelse return .done;
        // A sandbox binds its project, which a remote client could name as any path of ours.
        if (sandbox == .remote) if (request.project) |p| {
            self.allocator.free(p);
            request.project = null;
        };
        if (request.parsed.hasSwitch("--reconfigure")) {
            try self.serveReconfigure(socket, request.flags.tty, !is_remote and sandbox == .none);
            return .done;
        }
        if (request.parsed.hasSwitch("--status")) {
            const scope: status.Scope = switch (sandbox) {
                .none, .local => .host, // --sandbox makes no sandbox of a status request
                .remote => .remote_sandbox,
                .client => |c| .{ .mount_ns = c.ns },
            };
            try self.serveStatus(socket, request.parsed.getSwitch("--status"), request.flags.tty, scope);
            return .done;
        }
        if (sandbox == .remote and self.cfg.sandbox_session_bypass) if (labelOf(&request)) |label| {
            if (self.findLabelled(label, .host)) |found| {
                std.debug.print("Client {d}: session bypass — joining local worker {d} (label '{s}')\n", .{ self.client_id, found.w.id, label });
                if (try self.assignClientToExistingWorker(socket, &request, found.w)) return .done;
            }
        };
        const worker_key = try self.poolKey(&request, sandbox);
        defer self.allocator.free(worker_key);
        if (request.parsed.hasSwitch("--watch")) return self.serveWatch(socket, &request, worker_key, sandbox);
        if (syncRefusal(&request)) |why| {
            std.debug.print("Client {d}: refused: {s}", .{ self.client_id, why });
            try self.serveString(socket, why, 1);
            return .done;
        }
        if (request.parsed.hasSwitch("--sync")) std.debug.print("Client {d}: sync mode, session='{s}'\n", .{ self.client_id, labelOf(&request).? });
        if (request.parsed.hasSwitch("--restart")) {
            try self.serveRestart(socket, &request, worker_key, sandbox);
            return .done;
        }
        const outcome = self.assignClientToWorker(socket, &request, worker_key, sandbox, null, null) catch |err| {
            self.reportNoWorker(socket, err, sandbox);
            return .done;
        };
        request_held = outcome == .held;
        return outcome;
    }

    /// How the client's worker is sandboxed; null once the client has been
    /// refused one.
    fn sandboxFor(self: *Conductor, socket: posix.socket_t, is_remote: bool, request: *const ClientRequest) !?SandboxKind {
        const wants_sandbox = request.parsed.hasSwitch("--sandbox");
        // A client in another mount namespace is sandboxed by something we cannot
        // see into, so it spawns its own worker there.
        const foreign_ns = if (is_remote) null else platform.peerForeignMountNs(socket);
        const sandbox: SandboxKind = if (is_remote and (self.cfg.sandbox_remote_clients or wants_sandbox))
            .remote
        else if (foreign_ns) |ns| blk: {
            // Refused, not downgraded: we can neither see into nor nest in the client's sandbox.
            if (wants_sandbox) {
                std.debug.print("Client {d}: --sandbox from inside a sandbox, rejecting\n", .{self.client_id});
                try self.serveString(socket,
                    "--sandbox: this client is already inside a sandbox (its mount namespace differs from the\n" ++
                        "daemon's), and the daemon cannot nest another in it. Drop --sandbox: the worker runs\n" ++
                        "inside this sandbox as it is.\n", 1);
                return null;
            }
            break :blk .{ .client = .{ .socket = socket, .ns = ns } };
        } else if (wants_sandbox) blk: {
            const cwd = trimTrailingSlashes(request.cwd);
            const proj = trimTrailingSlashes(request.project orelse "");
            const has_local_project = proj.len > 0 and proj[0] != '@';
            const local = if (has_local_project and pathCoveredBy(cwd, &.{proj})) proj else cwd;
            if (local.len == 0) {
                try self.serveString(socket, "--sandbox: the working directory no longer exists, so there is nothing to bind.\n", 1);
                return null;
            }
            break :blk .{ .local = local };
        } else .none;
        if (sandbox == .none) return sandbox;
        if (comptime builtin.target.os.tag != .linux) {
            const msg = if (sandbox == .remote)
                "Remote clients are refused: sandboxed workers are only available on Linux.\n" ++
                    "To run them unsandboxed, as the daemon's user, turn off \"Refuse remote clients\"\n" ++
                    "in juliaclient --reconfigure (JULIA_DAEMON_SANDBOX_REMOTE_CLIENTS=0).\n"
            else
                "--sandbox requires Linux (user namespaces).\n";
            std.debug.print("Client {d}: sandbox rejected (Linux only)\n", .{self.client_id});
            try self.serveString(socket, msg, 1);
            return null;
        }
        std.debug.print("Client {d}: {s} sandbox\n", .{ self.client_id, @tagName(sandbox) });
        return sandbox;
    }

    /// The pool the request's workers are in: its project, Julia channel and
    /// thread counts, fixed as a worker starts, and its sandbox.
    fn poolKey(self: *Conductor, request: *const ClientRequest, sandbox: SandboxKind) ![]u8 {
        const project_path = request.project orelse "";
        const ch = request.parsed.julia_channel orelse "";
        const tkey = args.packThreads(resolveThreads(request));
        return switch (sandbox) {
            .none => self.allocator.print("{s}\x00{s}\x00{d}", .{ project_path, ch, tkey }),
            .remote => self.allocator.print("__sandbox__\x00{s}\x00{d}", .{ ch, tkey }),
            // Keyed by mount namespace: a worker never serves another sandbox or the host.
            .client => |c| self.allocator.print("__ns{d}__\x00{s}\x00{s}\x00{d}", .{ c.ns, project_path, ch, tkey }),
            // Workers share only when their mounts match.
            .local => |rw| self.allocator.print("__lsandbox__\x00{s}\x00{s}\x00{s}\x00{d}", .{ rw, trimTrailingSlashes(project_path), ch, tkey }),
        };
    }

    /// Why a `--sync` request is refused, if it is.
    fn syncRefusal(request: *const ClientRequest) ?[]const u8 {
        const pages = request.parsed.getSwitch("--sync") orelse return null;
        if (labelOf(request) == null) return "--sync requires --session=<label>\n";
        if (pages.len > 0) _ = std.fmt.parseInt(u16, pages, 10) catch
            return "--sync=<pages> takes a whole number of pages to replay, 0 for all\n";
        return null;
    }

    /// Ends the request's session, or without a label every worker of its pool.
    fn serveRestart(self: *Conductor, socket: posix.socket_t, request: *const ClientRequest, worker_key: []const u8, sandbox: SandboxKind) !void {
        if (labelOf(request)) |label| return self.restartSession(socket, request, worker_key, label, sandbox);
        const nkilled = self.killWorkersForProject(worker_key);
        const channel = request.parsed.julia_channel;
        std.debug.print("Restart: killed {d} worker(s) for {s}{s}{s}\n", .{
            nkilled, request.project orelse "", if (channel != null) " " else "", channel orelse "",
        });
        const msg = try self.allocator.print("Reset: killed {d} worker(s) for project\n", .{nkilled});
        defer self.allocator.free(msg);
        try self.serveString(socket, msg, 0);
    }

    /// With a label, that session; without, the one a `--session` run of the
    /// caller's would join: in its pool, on the worker running a client, else the
    /// one used last. A labelled worker holds a session of its own.
    fn serveWatch(self: *Conductor, socket: posix.socket_t, request: *const ClientRequest, worker_key: []const u8, sandbox: SandboxKind) !Outcome {
        const pool: []const *worker.Worker = if (self.workers.getPtr(worker_key)) |list| list.items else &.{};
        const label = labelOf(request);
        const found: ?*worker.Worker = if (label) |l|
            (if (sandbox != .none) findWorkerByLabel(pool, l) else if (self.findLabelled(l, .enterable)) |f| f.w else null)
        else blk: {
            var best: ?*worker.Worker = null;
            for (pool) |w| if (w.session_label == null) {
                const b = best orelse {
                    best = w;
                    continue;
                };
                const busy = w.busyClients() > 0;
                if (if (busy != (b.busyClients() > 0)) busy else w.last_active > b.last_active) best = w;
            };
            break :blk best;
        };
        const w = found orelse {
            const msg = if (label) |l|
                try self.allocator.print("No session '{s}' is running.\n", .{l})
            else
                try self.allocator.dupe(u8, "No worker is running for this project to watch.\n");
            defer self.allocator.free(msg);
            try self.serveString(socket, msg, 1);
            return .done;
        };
        if (!try self.assignClientToExistingWorker(socket, request, w))
            try self.serveString(socket, "The session's worker could not take a watcher.\n", 1);
        return .done;
    }

    fn reportNoWorker(self: *Conductor, socket: posix.socket_t, err: anyerror, sandbox: SandboxKind) void {
        std.debug.print("Client {d}: no worker: {}\n", .{ self.client_id, err });
        if (err == error.ClientGone) return;
        var msg_buf: [1024]u8 = undefined;
        const msg = std.mem.print(&msg_buf, "Could not run a Julia worker for this session ({s}).\n{s}", .{
            @errorName(err), self.spawnFailureHint(err, sandbox),
        }) catch return;
        self.serveString(socket, msg, 1) catch |e| std.debug.print("Client {d}: could not report the failure: {}\n", .{ self.client_id, e });
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
        raw_args: []const []const u8, // what `parsed` reads
        owned_env: ?[]worker.EnvVar = null, // a remote client's, kept out of the cache

        fn deinit(self: *ClientRequest, allocator: Allocator) void {
            if (self.owned_env) |env| worker.freeEnv(allocator, env);
            allocator.free(self.cwd);
            if (self.project) |p| allocator.free(p);
            for (self.raw_args) |arg| allocator.free(arg);
            allocator.free(self.raw_args);
        }
    };

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

    /// What the worker is sent of `request`, run where the client runs.
    fn clientInfo(self: *const Conductor, request: *const ClientRequest, port_set: u16) worker.ClientInfo {
        return .{
            .tty = request.flags.tty,
            .color = request.flags.color,
            .force = labelOf(request) != null,
            .id = self.client_id,
            .key = self.keyFor(.client, self.client_id),
            .ppid = request.ppid,
            .cwd = request.cwd,
            .env = request.env,
            .switches = request.parsed.switches(),
            .programfile = request.parsed.program_file,
            .args = request.parsed.program_args,
            .port_set = port_set,
        };
    }

    fn allocatePortSet(self: *Conductor) !u16 {
        const pool = if (self.port_pool) |*p| p else return protocol.PortPool.none;
        return pool.allocate() orelse {
            std.debug.print("Client {d}: port pool exhausted\n", .{self.client_id});
            return error.PortPoolExhausted;
        };
    }

    const PreparedClient = struct {
        info: worker.ClientInfo,
        sandbox_env: ?[]const worker.EnvVar = null,
    };

    fn prepareClient(self: *Conductor, request: *const ClientRequest, sandbox: SandboxKind) !PreparedClient {
        const port_set = try self.allocatePortSet();
        errdefer self.releasePortSet(port_set);
        var prepared = PreparedClient{ .info = self.clientInfo(request, port_set) };
        if (sandbox == .remote) {
            // So withenv(client.env...) doesn't leak the remote HOME etc.
            const env = try self.buildSandboxClientEnv(request.env);
            prepared.sandbox_env = env;
            prepared.info.env = env;
            prepared.info.cwd = sandbox_home;
        }
        return prepared;
    }

    /// `direct` is the worker started for the client; `existing_hold` resumes a hold.
    fn assignClientToWorker(self: *Conductor, socket: posix.socket_t, request: *ClientRequest, worker_key: []const u8, sandbox: SandboxKind, existing_hold: ?*HeldClient, direct: ?*worker.Worker) !Outcome {
        const list = try self.getWorkerList(worker_key);
        const session_label = request.parsed.getSwitch("--session");
        std.debug.print("Client {d}; pid: {d}{s}{s}{s}{s}, project: {s}{s}\n", .{
            self.client_id,
            request.pid,
            if (request.parsed.julia_channel != null) ", julia: " else "",
            request.parsed.julia_channel orelse "",
            if (session_label != null) ", session: " else "",
            if (session_label) |l| (if (l.len > 0) l else ".") else "",
            request.project orelse "(default)",
            if (sandbox != .none) " [sandboxed]" else "",
        });
        const starting = if (direct == null) self.findPendingSpawn(worker_key) else null;
        // A session's clients queue behind the worker starting for it, so it
        // can't end up with two.
        if (direct == null) if (labelOf(request)) |label| {
            if (self.findStartingSession(label, worker_key, request.parsed.hasSwitch("--project") or sandbox != .none)) |p|
                return self.queueBehind(p, socket, request, worker_key, sandbox, existing_hold);
        };
        const prepared = try self.prepareClient(request, sandbox);
        defer if (prepared.sandbox_env) |e| self.allocator.free(e);
        const port_set = prepared.info.port_set;
        const assignment = blk: {
            errdefer self.releasePortSet(port_set);
            break :blk if (direct) |w|
                self.tryAssignWorker(w, &prepared.info, .new_worker) orelse return error.WorkerUnavailable
            else
                try self.selectWorker(list, request, &prepared.info, sandbox);
        };
        if (assignment) |a| {
            self.finishAssignment(socket, request, worker_key, a, port_set);
            return .done;
        }
        self.releasePortSet(port_set);
        // With no worker free, the one starting is the next to be.
        if (starting) |p| return self.queueBehind(p, socket, request, worker_key, sandbox, existing_hold);
        const hold = existing_hold orelse try self.holdClient(socket, request, worker_key, sandbox);
        errdefer if (existing_hold == null) self.unholdClient(hold);
        try self.beginClientSpawn(hold);
        return .held;
    }

    fn queueBehind(self: *Conductor, p: *PendingSpawn, socket: posix.socket_t, request: *ClientRequest, worker_key: []const u8, sandbox: SandboxKind, existing_hold: ?*HeldClient) !Outcome {
        const hold = existing_hold orelse try self.holdClient(socket, request, worker_key, sandbox);
        errdefer if (existing_hold == null) self.unholdClient(hold);
        try p.waiters.append(self.allocator, hold);
        self.event_loop.watchFd(@intFromPtr(hold) | tag_spawn_client, hold.socket);
        std.debug.print("Client {d}: waiting for worker {d}\n", .{ self.client_id, p.spawn.worker.id });
        return .held;
    }

    fn labelOf(request: *const ClientRequest) ?[]const u8 {
        const label = request.parsed.getSwitch("--session") orelse return null;
        return if (label.len > 0) label else null;
    }

    fn finishAssignment(self: *Conductor, socket: posix.socket_t, request: *const ClientRequest, worker_key: []const u8, assignment: WorkerAssignment, port_set: u16) void {
        std.debug.print("Assigned client {d} to worker {d}: {s}\n", .{ self.client_id, assignment.w.id, @tagName(assignment.reason) });
        self.seatClient(socket, request, assignment, port_set);
        self.bumpCrf(worker_key, self.currentTime()); // count the summons only once the client is tracked
        if (self.cfg.reserve_worker) self.beginReserveSpawn() catch |err| {
            std.debug.print("Warning: failed to start a reserve worker: {}\n", .{err});
        };
    }

    /// Tracks the client on the worker now running it, and sends it there.
    fn seatClient(self: *Conductor, socket: posix.socket_t, request: *const ClientRequest, assignment: WorkerAssignment, port_set: u16) void {
        defer assignment.paths.deinit(self.allocator);
        const w = assignment.w;
        w.last_pinged = self.currentTime();
        w.recordPpid(request.ppid, self.cfg.worker_maxclients);
        self.registerClient(self.client_id, request, w, port_set) catch |err| {
            std.debug.print("Client {d}: cannot track: {}\n", .{ self.client_id, err });
        };
        self.sendSocketPaths(socket, assignment.paths);
    }

    // --- Held clients ---

    // The request changes hands: the caller must not deinit it while held.
    fn holdClient(self: *Conductor, socket: posix.socket_t, request: *const ClientRequest, worker_key: []const u8, sandbox: SandboxKind) !*HeldClient {
        const hold = try self.allocator.create(HeldClient);
        errdefer self.allocator.destroy(hold);
        const env = try worker.dupeEnv(self.allocator, request.env);
        errdefer worker.freeEnv(self.allocator, env);
        const key = try self.allocator.dupe(u8, worker_key);
        hold.* = .{ .socket = socket, .request = request.*, .worker_key = key, .sandbox = sandbox, .id = self.client_id };
        hold.request.env = env;
        return hold;
    }

    // Undo holdClient while the caller still owns the request.
    fn unholdClient(self: *Conductor, hold: *HeldClient) void {
        worker.freeEnv(self.allocator, hold.request.env);
        self.allocator.free(hold.worker_key);
        self.allocator.destroy(hold);
    }

    fn discardHold(self: *Conductor, hold: *HeldClient) void {
        platform.close(hold.socket);
        hold.request.deinit(self.allocator);
        self.unholdClient(hold);
    }

    const Resumption = union(enum) { select, on: *worker.Worker, refuse: anyerror };

    // A client served meanwhile (`--restart` fails spawns) stays the current one.
    fn resumeHeld(self: *Conductor, hold: *HeldClient, how: Resumption) void {
        const serving = self.client_id;
        defer self.client_id = serving;
        self.client_id = hold.id;
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
        const watcher = request.parsed.hasSwitch("--watch");
        const port_set = try self.allocatePortSet();
        var info = self.clientInfo(request, port_set);
        info.force = info.force or watcher;
        // A watch runs no code, so it carries no environment: whatever reaches a
        // worker is readable by the session's own code.
        if (watcher) info.env = &.{};
        const assignment = self.tryAssignWorker(w, &info, .session_label) orelse {
            self.releasePortSet(port_set);
            return false;
        };
        self.seatClient(socket, request, assignment, port_set);
        return true;
    }

    // --- Worker selection ---

    fn selectWorker(self: *Conductor, list: *WorkerList, request: *const ClientRequest, client_info: *const worker.ClientInfo, sandbox: SandboxKind) !?WorkerAssignment {
        const now = self.currentTime();
        const label = labelOf(request);
        const want_interactive = request.parsed.hasSwitch("--interactive");
        // 1. Labeled session: join its worker (global, or scoped to an explicit --project)
        if (label) |l| {
            if (self.findSession(list.items, l, request.parsed.hasSwitch("--project") or sandbox != .none)) |f| {
                // A host client carries into a sandbox only what the sandbox itself starts with.
                var info = client_info.*;
                const entering = sandbox == .none and f.w.launch == .sandboxed;
                const env = if (entering) try self.buildSandboxJoinEnv(client_info.env) else null;
                defer if (env) |e| self.allocator.free(e);
                if (env) |e| {
                    info.env = e;
                    info.cwd = sandboxWorkdir(f.pool_key);
                }
                if (self.tryAssignWorker(f.w, &info, .session_label)) |a| return a;
            }
        }
        // Skip ppid/recency reuse for remote clients (isolation) and labeled
        // sessions (their identity is the label, handled above and below).
        if (sandbox != .remote and label == null) {
            // 2. PPID-affinity (interactive flag must match)
            if (self.findWorkerByPpid(list, client_info.ppid, want_interactive, now)) |w| {
                if (self.tryAssignWorker(w, client_info, .ppid_affinity)) |a| return a;
            }
            // 3. Lightest available worker, sparing the most-recent for ppid reuse
            if (self.tryExistingWorkers(list, client_info, want_interactive, now)) |a| return a;
        }
        // 3b. New labeled session: claim an idle worker and tag it, else spawn.
        if (label != null and sandbox == .none) {
            if (self.findClaimableWorker(list, want_interactive, now)) |w| {
                if (w.session_label != null) self.clearLabel(w); // expired
                w.session_label = try self.allocator.dupe(u8, label.?);
                if (self.tryAssignWorker(w, client_info, .session_label)) |a| return a;
            }
        }
        // 4. The warm reserve, for a plain non-interactive request it matches.
        if (sandbox == .none and !want_interactive) {
            if (try self.claimReserve(list, request.project orelse "", request.parsed.julia_channel, resolveThreads(request), label)) |w| {
                if (self.tryAssignWorker(w, client_info, .new_worker)) |a| return a;
            }
        }
        return null; // nothing to be had: the caller starts a worker
    }

    fn isWorkerAvailable(self: *Conductor, w: *worker.Worker, interactive: bool, now: i64) bool {
        const max = self.cfg.worker_maxclients;
        if (max != 0 and w.busyClients() >= max) return false;
        if (w.unresponsive_interrupted) return false;
        if (w.session_label != null and !self.isLabelExpired(w, now)) return false;
        if (w.interactive != interactive) return false;
        return true;
    }

    fn tryAssignWorker(self: *Conductor, w: *worker.Worker, client_info: *const worker.ClientInfo, reason: AssignReason) ?WorkerAssignment {
        self.event_loop.cancelPendingPing(w);
        const paths = w.runClient(self.allocator, client_info, if (self.cfg.transport == .local) self.cfg.socket_dir else null) catch |err| {
            _ = self.handleRunClientError(w, err);
            return null;
        };
        return .{ .paths = paths, .w = w, .reason = reason };
    }

    fn findWorkerByPpid(self: *Conductor, list: *WorkerList, ppid: u32, interactive: bool, now: i64) ?*worker.Worker {
        for (list.items) |w| {
            if (!self.isWorkerAvailable(w, interactive, now)) continue;
            if (std.mem.findScalar(u32, &w.recent_ppids, ppid) != null) {
                if (self.isLabelExpired(w, now)) self.clearLabel(w);
                return w;
            }
        }
        return null;
    }

    fn findWorkerByLabel(pool: []const *worker.Worker, label: []const u8) ?*worker.Worker {
        for (pool) |w| {
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
            if (w.busyClients() != 0) continue;
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

    pub fn handleRunClientError(self: *Conductor, w: *worker.Worker, err: anyerror) bool {
        switch (err) {
            error.WorkerBusy => {
                w.log("busy (likely has stuck client), syncing", .{});
                self.syncWorkerClients(w);
                return true;
            },
            // A reply late or cut short would be read as the next one's.
            error.Timeout, error.WouldBlock, error.EndOfStream, error.BrokenPipe, error.ConnectionResetByPeer,
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
        const channel_matches = if (julia_channel) |ch|
            r.julia_channel != null and std.mem.eql(u8, ch, r.julia_channel.?)
        else
            r.julia_channel == null;
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
            w.log("assigning label '{s}'", .{l});
            w.session_label = try self.allocator.dupe(u8, l);
        };
        try list.append(self.allocator, w);
    }

    fn beginClientSpawn(self: *Conductor, hold: *HeldClient) !void {
        const proj = hold.request.project orelse "";
        // Conductor-built sandboxes are never interactive.
        const interactive = (hold.sandbox == .none or hold.sandbox == .client) and hold.request.parsed.hasSwitch("--interactive");
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
            .spawn = try worker.Worker.begin(self.allocator, self.io, &self.cfg, self.next_worker_id, julia_channel, threads, interactive, launch, self.environ_map),
            .purpose = purpose,
        };
        errdefer p.spawn.abandon(self.io);
        try self.pending_spawns.append(self.allocator, p);
        self.next_worker_id += 1;
        self.event_loop.watchFd(@intFromPtr(p) | tag_spawn_listener, p.spawn.listenerFd());
        if (p.spawn.worker.stderrFd()) |fd| self.event_loop.watchFd(@intFromPtr(p) | tag_spawn_stderr, fd);
        // It sends nothing until it has its paths, so readable means it hung up.
        if (p.purpose == .client) self.event_loop.watchFd(@intFromPtr(p.purpose.client) | tag_spawn_client, p.purpose.client.socket);
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
        const connected = p.spawn.accept(self.io, &self.cfg, self.keyFor(.worker, p.spawn.worker.id)) catch |err| return self.failSpawn(p, err);
        if (connected) |w| self.completeSpawn(p, w) else self.event_loop.watchFd(@intFromPtr(p) | tag_spawn_listener, p.spawn.listenerFd());
    }

    // Without the client it started for, the worker underway is not worth
    // keeping, and its waiters select again.
    fn onHeldClientGone(self: *Conductor, hold: *HeldClient) void {
        for (self.pending_spawns.items) |p| {
            const starts = p.purpose == .client and p.purpose.client == hold;
            const waiting = if (starts) null else std.mem.findScalar(*HeldClient, p.waiters.items, hold);
            if (!starts and waiting == null) continue;
            // A held client sends nothing, so only an end is a hangup: a readiness
            // that finds none is stale, its poll raced by a cancel, perhaps of an
            // earlier hold at this address.
            var byte: [1]u8 = undefined;
            if (platform.recvNonBlocking(hold.socket, &byte)) |got| {
                if (got > 0) self.event_loop.watchFd(@intFromPtr(hold) | tag_spawn_client, hold.socket);
                return;
            }
            if (starts) {
                std.debug.print("Client {d}: left while worker {d} was starting\n", .{ hold.id, p.spawn.worker.id });
                return self.failSpawn(p, error.ClientGone);
            }
            std.debug.print("Client {d}: left while waiting for worker {d}\n", .{ hold.id, p.spawn.worker.id });
            _ = p.waiters.orderedRemove(waiting.?);
            self.event_loop.unwatchFd(@intFromPtr(hold) | tag_spawn_client, hold.socket);
            return self.discardHold(hold);
        }
    }

    fn detachSpawn(self: *Conductor, p: *PendingSpawn) void {
        _ = removePending(&self.pending_spawns, p);
        self.event_loop.unwatchFd(@intFromPtr(p) | tag_spawn_listener, p.spawn.listenerFd());
        if (p.spawn.worker.stderrFd()) |fd| self.event_loop.unwatchFd(@intFromPtr(p) | tag_spawn_stderr, fd);
        if (p.purpose == .client) self.event_loop.unwatchFd(@intFromPtr(p.purpose.client) | tag_spawn_client, p.purpose.client.socket);
        for (p.waiters.items) |hold| self.event_loop.unwatchFd(@intFromPtr(hold) | tag_spawn_client, hold.socket);
    }

    fn failSpawn(self: *Conductor, p: *PendingSpawn, err: anyerror) void {
        if (err != error.ClientGone) p.spawn.worker.log("spawn failed: {}", .{err});
        self.detachSpawn(p);
        p.spawn.abandon(self.io);
        // A child it left, precompiling, may hold the pipe open.
        if (self.drainStderr(&p.spawn.worker, false)) p.spawn.worker.process.stderr.?.close(self.io);
        p.spawn.worker.recent.deinit(self.allocator);
        self.settleSpawn(p, .{ .refuse = err });
    }

    fn completeSpawn(self: *Conductor, p: *PendingSpawn, connected: worker.Worker) void {
        self.detachSpawn(p);
        p.spawn.listener.close(self.io);
        const w = self.allocator.create(worker.Worker) catch |err| {
            var lost = connected;
            lost.killAndReap();
            lost.deinit();
            return self.settleSpawn(p, .{ .refuse = err });
        };
        w.* = connected;
        if (w.stderrFd()) |fd| self.event_loop.watchFd(@intFromPtr(w) | tag_worker_stderr, fd);
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
            p.spawn.worker.recent.deinit(self.allocator);
            for (p.waiters.items) |hold| self.resumeHeld(hold, .{ .refuse = error.DaemonShuttingDown });
            p.waiters.clearRetainingCapacity();
            self.settleSpawn(p, .{ .refuse = error.DaemonShuttingDown });
        }
    }

    const LabelledWorker = struct { w: *worker.Worker, pool_key: []const u8 };

    /// The pools a session is looked for in: the host's own; those the host
    /// may enter too, the sandboxes the conductor built (a sandboxed pool
    /// never serves a caller from another sandbox); or any, a client-spawned
    /// worker's too, whose sockets are in a mount namespace the host cannot see.
    const Reach = enum { host, enterable, any };

    fn findLabelled(self: *Conductor, label: []const u8, reach: Reach) ?LabelledWorker {
        var it = self.workers.iterator();
        while (it.next()) |entry| {
            const pool = entry.value_ptr.items;
            const reachable = pool.len == 0 or switch (reach) {
                .host => pool[0].launch == .direct,
                .enterable => pool[0].launch != .client,
                .any => true,
            };
            if (!reachable) continue;
            if (findWorkerByLabel(pool, label)) |w| return .{ .w = w, .pool_key = entry.key_ptr.* };
        }
        return null;
    }

    /// The worker holding session `label` that a client would join: in its own
    /// pool when `scoped` (it names its project, or is sandboxed: joining a host
    /// worker would escape), else wherever the host may enter.
    fn findSession(self: *Conductor, pool: []const *worker.Worker, label: []const u8, scoped: bool) ?LabelledWorker {
        if (!scoped) return self.findLabelled(label, .enterable);
        return .{ .w = findWorkerByLabel(pool, label) orelse return null, .pool_key = "" };
    }

    /// The spawn underway for session `label` that a client would wait on,
    /// reached as `findSession` reaches a running one.
    fn findStartingSession(self: *Conductor, label: []const u8, worker_key: []const u8, scoped: bool) ?*PendingSpawn {
        for (self.pending_spawns.items) |p| {
            const hold = switch (p.purpose) {
                .reserve => continue,
                .client => |h| h,
            };
            const reachable = if (scoped) std.mem.eql(u8, hold.worker_key, worker_key) else hold.sandbox != .client;
            if (reachable and std.mem.eql(u8, labelOf(&hold.request) orelse "", label)) return p;
        }
        return null;
    }

    /// Whether `--status` from `scope` shows the worker. A sandboxed caller sees
    /// only its sandbox: the remote clients' pool, or the workers in its mount
    /// namespace, whether spawned there by the client or built by us.
    pub fn isVisible(scope: status.Scope, pool_key: []const u8, w: *const worker.Worker) bool {
        return switch (scope) {
            .host => true,
            .remote_sandbox => std.mem.startsWith(u8, pool_key, "__sandbox__\x00"),
            .mount_ns => |ns| switch (w.launch) {
                .direct => false,
                .client => blk: {
                    var buf: [32]u8 = undefined;
                    const prefix = std.mem.print(&buf, "__ns{d}__\x00", .{ns}) catch break :blk false;
                    break :blk std.mem.startsWith(u8, pool_key, prefix);
                },
                .sandboxed => platform.childMountNs(w.process) == ns,
            },
        };
    }

    /// Where a host client works in a conductor-built sandbox: a local
    /// sandbox's writable directory (its pool key's second field), else the
    /// remote sandbox's home.
    fn sandboxWorkdir(pool_key: []const u8) []const u8 {
        var fields = std.mem.splitScalar(u8, pool_key, 0);
        if (!std.mem.eql(u8, fields.first(), "__lsandbox__")) return sandbox_home;
        return fields.next() orelse sandbox_home;
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

    /// Ends session `label` wherever a client of `request`'s would join it,
    /// and a worker still starting for it; the rest of the pool is left alone.
    fn restartSession(self: *Conductor, socket: posix.socket_t, request: *const ClientRequest, worker_key: []const u8, label: []const u8, sandbox: SandboxKind) !void {
        const pool: []const *worker.Worker = if (self.workers.getPtr(worker_key)) |list| list.items else &.{};
        const scoped = request.parsed.hasSwitch("--project") or sandbox != .none;
        // The host may end even a session it cannot join.
        const running = if (scoped) self.findSession(pool, label, true) else self.findLabelled(label, .any);
        if (running) |f| {
            f.w.log("retired: --restart of session '{s}'", .{label});
            self.retireWorker(f.w);
        }
        const starting = for (self.pending_spawns.items) |p| switch (p.purpose) {
            .reserve => {},
            .client => |hold| if (std.mem.eql(u8, labelOf(&hold.request) orelse "", label) and
                (if (scoped) std.mem.eql(u8, hold.worker_key, worker_key) else hold.sandbox != .client)) break p,
        } else null;
        if (starting) |p| self.failSpawn(p, error.Restarted);
        const ended = running != null or starting != null;
        std.debug.print("Restart: session '{s}' {s}\n", .{ label, if (ended) "ended" else "not running" });
        const msg = try self.allocator.print("Reset: {s} session '{s}'\n", .{ if (ended) "ended" else "no running", label });
        defer self.allocator.free(msg);
        try self.serveString(socket, msg, 0);
    }

    fn killWorkersForProject(self: *Conductor, worker_key: []const u8) usize {
        var count: usize = 0;
        // The pool goes first: the clients of a failed spawn select again, and
        // must not land on a worker about to be killed.
        if (self.workers.getPtr(worker_key)) |list| {
            count = list.items.len;
            for (list.items) |w| {
                self.event_loop.cancelPendingPing(w);
                self.removeActiveClientsForWorker(w);
                self.enqueueKill(w);
            }
            // crf history is kept: --restart is a non-TTL death (may come back hot).
            self.dropPoolEntry(worker_key);
        }
        // A starting worker counts too; its clients are told to try again. There
        // is at most one per key, as later clients queue behind it.
        if (self.findPendingSpawn(worker_key)) |p| {
            self.failSpawn(p, error.Restarted);
            count += 1;
        }
        return count;
    }

    /// Retires every worker spawned before `before_ns` (on `nowNs`'s clock)
    /// that runs no client and holds no session, so those that replace them
    /// start afresh; returns how many.
    pub fn retireIdleWorkers(self: *Conductor, before_ns: i64) usize {
        var idle: std.ArrayList(*worker.Worker) = .empty;
        defer idle.deinit(self.allocator);
        var it = self.workers.valueIterator();
        while (it.next()) |list| for (list.items) |w| {
            if (isRetirable(w, before_ns)) idle.append(self.allocator, w) catch break;
        };
        for (idle.items) |w| {
            w.log("retired: idle, as settings changed", .{});
            self.retireWorker(w);
        }
        self.renewReserve();
        return idle.items.len;
    }

    pub fn isRetirable(w: *const worker.Worker, before_ns: i64) bool {
        return w.spawned_ns < before_ns and w.busyClients() == 0 and w.session_label == null and !w.hosts_session;
    }

    /// Replaces the reserve worker, so the next new project's starts with
    /// the settings as they are now.
    pub fn renewReserve(self: *Conductor) void {
        if (self.reserve) |r| {
            r.log("retired: the reserve, as settings changed", .{});
            self.retireWorker(r);
        }
        // One still starting started from the old environment.
        var i: usize = 0;
        while (i < self.pending_spawns.items.len) {
            const p = self.pending_spawns.items[i];
            if (p.purpose == .reserve) self.failSpawn(p, error.SettingsChanged) else i += 1;
        }
        if (self.cfg.reserve_worker) self.beginReserveSpawn() catch |err| {
            std.debug.print("Reserve worker: spawn failed: {}\n", .{err});
        };
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
            w.killAndReap();
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
        var it = self.liveWorkers();
        while (it.next()) |w| _ = refreshOne(w, now_ns, half_life_s);
    }

    /// Whether its stats could be read.
    fn refreshOne(w: *worker.Worker, now_ns: i64, half_life_s: ?f64) bool {
        const pid = w.livePid() orelse return false;
        const s = platform.getProcessStats(pid) orelse return false;
        w.mem = s.mem_bytes;
        w.mem_at = @divTrunc(now_ns, 1_000_000_000);
        w.cpu.update(now_ns, s.cpu_seconds, half_life_s);
        return true;
    }

    // Once per ping interval, so sizing tracks idle drift without an extra wakeup.
    pub fn refreshIdleMemIfStale(self: *Conductor, w: *worker.Worker, now_s: i64) void {
        if (w.busyClients() != 0) return;
        if (now_s - w.mem_at < @as(i64, @intCast(self.cfg.ping_interval))) return;
        _ = refreshOne(w, self.nowNs(), null);
    }

    // Only for a TTL-culled key; cleanupWorker has no handle on the crf map, enforcing this.
    fn dropColdKey(self: *Conductor, key: []const u8) void {
        if (self.crf.fetchRemove(key)) |kv| self.allocator.free(kv.key);
    }

    pub fn enforceMaxTtl(self: *Conductor) void {
        const now = self.currentTime();
        // Re-scan from the top after each cull: retireWorker mutates the pool.
        while (self.findExpired(now)) |hit| {
            hit.w.log("idle {d}s past activity-scaled budget (max TTL {d}s), retiring", .{ now - hit.w.last_active, self.cfg.max_ttl });
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
            // Unread, its size is unknown, not what it was.
            c.size = if (refreshOne(c.w, now_ns, half_life)) c.w.mem else 0;
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
                c.w.log("evicting under memory pressure (value={d:.5}, size n/a)", .{c.value})
            else
                c.w.log("evicting under memory pressure (value={d:.5}, {d}MB)", .{ c.value, c.size >> 20 });
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
        if (w.busyClients() > 0) return null;
        if (w.session_label != null and !self.isLabelExpired(w, now)) return null;
        return @intCast(@max(0, now - w.last_active));
    }
    // Past budget is expired instead: enforceMaxTtl culls it regardless. The
    // reserve, exempt from the budget, has no such end.
    fn inPressureBand(self: *Conductor, w: *worker.Worker, key: []const u8, now: i64) bool {
        const age = self.cullableAge(w, now) orelse return false;
        return age >= self.cfg.min_ttl and (self.reserve == w or age < self.idleBudget(w, key));
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
                // Reaped by `exited` above: one wedged past SIGTERM may be slow to die.
                .term => {
                    pk.w.signal(platform.SIG.KILL);
                    pk.stage = .kill;
                },
                .kill => {},
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

    // --- Session labels ---

    fn isLabelExpired(self: *Conductor, w: *worker.Worker, now: i64) bool {
        if (w.session_label == null or w.busyClients() > 0) return false;
        const idle_time: u64 = @intCast(@max(0, now - w.last_active));
        return idle_time >= self.cfg.label_ttl;
    }

    pub fn clearLabel(self: *Conductor, w: *worker.Worker) void {
        if (w.session_label) |label| {
            w.log("clearing label '{s}'", .{label});
            w.dropSession(label); // tear down the now-orphaned session REPL before reuse
            self.allocator.free(label);
            w.session_label = null;
        }
    }

    // --- Sandbox env filtering ---

    const sandbox_home = "/home/sandbox";
    const sandbox_identity_vars = [_]worker.EnvVar{
        .{ .key = "HOME", .value = sandbox_home },
        .{ .key = "USER", .value = "sandbox" },
        .{ .key = "LOGNAME", .value = "sandbox" },
    };

    /// Free only the slice, as `buildSandboxClientEnv`.
    fn buildSandboxJoinEnv(self: *Conductor, env: []const worker.EnvVar) ![]const worker.EnvVar {
        const result = try self.allocator.alloc(worker.EnvVar, env.len);
        errdefer self.allocator.free(result);
        var n: usize = 0;
        for (env) |e| if (worker.sandbox.envAllowed(e.key)) {
            result[n] = e;
            n += 1;
        };
        return self.allocator.realloc(result, n);
    }

    /// Free only the slice: its EnvVars point into `env` or static strings.
    fn buildSandboxClientEnv(self: *Conductor, env: []const worker.EnvVar) ![]const worker.EnvVar {
        const result = try self.allocator.alloc(worker.EnvVar, env.len + sandbox_identity_vars.len);
        errdefer self.allocator.free(result);
        var n: usize = 0;
        for (env) |e| {
            const is_identity = for (sandbox_identity_vars) |v| {
                if (std.mem.eql(u8, e.key, v.key)) break true;
            } else false;
            if (is_identity) continue;
            result[n] = e;
            n += 1;
        }
        @memcpy(result[n..][0..sandbox_identity_vars.len], &sandbox_identity_vars);
        return self.allocator.realloc(result, n + sandbox_identity_vars.len);
    }

    // --- Port pool ---

    pub fn releasePortSet(self: *Conductor, port_set: u16) void {
        if (port_set != protocol.PortPool.none) {
            if (self.port_pool) |*pool| pool.release(port_set);
        }
    }

    // --- Client tracking ---

    fn registerClient(self: *Conductor, id: u32, request: *const ClientRequest, w: *worker.Worker, port_set: u16) !void {
        try self.trackClient(id, .{
            .worker = w,
            .pid = request.host_pid orelse request.pid,
            .port_set = port_set,
            .watcher = request.parsed.hasSwitch("--watch"),
            .session = request.parsed.hasSwitch("--session"),
            .sync = request.parsed.hasSwitch("--sync"),
        });
    }

    pub fn trackClient(self: *Conductor, id: u32, info: ActiveClientInfo) !void {
        const now_us = @divTrunc(self.nowNs(), 1000);
        const now_s = @divTrunc(now_us, 1_000_000);
        var entry = info;
        entry.start_time_us = now_us;
        try self.active_clients.put(id, entry);
        const w = info.worker;
        w.hosts_session = w.hosts_session or (info.session and !info.watcher);
        if (!info.internal) w.log("{s} {d} attached", .{ if (info.watcher) "watcher" else "client", info.pid });
        if (info.watcher) {
            w.watchers += 1;
        } else if (!w.occupancy.fast.busy) {
            w.occupancy.attach(now_s, self.activityHalfLife(), self.budgetOccHalfLife());
        }
    }

    fn clientDone(self: *Conductor, id: u32) ?*worker.Worker {
        const info = (self.active_clients.fetchRemove(id) orelse return null).value;
        const w = info.worker;
        self.releasePortSet(info.port_set);
        if (w.active_clients > 0) {
            w.active_clients -= 1;
        } else {
            w.log("clientDone underflow (map/count drift)", .{});
        }
        const now_ns = self.nowNs();
        const now_us = @divTrunc(now_ns, 1000);
        const now_s = @divTrunc(now_us, 1_000_000);
        if (info.watcher) {
            w.watchers -|= 1;
        } else {
            w.last_active = now_s;
            if (w.busyClients() == 0) {
                w.occupancy.detach(now_s, self.activityHalfLife(), self.budgetOccHalfLife());
                _ = refreshOne(w, now_ns, null);
            }
        }
        const duration_us = now_us - info.start_time_us;
        const duration_s: u64 = @intCast(@divTrunc(duration_us, 1_000_000));
        const duration_ms: u64 = @intCast(@divTrunc(@mod(duration_us, 1_000_000), 1_000));
        std.debug.print("Client {d} disconnected; worker: {d}, duration: {d}.{d:0>3}s\n", .{ id, w.id, duration_s, duration_ms });
        if (!info.internal) w.log("{s} {d} left after {d}.{d:0>3}s", .{
            if (info.watcher) "watcher" else "client", info.pid, duration_s, duration_ms,
        });
        return if (w.busyClients() == 0) w else null;
    }

    pub fn syncWorkerClients(self: *Conductor, w: *worker.Worker) void {
        const synced = self.syncCounts(w) catch return;
        const remaining = synced.listed;
        const busy = w.busyClients();
        // The worker's surplus is departed clients' code it could not stop.
        if (synced.running > remaining and busy == 0) {
            w.log("{d} departed client(s) still running, retiring", .{synced.running});
            return self.retireWorker(w);
        }
        const now = self.currentTime();
        if (busy == 0 and w.occupancy.fast.busy) {
            w.occupancy.detach(now, self.activityHalfLife(), self.budgetOccHalfLife());
        } else if (busy > 0 and !w.occupancy.fast.busy) {
            w.occupancy.attach(now, self.activityHalfLife(), self.budgetOccHalfLife());
        }
        w.log("sync complete, {d} active clients", .{remaining});
    }

    /// Tells the worker the clients it has, and it stops any other; returns
    /// how many it still runs, and how many were listed. A worker that fails
    /// to answer is retired (`error.SyncFailed`).
    fn syncCounts(self: *Conductor, w: *worker.Worker) !struct { running: u16, listed: u32 } {
        // The worker kills every client not listed, so a partial list is never sent.
        var ids: [max_tracked_clients]u32 = undefined;
        var count: usize = 0;
        var it = self.active_clients.iterator();
        while (it.next()) |entry| if (entry.value_ptr.worker == w) {
            if (count == ids.len) {
                w.log("over {d} clients, skipping sync", .{ids.len});
                return error.TooManyClients;
            }
            ids[count] = entry.key_ptr.*;
            count += 1;
        };
        const running = w.syncClients(ids[0..count]) catch |err| {
            w.log("sync_clients failed: {}", .{err});
            self.retireWorker(w);
            return error.SyncFailed;
        };
        try self.reconcileClientMap(w);
        const counted = self.countMapClients(w);
        w.active_clients = counted.clients;
        w.watchers = counted.watchers;
        return .{ .running = running, .listed = counted.clients };
    }

    pub const Ending = enum { ended, interrupted, retired };

    /// Ends `ids`, clients of `w`: they are dropped here and the worker stops
    /// their tasks. One that won't stop, a CPU-bound loop, is force-interrupted
    /// (thread 0 runs it, so the interrupt lands there), and the worker retired
    /// if it still runs one, or stops answering.
    pub fn endClients(self: *Conductor, w: *worker.Worker, ids: []const u32) Ending {
        for (ids) |id| _ = self.clientDone(id);
        var ending: Ending = .ended;
        while (true) {
            self.event_loop.cancelPendingPing(w);
            if (w.answersWithin(end_probe_ms)) {
                const synced = self.syncCounts(w) catch |err| switch (err) {
                    error.SyncFailed => return .retired,
                    else => return ending,
                };
                if (synced.running <= synced.listed) return ending;
            }
            if (ending == .interrupted) break;
            w.forceInterrupt();
            ending = .interrupted;
        }
        w.log("an ended client would not stop, retiring", .{});
        self.retireWorker(w);
        return .retired;
    }

    fn countMapClients(self: *Conductor, w: *worker.Worker) struct { clients: u32, watchers: u32 } {
        var clients: u32 = 0;
        var watchers: u32 = 0;
        var it = self.active_clients.iterator();
        while (it.next()) |entry| if (entry.value_ptr.worker == w) {
            clients += 1;
            if (entry.value_ptr.watcher) watchers += 1;
        };
        return .{ .clients = clients, .watchers = watchers };
    }

    // Repairs a lost client_done, which the count-only sync can't. A worker
    // that fails to answer is retired (`error.SyncFailed`).
    fn reconcileClientMap(self: *Conductor, w: *worker.Worker) !void {
        var running_buf: [max_tracked_clients]u32 = undefined;
        const running = w.queryClients(&running_buf) catch |err| {
            w.log("queryClients failed: {}", .{err});
            // Past the whole list, the stream is in step still.
            if (err == error.TooManyClients) return;
            self.retireWorker(w);
            return error.SyncFailed;
        };
        var stale: [max_tracked_clients]u32 = undefined;
        var n: usize = 0;
        var it = self.active_clients.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.worker != w) continue;
            if (std.mem.findScalar(u32, running, entry.key_ptr.*) != null) continue;
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
        var it = self.liveWorkers();
        while (it.next()) |w| w.softExit();
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

    // Only the living: anyWorkerAlive reaped the rest, whose pids may be reused.
    fn signalAllWorkers(self: *Conductor, sig: platform.SIG) void {
        var it = self.liveWorkers();
        while (it.next()) |w| if (!w.exited()) w.signal(sig);
        // Workers mid-retirement are no longer in the pool but still dying.
        for (self.pending_kills.items) |pk| if (!pk.w.exited()) pk.w.signal(sig);
    }

    fn anyWorkerAlive(self: *Conductor) bool {
        var it = self.liveWorkers();
        while (it.next()) |w| if (!w.exited()) return true;
        for (self.pending_kills.items) |pk| if (!pk.w.exited()) return true;
        return false;
    }

    // --- Health checks ---
    // Policy only: each event loop supplies `awaitPong`, arming a pong read
    // and a timeout, and reports back through the handlers below.

    pub fn pressureIntervalS(self: *const Conductor) u64 {
        return @min(@as(u64, 5), self.cfg.ping_interval);
    }

    pub fn onPingTimer(self: *Conductor) void {
        if (!self.pressure_monitor.active()) self.sweepPendingKills();
        self.enforceMaxTtl();
        const now = self.currentTime();
        var it = self.liveWorkers();
        while (it.next()) |w| self.pingIfDue(w, now);
    }

    pub fn onPressureTimer(self: *Conductor) void {
        self.sweepPendingKills();
        self.runEvictionEpisode();
    }

    /// Scheduled after a client leaves, so an idle worker is checked promptly.
    pub fn onHealthCheck(self: *Conductor, w: *worker.Worker) void {
        const now = self.currentTime();
        self.refreshIdleMemIfStale(w, now);
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
            return self.retireWorker(w);
        };
        // Late for a ping whose timeout was let pass; this one's is still to come.
        if (pong.seq != w.ping_seq) return self.event_loop.awaitPong(w, self.cfg.ping_timeout * 1000);
        w.last_pinged = self.currentTime();
        w.unresponsive_interrupted = false;
        if (pong.clients != w.active_clients) {
            w.log("client count mismatch (worker={d}, conductor={d}), syncing", .{ pong.clients, w.active_clients });
            self.syncWorkerClients(w);
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
        self.retireWorker(w);
    }

    fn pingIfDue(self: *Conductor, w: *worker.Worker, now: i64) void {
        self.refreshIdleMemIfStale(w, now);
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
    const reply_accept_timeout_ms = 5000;
    const request_timeout_s = 10; // a client sends its whole request at once

    pub const ClientStreams = struct {
        c: *Conductor,
        listeners: [4]protocol.Listener,
        conns: [4]posix.socket_t,
        port_set_idx: u16,

        pub fn fd(self: *const ClientStreams, s: Stream) posix.socket_t {
            return self.conns[@intFromEnum(s)];
        }

        fn finish(self: *const ClientStreams, content: []const u8, exit_code: u8) void {
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
            self.c.releasePortSet(self.port_set_idx);
        }
    };

    // On failure everything partial is released first.
    fn openClientStreams(self: *Conductor, client_socket: posix.socket_t, keyed: bool) !ClientStreams {
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
            if (keyed) {
                var key: [8]u8 = undefined;
                try protocol.readExactWithin(self.io, conns[i], &key, reply_accept_timeout_ms);
                if (std.mem.readInt(u64, &key, .little) != self.keyFor(.client, self.client_id)) return error.WrongKey;
            }
        }
        return .{ .c = self, .listeners = listeners, .conns = conns, .port_set_idx = port_set_idx };
    }

    fn serveString(self: *Conductor, client_socket: posix.socket_t, content: []const u8, exit_code: u8) !void {
        var streams = try self.openClientStreams(client_socket, true);
        defer streams.deinit();
        streams.finish(content, exit_code);
    }

    // Only the conductor's own user, at a local socket, may change it.
    fn serveReconfigure(self: *Conductor, client_socket: posix.socket_t, tty: bool, allowed: bool) !void {
        if (!allowed) {
            std.debug.print("Client {d}: --reconfigure refused (not a local, unsandboxed client)\n", .{self.client_id});
            return self.serveString(client_socket, "--reconfigure needs a local, unsandboxed client of the conductor's own user.\n", 1);
        }
        if (!tty) {
            const text = try reconfigure.listing(self.allocator, &self.settings);
            defer self.allocator.free(text);
            return self.serveString(client_socket, text, 0);
        }
        var streams = try self.openClientStreams(client_socket, true);
        std.debug.print("Client {d}: --reconfigure\n", .{self.client_id});
        try reconfigure.subscribe(self, streams, self.probePalette(&streams));
    }

    // A TTY client is colour-probed first; a non-answering terminal gets the flat report.
    // A styled TTY one-shot waits a beat so its CPU meter resolves.
    fn serveStatus(self: *Conductor, client_socket: posix.socket_t, switch_value: ?[]const u8, tty: bool, scope: status.Scope) !void {
        // A bare `--status` has an empty value.
        const format = if (switch_value) |v| (if (v.len > 0) v else null) else null;
        var streams = try self.openClientStreams(client_socket, true);
        var held = false;
        defer if (!held) streams.deinit();
        const is_live = tty and format != null and std.mem.eql(u8, format.?, "live");
        const palette: ?pal.Palette = if (tty and (format == null or is_live)) self.probePalette(&streams) else null;
        if (is_live or (tty and format == null)) {
            try live.subscribe(self, streams, palette, scope, !is_live);
            held = true;
            return;
        }
        const report = self.renderStatus(format, tty, palette, scope, null, null, false) catch |err| {
            std.debug.print("Status: render failed: {}\n", .{err});
            streams.finish("Failed to generate status report.\n", 1);
            return;
        };
        defer report.deinit(self.allocator);
        streams.finish(report.bytes, 0);
    }

    pub fn renderStatus(self: *Conductor, format: ?[]const u8, tty: bool, palette: ?pal.Palette, scope: status.Scope, focus: ?u32, trend: ?*const status.Trend, hint: bool) !status.Report {
        return status.render(self, .{
            .format = format,
            .tty = tty,
            .scope = scope,
            .palette = if (palette) |*p| p else null,
            .focus = focus,
            .trend = trend,
            .hint = hint,
        });
    }

    const palette_probe_timeout_s = 2;

    pub fn noteLiveChange(self: *Conductor) void {
        live.noteChange(self);
    }

    pub fn onLiveTimer(self: *Conductor) void {
        live.onTimer(self);
    }

    // Read until the CSI 5n sentinel or a byte cap; a view's client is raw from
    // the start, so the replies come unechoed.
    fn probePalette(self: *Conductor, streams: *ClientStreams) ?pal.Palette {
        const stdin = streams.fd(.stdin);
        platform.write(streams.fd(.stdout), pal.queries);
        // This read blocks the event loop, so is bounded as a whole.
        const deadline = self.nowNs() + palette_probe_timeout_s * std.time.ns_per_s;
        var buf: [4096]u8 = undefined;
        var len: usize = 0;
        while (len < buf.len) {
            const left_ms = @divTrunc(deadline - self.nowNs(), std.time.ns_per_ms);
            if (left_ms <= 0 or !platform.waitReadable(stdin, @intCast(left_ms))) break;
            len += platform.recvNonBlocking(stdin, buf[len..]) orelse break;
            if (std.mem.find(u8, buf[0..len], pal.sentinel) != null) break;
        }
        var palette: pal.Palette = .{};
        pal.parse(buf[0..len], &palette);
        return if (palette.isPopulated()) palette else null;
    }

    /// Each path is at most `protocol.max_socket_path` long, as `runClient`
    /// and `createListener` ensure.
    fn sendSocketPaths(self: *Conductor, socket: posix.socket_t, paths: worker.Worker.SocketPaths) void {
        var buf: [1 + 4 + 4 * (2 + protocol.max_socket_path) + 8]u8 = undefined;
        var w = protocol.BufWriter{ .buf = &buf };
        w.writeInt(u8, protocol.client.socket_paths);
        w.writeInt(u32, self.client_id);
        // TCP: the client pairs the port with the conductor's host.
        const all = [_][]const u8{ paths.stdin, paths.stdout, paths.stderr, paths.signals };
        for (all) |path| {
            if (self.cfg.transport == .tcp) {
                const colon = std.mem.findScalarLast(u8, path, ':') orelse path.len;
                w.writeLenPrefixed(u16, path[colon..]);
            } else {
                w.writeLenPrefixed(u16, path);
            }
        }
        w.writeInt(u64, self.keyFor(.client, self.client_id));
        platform.write(socket, w.written());
    }
};

// --- Entry point ---

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const allocator = init.gpa;
    // The log is UTF-8, which a console shows as such only in its code page.
    const console = platform.setupConsoleIo(platform.getStderrHandle(), platform.getStderrHandle());
    defer platform.restoreConsoleIo(console);
    const cfg = try config.Config.load(allocator, init.environ_map);
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
    // Needed even in TCP mode: the worker setup socket is always local.
    _ = try Io.Dir.cwd().createDirPathStatus(io, cfg.runtime_dir, platform.runtime_dir_permissions);
    try platform.secureRuntimeDir(cfg.runtime_dir);
    conductor.cleanupRuntimeDir();
    try conductor.run();
}
