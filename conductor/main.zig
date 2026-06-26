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

/// Peer address info passed from the event loop's accept to connection handling.
pub const PeerInfo = struct {
    addr: posix.sockaddr = std.mem.zeroes(posix.sockaddr),
    len: posix.socklen_t = 0,
    /// True if the peer is a non-loopback TCP connection (remote client).
    pub fn isRemote(self: *const PeerInfo, transport: protocol.TransportMode) bool {
        if (transport != .tcp) return false;
        if (self.len == 0) return false;
        return !platform.isLoopback(&self.addr, self.len);
    }
};

pub const eventLoopImpl = if (builtin.os.tag == .linux)
    @import("eloop/linux.zig")
else if (builtin.os.tag.isBSD())
    @import("eloop/kqueue.zig")
else
    @compileError("unsupported OS");

const readExact = protocol.readExact;
const randomSocketPath = protocol.randomSocketPath;
const createListener = protocol.createListener;
const EventLocation = protocol.EventLocation;

const VERSION = blk: {
    const project_toml = @embedFile("Project.toml");
    const marker = "\nversion = \"";
    const start = if (std.mem.indexOf(u8, project_toml, marker)) |i| i + marker.len else unreachable;
    const end = if (std.mem.indexOfPos(u8, project_toml, start, "\"")) |i| i else unreachable;
    break :blk project_toml[start..end];
};
const VERSION_STRING = "juliaclient " ++ VERSION ++ "\n";

const DAEMON_MANAGEMENT_HELP = switch (builtin.os.tag) {
    .linux =>
        \\Daemon management (systemd):
        \\
        \\ systemctl --user {start | stop | restart | status} julia-daemon
        \\
    ,
    .macos =>
        \\Daemon management (launchd):
        \\
        \\ launchctl {start | stop} net.julialang.julia-daemon
        \\ tail -f ~/Library/Logs/julia-daemon.log
        \\
    ,
    else =>
        \\Daemon management:
        \\
        \\ pgrep -f julia-conductor   (status)
        \\ pkill -f julia-conductor   (stop)
        \\
    ,
};

const CLIENT_HELP =
    \\
    \\    juliaclient [switches] -- [programfile] [args...]
    \\
    \\Switches (a '*' marks the default value, if applicable):
    \\
    \\ -v, --version              Display version information
    \\ -h, --help                 Print this message
    \\ -P, --project[=<dir>|@.]    Set <dir> as the home project/environment
    \\ -e, --eval <expr>          Evaluate <expr>
    \\ -E, --print <expr>         Evaluate <expr> and display the result
    \\ -L, --load <file>          Load <file> immediately on all processors
    \\ -i                         Interactive mode; REPL runs and `isinteractive()` is true
    \\ --banner={yes|no|auto*}    Enable or disable startup banner
    \\ --color={yes|no|auto*}     Enable or disable color text
    \\ --history-file={yes*|no}   Load or save history
    \\
    \\Client-specific switches:
    \\
    \\ -a, --address <addr>       Connect to conductor at <addr> instead of default
    \\ --session[=<label>]        Reuse worker state in Main module. With a label,
    \\                            multiple clients can share the same session.
    \\ --sync                     Attach to shared REPL (requires --session=<label>)
    \\ --revise[=yes|no*]         Enable or disable Revise.jl integration
    \\ --restart                  Kill workers for the project and exit
    \\ --sandbox                  Run in an isolated sandbox (Linux only)
    \\ --status[=json]            Show the state of the workers, optionally in json
    \\
    \\
++ DAEMON_MANAGEMENT_HELP;

// --- Constants ---

/// Grace per retirement stage; SIGTERM/SIGKILL fire only for a wedged worker.
const retire_grace_s: i64 = 5;

/// Max workers retired per eviction episode (bounds runaway culling under
/// sustained exogenous pressure; see WORKER_CACHE.md §Bounding).
const max_evict_per_episode: usize = 4;

/// Upper bound on discretionary workers ranked per episode. Episodes that would
/// exceed this rank only the first `episode_capacity` (logged), never silently.
const episode_capacity: usize = 256;

// --- Global state for cleanup ---

pub var g_socket_path: [:0]const u8 = "";
pub var g_pid_path: [:0]const u8 = "";

// --- Types ---

pub const WorkerList = std.array_list.Aligned(*worker.Worker, null);

pub const ActiveClientInfo = struct {
    worker: *worker.Worker,
    client_num: u32,
    start_time_us: i64,
    port_set: u16, // PortPool index, or PortPool.none when unmanaged
};

pub const ActiveClientMap = std.AutoHashMap(u32, ActiveClientInfo);

/// A retiring worker awaiting reap; owns the `Worker` until then.
pub const PendingKill = struct {
    w: *worker.Worker,
    pid: posix.pid_t,
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
    /// Workers asked to exit, awaiting reap or escalation. Swept on the timer.
    pending_kills: PendingKillList,
    /// Per-pool-key combined recency+frequency (LRFU). Keyed like `workers`;
    /// outlives every worker death except a max-TTL cull (see dropColdKey).
    crf: std.StringHashMap(worker.Crf),
    /// Host memory-pressure monitor (inert unless JULIA_DAEMON_MEMORY_PRESSURE).
    pressure_monitor: pressure.Monitor,
    event_loop: eventLoopImpl.EventLoop,
    /// `--status=live` subscribers, repainted in place until they disconnect.
    live_clients: std.ArrayList(LiveClient),
    /// Live-repaint timer state; see noteLiveChange.
    live_armed: bool,
    dirty: bool,

    const LiveClient = struct {
        streams: ClientStreams, // held open across repaints
        palette: ?pal.Palette, // probed once at subscribe
        pid: u32, // matched for teardown on exit/interrupt
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
            .crf = std.StringHashMap(worker.Crf).init(allocator),
            .pressure_monitor = pressure.Monitor.init(&cfg),
            .event_loop = try eventLoopImpl.EventLoop.init(64),
            .live_clients = .empty,
            .live_armed = false,
            .dirty = false,
        };
    }

    pub fn deinit(self: *Conductor) void {
        self.event_loop.deinit();
        for (self.live_clients.items) |*lc| {
            platform.write(lc.streams.fd(.stdout), "\r\n" ++ live_cursor_show);
            lc.streams.deinit();
        }
        self.live_clients.deinit(self.allocator);
        self.cache.deinit();
        self.active_clients.deinit();
        for (self.pending_kills.items) |pk| {
            _ = platform.kill(pk.pid, platform.SIG.KILL);
            _ = platform.waitpidNonBlocking(pk.pid);
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

    // Whether `w` is still in the pool/reserve. retireWorker removes a worker
    // before it can be freed, so the event loops use this to drop stale
    // completions rather than dereference freed (or recycled) memory.
    pub fn isLiveWorker(self: *Conductor, w: *const worker.Worker) bool {
        if (self.reserve == w) return true;
        var it = self.workers.iterator();
        while (it.next()) |entry| {
            for (entry.value_ptr.items) |item| if (item == w) return true;
        }
        return false;
    }

    fn cleanupWorker(self: *Conductor, w: *worker.Worker) void {
        if (w.sandboxed) self.removeSandboxDir(w.id);
        w.deinit();
        self.allocator.destroy(w);
    }

    fn removeSandboxDir(self: *Conductor, worker_id: u32) void {
        var buf: [std.fs.max_path_bytes]u8 = undefined;
        const name = std.fmt.bufPrint(&buf, "sandbox-{d}", .{worker_id}) catch return;
        var dir = Io.Dir.openDirAbsolute(self.io, self.cfg.runtime_dir, .{}) catch return;
        defer dir.close(self.io);
        dir.deleteTree(self.io, name) catch {};
    }

    pub fn run(self: *Conductor) !void {
        g_socket_path = try self.allocator.dupeZ(u8, self.cfg.socket_path);
        try eventLoopImpl.installSignalHandlers();
        defer eventLoopImpl.cleanupSignalHandlers();
        if (self.cfg.transport == .unix) {
            const pid_path = try std.fmt.allocPrint(self.allocator, "{s}/conductor.pid", .{self.cfg.runtime_dir});
            g_pid_path = try self.allocator.dupeZ(u8, pid_path);
            self.allocator.free(pid_path);
            self.writePidFile();
        }
        defer if (self.cfg.transport == .unix) {
            Io.Dir.deleteFileAbsolute(self.io, g_pid_path) catch {};
        };
        var server = try self.createServer();
        defer server.deinit(self.io);
        defer if (self.cfg.transport == .unix) {
            Io.Dir.deleteFileAbsolute(self.io, self.cfg.socket_path) catch {};
        };
        std.debug.print("Conductor listening on {s}\n", .{self.cfg.socket_path});
        self.createReserveWorker(null) catch |err| {
            std.debug.print("Failed to create reserve worker: {}\n", .{err});
        };
        eventLoopImpl.run(self, &server);
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

    pub fn handleConnectionFd(self: *Conductor, socket: posix.socket_t, peer: *const PeerInfo) !void {
        var magic_buf: [4]u8 = undefined;
        try readExact(socket, &magic_buf);
        const magic = std.mem.readInt(u32, &magic_buf, .little);
        if (magic == protocol.client.magic) {
            try self.handleClient(socket, peer);
        } else if (magic == protocol.notification.magic) {
            self.handleNotification(socket);
        } else {
            std.debug.print("Invalid magic: {x}\n", .{magic});
            return error.InvalidMagic;
        }
    }

    fn handleNotification(self: *Conductor, socket: posix.socket_t) void {
        var buf: [5]u8 = undefined;
        readExact(socket, &buf) catch |err| {
            std.debug.print("Notification read error: {}\n", .{err});
            return;
        };
        const pid = std.mem.readInt(u32, buf[1..5], .little);
        const ntype = @as(protocol.notification.Type, @enumFromInt(buf[0]));
        // A live-status subscriber leaves on ^D (exit) or ^C (interrupt); it was
        // never assigned to a worker, so dropping it is all that's needed.
        if ((ntype == .client_exit or ntype == .client_interrupt) and self.dropLiveClient(pid)) return;
        switch (ntype) {
            .client_done => _ = self.clientDone(pid),
            .client_exit => {
                if (self.clientDone(pid)) |w| {
                    if (!w.ping_pending) self.event_loop.scheduleHealthCheck(w);
                }
            },
            .client_interrupt => {
                // SIGINT the worker process: Julia's runtime throws InterruptException
                // into the running client task (force-throwing a tight loop after rapid
                // Ctrl-C). Untargeted, but the common worker serves one client.
                if (self.active_clients.get(pid)) |info| {
                    if (info.worker.process.id) |wpid|
                        _ = platform.kill(wpid, platform.SIG.INT);
                }
            },
            .worker_unresponsive => std.debug.print("Worker unresponsive notification for pid {d}\n", .{pid}),
            .worker_exit => {
                if (self.findWorkerByPid(pid)) |w| {
                    std.debug.print("Worker {d} exiting (TTL expired)\n", .{w.id});
                    self.retireWorker(w);
                } else {
                    std.debug.print("Worker (pid {d}) exiting (TTL expired)\n", .{pid});
                }
            },
        }
    }

    fn handleClient(self: *Conductor, socket: posix.socket_t, peer: *const PeerInfo) !void {
        const is_remote = peer.isRemote(self.cfg.transport);
        var request = try self.readClientRequest(socket, is_remote);
        defer request.deinit(self.allocator);
        self.client_counter += 1;
        // Handle special commands
        if (request.parsed.hasSwitch("--help") or request.parsed.hasSwitch("-h")) {
            try self.serveString(socket, CLIENT_HELP);
            return;
        }
        if (request.parsed.hasSwitch("--version") or request.parsed.hasSwitch("-v")) {
            try self.serveString(socket, VERSION_STRING);
            return;
        }
        if (request.parsed.hasSwitch("--status")) {
            try self.serveStatus(socket, request.parsed.getSwitch("--status"), request.flags.tty, request.pid);
            return;
        }
        // Determine sandbox mode
        const SandboxMode = enum { none, remote, local };
        const sandbox_mode: SandboxMode = if (is_remote and (self.cfg.sandbox_remote_clients or request.parsed.hasSwitch("--sandbox")))
            .remote
        else if (request.parsed.hasSwitch("--sandbox"))
            .local
        else
            .none;
        // Platform check: sandboxing requires Linux
        if (sandbox_mode != .none) {
            if (comptime builtin.os.tag != .linux) {
                const msg = if (sandbox_mode == .remote)
                    "Sandboxed workers are only available on Linux. " ++
                        "Remote TCP clients from non-loopback addresses are rejected.\n"
                else
                    "--sandbox requires Linux (user namespaces).\n";
                std.debug.print("Client {d}: sandbox rejected (Linux only)\n", .{self.client_counter});
                try self.serveString(socket, msg);
                return;
            }
            std.debug.print("Client {d}: {s} sandbox\n", .{
                self.client_counter, if (sandbox_mode == .remote) "remote" else "local",
            });
        }
        // Session bypass: allow remote --session=<name> to join existing local workers
        if (sandbox_mode == .remote) {
            const session_label = request.parsed.getSwitch("--session");
            if (session_label != null and session_label.?.len > 0 and self.cfg.sandbox_session_bypass) {
                if (self.findWorkerByLabelGlobal(session_label.?)) |w| {
                    std.debug.print("Client {d}: session bypass — joining local worker {d} (label '{s}')\n", .{
                        self.client_counter, w.id, session_label.?,
                    });
                    if (try self.assignClientToExistingWorker(socket, &request, w)) return;
                }
            }
        }
        // Compute worker key and sandbox bind mounts
        const project_path = request.project orelse "";
        const julia_channel = request.parsed.julia_channel;
        // Thread count is fixed at worker startup, so it's part of pool identity.
        const threads = resolveThreads(&request);
        const tkey = args.packThreads(threads);
        const ch = julia_channel orelse "";
        var rw_binds: [1][]const u8 = undefined;
        const worker_key = switch (sandbox_mode) {
            .none => try std.fmt.allocPrint(self.allocator, "{s}\x00{s}\x00{d}", .{ project_path, ch, tkey }),
            .remote => try std.fmt.allocPrint(self.allocator, "__sandbox__\x00{s}\x00{d}", .{ ch, tkey }),
            .local => blk: {
                const cwd = trimTrailingSlashes(request.cwd);
                const proj = trimTrailingSlashes(project_path);
                // When cwd is inside a non-global project, mount the project rw
                // (subsumes cwd). Otherwise mount just cwd rw.
                const is_named_env = proj.len > 0 and proj[0] == '@';
                const has_local_project = proj.len > 0 and !is_named_env;
                const rw_mount: []const u8 = if (has_local_project and pathCoveredBy(cwd, &.{proj})) proj else cwd;
                rw_binds = .{rw_mount};
                // Key encodes rw mount + project so workers only share when their
                // mount configuration matches.
                break :blk try std.fmt.allocPrint(self.allocator, "__lsandbox__\x00{s}\x00{s}\x00{s}\x00{d}", .{ rw_mount, proj, ch, tkey });
            },
        };
        defer self.allocator.free(worker_key);
        const sandbox: SandboxKind = switch (sandbox_mode) {
            .none => .none,
            .remote => .remote,
            .local => .{ .local = &rw_binds },
        };
        // Validate --sync requires --session=<label>
        if (request.parsed.hasSwitch("--sync")) {
            const session = request.parsed.getSwitch("--session");
            if (session == null or session.?.len == 0) {
                std.debug.print("Client {d}: --sync without --session label, rejecting\n", .{self.client_counter});
                try self.serveString(socket, "--sync requires --session=<label>\n");
                return;
            }
            std.debug.print("Client {d}: sync mode, session='{s}'\n", .{ self.client_counter, session.? });
        }
        // Handle --restart: kill matching workers and report
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
            try self.serveString(socket, msg);
            return;
        }
        // Assign client to worker
        try self.assignClientToWorker(socket, &request, worker_key, threads, sandbox);
    }

    const ClientRequest = struct {
        flags: protocol.client.Flags,
        pid: u32,
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
        // NOTE: client_args ownership transfers to parsed.
        // The Switch structs in parsed.switches contain slices into these strings,
        // so we must NOT free them here. They are freed via request.deinit().
        // Remote clients: always request full env (fingerprint cache is per-machine)
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
        // Remote clients: skip project resolution (filesystem doesn't match)
        const proj = if (is_remote) null else blk: {
            const home_dir = self.environ_map.get("HOME") orelse "";
            break :blk try project.resolve(self.allocator, self.io, &parsed, cached.julia_project, home_dir, cwd);
        };
        return .{
            .flags = flags,
            .pid = pid,
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

    const SandboxKind = union(enum) {
        none,
        remote,
        local: []const []const u8, // rw bind mounts
    };

    fn assignClientToWorker(self: *Conductor, socket: posix.socket_t, request: *const ClientRequest, worker_key: []const u8, threads: args.Threads, sandbox: SandboxKind) !void {
        const list = try self.getWorkerList(worker_key);
        const session_label = request.parsed.getSwitch("--session");
        const is_labeled_session = session_label != null and session_label.?.len > 0;
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
        const port_set = if (self.port_pool) |*pool| blk: {
            break :blk pool.allocate() orelse {
                std.debug.print("Client {d}: port pool exhausted\n", .{self.client_counter});
                return error.PortPoolExhausted;
            };
        } else protocol.PortPool.none;
        errdefer self.releasePortSet(port_set);
        // Remote sandboxed workers: override identity env vars so the
        // worker's withenv(client.env...) doesn't leak the remote HOME etc.
        const sandbox_env = if (sandbox == .remote) try self.buildSandboxClientEnv(request.env) else null;
        defer if (sandbox_env) |e| self.allocator.free(e);
        const client_info = worker.ClientInfo{
            .tty = request.flags.tty,
            .force = is_labeled_session,
            .pid = request.pid,
            .ppid = request.ppid,
            .cwd = if (sandbox == .remote) "/home/sandbox" else request.cwd,
            .env = sandbox_env orelse request.env,
            .switches = request.parsed.switches.items,
            .programfile = request.parsed.program_file,
            .args = request.parsed.program_args,
            .port_set = port_set,
        };
        const now = self.currentTime();
        const assignment = try self.selectWorker(list, &client_info, session_label, is_labeled_session, request.project orelse "", request.parsed.julia_channel, threads, now, sandbox);
        std.debug.print("Assigned client {d} to worker {d}: {s}\n", .{ self.client_counter, assignment.w.id, @tagName(assignment.reason) });
        defer self.allocator.free(assignment.paths.stdin);
        defer self.allocator.free(assignment.paths.stdout);
        defer self.allocator.free(assignment.paths.stderr);
        defer self.allocator.free(assignment.paths.signals);
        assignment.w.last_pinged = now;
        assignment.w.recordPpid(request.ppid, self.cfg.worker_maxclients);
        try self.registerClient(request.pid, self.client_counter, assignment.w, port_set);
        self.bumpCrf(worker_key, now); // count the summons only once the client is tracked
        std.debug.print("Client {d}: sending socket paths to client\n", .{self.client_counter});
        self.sendSocketPaths(socket, assignment.paths);
        std.debug.print("Client {d}: done\n", .{self.client_counter});
        if (self.reserve == null) self.createReserveWorker(null) catch |err| {
            std.debug.print("Warning: failed to create reserve worker: {}\n", .{err});
        };
    }

    /// Assign a remote client to an existing (already-selected) worker.
    /// Used for session bypass where the worker was found via global label search.
    /// Returns false if the worker had already died and was retired, in which
    /// case the caller should fall through to normal worker selection.
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
        // Remote client's cwd doesn't exist on the host — use host home
        const client_info = worker.ClientInfo{
            .tty = request.flags.tty,
            .force = is_labeled_session,
            .pid = request.pid,
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
        try self.registerClient(request.pid, self.client_counter, w, port_set);
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
    ) !WorkerAssignment {
        const want_interactive = for (client_info.switches) |sw| {
            if (std.mem.eql(u8, sw.name, "-i")) break true;
        } else false;
        // 1. Labeled session: join its worker (global, or scoped to an explicit --project)
        if (is_labeled_session) {
            const explicit_project = for (client_info.switches) |sw| {
                if (std.mem.eql(u8, sw.name, "--project")) break true;
            } else false;
            const found = if (explicit_project)
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
        // 4. Spawn new worker
        const w = switch (sandbox) {
            .none => try self.addWorkerToPool(list, project_path, julia_channel, threads, want_interactive),
            .remote => try self.addSandboxedWorkerToPool(list, project_path, julia_channel, threads, &.{}),
            .local => |rw_binds| try self.addSandboxedWorkerToPool(list, project_path, julia_channel, threads, rw_binds),
        };
        if (is_labeled_session and w.session_label == null) {
            std.debug.print("Worker {d}: assigning label '{s}'\n", .{ w.id, session_label.? });
            w.session_label = try self.allocator.dupe(u8, session_label.?);
        }
        self.event_loop.cancelPendingPing(w);
        std.debug.print("Worker {d}: sending client to worker...\n", .{w.id});
        const paths = try w.runClient(self.allocator, client_info);
        std.debug.print("Worker {d}: got socket paths, sending to client\n", .{w.id});
        return .{ .paths = paths, .w = w, .reason = .new_worker };
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

    // A free worker a new labeled session can take over: no clients, no live label,
    // matching interactivity. Prefers the warmest (most recently active); null → spawn.
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

    // Resident size of a worker, or max when unreadable so it's never the lightest.
    fn workerRss(w: *worker.Worker) u64 {
        if (w.process.id) |pid| {
            if (platform.getProcessStats(pid)) |s| return s.rss_bytes;
        }
        return std.math.maxInt(u64);
    }

    // Spare the most-recently-active worker for its ppid owner; among the rest pick
    // the lightest, so heavy workers stay idle and age out. Recency breaks ties.
    fn tryExistingWorkers(self: *Conductor, list: *WorkerList, client_info: *const worker.ClientInfo, interactive: bool, now: i64) ?WorkerAssignment {
        var newest: ?*worker.Worker = null;
        for (list.items) |w| {
            if (!self.isWorkerAvailable(w, interactive, now)) continue;
            if (newest == null or w.last_active > newest.?.last_active) newest = w;
        }
        if (newest == null) return null;

        var pick: ?*worker.Worker = null;
        var pick_rss: u64 = 0;
        for (list.items) |w| {
            if (w == newest.? or !self.isWorkerAvailable(w, interactive, now)) continue;
            const rss = workerRss(w);
            if (pick == null or rss < pick_rss or (rss == pick_rss and w.last_active > pick.?.last_active)) {
                pick = w;
                pick_rss = rss;
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

    pub fn createReserveWorker(self: *Conductor, julia_channel: ?[]const u8) !void {
        const w = try self.allocator.create(worker.Worker);
        // Match the host's JULIA_NUM_THREADS so clients (which usually inherit it)
        // can reuse the reserve — thread count is fixed at Julia startup, and the
        // reuse gate requires an exact match.
        const reserve_threads = if (self.environ_map.get("JULIA_NUM_THREADS")) |v|
            args.parseThreads(v)
        else
            args.threads_none;
        w.* = try worker.Worker.spawn(
            self.allocator,
            self.io,
            &self.cfg,
            self.next_worker_id,
            self.cfg.runtime_dir,
            julia_channel,
            reserve_threads,
            false, // reserve workers are never interactive
        );
        self.next_worker_id += 1;
        self.reserve = w;
        try w.ping();
        std.debug.print("Reserve worker {d} created (pid {d})\n", .{ w.id, platform.getChildPid(w.process) });
    }

    fn addWorkerToPool(self: *Conductor, list: *WorkerList, proj: []const u8, julia_channel: ?[]const u8, threads: args.Threads, interactive: bool) !*worker.Worker {
        const proj_copy = try self.allocator.dupe(u8, proj);
        errdefer self.allocator.free(proj_copy);
        // The reserve serves only a non-interactive request whose threads + channel match.
        const can_use_reserve = if (!interactive) (if (self.reserve) |r| blk: {
            if (!std.meta.eql(threads, r.threads)) break :blk false;
            const reserve_ch = r.julia_channel;
            if (julia_channel == null and reserve_ch == null) break :blk true;
            if (julia_channel != null and reserve_ch != null)
                break :blk std.mem.eql(u8, julia_channel.?, reserve_ch.?);
            break :blk false;
        } else false) else false;
        const w = if (can_use_reserve) blk: {
            const reserve = self.reserve.?;
            self.reserve = null;
            std.debug.print("Assigning reserve worker {d} to project {s}{s}{s}\n", .{
                reserve.id,
                proj,
                if (julia_channel != null) " " else "",
                julia_channel orelse "",
            });
            break :blk reserve;
        } else blk: {
            const new = try self.allocator.create(worker.Worker);
            errdefer self.allocator.destroy(new);
            new.* = try worker.Worker.spawn(
                self.allocator,
                self.io,
                &self.cfg,
                self.next_worker_id,
                self.cfg.runtime_dir,
                julia_channel,
                threads,
                interactive,
            );
            std.debug.print("Spawning {s}worker {d} (pid {d}) for project {s}{s}{s}\n", .{
                if (interactive) "interactive " else "",
                self.next_worker_id,
                platform.getChildPid(new.process),
                proj,
                if (julia_channel != null) " " else "",
                julia_channel orelse "",
            });
            self.next_worker_id += 1;
            break :blk new;
        };
        self.event_loop.cancelPendingPing(w);
        try w.setProject(proj_copy);
        try list.append(self.allocator, w);
        return w;
    }

    /// Search ALL worker lists for a worker with matching session label.
    /// Used for session bypass (remote client joining local worker by label).
    fn findWorkerByLabelGlobal(self: *Conductor, label: []const u8) ?*worker.Worker {
        var it = self.workers.iterator();
        while (it.next()) |entry| {
            if (findWorkerByLabel(entry.value_ptr, label)) |w| return w;
        }
        return null;
    }

    fn addSandboxedWorkerToPool(
        self: *Conductor,
        list: *WorkerList,
        project_path: []const u8,
        julia_channel: ?[]const u8,
        threads: args.Threads,
        rw_binds: []const []const u8,
    ) !*worker.Worker {
        const proj_copy = if (project_path.len > 0) try self.allocator.dupe(u8, project_path) else null;
        errdefer if (proj_copy) |p| self.allocator.free(p);
        const w = try self.allocator.create(worker.Worker);
        errdefer self.allocator.destroy(w);
        // When the project dir isn't already covered by an rw bind, mount it ro
        const proj_ro = if (project_path.len > 0 and !pathCoveredBy(project_path, rw_binds))
            &[_][]const u8{project_path}
        else
            &[_][]const u8{};
        w.* = try worker.Worker.spawnSandboxed(
            self.allocator,
            self.io,
            &self.cfg,
            self.next_worker_id,
            self.cfg.runtime_dir,
            julia_channel,
            threads,
            self.environ_map,
            proj_ro,
            rw_binds,
        );
        std.debug.print("Spawning sandboxed worker {d} (pid {d}){s}{s}\n", .{
            self.next_worker_id,
            platform.getChildPid(w.process),
            if (project_path.len > 0) " for project " else "",
            if (project_path.len > 0) project_path else "",
        });
        self.next_worker_id += 1;
        self.event_loop.cancelPendingPing(w);
        if (proj_copy) |p| try w.setProject(p);
        try list.append(self.allocator, w);
        return w;
    }

    fn trimTrailingSlashes(path: []const u8) []const u8 {
        var end = path.len;
        while (end > 1 and path[end - 1] == '/') end -= 1;
        return path[0..end];
    }

    /// Test whether `path` is equal to or a subdirectory of any entry in `dirs`.
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
        if (self.workers.getPtr(proj)) |list| {
            const count = list.items.len;
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
        return 0;
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
        const pid = w.process.id orelse {
            self.cleanupWorker(w);
            return;
        };
        w.softExit();
        self.pending_kills.append(self.allocator, .{
            .w = w, .pid = pid, .stage = .soft, .deadline = self.currentTime() + retire_grace_s,
        }) catch {
            _ = platform.kill(pid, platform.SIG.KILL);
            _ = platform.waitpidNonBlocking(pid);
            self.cleanupWorker(w);
        };
    }

    // --- Activity signals ---

    fn activityHalfLife(self: *const Conductor) u64 {
        return self.cfg.min_ttl;
    }

    fn bumpCrf(self: *Conductor, key: []const u8, now: i64) void {
        if (self.crf.getPtr(key)) |e| return e.summon(now, self.activityHalfLife());
        const key_copy = self.allocator.dupe(u8, key) catch return;
        self.crf.put(key_copy, .{ .last_update = now }) catch return self.allocator.free(key_copy);
        self.crf.getPtr(key_copy).?.summon(now, self.activityHalfLife());
    }

    fn readCrf(self: *Conductor, key: []const u8, now: i64) f64 {
        const e = self.crf.getPtr(key) orelse return 0;
        return e.read(now, self.activityHalfLife());
    }

    // Eviction warmth of an idle worker: max(crf_norm, occupancy) in [0,1).
    // `key` is the worker's pool key (null for the reserve, which has no crf).
    // Pure, so safe to call from the status renderer.
    pub fn workerActivity(self: *Conductor, w: *const worker.Worker, key: ?[]const u8, now: i64) f64 {
        const crf_norm = if (key) |k| worker.Crf.normalize(self.readCrf(k, now)) else 0;
        return @max(crf_norm, w.occupancy.read(now, self.activityHalfLife()));
    }

    // Read process stats and fold the CPU figure into the worker's meter, timed
    // with the ns clock. `half_life_s` blends into the EWMA (live view); null sets
    // util to the raw rate (one-shot, where two reads a beat apart bracket it).
    pub fn statWorker(self: *Conductor, w: *worker.Worker, half_life_s: ?f64) ?platform.ProcessStats {
        const pid = w.process.id orelse return null;
        const s = platform.getProcessStats(pid) orelse return null;
        const now_ns: i64 = @intCast(Io.Clock.now(.awake, self.io).nanoseconds);
        w.cpu.update(now_ns, s.cpu_seconds, half_life_s);
        return s;
    }

    // One getProcessStats per worker, caching rss and folding cpu into the meter,
    // so the status render reads both off the worker (no re-statting) and stays
    // clock-free. Half-life null sets util to the raw rate (one-shot); a value
    // blends the EWMA (live). Callers: the live/one-shot driver and the test.
    pub fn refreshStats(self: *Conductor, half_life_s: ?f64) void {
        const now_ns: i64 = @intCast(Io.Clock.now(.awake, self.io).nanoseconds);
        var it = self.workers.iterator();
        while (it.next()) |entry| {
            for (entry.value_ptr.items) |w| refreshOne(w, now_ns, half_life_s);
        }
        if (self.reserve) |r| refreshOne(r, now_ns, half_life_s);
    }

    fn refreshOne(w: *worker.Worker, now_ns: i64, half_life_s: ?f64) void {
        const pid = w.process.id orelse return;
        const s = platform.getProcessStats(pid) orelse return;
        w.rss = s.rss_bytes;
        w.cpu.update(now_ns, s.cpu_seconds, half_life_s);
    }

    // Drop crf history. Only ever called for a TTL-culled key (gone cold); a
    // crash/pressure death keeps the key for re-warming, and cleanupWorker — the
    // shared death funnel — has no handle to the crf map, enforcing this.
    fn dropColdKey(self: *Conductor, key: []const u8) void {
        if (self.crf.fetchRemove(key)) |kv| self.allocator.free(kv.key);
    }

    // The conductor-owned idle policy: cull workers past max_ttl regardless of
    // pressure, dropping the crf history of any key left cold.
    pub fn enforceMaxTtl(self: *Conductor) void {
        if (self.cfg.max_ttl == 0) return;
        const now = self.currentTime();
        // Re-scan from the top after each cull: retireWorker mutates the pool.
        while (self.findExpired(now)) |hit| {
            std.debug.print("Worker {d}: idle {d}s >= max TTL {d}s, retiring\n", .{ hit.w.id, now - hit.w.last_active, self.cfg.max_ttl });
            self.retireWorker(hit.w);
            // Order matters: both calls read hit.key, which dropPoolEntry frees,
            // so dropColdKey (a content lookup) must run first.
            if (self.workers.getPtr(hit.key)) |list| {
                if (list.items.len == 0) {
                    self.dropColdKey(hit.key);
                    self.dropPoolEntry(hit.key);
                }
            }
        }
    }

    // Free a pool entry's list backing and map key (callers own any workers in
    // it first; `key` dangles afterward).
    fn dropPoolEntry(self: *Conductor, key: []const u8) void {
        if (self.workers.fetchRemove(key)) |kv| {
            var list = kv.value;
            list.deinit(self.allocator);
            self.allocator.free(kv.key);
        }
    }

    const Expired = struct { w: *worker.Worker, key: []const u8 };

    // One at a time, so the caller can retire (mutating the pool) between calls.
    // The reserve is exempt: it is meant to sit idle ready for the next client, so
    // idle TTL never culls it (memory pressure still can — see collectDiscretionary
    // — after which the next client assignment recreates it).
    fn findExpired(self: *Conductor, now: i64) ?Expired {
        var it = self.workers.iterator();
        while (it.next()) |entry| {
            for (entry.value_ptr.items) |w| {
                if (self.isExpired(w, now)) return .{ .w = w, .key = entry.key_ptr.* };
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
        // Selection pass: read current RSS and rank ascending by value(). An
        // unreadable footprint (size 0) ranks by activity alone — see workerValue.
        for (cands) |*c| {
            if (self.statWorker(c.w, @floatFromInt(self.cfg.ping_interval))) |s| c.size = s.rss_bytes;
            c.value = self.workerValue(c.w, c.key, now, c.size);
        }
        std.sort.pdq(Candidate, cands, {}, lessByValue);
        // Validation pass: where the selection figure was RSS (Linux), refine the
        // bottom 2*cap band with true USS and re-rank. Skipped where getProcessStats
        // already reports the reclaimable footprint cheaply (macOS).
        const band = @min(2 * max_evict_per_episode, cands.len);
        if (!platform.mem_is_reclaimable) {
            for (cands[0..band]) |*c| {
                if (c.w.process.id) |pid| {
                    if (platform.processReclaimable(pid)) |uss| c.size = uss;
                }
                c.value = self.workerValue(c.w, c.key, now, c.size);
            }
            std.sort.pdq(Candidate, cands[0..band], {}, lessByValue);
        }
        // Retire the true bottom, re-checking each is still a valid victim (the
        // rank snapshot may predate an assignment from a prior CQE).
        var evicted: usize = 0;
        for (cands[0..band]) |c| {
            if (evicted >= max_evict_per_episode) break;
            if (!self.inPressureBand(c.w, now)) continue;
            if (c.size == 0)
                std.debug.print("Worker {d}: evicting under memory pressure (value={d:.5}, size n/a)\n", .{ c.w.id, c.value })
            else
                std.debug.print("Worker {d}: evicting under memory pressure (value={d:.5}, {d}MB)\n", .{ c.w.id, c.value, c.size >> 20 });
            self.retireWorker(c.w);
            evicted += 1;
        }
    }

    // Idle in-band workers (+ the reserve), capped at episode_capacity.
    fn collectDiscretionary(self: *Conductor, buf: []Candidate, now: i64) []Candidate {
        var n: usize = 0;
        var it = self.workers.iterator();
        while (it.next()) |entry| {
            for (entry.value_ptr.items) |w| {
                if (n >= buf.len) {
                    std.debug.print("Eviction episode: discretionary set exceeds cap; ranking first {d} only\n", .{buf.len});
                    return buf[0..n];
                }
                if (self.inPressureBand(w, now)) {
                    buf[n] = .{ .w = w, .key = entry.key_ptr.*, .size = 0, .value = 0 };
                    n += 1;
                }
            }
        }
        // The keyless reserve (crf=0) is the cheapest thing to drop under pressure.
        if (self.reserve) |r| {
            if (n < buf.len and self.inPressureBand(r, now)) {
                buf[n] = .{ .w = r, .key = "", .size = 0, .value = 0 };
                n += 1;
            }
        }
        return buf[0..n];
    }

    // Idle age of a cullable worker, or null if it has clients or a live label.
    fn cullableAge(self: *Conductor, w: *worker.Worker, now: i64) ?u64 {
        if (w.active_clients > 0) return null;
        if (w.session_label != null and !self.isLabelExpired(w, now)) return null;
        return @intCast(@max(0, now - w.last_active));
    }
    fn inPressureBand(self: *Conductor, w: *worker.Worker, now: i64) bool {
        const age = self.cullableAge(w, now) orelse return false;
        return age >= self.cfg.min_ttl and age < self.cfg.max_ttl;
    }
    fn isExpired(self: *Conductor, w: *worker.Worker, now: i64) bool {
        const age = self.cullableAge(w, now) orelse return false;
        return age >= self.cfg.max_ttl;
    }

    // value(w) = activity / size_MiB, evicted lowest-first. An unmeasured
    // footprint (size 0: no /proc, or a platform without per-process stats)
    // falls back to activity alone, so it ranks well above any measured worker
    // and is spared rather than evicted on a fabricated size — and on a
    // footprint-less platform all workers compare by activity uniformly.
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
            if (platform.waitpidNonBlocking(pk.pid).exited) {
                self.cleanupWorker(pk.w);
                _ = self.pending_kills.swapRemove(i);
                continue;
            }
            if (now >= pk.deadline) switch (pk.stage) {
                .soft => {
                    _ = platform.kill(pk.pid, platform.SIG.TERM);
                    pk.stage = .term;
                    pk.deadline = now + retire_grace_s;
                },
                .term => {
                    _ = platform.kill(pk.pid, platform.SIG.KILL);
                    self.cleanupWorker(pk.w);
                    _ = self.pending_kills.swapRemove(i);
                    continue;
                },
            };
            i += 1;
        }
    }

    fn removeActiveClientsForWorker(self: *Conductor, w: *worker.Worker) void {
        // Collect-then-remove loop: repeat until no more matches, since
        // the fixed buffer may not hold all entries in one pass.
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
            for (to_remove[0..remove_count]) |pid| {
                _ = self.active_clients.remove(pid);
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

    /// Build a client env slice with identity vars overridden for sandbox.
    /// Caller must free the returned slice (but not the individual EnvVars,
    /// which point into the original env or static strings).
    fn buildSandboxClientEnv(self: *Conductor, env: []const worker.EnvVar) ![]const worker.EnvVar {
        // Upper bound: original env + identity overrides
        const result = try self.allocator.alloc(worker.EnvVar, env.len + sandbox_identity_vars.len);
        var n: usize = 0;
        for (env) |e| {
            var is_identity = false;
            for (sandbox_identity_keys) |k|
                if (std.mem.eql(u8, e.key, k)) { is_identity = true; };
            if (!is_identity) { result[n] = e; n += 1; }
        }
        for (sandbox_identity_vars) |e| { result[n] = e; n += 1; }
        return result[0..n];
    }

    // --- Port pool ---

    fn releasePortSet(self: *Conductor, port_set: u16) void {
        if (port_set != protocol.PortPool.none) {
            if (self.port_pool) |*pool| pool.release(port_set);
        }
    }

    // --- Client tracking ---

    fn registerClient(self: *Conductor, pid: u32, client_num: u32, w: *worker.Worker, port_set: u16) !void {
        const now_us: i64 = @intCast(@divTrunc(Io.Clock.now(.awake, self.io).nanoseconds, 1000));
        if (!w.occupancy.busy) w.occupancy.attach(@divTrunc(now_us, 1_000_000), self.activityHalfLife());
        try self.active_clients.put(pid, .{ .worker = w, .client_num = client_num, .start_time_us = now_us, .port_set = port_set });
    }

    fn clientDone(self: *Conductor, pid: u32) ?*worker.Worker {
        if (self.active_clients.fetchRemove(pid)) |entry| {
            const info = entry.value;
            self.releasePortSet(info.port_set);
            if (info.worker.active_clients > 0) info.worker.active_clients -= 1;
            const now_us: i64 = @intCast(@divTrunc(Io.Clock.now(.awake, self.io).nanoseconds, 1000));
            const now_s = @divTrunc(now_us, 1_000_000);
            info.worker.last_active = now_s;
            if (info.worker.active_clients == 0) info.worker.occupancy.detach(now_s, self.activityHalfLife());
            const duration_us = now_us - info.start_time_us;
            const duration_s: u64 = @intCast(@divTrunc(duration_us, 1_000_000));
            const duration_ms: u64 = @intCast(@divTrunc(@mod(duration_us, 1_000_000), 1_000));
            std.debug.print("Client {d} disconnected; worker: {d}, duration: {d}.{d:0>3}s\n", .{
                info.client_num,
                info.worker.id,
                duration_s,
                duration_ms,
            });
            if (info.worker.active_clients == 0) return info.worker;
        }
        return null;
    }

    pub fn syncWorkerClients(self: *Conductor, w: *worker.Worker) void {
        var pids: [32]u32 = undefined;
        var count: u16 = 0;
        var it = self.active_clients.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.worker == w and count < 32) {
                pids[count] = entry.key_ptr.*;
                count += 1;
            }
        }
        const remaining = w.syncClients(pids[0..count]) catch |err| {
            std.debug.print("Worker {d}: sync_clients failed: {}\n", .{ w.id, err });
            self.retireWorker(w);
            return;
        };
        w.active_clients = remaining;
        // Keep the occupancy busy/idle transition consistent with the synced count.
        if (remaining == 0 and w.occupancy.busy) {
            w.occupancy.detach(self.currentTime(), self.activityHalfLife());
        } else if (remaining > 0 and !w.occupancy.busy) {
            w.occupancy.attach(self.currentTime(), self.activityHalfLife());
        }
        std.debug.print("Worker {d}: sync complete, {d} active clients\n", .{ w.id, remaining });
    }

    // --- Shutdown ---

    pub fn gracefulShutdown(self: *Conductor) void {
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
            for (entry.value_ptr.items) |w| {
                if (w.process.id) |id| _ = platform.kill(id, sig);
            }
        }
        if (self.reserve) |r| {
            if (r.process.id) |id| _ = platform.kill(id, sig);
        }
        // Workers mid-retirement are no longer in the pool but still dying.
        for (self.pending_kills.items) |pk| _ = platform.kill(pk.pid, sig);
    }

    fn anyWorkerAlive(self: *Conductor) bool {
        var it = self.workers.iterator();
        while (it.next()) |entry| {
            for (entry.value_ptr.items) |w| {
                if (w.process.id) |pid| {
                    const result = platform.waitpidNonBlocking(pid);
                    if (result.exited) continue;
                    if (result.pid == 0) return true;
                }
            }
        }
        for (self.pending_kills.items) |pk| {
            if (!platform.waitpidNonBlocking(pk.pid).exited) return true;
        }
        if (self.reserve) |r| {
            if (r.process.id) |pid| {
                const result = platform.waitpidNonBlocking(pid);
                if (result.exited) return false;
                if (result.pid == 0) return true;
            }
        }
        return false;
    }

    // --- Utilities ---

    pub fn processPong(self: *Conductor, w: *worker.Worker, pong_buf: *const [5]u8) void {
        w.last_pinged = self.currentTime();
        const worker_count = std.mem.readInt(u16, pong_buf[3..5], .little);
        if (worker_count != w.active_clients) {
            std.debug.print("Worker {d}: client count mismatch (worker={d}, conductor={d}), syncing\n", .{
                w.id, worker_count, w.active_clients,
            });
            self.syncWorkerClients(w);
        }
    }

    pub fn currentTime(self: *Conductor) i64 {
        return platform.timeSeconds(self.io);
    }

    pub fn createServer(self: *Conductor) !Io.net.Server {
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

    // The four stdio streams of a session, owning their listeners and port-set
    // reservation; `deinit` closes everything.
    const Stream = enum(usize) { stdin, stdout, stderr, signals };
    const ClientStreams = struct {
        c: *Conductor,
        listeners: [4]protocol.Listener,
        conns: [4]Io.net.Stream,
        port_set_idx: u16,
        // Owned socket paths. createListener returns a slice into a caller's
        // stack buffer; a held live connection (and the struct's own moves)
        // outlive it, so store length-bounded copies and never alias.
        addrs: [4][std.fs.max_path_bytes]u8 = undefined,
        addr_lens: [4]usize = .{ 0, 0, 0, 0 },

        fn fd(self: *const ClientStreams, s: Stream) posix.socket_t {
            return self.conns[@intFromEnum(s)].socket.handle;
        }

        fn deinit(self: *ClientStreams) void {
            const io = self.c.io;
            for (self.conns) |conn| conn.close(io);
            for (&self.listeners, self.addrs[0..], self.addr_lens) |*l, *addr, len| {
                if (self.c.cfg.transport == .unix) Io.Dir.deleteFileAbsolute(io, addr[0..len]) catch {};
                l.server.deinit(io);
            }
            self.c.releasePortSet(self.port_set_idx);
        }
    };

    // Create the four response listeners, hand their addresses to the client,
    // and accept the connections it opens back. Caller owns the result and must
    // `deinit` it; on any failure all partial resources are released first.
    fn openClientStreams(self: *Conductor, client_socket: posix.socket_t) !ClientStreams {
        const mode = self.cfg.transport;
        const bind = self.cfg.bind_address;
        const rdir = self.cfg.runtime_dir;
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
        var bufs: [4][std.fs.max_path_bytes]u8 = undefined;
        var listeners: [4]protocol.Listener = undefined;
        var created: usize = 0;
        errdefer for (listeners[0..created]) |*l| {
            if (mode == .unix) Io.Dir.deleteFileAbsolute(self.io, l.addr) catch {};
            l.server.deinit(self.io);
        };
        for (0..4) |i| {
            listeners[i] = if (ports) |p|
                try protocol.listenTcp(self.io, bind, p[i], &bufs[i])
            else
                try createListener(self.io, mode, rdir, suffixes[i], bind, &bufs[i]);
            created += 1;
        }
        self.sendSocketPaths(client_socket, .{
            .stdin = listeners[0].addr, .stdout = listeners[1].addr,
            .stderr = listeners[2].addr, .signals = listeners[3].addr,
        });
        var conns: [4]Io.net.Stream = undefined;
        var accepted: usize = 0;
        errdefer for (conns[0..accepted]) |c| c.close(self.io);
        for (0..4) |i| {
            conns[i] = try listeners[i].server.accept(self.io);
            accepted += 1;
        }
        var streams = ClientStreams{ .c = self, .listeners = listeners, .conns = conns, .port_set_idx = port_set_idx };
        for (listeners, &streams.addrs, &streams.addr_lens) |l, *addr, *len| {
            @memcpy(addr[0..l.addr.len], l.addr);
            len.* = l.addr.len;
        }
        return streams;
    }

    fn serveString(self: *Conductor, client_socket: posix.socket_t, content: []const u8) !void {
        var streams = try self.openClientStreams(client_socket);
        defer streams.deinit();
        self.finishStreams(&streams, content);
    }

    fn isLiveStatus(format: ?[]const u8) bool {
        return format != null and std.mem.eql(u8, format.?, "live");
    }

    // Serve the `--status` report. A TTY client is colour-probed first so stat
    // gradients track its palette; a non-answering terminal degrades to the flat
    // report. `--status=live` holds the connection for in-place repaints rather
    // than finishing after one frame.
    fn serveStatus(self: *Conductor, client_socket: posix.socket_t, format: ?[]const u8, tty: bool, pid: u32) !void {
        var streams = try self.openClientStreams(client_socket);
        var held = false;
        defer if (!held) streams.deinit();
        const live = tty and isLiveStatus(format);
        const palette: ?pal.Palette = if (tty and (format == null or live)) probePalette(&streams) else null;
        // A styled TTY one-shot is deferred so its CPU meter resolves over a beat;
        // live holds for repaints; everything else renders once and closes.
        if (tty and format == null) {
            try self.subscribeOneshot(streams, palette, pid);
            held = true;
            return;
        }
        const report = self.renderStatus(format, tty, palette) catch |err| {
            std.debug.print("Status: render failed: {}\n", .{err});
            self.finishStreams(&streams, "Failed to generate status report.\n");
            return;
        };
        defer self.allocator.free(report.bytes);
        platform.write(streams.fd(.stdout), report.bytes);
        if (live) {
            try self.subscribeLive(streams, palette, pid, report.lines);
            held = true; // ownership moved into live_clients
        } else {
            self.closeStreams(&streams);
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
    // One self-perpetuating timer drives live `--status` repaints. A change with
    // no timer armed repaints immediately (leading edge); further changes only
    // set `dirty`, coalescing a burst. Each fire repaints, then re-arms fast if
    // more changes arrived, else at the slow heartbeat to refresh stat numbers,
    // and stops once no clients remain.
    const live_debounce_ms = 100;
    const live_heartbeat_ms = 1000;
    const live_cursor_hide = "\x1b[?25l";
    const live_cursor_show = "\x1b[?25h";
    // Live meter half-life: ~1.4s fades prior activity tracking the 1s heartbeat.
    const live_cpu_half_life: f64 = 1.4;

    // First frame was sent by serveStatus; hide the cursor for the live view and
    // start the heartbeat (dirty stays false, so no redundant immediate repaint).
    fn subscribeLive(self: *Conductor, streams: ClientStreams, palette: ?pal.Palette, pid: u32, lines: usize) !void {
        try self.live_clients.append(self.allocator, .{
            .streams = streams,
            .palette = palette,
            .pid = pid,
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

    // One-shot CPU-resolved status: prime every meter now, hold the connection,
    // and fire a single frame after a beat. fireLive's refreshStats takes the second
    // reading, so util lands at the busy-cores rate over the window. No frame is
    // drawn yet and the cursor is left alone, so the delayed frame is a static report.
    fn subscribeOneshot(self: *Conductor, streams: ClientStreams, palette: ?pal.Palette, pid: u32) !void {
        self.refreshStats(null); // first reading; the deferred fire takes the second
        try self.live_clients.append(self.allocator, .{
            .streams = streams,
            .palette = palette,
            .pid = pid,
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

    // A disconnected live client is reaped via its exit/interrupt notification; a
    // one-shot disconnects itself in repaintOne after its single frame, so an
    // all-one-shot fire leaves no clients and the timer stops.
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

    // Paint one frame; returns whether the client stays subscribed. A one-shot
    // gets its single CPU-resolved frame, then is closed and reaped (false).
    fn repaintOne(self: *Conductor, lc: *LiveClient) bool {
        const report = self.renderStatus("live", true, lc.palette) catch return !lc.oneshot;
        defer self.allocator.free(report.bytes);
        const fd = lc.streams.fd(.stdout);
        // Wrap in a synchronized update (DEC 2026) so the terminal applies the
        // whole frame atomically — no tearing. ESC[<n>F moves up to column 0 of
        // the prior frame; ESC[0J clears down so a shorter frame leaves no tail.
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
        self.closeStreams(&lc.streams);
        lc.streams.deinit();
        return false;
    }

    // Remove the live client with `pid` (if any), restoring its cursor. Returns
    // whether one was found.
    fn dropLiveClient(self: *Conductor, pid: u32) bool {
        for (self.live_clients.items, 0..) |*lc, i| {
            if (lc.pid != pid) continue;
            var removed = self.live_clients.swapRemove(i);
            // Newline below the final frame, then restore the cursor, so the
            // shell prompt lands cleanly under the frozen snapshot.
            platform.write(removed.streams.fd(.stdout), "\r\n" ++ live_cursor_show);
            removed.streams.deinit();
            return true;
        }
        return false;
    }

    // Write `content` to stdout, then shut down stdout/stderr and signal a clean
    // exit. Shared by the report and failure paths.
    fn finishStreams(self: *Conductor, streams: *ClientStreams, content: []const u8) void {
        platform.write(streams.fd(.stdout), content);
        self.closeStreams(streams);
    }

    // Shut down stdout/stderr and signal a clean client exit (no content write).
    fn closeStreams(self: *Conductor, streams: *ClientStreams) void {
        streams.conns[@intFromEnum(Stream.stdout)].shutdown(self.io, .send) catch {};
        streams.conns[@intFromEnum(Stream.stderr)].shutdown(self.io, .send) catch {};
        platform.write(streams.fd(.signals), &[_]u8{ protocol.signals.exit, 0x01, 0x00 });
        streams.conns[@intFromEnum(Stream.signals)].shutdown(self.io, .send) catch {};
    }

    // Probe the terminal palette: enter raw mode (replies un-echoed), write the
    // queries, read stdin until the CSI 5n sentinel or a byte cap. Cooked mode is
    // left for the client's exitClient to restore. Null if no colour reply parsed.
    fn probePalette(streams: *ClientStreams) ?pal.Palette {
        const stdin = streams.fd(.stdin);
        const signals = streams.fd(.signals);
        platform.write(signals, &[_]u8{ protocol.signals.raw_mode, 0x01, 0x01 });
        var qbuf: [pal.query_buf_len]u8 = undefined;
        platform.write(streams.fd(.stdout), pal.writeQueries(&qbuf));
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
        // In TCP mode, send just the port — the client uses the conductor host
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
    if (!cfg.sandbox_remote_clients)
        std.debug.print(" - Sandbox remote clients: disabled\n", .{});
    if (cfg.sandbox_session_bypass)
        std.debug.print(" - Sandbox session bypass: enabled\n", .{});
    // The runtime dir is needed even in TCP mode: the conductor↔worker setup
    // socket (wsetup.sock) is always a unix socket created there (see worker.zig).
    try Io.Dir.cwd().createDirPath(io, cfg.runtime_dir);
    conductor.cleanupRuntimeDir();
    try conductor.run();
}
