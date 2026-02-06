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
pub const worker = @import("worker.zig");

pub const eventLoopImpl = if (builtin.os.tag == .linux)
    @import("eloop/linux.zig")
else if (builtin.os.tag.isBSD())
    @import("eloop/kqueue.zig")
else
    @compileError("unsupported OS");

const readExact = protocol.readExact;
const randomSocketPath = protocol.randomSocketPath;
const EventLocation = protocol.EventLocation;

const VERSION = blk: {
    const project_toml = @embedFile("Project.toml");
    const marker = "\nversion = \"";
    const start = if (std.mem.indexOf(u8, project_toml, marker)) |i| i + marker.len else unreachable;
    const end = if (std.mem.indexOfPos(u8, project_toml, start, "\"")) |i| i else unreachable;
    break :blk project_toml[start..end];
};

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
    \\ --project[=<dir>|@.]       Set <dir> as the home project/environment
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
    \\ --session[=<label>]        Reuse worker state in Main module. With a label,
    \\                            multiple clients can share the same session.
    \\ --revise[=yes|no*]         Enable or disable Revise.jl integration
    \\ --restart                  Kill workers for the project and exit
    \\
++ DAEMON_MANAGEMENT_HELP;

// ============================================================================
// Global state for cleanup
// ============================================================================

pub var g_socket_path: [:0]const u8 = "";
pub var g_pid_path: [:0]const u8 = "";

// ============================================================================
// Types
// ============================================================================

const WorkerList = std.array_list.Aligned(*worker.Worker, null);

const ActiveClientInfo = struct {
    worker: *worker.Worker,
    client_num: u32,
    start_time_us: i64,
};

const ActiveClientMap = std.AutoHashMap(u32, ActiveClientInfo);

const AssignReason = enum {
    session_label,
    ppid_affinity,
    recent_worker,
    new_worker,

    pub fn description(self: AssignReason) []const u8 {
        return switch (self) {
            .session_label => "session label match",
            .ppid_affinity => "PPID affinity",
            .recent_worker => "recent worker",
            .new_worker => "new worker",
        };
    }
};

const WorkerAssignment = struct {
    paths: worker.Worker.SocketPaths,
    w: *worker.Worker,
    reason: AssignReason,
};

// ============================================================================
// Conductor
// ============================================================================

pub const Conductor = struct {
    io: Io,
    allocator: Allocator,
    cfg: config.Config,
    environ_map: *std.process.Environ.Map,
    cache: env_cache.EnvCache,
    workers: std.StringHashMap(WorkerList),
    active_clients: ActiveClientMap,
    reserve: ?*worker.Worker,
    next_worker_id: u32,
    client_counter: u32,
    event_loop: eventLoopImpl.EventLoop,

    // ========================================================================
    // Lifecycle
    // ========================================================================

    pub fn init(io: Io, allocator: Allocator, cfg: config.Config, environ_map: *std.process.Environ.Map) !Conductor {
        return .{
            .io = io,
            .allocator = allocator,
            .cfg = cfg,
            .environ_map = environ_map,
            .cache = env_cache.EnvCache.init(allocator),
            .workers = std.StringHashMap(WorkerList).init(allocator),
            .active_clients = ActiveClientMap.init(allocator),
            .reserve = null,
            .next_worker_id = 0,
            .client_counter = 0,
            .event_loop = try eventLoopImpl.EventLoop.init(64),
        };
    }

    pub fn deinit(self: *Conductor) void {
        self.event_loop.deinit();
        self.cache.deinit();
        self.active_clients.deinit();
        if (self.reserve) |r| {
            r.deinit();
            self.allocator.destroy(r);
        }
        var it = self.workers.iterator();
        while (it.next()) |entry| {
            for (entry.value_ptr.items) |w| {
                w.deinit();
                self.allocator.destroy(w);
            }
            entry.value_ptr.deinit(self.allocator);
            self.allocator.free(entry.key_ptr.*);
        }
        self.workers.deinit();
        if (g_socket_path.len > 0) self.allocator.free(g_socket_path);
        if (g_pid_path.len > 0) self.allocator.free(g_pid_path);
        self.cfg.deinit();
    }

    pub fn run(self: *Conductor) !void {
        g_socket_path = try self.allocator.dupeZ(u8, self.cfg.socket_path);
        const pid_path = try std.fmt.allocPrint(self.allocator, "{s}/conductor.pid", .{self.cfg.runtime_dir});
        g_pid_path = try self.allocator.dupeZ(u8, pid_path);
        self.allocator.free(pid_path);
        try eventLoopImpl.installSignalHandlers();
        defer eventLoopImpl.cleanupSignalHandlers();
        self.writePidFile();
        defer Io.Dir.deleteFileAbsolute(self.io, g_pid_path) catch {};
        var server = try self.createServer();
        defer server.deinit(self.io);
        defer Io.Dir.deleteFileAbsolute(self.io, self.cfg.socket_path) catch {};
        std.debug.print("Conductor listening on {s}\n", .{self.cfg.socket_path});
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
            dir.deleteFile(self.io, entry.name) catch {};
        }
    }

    // --- Connection handling ---

    pub fn handleConnectionFd(self: *Conductor, socket: posix.socket_t) !void {
        var magic_buf: [4]u8 = undefined;
        try readExact(socket, &magic_buf);
        const magic = std.mem.readInt(u32, &magic_buf, .little);
        if (magic == protocol.client.magic) {
            try self.handleClient(socket);
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
        switch (@as(protocol.notification.Type, @enumFromInt(buf[0]))) {
            .client_done => _ = self.clientDone(pid),
            .client_exit => {
                if (self.clientDone(pid)) |w| {
                    if (!w.ping_pending) self.event_loop.scheduleHealthCheck(w);
                }
            },
            .worker_unresponsive => std.debug.print("Worker unresponsive notification for pid {d}\n", .{pid}),
            .worker_exit => {
                if (self.findWorkerIdByPid(pid)) |id| {
                    std.debug.print("Worker {d} exiting (TTL expired)\n", .{id});
                } else {
                    std.debug.print("Worker (pid {d}) exiting (TTL expired)\n", .{pid});
                }
            },
        }
    }

    fn handleClient(self: *Conductor, socket: posix.socket_t) !void {
        var request = try self.readClientRequest(socket);
        defer request.deinit(self.allocator);
        self.client_counter += 1;
        // Handle special commands
        if (request.parsed.hasSwitch("--help") or request.parsed.hasSwitch("-h")) {
            try self.serveString(socket, CLIENT_HELP);
            return;
        }
        if (request.parsed.hasSwitch("--version") or request.parsed.hasSwitch("-v")) {
            const version_str = try std.fmt.allocPrint(self.allocator, "juliaclient {s}\n", .{VERSION});
            defer self.allocator.free(version_str);
            try self.serveString(socket, version_str);
            return;
        }
        const project_path = request.project orelse "";
        const julia_channel = request.parsed.julia_channel;
        const worker_key = try self.makeWorkerKey(project_path, julia_channel);
        defer self.allocator.free(worker_key);
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
        // Normal client: assign to worker
        try self.assignClientToWorker(socket, &request, worker_key);
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

    fn readClientRequest(self: *Conductor, socket: posix.socket_t) !ClientRequest {
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
        const cached = self.cache.lookup(fingerprint) orelse blk: {
            platform.write(socket, &[_]u8{protocol.client.env_request});
            const full_env = try self.readFullEnv(&r);
            break :blk self.cache.insert(fingerprint, full_env);
        };
        var parsed = try args.parse(self.allocator, client_args);
        errdefer parsed.deinit();
        const home_dir = self.environ_map.get("HOME") orelse "";
        const proj = try project.resolve(self.allocator, self.io, &parsed, cached.julia_project, home_dir, cwd);
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

    fn assignClientToWorker(self: *Conductor, socket: posix.socket_t, request: *const ClientRequest, worker_key: []const u8) !void {
        const list = try self.getWorkerList(worker_key);
        const session_label = request.parsed.getSwitch("--session");
        const is_labeled_session = session_label != null and session_label.?.len > 0;
        std.debug.print("Client {d}; pid: {d}{s}{s}{s}{s}, project: {s}\n", .{
            self.client_counter,
            request.pid,
            if (request.parsed.julia_channel != null) ", julia: " else "",
            request.parsed.julia_channel orelse "",
            if (session_label != null) ", session: " else "",
            if (session_label) |l| (if (l.len > 0) l else ".") else "",
            request.project orelse "(default)",
        });
        const client_info = worker.ClientInfo{
            .tty = request.flags.tty,
            .force = is_labeled_session,
            .pid = request.pid,
            .ppid = request.ppid,
            .cwd = request.cwd,
            .env = request.env,
            .switches = request.parsed.switches.items,
            .programfile = request.parsed.program_file,
            .args = request.parsed.program_args,
        };
        const now = self.currentTime();
        const assignment = try self.selectWorker(list, &client_info, session_label, is_labeled_session, request.project orelse "", request.parsed.julia_channel, now);
        std.debug.print("Assigned client {d} to worker {d}: {s}\n", .{ self.client_counter, assignment.w.id, assignment.reason.description() });
        defer self.allocator.free(assignment.paths.stdio);
        defer self.allocator.free(assignment.paths.signals);
        assignment.w.last_pinged = now;
        assignment.w.recordPpid(request.ppid, self.cfg.worker_maxclients);
        try self.registerClient(request.pid, self.client_counter, assignment.w);
        self.sendSocketPaths(socket, assignment.paths.stdio, assignment.paths.signals);
    }

    // ========================================================================
    // Worker selection
    // ========================================================================

    fn selectWorker(
        self: *Conductor,
        list: *WorkerList,
        client_info: *const worker.ClientInfo,
        session_label: ?[]const u8,
        is_labeled_session: bool,
        project_path: []const u8,
        julia_channel: ?[]const u8,
        now: i64,
    ) !WorkerAssignment {
        // 1. Labeled session: find worker with matching label
        if (is_labeled_session) {
            if (findWorkerByLabel(list, session_label.?)) |w| {
                if (self.tryAssignWorker(w, client_info, .session_label)) |a| return a;
            }
        }
        // 2. PPID-affinity
        if (self.findWorkerByPpid(list, client_info.ppid, now)) |w| {
            if (self.tryAssignWorker(w, client_info, .ppid_affinity)) |a| return a;
        }
        // 3. Second-most-recent available worker
        if (self.tryExistingWorkers(list, client_info, now)) |a| return a;
        // 4. Spawn new worker
        const w = try self.addWorkerToPool(list, project_path, julia_channel);
        if (is_labeled_session and w.session_label == null) {
            std.debug.print("Worker {d}: assigning label '{s}'\n", .{ w.id, session_label.? });
            w.session_label = try self.allocator.dupe(u8, session_label.?);
        }
        self.event_loop.cancelPendingPing(w);
        return .{ .paths = try w.runClient(self.allocator, client_info), .w = w, .reason = .new_worker };
    }

    fn isWorkerAvailable(self: *Conductor, w: *worker.Worker, now: i64) bool {
        const max = self.cfg.worker_maxclients;
        if (max != 0 and w.active_clients >= max) return false;
        if (w.session_label != null and !self.isLabelExpired(w, now)) return false;
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

    fn findWorkerByPpid(self: *Conductor, list: *WorkerList, ppid: u32, now: i64) ?*worker.Worker {
        for (list.items) |w| {
            if (!self.isWorkerAvailable(w, now)) continue;
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

    fn tryExistingWorkers(self: *Conductor, list: *WorkerList, client_info: *const worker.ClientInfo, now: i64) ?WorkerAssignment {
        var best: ?*worker.Worker = null;
        var second: ?*worker.Worker = null;
        for (list.items) |w| {
            if (!self.isWorkerAvailable(w, now)) continue;
            if (best == null or w.last_active > best.?.last_active) {
                second = best;
                best = w;
            } else if (second == null or w.last_active > second.?.last_active) {
                second = w;
            }
        }
        const chosen = second orelse best orelse return null;
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
                self.killUnresponsiveWorker(w);
                return true;
            },
            else => return false,
        }
    }

    // ========================================================================
    // Worker pool management
    // ========================================================================

    pub fn createReserveWorker(self: *Conductor, julia_channel: ?[]const u8) !void {
        const w = try self.allocator.create(worker.Worker);
        w.* = try worker.Worker.spawn(
            self.allocator,
            self.io,
            &self.cfg,
            self.next_worker_id,
            self.cfg.runtime_dir,
            julia_channel,
        );
        self.next_worker_id += 1;
        self.reserve = w;
        try w.ping();
        std.debug.print("Reserve worker {d} created (pid {d})\n", .{ w.id, platform.getChildPid(w.process) });
    }

    fn addWorkerToPool(self: *Conductor, list: *WorkerList, proj: []const u8, julia_channel: ?[]const u8) !*worker.Worker {
        const proj_copy = try self.allocator.dupe(u8, proj);
        errdefer self.allocator.free(proj_copy);
        const can_use_reserve = if (self.reserve) |r| blk: {
            const reserve_ch = r.julia_channel;
            if (julia_channel == null and reserve_ch == null) break :blk true;
            if (julia_channel != null and reserve_ch != null)
                break :blk std.mem.eql(u8, julia_channel.?, reserve_ch.?);
            break :blk false;
        } else false;
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
            );
            std.debug.print("Spawning worker {d} (pid {d}) for project {s}{s}{s}\n", .{
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
        if (self.reserve == null) self.createReserveWorker(null) catch |err| {
            std.debug.print("Warning: failed to create reserve worker: {}\n", .{err});
        };
        return w;
    }

    fn killWorkersForProject(self: *Conductor, proj: []const u8) usize {
        if (self.workers.getPtr(proj)) |list| {
            const count = list.items.len;
            for (list.items) |w| {
                self.removeActiveClientsForWorker(w);
                w.softExit();
                w.deinit();
                self.allocator.destroy(w);
            }
            list.deinit(self.allocator);
            _ = self.workers.remove(proj);
            return count;
        }
        return 0;
    }

    pub fn killUnresponsiveWorker(self: *Conductor, w: *worker.Worker) void {
        std.debug.print("Killing unresponsive worker {d}\n", .{w.id});
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
        if (w.process.id) |id| _ = platform.kill(id, platform.SIG.KILL);
        w.deinit();
        self.allocator.destroy(w);
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

    fn makeWorkerKey(self: *Conductor, proj: []const u8, julia_channel: ?[]const u8) ![]const u8 {
        if (julia_channel) |ch| {
            return try std.fmt.allocPrint(self.allocator, "{s}\x00{s}", .{ proj, ch });
        }
        return try self.allocator.dupe(u8, proj);
    }

    fn getWorkerList(self: *Conductor, key: []const u8) !*WorkerList {
        if (!self.workers.contains(key)) {
            const key_copy = try self.allocator.dupe(u8, key);
            errdefer self.allocator.free(key_copy);
            try self.workers.put(key_copy, .empty);
        }
        return self.workers.getPtr(key).?;
    }

    fn findWorkerIdByPid(self: *Conductor, pid: u32) ?u32 {
        var it = self.workers.iterator();
        while (it.next()) |entry| {
            for (entry.value_ptr.items) |w| {
                if (platform.getChildPid(w.process) == pid) return w.id;
            }
        }
        if (self.reserve) |r| {
            if (platform.getChildPid(r.process) == pid) return r.id;
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
            self.allocator.free(label);
            w.session_label = null;
        }
    }

    // ========================================================================
    // Client tracking
    // ========================================================================

    fn registerClient(self: *Conductor, pid: u32, client_num: u32, w: *worker.Worker) !void {
        const now_us: i64 = @intCast(@divTrunc((Io.Clock.now(.awake, self.io) catch Io.Timestamp{ .nanoseconds = 0 }).nanoseconds, 1000));
        try self.active_clients.put(pid, .{ .worker = w, .client_num = client_num, .start_time_us = now_us });
    }

    fn clientDone(self: *Conductor, pid: u32) ?*worker.Worker {
        if (self.active_clients.fetchRemove(pid)) |entry| {
            const info = entry.value;
            if (info.worker.active_clients > 0) info.worker.active_clients -= 1;
            const now_us: i64 = @intCast(@divTrunc((Io.Clock.now(.awake, self.io) catch Io.Timestamp{ .nanoseconds = 0 }).nanoseconds, 1000));
            info.worker.last_active = @divTrunc(now_us, 1_000_000);
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
            self.killUnresponsiveWorker(w);
            return;
        };
        w.active_clients = remaining;
        std.debug.print("Worker {d}: sync complete, {d} active clients\n", .{ w.id, remaining });
    }

    // ========================================================================
    // Shutdown
    // ========================================================================

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
        const addr = try Io.net.UnixAddress.init(self.cfg.socket_path);
        return addr.listen(self.io, .{ .kernel_backlog = 128 });
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

    fn serveString(self: *Conductor, client_socket: posix.socket_t, content: []const u8) !void {
        var stdio_buf: [std.fs.max_path_bytes]u8 = undefined;
        var signals_buf: [std.fs.max_path_bytes]u8 = undefined;
        const stdio_path = try randomSocketPath(self.io, self.cfg.runtime_dir, "stdio.sock", &stdio_buf);
        const signals_path = try randomSocketPath(self.io, self.cfg.runtime_dir, "signals.sock", &signals_buf);
        const stdio_addr = try Io.net.UnixAddress.init(stdio_path);
        var stdio_server = try stdio_addr.listen(self.io, .{});
        defer stdio_server.deinit(self.io);
        defer Io.Dir.deleteFileAbsolute(self.io, stdio_path) catch {};
        const signals_addr = try Io.net.UnixAddress.init(signals_path);
        var signals_server = try signals_addr.listen(self.io, .{});
        defer signals_server.deinit(self.io);
        defer Io.Dir.deleteFileAbsolute(self.io, signals_path) catch {};
        self.sendSocketPaths(client_socket, stdio_path, signals_path);
        const stdio_conn = try stdio_server.accept(self.io);
        defer stdio_conn.close(self.io);
        const signals_conn = try signals_server.accept(self.io);
        defer signals_conn.close(self.io);
        platform.write(stdio_conn.socket.handle, content);
        platform.write(signals_conn.socket.handle, &[_]u8{ protocol.signals.exit, 0x01, 0x00 });
        stdio_conn.shutdown(self.io, .send) catch {};
        signals_conn.shutdown(self.io, .send) catch {};
    }

    fn sendSocketPaths(_: *Conductor, socket: posix.socket_t, stdio: []const u8, signals: []const u8) void {
        var buf: [512]u8 = undefined;
        var w = protocol.BufWriter{ .buf = &buf };
        w.writeLenPrefixed(u16, stdio);
        w.writeLenPrefixed(u16, signals);
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
    std.debug.print(" - Worker TTL: {d} seconds\n", .{cfg.worker_ttl});
    Io.Dir.createDirAbsolute(io, cfg.runtime_dir, .default_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    conductor.cleanupRuntimeDir();
    conductor.createReserveWorker(null) catch |err| {
        std.debug.print("Failed to create reserve worker: {}\n", .{err});
    };
    try conductor.run();
}
