// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0
//
// Which worker a client runs on, and seating it there: its session's,
// one it has used, an idle one, or the reserve; else it is held while one starts.

const std = @import("std");
const posix = std.posix;
const Io = std.Io;
const platform = @import("platform/main.zig");
const protocol = @import("protocol.zig");
const args = @import("args.zig");
const status = @import("status.zig");

const main = @import("main.zig");
const Conductor = main.Conductor;
const worker = main.worker;
const AssignReason = main.AssignReason;
const WorkerAssignment = main.WorkerAssignment;
const WorkerList = main.WorkerList;
const end_probe_ms = main.end_probe_ms;
const ClientRequest = Conductor.ClientRequest;
const HeldClient = Conductor.HeldClient;
const Outcome = Conductor.Outcome;
const PendingSpawn = Conductor.PendingSpawn;
const SandboxKind = Conductor.SandboxKind;
const tag_spawn_client = Conductor.tag_spawn_client;
const requests = @import("requests.zig");
const tracking = @import("tracking.zig");
const spawns = @import("spawns.zig");
const retire = @import("retire.zig");
const eviction = @import("eviction.zig");
const replies = @import("replies.zig");

const LabelledWorker = struct { w: *worker.Worker, pool_key: []const u8 };

/// The pools a session is looked for in: the host's own; those the host
/// may enter too, the sandboxes the conductor built (a sandboxed pool
/// never serves a caller from another sandbox); or any, a client-spawned
/// worker's too, whose sockets are in a mount namespace the host cannot see.
const Reach = enum { host, enterable, any };

const PreparedClient = struct {
    info: worker.ClientInfo,
    sandbox_env: ?[]const worker.EnvVar = null,
};

/// Why no worker serves a client: an error, and what a failed spawn wrote.
const Refusal = struct { err: anyerror, output: []const u8 = "" };

pub const Resumption = union(enum) { select, on: *worker.Worker, refuse: Refusal };

const sandbox_home = "/home/sandbox";

const sandbox_identity_vars = [_]worker.EnvVar{
    .{ .key = "HOME", .value = sandbox_home },
    .{ .key = "USER", .value = "sandbox" },
    .{ .key = "LOGNAME", .value = "sandbox" },
};

/// What the worker is sent of `request`, run where the client runs.
pub fn clientInfo(c: *const Conductor, request: *const ClientRequest, port_set: u16) worker.ClientInfo {
    return .{
        .tty = request.flags.tty,
        .color = request.flags.color,
        .force = labelOf(request) != null,
        .size = request.size,
        .id = c.client_id,
        .key = c.keyFor(.client, c.client_id),
        .ppid = request.ppid,
        .cwd = request.cwd,
        .env = request.env,
        .switches = request.parsed.switches(),
        .programfile = request.parsed.program_file,
        .args = request.parsed.program_args,
        .port_set = port_set,
    };
}

pub fn allocatePortSet(c: *Conductor) !u16 {
    const pool = if (c.port_pool) |*p| p else return protocol.PortPool.none;
    return pool.allocate() orelse {
        std.debug.print("Client {d}: port pool exhausted\n", .{c.client_id});
        return error.PortPoolExhausted;
    };
}

pub fn prepareClient(c: *Conductor, request: *const ClientRequest, sandbox: SandboxKind) !PreparedClient {
    const port_set = try allocatePortSet(c);
    errdefer releasePortSet(c, port_set);
    var prepared = PreparedClient{ .info = clientInfo(c, request, port_set) };
    if (sandbox == .remote) {
        // So withenv(client.env...) doesn't leak the remote HOME etc.
        const env = try buildSandboxClientEnv(c, request.env);
        prepared.sandbox_env = env;
        prepared.info.env = env;
        prepared.info.cwd = sandbox_home;
    }
    return prepared;
}

/// `direct` is the worker started for the client; `existing_hold` resumes a hold.
pub fn assignClientToWorker(c: *Conductor, socket: posix.socket_t, request: *ClientRequest, worker_key: []const u8, sandbox: SandboxKind, existing_hold: ?*HeldClient, direct: ?*worker.Worker) !Outcome {
    const list = try getWorkerList(c, worker_key);
    const session_label = request.parsed.getSwitch("--session");
    std.debug.print("Client {d}; pid: {d}{s}{s}{s}{s}, project: {s}{s}\n", .{
        c.client_id,
        request.pid,
        if (request.parsed.julia_channel != null) ", julia: " else "",
        request.parsed.julia_channel orelse "",
        if (session_label != null) ", session: " else "",
        if (session_label) |l| (if (l.len > 0) l else ".") else "",
        request.project orelse "(default)",
        if (sandbox != .none) " [sandboxed]" else "",
    });
    const starting = if (direct == null) spawns.findPendingSpawn(c, worker_key) else null;
    // A session's clients queue behind the worker starting for it, so it
    // can't end up with two.
    if (direct == null) if (labelOf(request)) |label| {
        if (findStartingSession(c, label, worker_key, request.parsed.hasSwitch("--project") or sandbox != .none)) |p|
            return queueBehind(c, p, socket, request, worker_key, sandbox, existing_hold);
    };
    const prepared = try prepareClient(c, request, sandbox);
    defer if (prepared.sandbox_env) |e| c.allocator.free(e);
    const port_set = prepared.info.port_set;
    const assignment = blk: {
        errdefer releasePortSet(c, port_set);
        break :blk if (direct) |w|
            tryAssignWorker(c, w, &prepared.info, .new_worker) orelse return error.WorkerUnavailable
        else
            try selectWorker(c, list, request, &prepared.info, sandbox);
    };
    if (assignment) |a| {
        finishAssignment(c, socket, request, worker_key, a, port_set);
        return .done;
    }
    releasePortSet(c, port_set);
    // With no worker free, the one starting is the next to be.
    if (starting) |p| return queueBehind(c, p, socket, request, worker_key, sandbox, existing_hold);
    const hold = existing_hold orelse try holdClient(c, socket, request, worker_key, sandbox);
    errdefer if (existing_hold == null) unholdClient(c, hold);
    try spawns.beginClientSpawn(c, hold);
    return .held;
}

pub fn queueBehind(c: *Conductor, p: *PendingSpawn, socket: posix.socket_t, request: *ClientRequest, worker_key: []const u8, sandbox: SandboxKind, existing_hold: ?*HeldClient) !Outcome {
    const hold = existing_hold orelse try holdClient(c, socket, request, worker_key, sandbox);
    errdefer if (existing_hold == null) unholdClient(c, hold);
    try p.waiters.append(c.allocator, hold);
    c.event_loop.watchFd(@intFromPtr(hold) | tag_spawn_client, hold.socket);
    std.debug.print("Client {d}: waiting for worker {d}\n", .{ c.client_id, p.spawn.worker.id });
    return .held;
}

pub fn labelOf(request: *const ClientRequest) ?[]const u8 {
    const label = request.parsed.getSwitch("--session") orelse return null;
    return if (label.len > 0) label else null;
}

pub fn finishAssignment(c: *Conductor, socket: posix.socket_t, request: *const ClientRequest, worker_key: []const u8, assignment: WorkerAssignment, port_set: u16) void {
    std.debug.print("Assigned client {d} to worker {d}: {s}\n", .{ c.client_id, assignment.w.id, @tagName(assignment.reason) });
    seatClient(c, socket, request, assignment, port_set);
    eviction.bumpCrf(c, worker_key, c.currentTime()); // count the summons only once the client is tracked
    if (c.cfg.reserve_worker) spawns.beginReserveSpawn(c) catch |err| {
        std.debug.print("Warning: failed to start a reserve worker: {}\n", .{err});
    };
}

/// Tracks the client on the worker now running it, and sends it there.
pub fn seatClient(c: *Conductor, socket: posix.socket_t, request: *const ClientRequest, assignment: WorkerAssignment, port_set: u16) void {
    defer assignment.paths.deinit(c.allocator);
    const w = assignment.w;
    w.last_pinged = c.currentTime();
    w.recordPpid(request.ppid, c.cfg.worker_maxclients);
    tracking.registerClient(c, c.client_id, request, w, port_set) catch |err| {
        std.debug.print("Client {d}: cannot track: {}\n", .{ c.client_id, err });
    };
    replies.sendSocketPaths(c, socket, assignment.paths);
}

// The request changes hands: the caller must not deinit it while held.
pub fn holdClient(c: *Conductor, socket: posix.socket_t, request: *const ClientRequest, worker_key: []const u8, sandbox: SandboxKind) !*HeldClient {
    const hold = try c.allocator.create(HeldClient);
    errdefer c.allocator.destroy(hold);
    const env = try worker.dupeEnv(c.allocator, request.env);
    errdefer worker.freeEnv(c.allocator, env);
    const key = try c.allocator.dupe(u8, worker_key);
    hold.* = .{ .socket = socket, .request = request.*, .worker_key = key, .sandbox = sandbox, .id = c.client_id };
    hold.request.env = env;
    platform.write(socket, &.{protocol.client.starting_worker});
    return hold;
}

// Undo holdClient while the caller still owns the request.
pub fn unholdClient(c: *Conductor, hold: *HeldClient) void {
    worker.freeEnv(c.allocator, hold.request.env);
    c.allocator.free(hold.worker_key);
    c.allocator.destroy(hold);
}

pub fn discardHold(c: *Conductor, hold: *HeldClient) void {
    if (!hold.gone) platform.close(hold.socket);
    hold.request.deinit(c.allocator);
    unholdClient(c, hold);
}

// A client served meanwhile (`--restart` fails spawns) stays the current one.
pub fn resumeHeld(c: *Conductor, hold: *HeldClient, how: Resumption) void {
    const serving = c.client_id;
    defer c.client_id = serving;
    c.client_id = hold.id;
    const output = if (how == .refuse) how.refuse.output else "";
    const attempt: anyerror!Outcome = switch (how) {
        .refuse => |refusal| refusal.err,
        .select => assignClientToWorker(c, hold.socket, &hold.request, hold.worker_key, hold.sandbox, hold, null),
        .on => |w| assignClientToWorker(c, hold.socket, &hold.request, hold.worker_key, hold.sandbox, hold, w),
    };
    const outcome = attempt catch |err| blk: {
        requests.reportNoWorker(c, hold.socket, err, hold.sandbox, output);
        break :blk Outcome.done;
    };
    if (outcome == .done) discardHold(c, hold);
}

/// False when the worker already died; the caller falls back to selection.
pub fn assignClientToExistingWorker(c: *Conductor, socket: posix.socket_t, request: *const ClientRequest, w: *worker.Worker) !bool {
    const watcher = request.parsed.hasSwitch("--watch");
    const port_set = try allocatePortSet(c);
    var info = clientInfo(c, request, port_set);
    info.force = info.force or watcher;
    // A watch runs no code, so it carries no environment: whatever reaches a
    // worker is readable by the session's own code.
    if (watcher) info.env = &.{};
    if (!answersNow(c, w)) {
        releasePortSet(c, port_set);
        return error.SessionBusy;
    }
    const assignment = tryAssignWorker(c, w, &info, .session_label) orelse {
        releasePortSet(c, port_set);
        return false;
    };
    seatClient(c, socket, request, assignment, port_set);
    return true;
}

pub fn selectWorker(c: *Conductor, list: *WorkerList, request: *const ClientRequest, client_info: *const worker.ClientInfo, sandbox: SandboxKind) !?WorkerAssignment {
    const now = c.currentTime();
    const label = labelOf(request);
    const want_interactive = request.parsed.hasSwitch("--interactive");
    // 1. Labeled session: join its worker (global, or scoped to an explicit --project)
    if (label) |l| {
        if (findSession(c, list.items, l, request.parsed.hasSwitch("--project") or sandbox != .none)) |f| {
            if (!answersNow(c, f.w)) return error.SessionBusy;
            // A host client carries into a sandbox only what the sandbox itself starts with.
            var info = client_info.*;
            const entering = sandbox == .none and f.w.launch == .sandboxed;
            const env = if (entering) try buildSandboxJoinEnv(c, client_info.env) else null;
            defer if (env) |e| c.allocator.free(e);
            if (env) |e| {
                info.env = e;
                info.cwd = sandboxWorkdir(f.pool_key);
            }
            if (tryAssignWorker(c, f.w, &info, .session_label)) |a| return a;
        }
    }
    // Skip ppid/recency reuse for labeled sessions (their identity is the
    // label, handled above and below), and for a remote client but of a
    // worker started for its own host, as its setting allows (isolation).
    const reusable = switch (sandbox) {
        .remote => |host| c.cfg.sandbox_reuse and host != null,
        else => true,
    };
    if (reusable and label == null) {
        const host = if (sandbox == .remote) sandbox.remote else null;
        // 2. PPID-affinity (interactive flag must match)
        if (findWorkerByPpid(c, list, client_info.ppid, want_interactive, now, host)) |w| {
            if (tryAssignWorker(c, w, client_info, .ppid_affinity)) |a| return a;
        }
        // 3. Lightest available worker, sparing the most-recent for ppid reuse
        if (tryExistingWorkers(c, list, client_info, want_interactive, now, host)) |a| return a;
    }
    // 3b. New labeled session: claim an idle worker and tag it, else spawn.
    if (label != null and sandbox == .none) {
        if (findClaimableWorker(c, list, want_interactive, now)) |w| {
            if (w.session_label != null) clearLabel(c, w); // expired
            w.session_label = try c.allocator.dupe(u8, label.?);
            if (tryAssignWorker(c, w, client_info, .session_label)) |a| return a;
        }
    }
    // 4. The warm reserve, for a plain non-interactive request it matches.
    if (sandbox == .none and !want_interactive) {
        if (try spawns.claimReserve(c, list, request.project orelse "", request.parsed.julia_channel, resolveThreads(request), label)) |w| {
            if (tryAssignWorker(c, w, client_info, .new_worker)) |a| return a;
        }
    }
    return null; // nothing to be had: the caller starts a worker
}

pub fn isWorkerAvailable(c: *Conductor, w: *worker.Worker, interactive: bool, now: i64) bool {
    const max = c.cfg.worker_maxclients;
    if (max != 0 and w.busyClients() >= max) return false;
    if (w.unresponsive_interrupted) return false;
    if (w.session_label != null and !isLabelExpired(c, w, now)) return false;
    if (w.interactive != interactive) return false;
    return true;
}

/// Whether a session's worker answers at once, as one whose code holds its
/// message loop won't: a request it then answered too late would retire
/// it, ending the session, where the client joining it is turned away.
pub fn answersNow(c: *Conductor, w: *worker.Worker) bool {
    c.event_loop.cancelPendingPing(w);
    if (w.answersWithin(end_probe_ms)) return true;
    w.log("too busy to answer a client joining its session", .{});
    return false;
}

pub fn tryAssignWorker(c: *Conductor, w: *worker.Worker, client_info: *const worker.ClientInfo, reason: AssignReason) ?WorkerAssignment {
    c.event_loop.cancelPendingPing(w);
    const paths = w.runClient(c.allocator, client_info, if (c.cfg.transport == .local) c.cfg.socket_dir else null) catch |err| {
        _ = handleRunClientError(c, w, err);
        return null;
    };
    return .{ .paths = paths, .w = w, .reason = reason };
}

pub fn findWorkerByPpid(c: *Conductor, list: *WorkerList, ppid: u32, interactive: bool, now: i64, host: ?Io.net.IpAddress) ?*worker.Worker {
    for (list.items) |w| {
        if (!isWorkerAvailable(c, w, interactive, now) or !std.meta.eql(w.origin, host)) continue;
        if (std.mem.findScalar(u32, &w.recent_ppids, ppid) != null) {
            if (isLabelExpired(c, w, now)) clearLabel(c, w);
            return w;
        }
    }
    return null;
}

pub fn findWorkerByLabel(pool: []const *worker.Worker, label: []const u8) ?*worker.Worker {
    for (pool) |w| {
        if (w.session_label) |wl| {
            if (std.mem.eql(u8, wl, label)) return w;
        }
    }
    return null;
}

// Warmest first; null → spawn.
pub fn findClaimableWorker(c: *Conductor, list: *WorkerList, interactive: bool, now: i64) ?*worker.Worker {
    var best: ?*worker.Worker = null;
    for (list.items) |w| {
        if (w.busyClients() != 0) continue;
        if (w.session_label != null and !isLabelExpired(c, w, now)) continue;
        if (w.interactive != interactive) continue;
        if (best == null or w.last_active > best.?.last_active) best = w;
    }
    return best;
}

// Spare the most recent for its ppid owner; the lightest goes, so heavy workers age out.
pub fn tryExistingWorkers(c: *Conductor, list: *WorkerList, client_info: *const worker.ClientInfo, interactive: bool, now: i64, host: ?Io.net.IpAddress) ?WorkerAssignment {
    var newest: ?*worker.Worker = null;
    for (list.items) |w| {
        if (!isWorkerAvailable(c, w, interactive, now) or !std.meta.eql(w.origin, host)) continue;
        if (newest == null or w.last_active > newest.?.last_active) newest = w;
    }
    if (newest == null) return null;

    var pick: ?*worker.Worker = null;
    var pick_mem: u64 = 0;
    for (list.items) |w| {
        if (w == newest.? or !isWorkerAvailable(c, w, interactive, now) or !std.meta.eql(w.origin, host)) continue;
        // Unmeasured ranks heaviest; an idle candidate's mem is current.
        const mem = if (w.mem > 0) w.mem else std.math.maxInt(u64);
        if (pick == null or mem < pick_mem or (mem == pick_mem and w.last_active > pick.?.last_active)) {
            pick = w;
            pick_mem = mem;
        }
    }
    const chosen = pick orelse newest.?;
    if (isLabelExpired(c, chosen, now)) clearLabel(c, chosen);
    return tryAssignWorker(c, chosen, client_info, .recent_worker);
}

pub fn handleRunClientError(c: *Conductor, w: *worker.Worker, err: anyerror) bool {
    switch (err) {
        error.WorkerBusy => {
            w.log("busy (likely has stuck client), syncing", .{});
            tracking.syncWorkerClients(c, w);
            return true;
        },
        // A reply late or cut short would be read as the next one's.
        error.Timeout, error.WouldBlock, error.EndOfStream, error.BrokenPipe, error.ConnectionResetByPeer,
        error.UnexpectedResponse, error.WorkerError => {
            retire.retireWorker(c, w);
            return true;
        },
        else => return false,
    }
}

pub fn findLabelled(c: *Conductor, label: []const u8, reach: Reach) ?LabelledWorker {
    var it = c.workers.iterator();
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
pub fn findSession(c: *Conductor, pool: []const *worker.Worker, label: []const u8, scoped: bool) ?LabelledWorker {
    if (!scoped) return findLabelled(c, label, .enterable);
    return .{ .w = findWorkerByLabel(pool, label) orelse return null, .pool_key = "" };
}

/// The spawn underway for session `label` that a client would wait on,
/// reached as `findSession` reaches a running one.
pub fn findStartingSession(c: *Conductor, label: []const u8, worker_key: []const u8, scoped: bool) ?*PendingSpawn {
    for (c.pending_spawns.items) |p| {
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
        .remote_sandbox => |host| std.mem.startsWith(u8, pool_key, "__sandbox__\x00") and
            (host == null or std.meta.eql(w.origin, host)),
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
pub fn sandboxWorkdir(pool_key: []const u8) []const u8 {
    var fields = std.mem.splitScalar(u8, pool_key, 0);
    if (!std.mem.eql(u8, fields.first(), "__lsandbox__")) return sandbox_home;
    return fields.next() orelse sandbox_home;
}

pub fn trimTrailingSlashes(path: []const u8) []const u8 {
    var end = path.len;
    while (end > 1 and path[end - 1] == '/') end -= 1;
    return path[0..end];
}

pub fn pathCoveredBy(path: []const u8, dirs: []const []const u8) bool {
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

pub fn resolveThreads(request: *const ClientRequest) args.Threads {
    const sw = request.parsed.threadSwitch();
    if (!std.meta.eql(sw, args.threads_none)) return sw;
    for (request.env) |e| {
        if (std.mem.eql(u8, e.key, "JULIA_NUM_THREADS")) return args.parseThreads(e.value);
    }
    return args.threads_none;
}

pub fn getWorkerList(c: *Conductor, key: []const u8) !*WorkerList {
    if (!c.workers.contains(key)) {
        const key_copy = try c.allocator.dupe(u8, key);
        errdefer c.allocator.free(key_copy);
        try c.workers.put(key_copy, .empty);
    }
    return c.workers.getPtr(key).?;
}

pub fn isLabelExpired(c: *Conductor, w: *worker.Worker, now: i64) bool {
    if (w.session_label == null or w.busyClients() > 0) return false;
    const idle_time: u64 = @intCast(@max(0, now - w.last_active));
    return idle_time >= c.cfg.label_ttl;
}

pub fn clearLabel(c: *Conductor, w: *worker.Worker) void {
    if (w.session_label) |label| {
        w.log("clearing label '{s}'", .{label});
        w.dropSession(label); // tear down the now-orphaned session REPL before reuse
        c.allocator.free(label);
        w.session_label = null;
    }
}

/// Free only the slice, as `buildSandboxClientEnv`.
pub fn buildSandboxJoinEnv(c: *Conductor, env: []const worker.EnvVar) ![]const worker.EnvVar {
    const result = try c.allocator.alloc(worker.EnvVar, env.len);
    errdefer c.allocator.free(result);
    var n: usize = 0;
    for (env) |e| if (worker.sandbox.envAllowed(e.key)) {
        result[n] = e;
        n += 1;
    };
    return c.allocator.realloc(result, n);
}

/// Free only the slice: its EnvVars point into `env` or static strings.
pub fn buildSandboxClientEnv(c: *Conductor, env: []const worker.EnvVar) ![]const worker.EnvVar {
    const result = try c.allocator.alloc(worker.EnvVar, env.len + sandbox_identity_vars.len);
    errdefer c.allocator.free(result);
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
    return c.allocator.realloc(result, n + sandbox_identity_vars.len);
}

pub fn releasePortSet(c: *Conductor, port_set: u16) void {
    if (port_set != protocol.PortPool.none) {
        if (c.port_pool) |*pool| pool.release(port_set);
    }
}
