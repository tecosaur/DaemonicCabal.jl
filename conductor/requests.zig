// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0
//
// A client's request, read as it arrives, and what serves it: the
// sandbox it gets, the pool it draws from, and the replies that refuse it.

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const Io = std.Io;
const platform = @import("platform/main.zig");
const protocol = @import("protocol.zig");
const args = @import("args.zig");
const project = @import("project.zig");
const env_cache = @import("env_cache.zig");
const status = @import("status.zig");
const live = @import("live.zig");
const reconfigure = @import("reconfigure.zig");

const main = @import("main.zig");
const Conductor = main.Conductor;
const worker = main.worker;
const PeerInfo = main.PeerInfo;
const ClientRequest = Conductor.ClientRequest;
const HeldClient = Conductor.HeldClient;
const Outcome = Conductor.Outcome;
const PendingConnection = Conductor.PendingConnection;
const SandboxKind = Conductor.SandboxKind;
const max_message_bytes = Conductor.max_message_bytes;
const assign = @import("assign.zig");
const tracking = @import("tracking.zig");
const spawns = @import("spawns.zig");
const retire = @import("retire.zig");
const replies = @import("replies.zig");

const Notification = struct {
    kind: protocol.notification.Type,
    subject: u32, // client id, or a peek's worker id
    key: u64, // its sender's
    evaluation: u32 = 0, // an interrupt's
    report: []const u8 = "", // a peek's, in the connection's buffer
};

/// A request's fixed part, its lengths checked against what has arrived.
const RequestHead = struct {
    flags: protocol.client.Flags,
    pid: u32, // self-reported
    ppid: u32,
    host_key: *const protocol.client.HostKey,
    size: protocol.TerminalSize,
    cwd: []const u8,
    fingerprint: u64,
    args_at: usize, // their count
};

const max_peek_report_bytes = 1 << 20;

pub fn discardConnection(c: *Conductor, pc: *PendingConnection) void {
    if (pc.socket != platform.no_socket) platform.close(pc.socket);
    pc.received.deinit(c.allocator);
    c.allocator.destroy(pc);
}

/// Takes what has arrived; null while the message is still incomplete.
pub fn receive(c: *Conductor, pc: *PendingConnection) !?Outcome {
    var chunk: [16 << 10]u8 = undefined;
    const n = platform.recvNonBlocking(pc.socket, &chunk) orelse {
        // A silent close is `juliaclient --version` probing.
        if (pc.received.items.len == 0) return .done;
        return error.EndOfStream;
    };
    if (n == 0) return null;
    if (pc.received.items.len + n > max_message_bytes) return error.MessageTooLarge;
    try pc.received.appendSlice(c.allocator, chunk[0..n]);
    var r = protocol.SliceReader{ .bytes = pc.received.items };
    const magic = r.int(u32) catch return null;
    if (magic == protocol.client.magic) return receiveRequest(c, pc, &r);
    if (magic == protocol.notification.magic) {
        const note = parseNotification(&r) catch |err| return if (err == error.Truncated) null else err;
        handleNotification(c, note);
        return .done;
    }
    if (magic >> 8 == protocol.client.magic_prefix) {
        try rejectClientVersion(c, pc.socket, @intCast(magic & 0xFF));
        return .done;
    }
    std.debug.print("Invalid magic: {x}\n", .{magic});
    return error.InvalidMagic;
}

// Its request is left unread: however it is framed, the reply's opening
// (a socket_paths frame) is the same.
pub fn rejectClientVersion(c: *Conductor, socket: posix.socket_t, theirs: u8) !void {
    const ours = protocol.client.version;
    std.debug.print("Client speaks protocol v{d}, this daemon v{d}; rejecting\n", .{ theirs, ours });
    var buf: [256]u8 = undefined;
    const msg = try std.mem.print(&buf, "This juliaclient speaks protocol v{d} but the daemon speaks v{d}: {s}.\n", .{
        theirs, ours, if (theirs < ours) "rebuild or reinstall juliaclient to match the daemon" else "restart the daemon so it runs the newly installed version",
    });
    // Its streams come without a key: it knows of none. Id 0 is no
    // client's, so neither is the key it is sent.
    c.client_id = 0;
    var streams = try replies.openClientStreams(c, socket, false);
    defer streams.deinit();
    streams.finish(msg, 1);
}

pub fn parseNotification(r: *protocol.SliceReader) !Notification {
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
pub fn isGenuine(c: *Conductor, note: Notification) bool {
    const worker_id = switch (note.kind) {
        .client_exit, .client_interrupt => return note.key == c.keyFor(.client, note.subject),
        // Of a client gone already, it can do nothing.
        .client_done => (c.active_clients.get(note.subject) orelse return true).worker.id,
        .peek_report, .interrupted => note.subject,
    };
    return note.key == c.keyFor(.worker, worker_id);
}

pub fn handleNotification(c: *Conductor, note: Notification) void {
    if (!isGenuine(c, note)) return std.debug.print("Dropped a {s} notification with a wrong key\n", .{@tagName(note.kind)});
    const subject = note.subject;
    // A view's client was never assigned a worker.
    if ((note.kind == .client_exit or note.kind == .client_interrupt) and
        (live.dropById(c, subject) or reconfigure.dropById(c, subject))) return;
    switch (note.kind) {
        .client_done => _ = tracking.clientDone(c, subject),
        .client_exit => {
            if (tracking.clientDone(c, subject)) |w| {
                if (!w.ping_pending) c.event_loop.scheduleHealthCheck(w);
            }
        },
        .client_interrupt => if (c.active_clients.get(subject)) |info| info.worker.interrupt(subject, note.evaluation),
        .interrupted => if (c.findWorkerById(subject)) |w| {
            w.interrupt_unread = false;
        },
        .peek_report => {
            const w = c.findWorkerById(subject) orelse return;
            live.onProfile(c, w, c.allocator.dupe(u8, note.report) catch return);
        },
    }
}

pub fn parseRequestHead(r: *protocol.SliceReader) !RequestHead {
    // flags(1) + reserved(3) + pid(4) + ppid(4) + host key(16) + size(4)
    const fixed = try r.take(32);
    const cwd = try r.lenPrefixed(u32);
    const fingerprint = try r.int(u64);
    return .{
        .flags = @bitCast(fixed[0]),
        .pid = std.mem.readInt(u32, fixed[4..8], .little),
        .ppid = std.mem.readInt(u32, fixed[8..12], .little),
        .host_key = fixed[12..28],
        .size = .decode(fixed[28..32]),
        .cwd = cwd,
        .fingerprint = fingerprint,
        .args_at = r.pos,
    };
}

/// The host `peer` connects from, which its port doesn't change.
pub fn hostOf(peer: ?Io.net.IpAddress) ?Io.net.IpAddress {
    var host = peer orelse return null;
    host.setPort(0);
    return host;
}

/// Over TCP, a loopback peer is the host's only with the host key: a
/// sandbox shares the host's network, but not its runtime dir.
pub fn isRemote(c: *const Conductor, peer: *const PeerInfo, host_key: *const protocol.client.HostKey) bool {
    if (peer.isRemote(c.cfg.transport)) return true;
    return c.cfg.transport == .tcp and !std.crypto.timing_safe.eql(protocol.client.HostKey, host_key.*, c.host_key);
}

/// A local client's environment comes from the cache, where its first
/// request leaves it; the rest are asked for theirs.
pub fn receiveRequest(c: *Conductor, pc: *PendingConnection, r: *protocol.SliceReader) !?Outcome {
    const head = parseRequestHead(r) catch |err| return if (err == error.Truncated) null else err;
    const args_end = pc.env_at orelse pc.listEnd(head.args_at, 1) catch |err| return if (err == error.Truncated) null else err;
    if (head.flags.env_follows) pc.env_at = args_end;
    const is_remote = isRemote(c, &pc.peer, head.host_key);
    // The cache is this machine's: a remote client's environment would
    // only evict local ones.
    const cached = if (is_remote or pc.env_at != null) null else c.cache.lookup(head.fingerprint);
    if (cached == null and pc.env_at == null) {
        pc.env_at = args_end;
        platform.write(pc.socket, &[_]u8{protocol.client.env_request});
        return null;
    }
    var owned_env: ?[]worker.EnvVar = null;
    const env = cached orelse blk: {
        _ = pc.listEnd(pc.env_at.?, 2) catch |err| return if (err == error.Truncated) null else err;
        var er = protocol.SliceReader{ .bytes = r.bytes, .pos = pc.env_at.? };
        const full = try copyEnv(c, &er);
        if (!is_remote) break :blk c.cache.insert(head.fingerprint, full);
        owned_env = full;
        break :blk env_cache.EnvCache.LookupResult{ .env = full, .julia_project = null };
    };
    // Its parts are freed here only until handleClient owns them.
    const request: ClientRequest = request: {
        errdefer if (owned_env) |e| worker.freeEnv(c.allocator, e);
        var args_reader = protocol.SliceReader{ .bytes = r.bytes, .pos = head.args_at };
        const raw_args = try copyArgs(c, &args_reader);
        errdefer {
            for (raw_args) |a| c.allocator.free(a);
            c.allocator.free(raw_args);
        }
        var problem: args.Problem = undefined;
        const parsed = args.parseReporting([]const u8, raw_args, &problem) catch |err| {
            var buf: [512]u8 = undefined;
            c.client_id = 0;
            try replies.serveString(c, pc.socket, std.mem.print(&buf, "ERROR: {f}\n", .{problem}) catch "ERROR: invalid command line\n", 1);
            return err;
        };
        // A remote client's filesystem isn't ours: it names a project of ours
        // only by --project, and starts in its directory, else in our home.
        const home = if (c.cfg.host_home.len > 0) c.cfg.host_home else "/";
        const proj = project.resolve(c.allocator, c.io, &parsed, if (is_remote) null else env.julia_project, c.cfg.host_home, if (is_remote) home else head.cwd) catch |err| {
            if (err == error.CurrentDirUnavailable) {
                c.client_id = 0;
                try replies.serveString(c, pc.socket, "The project is named relative to the working directory, which no longer exists.\n", 1);
            }
            return err;
        };
        errdefer if (proj) |p| c.allocator.free(p);
        const project_dir = if (proj) |p| (if (p[0] == '@') home else if (std.mem.endsWith(u8, p, ".toml")) std.Io.Dir.path.dirname(p) orelse home else p) else home;
        const cwd = try c.allocator.dupe(u8, if (is_remote) project_dir else head.cwd);
        errdefer c.allocator.free(cwd);
        break :request .{
            .flags = head.flags,
            .size = head.size,
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
    return try handleClient(c, pc.socket, is_remote, pc.peer.address, request);
}

// `r`'s lengths are already checked.
pub fn copyArgs(c: *Conductor, r: *protocol.SliceReader) ![][]const u8 {
    const client_args = try c.allocator.alloc([]const u8, try r.int(u32));
    errdefer c.allocator.free(client_args);
    var copied: usize = 0;
    errdefer for (client_args[0..copied]) |arg| c.allocator.free(arg);
    for (client_args) |*arg| {
        arg.* = try c.allocator.dupe(u8, try r.lenPrefixed(u32));
        copied += 1;
    }
    return client_args;
}

// `r`'s lengths are already checked.
pub fn copyEnv(c: *Conductor, r: *protocol.SliceReader) ![]worker.EnvVar {
    const env = try c.allocator.alloc(worker.EnvVar, try r.int(u32));
    defer c.allocator.free(env);
    for (env) |*e| e.* = .{ .key = try r.lenPrefixed(u32), .value = try r.lenPrefixed(u32) };
    return worker.dupeEnv(c.allocator, env);
}

pub fn handleClient(c: *Conductor, socket: posix.socket_t, is_remote: bool, peer: ?Io.net.IpAddress, received: ClientRequest) !Outcome {
    var request = received;
    var request_held = false; // moved into a HeldClient while its worker starts
    defer if (!request_held) request.deinit(c.allocator);
    c.client_counter += 1;
    c.client_id = c.client_counter;
    const sandbox = try sandboxFor(c, socket, is_remote, peer, &request) orelse return .done;
    // A sandbox binds its project, which a remote client could name as any path of ours.
    if (sandbox == .remote) if (request.project) |p| {
        c.allocator.free(p);
        request.project = null;
    };
    if (request.parsed.hasSwitch("--reconfigure")) {
        try replies.serveReconfigure(c, socket, request.flags.tty, request.size, !is_remote and sandbox == .none);
        return .done;
    }
    if (request.parsed.hasSwitch("--status")) {
        const scope: status.Scope = switch (sandbox) {
            .none, .local => .host, // --sandbox makes no sandbox of a status request
            .remote => |host| .{ .remote_sandbox = if (c.cfg.sandbox_isolate_hosts) host orelse return error.UnknownHost else null },
            .client => |client| .{ .mount_ns = client.ns },
        };
        try replies.serveStatus(c, socket, request.parsed.getSwitch("--status"), request.flags.tty, request.size, scope);
        return .done;
    }
    if (sandbox == .remote and c.cfg.sandbox_session_bypass) if (assign.labelOf(&request)) |label| {
        if (assign.findLabelled(c, label, .host)) |found| {
            std.debug.print("Client {d}: session bypass — joining local worker {d} (label '{s}')\n", .{ c.client_id, found.w.id, label });
            const seated = assign.assignClientToExistingWorker(c, socket, &request, found.w) catch |err| {
                if (err != error.SessionBusy) return err;
                reportNoWorker(c, socket, err, sandbox, "");
                return .done;
            };
            if (seated) return .done;
        }
    };
    const worker_key = try poolKey(c, &request, sandbox);
    defer c.allocator.free(worker_key);
    if (request.parsed.hasSwitch("--watch")) return serveWatch(c, socket, &request, worker_key, sandbox);
    if (syncRefusal(&request)) |why| {
        std.debug.print("Client {d}: refused: {s}", .{ c.client_id, why });
        try replies.serveString(c, socket, why, 1);
        return .done;
    }
    if (request.parsed.hasSwitch("--sync")) std.debug.print("Client {d}: sync mode, session='{s}'\n", .{ c.client_id, assign.labelOf(&request).? });
    if (request.parsed.hasSwitch("--restart")) {
        try serveRestart(c, socket, &request, worker_key, sandbox);
        return .done;
    }
    const outcome = assign.assignClientToWorker(c, socket, &request, worker_key, sandbox, null, null) catch |err| {
        reportNoWorker(c, socket, err, sandbox, "");
        return .done;
    };
    request_held = outcome == .held;
    return outcome;
}

/// How the client's worker is sandboxed; null once the client has been
/// refused one.
pub fn sandboxFor(c: *Conductor, socket: posix.socket_t, is_remote: bool, peer: ?Io.net.IpAddress, request: *const ClientRequest) !?SandboxKind {
    const wants_sandbox = request.parsed.hasSwitch("--sandbox");
    // A client in another mount namespace is sandboxed by something we cannot
    // see into, so it spawns its own worker there. Over TCP a sandbox lacks
    // the host key, so is remote.
    const namespace: platform.PeerNamespace = if (is_remote or c.cfg.transport == .tcp) .own else platform.peerNamespace(socket);
    if (namespace == .unknown) {
        std.debug.print("Client {d}: its mount namespace cannot be read, refusing\n", .{c.client_id});
        try replies.serveString(c, socket, "The daemon cannot tell whether this client is inside a sandbox, so refuses it.\n", 1);
        return null;
    }
    const foreign_ns = if (namespace == .foreign) namespace.foreign else null;
    const sandbox: SandboxKind = if (is_remote and (c.cfg.sandbox_remote_clients or wants_sandbox))
        .{ .remote = hostOf(peer) }
    else if (foreign_ns) |ns| blk: {
        // Refused, not downgraded: we can neither see into nor nest in the client's sandbox.
        if (wants_sandbox) {
            std.debug.print("Client {d}: --sandbox from inside a sandbox, rejecting\n", .{c.client_id});
            try replies.serveString(c, socket,
                "--sandbox: this client is already inside a sandbox (its mount namespace differs from the\n" ++
                    "daemon's), and the daemon cannot nest another in it. Drop --sandbox: the worker runs\n" ++
                    "inside this sandbox as it is.\n", 1);
            return null;
        }
        break :blk .{ .client = .{ .socket = socket, .ns = ns } };
    } else if (wants_sandbox) blk: {
        const cwd = assign.trimTrailingSlashes(request.cwd);
        const proj = assign.trimTrailingSlashes(request.project orelse "");
        const has_local_project = proj.len > 0 and proj[0] != '@';
        const local = if (has_local_project and assign.pathCoveredBy(cwd, &.{proj})) proj else cwd;
        if (local.len == 0) {
            try replies.serveString(c, socket, "--sandbox: the working directory no longer exists, so there is nothing to bind.\n", 1);
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
        std.debug.print("Client {d}: sandbox rejected (Linux only)\n", .{c.client_id});
        try replies.serveString(c, socket, msg, 1);
        return null;
    }
    std.debug.print("Client {d}: {s} sandbox\n", .{ c.client_id, @tagName(sandbox) });
    return sandbox;
}

/// The pool the request's workers are in: its project, Julia channel and
/// thread counts, fixed as a worker starts, and its sandbox.
pub fn poolKey(c: *Conductor, request: *const ClientRequest, sandbox: SandboxKind) ![]u8 {
    const project_path = request.project orelse "";
    const ch = request.parsed.julia_channel orelse "";
    const tkey = args.packThreads(assign.resolveThreads(request));
    return switch (sandbox) {
        .none => c.allocator.print("{s}\x00{s}\x00{d}", .{ project_path, ch, tkey }),
        // Isolated, each host's workers apart; one of unknown address shares with no other.
        .remote => |host| if (!c.cfg.sandbox_isolate_hosts)
            c.allocator.print("__sandbox__\x00\x00{s}\x00{d}", .{ ch, tkey })
        else if (host) |h|
            c.allocator.print("__sandbox__\x00{f}\x00{s}\x00{d}", .{ h, ch, tkey })
        else
            c.allocator.print("__sandbox__\x00?{d}\x00{s}\x00{d}", .{ c.client_id, ch, tkey }),
        // Keyed by mount namespace: a worker never serves another sandbox or the host.
        .client => |client| c.allocator.print("__ns{d}__\x00{s}\x00{s}\x00{d}", .{ client.ns, project_path, ch, tkey }),
        // Workers share only when their mounts match.
        .local => |rw| c.allocator.print("__lsandbox__\x00{s}\x00{s}\x00{s}\x00{d}", .{ rw, assign.trimTrailingSlashes(project_path), ch, tkey }),
    };
}

/// Why a `--sync` request is refused, if it is.
pub fn syncRefusal(request: *const ClientRequest) ?[]const u8 {
    const pages = request.parsed.getSwitch("--sync") orelse return null;
    if (assign.labelOf(request) == null) return "--sync requires --session=<label>\n";
    if (pages.len > 0) _ = std.fmt.parseInt(u16, pages, 10) catch
        return "--sync=<pages> takes a whole number of pages to replay, 0 for all\n";
    return null;
}

/// Ends the request's session, or without a label every worker of its pool.
pub fn serveRestart(c: *Conductor, socket: posix.socket_t, request: *const ClientRequest, worker_key: []const u8, sandbox: SandboxKind) !void {
    if (assign.labelOf(request)) |label| return restartSession(c, socket, request, worker_key, label, sandbox);
    const nkilled = retire.killWorkersForProject(c, worker_key);
    const channel = request.parsed.julia_channel;
    std.debug.print("Restart: killed {d} worker(s) for {s}{s}{s}\n", .{
        nkilled, request.project orelse "", if (channel != null) " " else "", channel orelse "",
    });
    const msg = try c.allocator.print("Reset: killed {d} worker(s) for project\n", .{nkilled});
    defer c.allocator.free(msg);
    try replies.serveString(c, socket, msg, 0);
}

/// With a label, that session; without, the one a `--session` run of the
/// caller's would join: in its pool, on the worker running a client, else the
/// one used last. A labelled worker holds a session of its own.
pub fn serveWatch(c: *Conductor, socket: posix.socket_t, request: *const ClientRequest, worker_key: []const u8, sandbox: SandboxKind) !Outcome {
    const pool: []const *worker.Worker = if (c.workers.getPtr(worker_key)) |list| list.items else &.{};
    const label = assign.labelOf(request);
    const found: ?*worker.Worker = if (label) |l|
        (if (sandbox != .none) assign.findWorkerByLabel(pool, l) else if (assign.findLabelled(c, l, .enterable)) |f| f.w else null)
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
            try c.allocator.print("No session '{s}' is running.\n", .{l})
        else
            try c.allocator.dupe(u8, "No worker is running for this project to watch.\n");
        defer c.allocator.free(msg);
        try replies.serveString(c, socket, msg, 1);
        return .done;
    };
    const seated = assign.assignClientToExistingWorker(c, socket, request, w) catch |err| {
        if (err != error.SessionBusy) return err;
        reportNoWorker(c, socket, err, sandbox, "");
        return .done;
    };
    if (!seated) try replies.serveString(c, socket, "The session's worker could not take a watcher.\n", 1);
    return .done;
}

/// `output` is what a failed spawn wrote last, shown in place of a hint.
pub fn reportNoWorker(c: *Conductor, socket: posix.socket_t, err: anyerror, sandbox: SandboxKind, output: []const u8) void {
    std.debug.print("Client {d}: no worker: {}\n", .{ c.client_id, err });
    if (err == error.ClientGone) return;
    var msg_buf: [2048]u8 = undefined;
    // Julia moved or upgraded since the service was set up, most likely.
    const msg = (if (err == error.SessionBusy)
        std.mem.print(&msg_buf, "The session's worker is too busy to answer: its code holds the worker's message loop.\n" ++
            "Try again once it yields, or end the session with --restart.\n", .{})
    else if (err == error.FileNotFound)
        std.mem.print(&msg_buf, "Could not run a Julia worker: its executable, {s}, cannot be found.\n" ++
            "Run juliaclient --reconfigure to set another (Workers, Julia executable), or DaemonicCabal.install() again.\n", .{c.cfg.worker_executable})
    else if (output.len > 0)
        std.mem.print(&msg_buf, "Could not run a Julia worker for this session ({s}). It wrote:\n{s}\n", .{ @errorName(err), output })
    else
        std.mem.print(&msg_buf, "Could not run a Julia worker for this session ({s}).\n{s}", .{
            @errorName(err), spawnFailureHint(c, err, sandbox),
        })) catch return;
    replies.serveString(c, socket, msg, 1) catch |e| std.debug.print("Client {d}: could not report the failure: {}\n", .{ c.client_id, e });
}

pub fn spawnFailureHint(c: *Conductor, err: anyerror, sandbox: SandboxKind) []const u8 {
    return switch (err) {
        error.WorkerSpawnTimeout => if (sandbox == .client)
            "The worker started inside your sandbox never connected to the daemon. Julia, the DaemonWorker project\n" ++
                "and the Julia depot must all be visible inside the sandbox; a fresh depot precompiles first, which\n" ++
                "JULIA_DAEMON_SPAWN_TIMEOUT bounds.\n"
        else
            "The worker never connected to the daemon within JULIA_DAEMON_SPAWN_TIMEOUT.\n",
        error.WorkerExitedEarly => "The worker exited while starting up; its output is in the daemon log.\n",
        error.ExecutableNotFound => if (c.cfg.worker_executable.len > 0)
            "The daemon cannot resolve its worker executable to an absolute path to hand to your sandbox;\n" ++
                "set JULIA_DAEMON_WORKER_EXECUTABLE to one.\n"
        else
            "",
        else => "See the daemon log for details.\n",
    };
}

/// Ends session `label` wherever a client of `request`'s would join it,
/// and a worker still starting for it; the rest of the pool is left alone.
pub fn restartSession(c: *Conductor, socket: posix.socket_t, request: *const ClientRequest, worker_key: []const u8, label: []const u8, sandbox: SandboxKind) !void {
    const pool: []const *worker.Worker = if (c.workers.getPtr(worker_key)) |list| list.items else &.{};
    const scoped = request.parsed.hasSwitch("--project") or sandbox != .none;
    // The host may end even a session it cannot join.
    const running = if (scoped) assign.findSession(c, pool, label, true) else assign.findLabelled(c, label, .any);
    if (running) |f| {
        f.w.log("retired: --restart of session '{s}'", .{label});
        retire.retireWorker(c, f.w);
    }
    const starting = for (c.pending_spawns.items) |p| switch (p.purpose) {
        .reserve => {},
        .client => |hold| if (std.mem.eql(u8, assign.labelOf(&hold.request) orelse "", label) and
            (if (scoped) std.mem.eql(u8, hold.worker_key, worker_key) else hold.sandbox != .client)) break p,
    } else null;
    if (starting) |p| spawns.failSpawn(c, p, error.Restarted);
    const ended = running != null or starting != null;
    std.debug.print("Restart: session '{s}' {s}\n", .{ label, if (ended) "ended" else "not running" });
    const msg = try c.allocator.print("Reset: {s} session '{s}'\n", .{ if (ended) "ended" else "no running", label });
    defer c.allocator.free(msg);
    try replies.serveString(c, socket, msg, 0);
}
