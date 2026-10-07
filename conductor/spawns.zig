// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0
//
// Starting workers: the reserve, and one for a held client, which
// others for its pool queue behind until it connects or fails.

const std = @import("std");
const platform = @import("platform/main.zig");
const args = @import("args.zig");

const main = @import("main.zig");
const Conductor = main.Conductor;
const worker = main.worker;
const WorkerList = main.WorkerList;
const HeldClient = Conductor.HeldClient;
const PendingSpawn = Conductor.PendingSpawn;
const Resumption = assign.Resumption;
const removePending = Conductor.removePending;
const tag_spawn_client = Conductor.tag_spawn_client;
const tag_spawn_listener = Conductor.tag_spawn_listener;
const tag_spawn_stderr = Conductor.tag_spawn_stderr;
const tag_worker_stderr = Conductor.tag_worker_stderr;
const assign = @import("assign.zig");
const retire = @import("retire.zig");

pub fn beginReserveSpawn(c: *Conductor) !void {
    if (c.reserve != null) return;
    for (c.pending_spawns.items) |p| if (p.purpose == .reserve) return;
    // Clients usually inherit JULIA_NUM_THREADS, and reuse needs an exact match.
    const reserve_threads = if (c.environ_map.get("JULIA_NUM_THREADS")) |v|
        args.parseThreads(v)
    else
        args.threads_none;
    const p = try beginSpawn(c, .reserve, null, reserve_threads, false, .direct);
    std.debug.print("Spawning reserve worker {d} (pid {d})\n", .{ p.spawn.worker.id, platform.getChildPid(p.spawn.worker.process) });
}

// Seated in `list` (and labelled) on return.
pub fn claimReserve(c: *Conductor, list: *WorkerList, proj: []const u8, julia_channel: ?[]const u8, threads: args.Threads, label: ?[]const u8) !?*worker.Worker {
    const r = c.reserve orelse return null;
    if (!std.meta.eql(threads, r.threads)) return null;
    const channel_matches = if (julia_channel) |ch|
        r.julia_channel != null and std.mem.eql(u8, ch, r.julia_channel.?)
    else
        r.julia_channel == null;
    if (!channel_matches) return null;
    c.reserve = null;
    std.debug.print("Assigning reserve worker {d} to project {s}{s}{s}\n", .{
        r.id, proj, if (julia_channel != null) " " else "", julia_channel orelse "",
    });
    try seatWorker(c, list, r, proj, label);
    return r;
}

// Killed if seating fails, else it would orphan.
pub fn seatWorker(c: *Conductor, list: *WorkerList, w: *worker.Worker, proj: []const u8, label: ?[]const u8) !void {
    c.event_loop.cancelPendingPing(w);
    errdefer retire.enqueueKill(c, w);
    if (w.launch != .sandboxed or proj.len > 0) {
        const proj_copy = try c.allocator.dupe(u8, proj);
        w.setProject(proj_copy) catch |err| {
            c.allocator.free(proj_copy);
            return err;
        };
    }
    if (label) |l| if (w.session_label == null) {
        w.log("assigning label '{s}'", .{l});
        w.session_label = try c.allocator.dupe(u8, l);
    };
    try list.append(c.allocator, w);
}

pub fn beginClientSpawn(c: *Conductor, hold: *HeldClient) !void {
    const proj = hold.request.project orelse "";
    // Conductor-built sandboxes are never interactive.
    const interactive = (hold.sandbox == .none or hold.sandbox == .client) and hold.request.parsed.hasSwitch("--interactive");
    var rw_bind: [1][]const u8 = undefined;
    var ro_bind: [1][]const u8 = undefined;
    const launch: worker.Worker.Launch = switch (hold.sandbox) {
        .none => .direct,
        .client => |client| .{ .client = .{ .socket = client.socket, .environ = c.environ_map, .ns = client.ns } },
        .remote => .{ .sandboxed = .{ .environ = c.environ_map, .ro_binds = projectRoBind(proj, &.{}, &ro_bind), .rw_binds = &.{} } },
        .local => |rw| blk: {
            rw_bind = .{rw};
            break :blk .{ .sandboxed = .{ .environ = c.environ_map, .ro_binds = projectRoBind(proj, &rw_bind, &ro_bind), .rw_binds = &rw_bind } };
        },
    };
    const p = try beginSpawn(c, .{ .client = hold }, hold.request.parsed.julia_channel, assign.resolveThreads(&hold.request), interactive, launch);
    if (hold.sandbox == .remote) p.spawn.worker.origin = hold.sandbox.remote;
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
pub fn projectRoBind(proj: []const u8, rw_binds: []const []const u8, buf: *[1][]const u8) []const []const u8 {
    if (proj.len == 0 or assign.pathCoveredBy(proj, rw_binds)) return &.{};
    buf[0] = proj;
    return buf[0..1];
}

pub fn beginSpawn(c: *Conductor, purpose: @FieldType(PendingSpawn, "purpose"), julia_channel: ?[]const u8, threads: args.Threads, interactive: bool, launch: worker.Worker.Launch) !*PendingSpawn {
    // Made by `begin` before anything that may fail.
    errdefer if (launch == .sandboxed) retire.dropSandbox(c, c.next_worker_id);
    const p = try c.allocator.create(PendingSpawn);
    errdefer c.allocator.destroy(p);
    p.* = .{
        .spawn = try worker.Worker.begin(c.allocator, c.io, &c.cfg, c.next_worker_id, julia_channel, threads, interactive, launch, c.environ_map),
        .purpose = purpose,
    };
    errdefer p.spawn.abandon(c.io);
    try c.pending_spawns.append(c.allocator, p);
    c.next_worker_id += 1;
    c.event_loop.watchFd(@intFromPtr(p) | tag_spawn_listener, p.spawn.listenerFd());
    if (p.spawn.worker.stderrFd()) |fd| c.event_loop.watchFd(@intFromPtr(p) | tag_spawn_stderr, fd);
    // It sends nothing until it has its paths, so readable means it hung up.
    if (p.purpose == .client) c.event_loop.watchFd(@intFromPtr(p.purpose.client) | tag_spawn_client, p.purpose.client.socket);
    c.event_loop.armTick();
    return p;
}

pub fn findPendingSpawn(c: *Conductor, key: []const u8) ?*PendingSpawn {
    for (c.pending_spawns.items) |p| switch (p.purpose) {
        .reserve => {},
        .client => |hold| if (std.mem.eql(u8, hold.worker_key, key)) return p,
    };
    return null;
}

// The setup listener turned readable: the worker, or an impostor, connected.
pub fn onSpawnReadable(c: *Conductor, p: *PendingSpawn) void {
    const connected = p.spawn.accept(c.io, &c.cfg, c.keyFor(.worker, p.spawn.worker.id)) catch |err| return failSpawn(c, p, err);
    if (connected) |w| completeSpawn(c, p, w) else c.event_loop.watchFd(@intFromPtr(p) | tag_spawn_listener, p.spawn.listenerFd());
}

// Without the client it started for, the worker underway is worth keeping
// only for those waiting on it.
pub fn onHeldClientGone(c: *Conductor, hold: *HeldClient) void {
    for (c.pending_spawns.items) |p| {
        const starts = p.purpose == .client and p.purpose.client == hold;
        const waiting = if (starts) null else std.mem.findScalar(*HeldClient, p.waiters.items, hold);
        if (!starts and waiting == null) continue;
        // A held client sends nothing, so only an end is a hangup: a readiness
        // that finds none is stale, its poll raced by a cancel, perhaps of an
        // earlier hold at this address.
        var byte: [1]u8 = undefined;
        if (platform.recvNonBlocking(hold.socket, &byte)) |got| {
            if (got > 0) c.event_loop.watchFd(@intFromPtr(hold) | tag_spawn_client, hold.socket);
            return;
        }
        if (starts) {
            std.debug.print("Client {d}: left while worker {d} was starting\n", .{ hold.id, p.spawn.worker.id });
            // A worker the client spawned in its sandbox is its own.
            if (p.waiters.items.len == 0 or hold.sandbox == .client) return failSpawn(c, p, error.ClientGone);
            c.event_loop.unwatchFd(@intFromPtr(hold) | tag_spawn_client, hold.socket);
            platform.close(hold.socket);
            hold.gone = true;
            return;
        }
        std.debug.print("Client {d}: left while waiting for worker {d}\n", .{ hold.id, p.spawn.worker.id });
        _ = p.waiters.orderedRemove(waiting.?);
        c.event_loop.unwatchFd(@intFromPtr(hold) | tag_spawn_client, hold.socket);
        return assign.discardHold(c, hold);
    }
}

pub fn detachSpawn(c: *Conductor, p: *PendingSpawn) void {
    _ = removePending(&c.pending_spawns, p);
    c.event_loop.unwatchFd(@intFromPtr(p) | tag_spawn_listener, p.spawn.listenerFd());
    if (p.spawn.worker.stderrFd()) |fd| c.event_loop.unwatchFd(@intFromPtr(p) | tag_spawn_stderr, fd);
    if (p.purpose == .client and !p.purpose.client.gone) c.event_loop.unwatchFd(@intFromPtr(p.purpose.client) | tag_spawn_client, p.purpose.client.socket);
    for (p.waiters.items) |hold| c.event_loop.unwatchFd(@intFromPtr(hold) | tag_spawn_client, hold.socket);
}

pub fn failSpawn(c: *Conductor, p: *PendingSpawn, err: anyerror) void {
    if (err != error.ClientGone) p.spawn.worker.log("spawn failed: {}", .{err});
    detachSpawn(c, p);
    p.spawn.abandon(c.io);
    if (p.spawn.worker.launch == .sandboxed) retire.dropSandbox(c, p.spawn.worker.id);
    // A child it left, precompiling, may hold the pipe open.
    if (c.drainStderr(&p.spawn.worker, false)) p.spawn.worker.process.stderr.?.close(c.io);
    var output_buf: [1024]u8 = undefined;
    const output = p.spawn.worker.recent.tail(.worker, 8, &output_buf);
    p.spawn.worker.recent.deinit(c.allocator);
    settleSpawn(c, p, .{ .refuse = .{ .err = err, .output = output } });
}

pub fn completeSpawn(c: *Conductor, p: *PendingSpawn, connected: worker.Worker) void {
    detachSpawn(c, p);
    p.spawn.listener.close(c.io);
    const w = c.allocator.create(worker.Worker) catch |err| {
        var lost = connected;
        lost.killAndReap();
        lost.deinit();
        return settleSpawn(c, p, .{ .refuse = .{ .err = err } });
    };
    w.* = connected;
    if (w.stderrFd()) |fd| c.event_loop.watchFd(@intFromPtr(w) | tag_worker_stderr, fd);
    std.debug.print("Worker {d} (pid {d}) connected\n", .{ w.id, platform.getChildPid(w.process) });
    switch (p.purpose) {
        .reserve => if (w.ping()) {
            c.reserve = w;
        } else |err| {
            std.debug.print("Reserve worker {d}: first ping failed: {}\n", .{ w.id, err });
            retire.enqueueKill(c, w);
        },
        .client => |hold| {
            const list = assign.getWorkerList(c, hold.worker_key) catch |err| return settleSpawn(c, p, .{ .refuse = .{ .err = err } });
            seatWorker(c, list, w, hold.request.project orelse "", assign.labelOf(&hold.request)) catch |err| return settleSpawn(c, p, .{ .refuse = .{ .err = err } });
            return settleSpawn(c, p, .{ .on = w });
        },
    }
    settleSpawn(c, p, .select);
}

pub fn settleSpawn(c: *Conductor, p: *PendingSpawn, how: Resumption) void {
    // A worker seated for a client gone is the waiters' to select.
    if (p.purpose == .client) {
        const hold = p.purpose.client;
        if (hold.gone) assign.discardHold(c, hold) else assign.resumeHeld(c, hold, how);
    }
    for (p.waiters.items) |hold| assign.resumeHeld(c, hold, .select);
    p.waiters.deinit(c.allocator);
    c.allocator.destroy(p);
}

pub fn abandonSpawns(c: *Conductor) void {
    while (c.pending_spawns.pop()) |p| {
        detachSpawn(c, p);
        p.spawn.abandon(c.io);
        if (p.spawn.worker.launch == .sandboxed) retire.dropSandbox(c, p.spawn.worker.id);
        p.spawn.worker.recent.deinit(c.allocator);
        for (p.waiters.items) |hold| assign.resumeHeld(c, hold, .{ .refuse = .{ .err = error.DaemonShuttingDown } });
        p.waiters.clearRetainingCapacity();
        settleSpawn(c, p, .{ .refuse = .{ .err = error.DaemonShuttingDown } });
    }
}
