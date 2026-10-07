// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0
//
// The clients each worker runs, as the conductor tracks them, and
// reconciling that with the worker's own count.

const std = @import("std");

const main = @import("main.zig");
const Conductor = main.Conductor;
const worker = main.worker;
const ActiveClientInfo = main.ActiveClientInfo;
const end_probe_ms = main.end_probe_ms;
const ClientRequest = Conductor.ClientRequest;
const assign = @import("assign.zig");
const retire = @import("retire.zig");
const eviction = @import("eviction.zig");

pub const Ending = enum { ended, interrupted, retired };

/// Per-worker client ids a single reconciliation pass can hold.
const max_tracked_clients = 256;

pub fn removeActiveClientsForWorker(c: *Conductor, w: *worker.Worker) void {
    // Repeat: the fixed buffer may not hold every match in one pass.
    var to_remove: [64]u32 = undefined;
    while (true) {
        var remove_count: usize = 0;
        var it = c.active_clients.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.worker == w) {
                assign.releasePortSet(c, entry.value_ptr.port_set);
                to_remove[remove_count] = entry.key_ptr.*;
                remove_count += 1;
                if (remove_count >= to_remove.len) break;
            }
        }
        for (to_remove[0..remove_count]) |id| {
            _ = c.active_clients.remove(id);
        }
        if (remove_count < to_remove.len) break;
    }
}

pub fn registerClient(c: *Conductor, id: u32, request: *const ClientRequest, w: *worker.Worker, port_set: u16) !void {
    try trackClient(c, id, .{
        .worker = w,
        .pid = request.host_pid orelse request.pid,
        .port_set = port_set,
        .watcher = request.parsed.hasSwitch("--watch"),
        .session = request.parsed.hasSwitch("--session"),
        .sync = request.parsed.hasSwitch("--sync"),
    });
}

pub fn trackClient(c: *Conductor, id: u32, info: ActiveClientInfo) !void {
    const now_us = @divTrunc(c.nowNs(), 1000);
    const now_s = @divTrunc(now_us, 1_000_000);
    var entry = info;
    entry.start_time_us = now_us;
    try c.active_clients.put(id, entry);
    const w = info.worker;
    w.hosts_session = w.hosts_session or (info.session and !info.watcher);
    if (!info.internal) w.log("{s} {d} attached", .{ if (info.watcher) "watcher" else "client", info.pid });
    if (info.watcher) {
        w.watchers += 1;
    } else if (!w.occupancy.fast.busy) {
        w.occupancy.attach(now_s, eviction.activityHalfLife(c), eviction.budgetOccHalfLife(c));
    }
}

pub fn clientDone(c: *Conductor, id: u32) ?*worker.Worker {
    const info = (c.active_clients.fetchRemove(id) orelse return null).value;
    const w = info.worker;
    assign.releasePortSet(c, info.port_set);
    if (w.active_clients > 0) {
        w.active_clients -= 1;
    } else {
        w.log("clientDone underflow (map/count drift)", .{});
    }
    const now_ns = c.nowNs();
    const now_us = @divTrunc(now_ns, 1000);
    const now_s = @divTrunc(now_us, 1_000_000);
    if (info.watcher) {
        w.watchers -|= 1;
    } else {
        w.last_active = now_s;
        if (w.busyClients() == 0) {
            w.occupancy.detach(now_s, eviction.activityHalfLife(c), eviction.budgetOccHalfLife(c));
            _ = eviction.refreshOne(w, now_ns, null);
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

pub fn syncWorkerClients(c: *Conductor, w: *worker.Worker) void {
    const synced = syncCounts(c, w) catch return;
    const remaining = synced.listed;
    const busy = w.busyClients();
    // The worker's surplus is departed clients' code it could not stop.
    if (synced.running > remaining and busy == 0) {
        w.log("{d} departed client(s) still running, retiring", .{synced.running});
        return retire.retireWorker(c, w);
    }
    const now = c.currentTime();
    if (busy == 0 and w.occupancy.fast.busy) {
        w.occupancy.detach(now, eviction.activityHalfLife(c), eviction.budgetOccHalfLife(c));
    } else if (busy > 0 and !w.occupancy.fast.busy) {
        w.occupancy.attach(now, eviction.activityHalfLife(c), eviction.budgetOccHalfLife(c));
    }
    w.log("sync complete, {d} active clients", .{remaining});
}

/// Tells the worker the clients it has, and it stops any other; returns
/// how many it still runs, and how many were listed. A worker that fails
/// to answer is retired (`error.SyncFailed`).
pub fn syncCounts(c: *Conductor, w: *worker.Worker) !struct { running: u16, listed: u32 } {
    // The worker kills every client not listed, so a partial list is never sent.
    var ids: [max_tracked_clients]u32 = undefined;
    var count: usize = 0;
    var it = c.active_clients.iterator();
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
        retire.retireWorker(c, w);
        return error.SyncFailed;
    };
    try reconcileClientMap(c, w);
    const counted = countMapClients(c, w);
    w.active_clients = counted.clients;
    w.watchers = counted.watchers;
    return .{ .running = running, .listed = counted.clients };
}

/// Ends `ids`, clients of `w`: they are dropped here and the worker stops
/// their tasks. One that won't stop, a CPU-bound loop, is force-interrupted
/// (thread 0 runs it, so the interrupt lands there), and the worker retired
/// if it still runs one, or stops answering.
pub fn endClients(c: *Conductor, w: *worker.Worker, ids: []const u32) Ending {
    for (ids) |id| _ = clientDone(c, id);
    var ending: Ending = .ended;
    while (true) {
        c.event_loop.cancelPendingPing(w);
        if (w.answersWithin(end_probe_ms)) {
            const synced = syncCounts(c, w) catch |err| switch (err) {
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
    retire.retireWorker(c, w);
    return .retired;
}

pub fn countMapClients(c: *Conductor, w: *worker.Worker) struct { clients: u32, watchers: u32 } {
    var clients: u32 = 0;
    var watchers: u32 = 0;
    var it = c.active_clients.iterator();
    while (it.next()) |entry| if (entry.value_ptr.worker == w) {
        clients += 1;
        if (entry.value_ptr.watcher) watchers += 1;
    };
    return .{ .clients = clients, .watchers = watchers };
}

// Repairs a lost client_done, which the count-only sync can't. A worker
// that fails to answer is retired (`error.SyncFailed`).
pub fn reconcileClientMap(c: *Conductor, w: *worker.Worker) !void {
    var running_buf: [max_tracked_clients]u32 = undefined;
    const running = w.queryClients(&running_buf) catch |err| {
        w.log("queryClients failed: {}", .{err});
        // Past the whole list, the stream is in step still.
        if (err == error.TooManyClients) return;
        retire.retireWorker(c, w);
        return error.SyncFailed;
    };
    var stale: [max_tracked_clients]u32 = undefined;
    var n: usize = 0;
    var it = c.active_clients.iterator();
    while (it.next()) |entry| {
        if (entry.value_ptr.worker != w) continue;
        if (std.mem.findScalar(u32, running, entry.key_ptr.*) != null) continue;
        if (n < stale.len) {
            stale[n] = entry.key_ptr.*;
            n += 1;
        }
    }
    for (stale[0..n]) |id| {
        if (c.active_clients.fetchRemove(id)) |e| assign.releasePortSet(c, e.value.port_set);
    }
}
