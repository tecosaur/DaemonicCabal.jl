// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0
//
// Retiring workers: soft exit, then SIGTERM, then SIGKILL, to the
// worker's process group; what a sandbox leaves behind; shutdown.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const platform = @import("platform/main.zig");

const main = @import("main.zig");
const Conductor = main.Conductor;
const worker = main.worker;
const tag_worker_stderr = Conductor.tag_worker_stderr;
const tracking = @import("tracking.zig");
const spawns = @import("spawns.zig");

/// Grace per retirement stage; SIGTERM/SIGKILL fire only for a wedged worker.
const retire_grace_s: i64 = 5;

pub fn cleanupWorker(c: *Conductor, w: *worker.Worker) void {
    if (w.exited()) platform.dumpChildStderr(c.io, c.allocator, &w.process, w.id);
    if (w.stderrFd()) |fd| {
        c.event_loop.unwatchFd(@intFromPtr(w) | tag_worker_stderr, fd);
        _ = c.drainStderr(w, false);
        if (w.process.stderr) |f| f.close(c.io);
        w.process.stderr = null;
    }
    if (w.launch == .sandboxed) dropSandbox(c, w.id);
    w.deinit();
    c.allocator.destroy(w);
}

/// What a sandbox left in the runtime directory and the cgroup tree.
pub fn dropSandbox(c: *Conductor, worker_id: u32) void {
    removeSandboxDir(c, worker_id);
    if (builtin.target.os.tag != .linux or worker.sandbox.removeCgroup(worker_id)) return;
    c.cgroups_left.append(c.allocator, worker_id) catch {};
}

pub fn retryCgroups(c: *Conductor) void {
    if (builtin.target.os.tag != .linux) return;
    var i: usize = 0;
    while (i < c.cgroups_left.items.len) {
        if (worker.sandbox.removeCgroup(c.cgroups_left.items[i])) _ = c.cgroups_left.swapRemove(i) else i += 1;
    }
}

/// Those of sandboxes a conductor before this one left.
pub fn cleanupCgroups(c: *Conductor) void {
    if (builtin.target.os.tag != .linux) return;
    const root = worker.sandbox.cgroupRoot() orelse return;
    var dir = Io.Dir.openDirAbsolute(c.io, root, .{ .iterate = true }) catch return;
    defer dir.close(c.io);
    var iter = dir.iterate();
    while (iter.next(c.io) catch null) |entry| {
        if (entry.kind != .directory) continue;
        const id = std.mem.cutPrefix(u8, entry.name, "sandbox-") orelse continue;
        if (!worker.sandbox.removeCgroup(std.fmt.parseInt(u32, id, 10) catch continue))
            std.debug.print("Warning: a sandbox cgroup from before, {s}, still holds processes\n", .{entry.name});
    }
}

pub fn removeSandboxDir(c: *Conductor, worker_id: u32) void {
    var buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const name = std.mem.print(&buf, "sandbox-{d}", .{worker_id}) catch return;
    var dir = Io.Dir.openDirAbsolute(c.io, c.cfg.socket_dir, .{}) catch return;
    defer dir.close(c.io);
    dir.deleteTree(c.io, name) catch {};
}

pub fn killWorkersForProject(c: *Conductor, worker_key: []const u8) usize {
    var count: usize = 0;
    // The pool goes first: the clients of a failed spawn select again, and
    // must not land on a worker about to be killed.
    if (c.workers.getPtr(worker_key)) |list| {
        count = list.items.len;
        for (list.items) |w| {
            c.event_loop.cancelPendingPing(w);
            tracking.removeActiveClientsForWorker(c, w);
            enqueueKill(c, w);
        }
        // crf history is kept: --restart is a non-TTL death (may come back hot).
        dropPoolEntry(c, worker_key);
    }
    // A starting worker counts too; its clients are told to try again. There
    // is at most one per key, as later clients queue behind it.
    if (spawns.findPendingSpawn(c, worker_key)) |p| {
        spawns.failSpawn(c, p, error.Restarted);
        count += 1;
    }
    return count;
}

/// Retires every worker spawned before `before_ns` (on `nowNs`'s clock)
/// that runs no client and holds no session, so those that replace them
/// start afresh; returns how many.
pub fn retireIdleWorkers(c: *Conductor, before_ns: i64) usize {
    var idle: std.ArrayList(*worker.Worker) = .empty;
    defer idle.deinit(c.allocator);
    var it = c.workers.valueIterator();
    while (it.next()) |list| for (list.items) |w| {
        if (isRetirable(w, before_ns)) idle.append(c.allocator, w) catch break;
    };
    for (idle.items) |w| {
        w.log("retired: idle, as settings changed", .{});
        retireWorker(c, w);
    }
    renewReserve(c);
    return idle.items.len;
}

pub fn isRetirable(w: *const worker.Worker, before_ns: i64) bool {
    return w.spawned_ns < before_ns and w.busyClients() == 0 and w.session_label == null and !w.hosts_session;
}

/// Replaces the reserve worker, so the next new project's starts with
/// the settings as they are now.
pub fn renewReserve(c: *Conductor) void {
    if (c.reserve) |r| {
        r.log("retired: the reserve, as settings changed", .{});
        retireWorker(c, r);
    }
    // One still starting started from the old environment.
    var i: usize = 0;
    while (i < c.pending_spawns.items.len) {
        const p = c.pending_spawns.items[i];
        if (p.purpose == .reserve) spawns.failSpawn(c, p, error.SettingsChanged) else i += 1;
    }
    if (c.cfg.reserve_worker) spawns.beginReserveSpawn(c) catch |err| {
        std.debug.print("Reserve worker: spawn failed: {}\n", .{err});
    };
}

// Returns at once; the sweep escalates soft -> SIGTERM -> SIGKILL and reaps.
pub fn retireWorker(c: *Conductor, w: *worker.Worker) void {
    c.event_loop.cancelPendingPing(w);
    if (c.reserve == w) c.reserve = null;
    tracking.removeActiveClientsForWorker(c, w);
    var it = c.workers.iterator();
    while (it.next()) |entry| {
        for (entry.value_ptr.items, 0..) |item, i| {
            if (item == w) {
                _ = entry.value_ptr.swapRemove(i);
                break;
            }
        }
    }
    enqueueKill(c, w);
}

// Precondition: `w` is already detached from the pool.
pub fn enqueueKill(c: *Conductor, w: *worker.Worker) void {
    if (w.process.id == null) {
        cleanupWorker(c, w);
        return;
    }
    w.softExit();
    c.pending_kills.append(c.allocator, .{
        .w = w, .stage = .soft, .deadline = c.currentTime() + retire_grace_s,
    }) catch {
        w.killAndReap();
        cleanupWorker(c, w);
    };
}

// Callers own the list's workers first; `key` dangles afterward.
pub fn dropPoolEntry(c: *Conductor, key: []const u8) void {
    if (c.workers.fetchRemove(key)) |kv| {
        var list = kv.value;
        list.deinit(c.allocator);
        c.allocator.free(kv.key);
    }
}

pub fn sweepPendingKills(c: *Conductor) void {
    retryCgroups(c);
    const now = c.currentTime();
    var i: usize = 0;
    while (i < c.orphan_groups.items.len) {
        const orphans = c.orphan_groups.items[i];
        if (now < orphans.deadline) {
            i += 1;
            continue;
        }
        _ = platform.killGroup(orphans.pgid, platform.SIG.KILL);
        _ = c.orphan_groups.swapRemove(i);
    }
    i = 0;
    while (i < c.pending_kills.items.len) {
        var pk = &c.pending_kills.items[i];
        if (reaped(c, pk.w)) {
            cleanupWorker(c, pk.w);
            _ = c.pending_kills.swapRemove(i);
            continue;
        }
        if (now >= pk.deadline) switch (pk.stage) {
            .soft => {
                pk.w.signalGroup(platform.SIG.TERM);
                pk.stage = .term;
                pk.deadline = now + retire_grace_s;
            },
            // Reaped above: one wedged past SIGTERM may be slow to die.
            .term => {
                pk.w.signalGroup(platform.SIG.KILL);
                pk.stage = .kill;
            },
            .kill => {},
        };
        i += 1;
    }
}

/// `w.exited()`, ending what its code left running as it is reaped. The
/// group outlives its leader while it has members, so its id can't yet
/// be another's.
pub fn reaped(c: *Conductor, w: *worker.Worker) bool {
    const group = w.processGroup();
    if (!w.exited()) return false;
    const pgid = group orelse return true;
    if (platform.killGroup(pgid, platform.SIG.TERM))
        c.orphan_groups.append(c.allocator, .{ .pgid = pgid, .deadline = c.currentTime() + retire_grace_s }) catch {};
    return true;
}

pub fn gracefulShutdown(c: *Conductor) void {
    spawns.abandonSpawns(c);
    var it = c.liveWorkers();
    while (it.next()) |w| w.softExit();
    if (waitForWorkers(c, 1000)) return;
    std.debug.print("Timeout waiting for soft exit, sending SIGTERM\n", .{});
    signalAllWorkers(c, platform.SIG.TERM);
    if (waitForWorkers(c, 1000)) return;
    std.debug.print("Timeout waiting for SIGTERM, sending SIGKILL\n", .{});
    signalAllWorkers(c, platform.SIG.KILL);
}

pub fn waitForWorkers(c: *Conductor, timeout_ms: u32) bool {
    var elapsed: u32 = 0;
    while (elapsed < timeout_ms) : (elapsed += 100) {
        Io.sleep(c.io, Io.Duration.fromMilliseconds(100), .awake) catch {};
        if (!anyWorkerAlive(c)) return true;
    }
    return false;
}

// Only the living: anyWorkerAlive reaped the rest, whose pids may be reused.
pub fn signalAllWorkers(c: *Conductor, sig: platform.SIG) void {
    var it = c.liveWorkers();
    while (it.next()) |w| if (!reaped(c, w)) w.signalGroup(sig);
    // Workers mid-retirement are no longer in the pool but still dying.
    for (c.pending_kills.items) |pk| if (!reaped(c, pk.w)) pk.w.signalGroup(sig);
}

pub fn anyWorkerAlive(c: *Conductor) bool {
    var it = c.liveWorkers();
    while (it.next()) |w| if (!reaped(c, w)) return true;
    for (c.pending_kills.items) |pk| if (!reaped(c, pk.w)) return true;
    return false;
}
