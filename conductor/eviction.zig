// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0
//
// Which idle workers go: activity signals (LRFU crf and PELT
// occupancy), the activity-scaled TTL, and pressure-reactive eviction. See
// WORKER_CACHE.md.

const std = @import("std");
const platform = @import("platform/main.zig");

const main = @import("main.zig");
const Conductor = main.Conductor;
const worker = main.worker;
const assign = @import("assign.zig");
const retire = @import("retire.zig");

const Expired = struct { w: *worker.Worker, key: []const u8 };

const Candidate = struct { w: *worker.Worker, key: []const u8, size: u64, value: f64 };

/// Bounds runaway culling under sustained pressure.
const max_evict_per_episode: usize = 4;

/// Episodes beyond this rank only the first `episode_capacity`, logged.
const episode_capacity: usize = 256;

/// Flattens the occupancy term's early climb (smaller → steeper near 0). See idleBudget.
const idle_budget_bias: f64 = 0.25;
const idle_budget_log_span: f64 = @log2((1 + idle_budget_bias) / idle_budget_bias);

/// k in the cadence multiplier 1+log2(1+(crf-1)/k): smaller → frequency earns longevity faster.
const cadence_mult_divisor: f64 = 2;

pub fn activityHalfLife(c: *const Conductor) u64 {
    return c.cfg.min_ttl;
}

// Slow half-lives: occupancy over half the budget span, crf a quarter (it compounds).
pub fn budgetOccHalfLife(c: *const Conductor) u64 {
    return (c.cfg.max_ttl - c.cfg.min_ttl) / 2;
}

pub fn crfHalfLife(c: *const Conductor) u64 {
    return (c.cfg.max_ttl - c.cfg.min_ttl) / 4;
}

pub fn bumpCrf(c: *Conductor, key: []const u8, now: i64) void {
    if (c.crf.getPtr(key)) |e| return e.summon(now, crfHalfLife(c));
    const key_copy = c.allocator.dupe(u8, key) catch return;
    c.crf.put(key_copy, .{ .last_update = now }) catch return c.allocator.free(key_copy);
    c.crf.getPtr(key_copy).?.summon(now, crfHalfLife(c));
}

pub fn readCrf(c: *Conductor, key: []const u8, now: i64) f64 {
    const e = c.crf.getPtr(key) orelse return 0;
    return e.read(now, crfHalfLife(c));
}

// Discounts the first summon: only reuse counts as warmth.
pub fn crfWarmth(c: *Conductor, key: ?[]const u8, now: i64) f64 {
    const k = key orelse return 0;
    return worker.Crf.normalize(@max(0, readCrf(c, k, now) - 1));
}

// Pure, so safe from the status renderer.
pub fn workerActivity(c: *Conductor, w: *const worker.Worker, key: ?[]const u8, now: i64) f64 {
    return @max(crfWarmth(c, key, now), w.occupancy.fast.read(now, activityHalfLife(c)));
}

// Caches mem and folds cpu into the meter, so the status render stays clock-free.
// Null `half_life_s` sets util to the raw rate (one-shot); a value blends the EWMA.
pub fn refreshStats(c: *Conductor, half_life_s: ?f64) void {
    const now_ns = c.nowNs();
    var it = c.liveWorkers();
    while (it.next()) |w| _ = refreshOne(w, now_ns, half_life_s);
}

/// Whether its stats could be read.
pub fn refreshOne(w: *worker.Worker, now_ns: i64, half_life_s: ?f64) bool {
    const pid = w.livePid() orelse return false;
    const s = platform.getProcessStats(pid) orelse return false;
    w.mem = s.mem_bytes;
    w.mem_at = @divTrunc(now_ns, 1_000_000_000);
    w.cpu.update(now_ns, s.cpu_seconds, half_life_s);
    return true;
}

// Once per ping interval, so sizing tracks idle drift without an extra wakeup.
pub fn refreshIdleMemIfStale(c: *Conductor, w: *worker.Worker, now_s: i64) void {
    if (w.busyClients() != 0) return;
    if (now_s - w.mem_at < @as(i64, @intCast(c.cfg.ping_interval))) return;
    _ = refreshOne(w, c.nowNs(), null);
}

// Only for a TTL-culled key; cleanupWorker has no handle on the crf map, enforcing this.
pub fn dropColdKey(c: *Conductor, key: []const u8) void {
    if (c.crf.fetchRemove(key)) |kv| c.allocator.free(kv.key);
}

pub fn enforceMaxTtl(c: *Conductor) void {
    const now = c.currentTime();
    // Re-scan from the top after each cull: retireWorker mutates the pool.
    while (findExpired(c, now)) |hit| {
        hit.w.log("idle {d}s past activity-scaled budget (max TTL {d}s), retiring", .{ now - hit.w.last_active, c.cfg.max_ttl });
        retire.retireWorker(c, hit.w);
        // dropColdKey reads hit.key, which dropPoolEntry frees.
        if (c.workers.getPtr(hit.key)) |list| {
            if (list.items.len == 0) {
                dropColdKey(c, hit.key);
                retire.dropPoolEntry(c, hit.key);
            }
        }
    }
}

// One at a time: the caller mutates the pool between calls. The reserve is
// exempt from TTL, though not from pressure.
pub fn findExpired(c: *Conductor, now: i64) ?Expired {
    var it = c.workers.iterator();
    while (it.next()) |entry| {
        for (entry.value_ptr.items) |w| {
            if (isExpired(c, w, entry.key_ptr.*, now)) return .{ .w = w, .key = entry.key_ptr.* };
        }
    }
    return null;
}

// Under pressure: rank idle in-band workers by value() on cheap RSS, validate
// the lowest band with true USS, retire the lowest up to the cap.
pub fn runEvictionEpisode(c: *Conductor) void {
    if (!c.pressure_monitor.poll(&c.cfg)) return;
    const now = c.currentTime();
    var buf: [episode_capacity]Candidate = undefined;
    const cands = collectDiscretionary(c, &buf, now);
    if (cands.len == 0) return;
    // An unreadable footprint (size 0) ranks by activity alone.
    const now_ns = c.nowNs();
    const half_life: f64 = @floatFromInt(c.cfg.ping_interval);
    for (cands) |*cand| {
        // Unread, its size is unknown, not what it was.
        cand.size = if (refreshOne(cand.w, now_ns, half_life)) cand.w.mem else 0;
        cand.value = workerValue(c, cand.w, cand.key, now, cand.size);
    }
    std.sort.pdq(Candidate, cands, {}, lessByValue);
    // Where selection used RSS, refine the bottom 2*cap band with true USS.
    const band = @min(2 * max_evict_per_episode, cands.len);
    if (!platform.mem_is_reclaimable) {
        for (cands[0..band]) |*cand| {
            if (cand.w.livePid()) |pid| {
                if (platform.processReclaimable(pid)) |uss| cand.size = uss;
            }
            cand.value = workerValue(c, cand.w, cand.key, now, cand.size);
        }
        std.sort.pdq(Candidate, cands[0..band], {}, lessByValue);
    }
    // Re-check each: the ranking may predate an assignment.
    var evicted: usize = 0;
    for (cands[0..band]) |cand| {
        if (evicted >= max_evict_per_episode) break;
        if (!inPressureBand(c, cand.w, cand.key, now)) continue;
        if (cand.size == 0)
            cand.w.log("evicting under memory pressure (value={d:.5}, size n/a)", .{cand.value})
        else
            cand.w.log("evicting under memory pressure (value={d:.5}, {d}MB)", .{ cand.value, cand.size >> 20 });
        retire.retireWorker(c, cand.w);
        evicted += 1;
    }
}

pub fn collectDiscretionary(c: *Conductor, buf: []Candidate, now: i64) []Candidate {
    var n: usize = 0;
    var it = c.workers.iterator();
    while (it.next()) |entry| {
        for (entry.value_ptr.items) |w| {
            if (n >= buf.len) {
                std.debug.print("Eviction episode: discretionary set exceeds cap; ranking first {d} only\n", .{buf.len});
                return buf[0..n];
            }
            if (inPressureBand(c, w, entry.key_ptr.*, now)) {
                buf[n] = .{ .w = w, .key = entry.key_ptr.*, .size = 0, .value = 0 };
                n += 1;
            }
        }
    }
    // The keyless reserve (crf=0) is the cheapest thing to drop under pressure.
    if (c.reserve) |r| {
        if (n < buf.len and inPressureBand(c, r, "", now)) {
            buf[n] = .{ .w = r, .key = "", .size = 0, .value = 0 };
            n += 1;
        }
    }
    return buf[0..n];
}

pub fn cullableAge(c: *Conductor, w: *worker.Worker, now: i64) ?u64 {
    if (w.busyClients() > 0) return null;
    if (w.session_label != null and !assign.isLabelExpired(c, w, now)) return null;
    return @intCast(@max(0, now - w.last_active));
}

// Past budget is expired instead: enforceMaxTtl culls it regardless. The
// reserve, exempt from the budget, has no such end.
pub fn inPressureBand(c: *Conductor, w: *worker.Worker, key: []const u8, now: i64) bool {
    const age = cullableAge(c, w, now) orelse return false;
    return age >= c.cfg.min_ttl and (c.reserve == w or age < idleBudget(c, w, key));
}

// Idle seconds before TTL culls a worker, the larger of two earned terms:
//  • cadence: the key's expected next-summon time (RFC 6298 RTO), scaled by a
//    log multiplier of crf so established frequency earns more headroom.
//  • occupancy: sustained busy-time, so a long single session earns budget too.
pub fn idleBudget(c: *Conductor, w: *const worker.Worker, key: []const u8) u64 {
    const max_ttl: f64 = @floatFromInt(c.cfg.max_ttl);
    // A session worker's floor is the geomean of min/max_ttl.
    const min_ttl: f64 = if (w.session_label != null)
        @sqrt(@as(f64, @floatFromInt(c.cfg.min_ttl)) * max_ttl)
    else
        @floatFromInt(c.cfg.min_ttl);
    var cadence: f64 = 0;
    if (key.len > 0) if (c.crf.getPtr(key)) |e| {
        const mult = 1 + @log2(1 + @max(0, e.read(w.last_active, crfHalfLife(c)) - 1) / cadence_mult_divisor);
        cadence = mult * @max(min_ttl, e.intervalBudget());
    };
    const occ = w.occupancy.slow.read(w.last_active, budgetOccHalfLife(c));
    const occ_budget = min_ttl + (max_ttl - min_ttl) * @log2((occ + idle_budget_bias) / idle_budget_bias) / idle_budget_log_span;
    return @intFromFloat(std.math.clamp(@max(cadence, occ_budget), min_ttl, max_ttl));
}

pub fn isExpired(c: *Conductor, w: *worker.Worker, key: []const u8, now: i64) bool {
    const age = cullableAge(c, w, now) orelse return false;
    return age >= idleBudget(c, w, key);
}

// value = activity / size_MiB, lowest evicted first. An unmeasured footprint
// (size 0) ranks by activity alone, spared rather than evicted on a made-up size.
pub fn workerValue(c: *Conductor, w: *worker.Worker, key: []const u8, now: i64, size_bytes: u64) f64 {
    const activity_val = workerActivity(c, w, key, now);
    if (size_bytes == 0) return activity_val;
    return activity_val / (@as(f64, @floatFromInt(size_bytes)) / (1 << 20));
}

pub fn lessByValue(_: void, a: Candidate, b: Candidate) bool {
    return a.value < b.value;
}
