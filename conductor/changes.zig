// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0
//
// The daemon's settings as `--reconfigure` changes them (`RECONFIGURE.md`):
// what the conductor started with, what's applied, what a restart would
// bring, and a viewer's staged changes. No I/O: `reconfigure.zig` is the
// conductor's side.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Environ = std.process.Environ;
const settings = @import("settings.zig");
const service = @import("service.zig");

const all = settings.all;

/// Each setting's value, as `settings.all` orders them; null is unset.
pub const Values = [all.len]?[]const u8;

/// The settings as the conductor holds them, each value owned.
pub const State = struct {
    running: Values = @splat(null), // as the conductor started
    applied: Values = @splat(null),
    saved: Values = @splat(null), // as a restart would bring them
    inherited: Values = @splat(null), // from what starts the service, where it declares nothing
    /// When a setting workers read as they start last changed, on the
    /// clock of `Worker.spawned_ns`.
    workers_changed_ns: i64 = 0,

    /// From `env`, the conductor's environment, and `declared`, what its
    /// service declares, when there's one to read.
    pub fn init(gpa: Allocator, env: *const Environ.Map, declared: ?*const service.Declared) Allocator.Error!State {
        var self: State = .{};
        errdefer self.deinit(gpa);
        for (settings.fromEnv(env), 0..) |value, i| {
            try setOwned(gpa, &self.running[i], value);
            try setOwned(gpa, &self.applied[i], value);
            const from_service = if (declared) |d| declares(d, i) else false;
            try setOwned(gpa, &self.inherited[i], if (from_service) null else value);
        }
        try self.reread(gpa, declared);
        return self;
    }

    pub fn deinit(self: *State, gpa: Allocator) void {
        for ([_][]?[]const u8{ &self.running, &self.applied, &self.saved, &self.inherited }) |values| {
            for (values) |value| if (value) |text| gpa.free(text);
        }
    }

    /// What a restart would bring, now the service declares `declared`.
    pub fn reread(self: *State, gpa: Allocator, declared: ?*const service.Declared) Allocator.Error!void {
        const set: Values = if (declared) |d| settings.fromEnv(&d.set) else @splat(null);
        for (&self.saved, set, self.inherited, 0..) |*saved, value, inherited, i| {
            const unset = if (declared) |d| d.unset.contains(all[i].key) else false;
            try setOwned(gpa, saved, if (unset) null else value orelse inherited);
        }
    }

    pub fn isUnsaved(self: *const State, i: usize) bool {
        return !same(self.applied[i], self.saved[i]);
    }

    /// The service writes what `changesToSave` gave.
    pub fn markSaved(self: *State, gpa: Allocator) Allocator.Error!void {
        for (&self.saved, self.applied) |*saved, applied| try setOwned(gpa, saved, applied);
    }

    /// What saving writes, into `buf`: each unsaved setting, and the
    /// deprecated alias of one dropped.
    pub fn changesToSave(self: *const State, buf: *[2 * all.len]service.Change) []service.Change {
        var n: usize = 0;
        for (all, 0..) |s, i| {
            if (!self.isUnsaved(i)) continue;
            buf[n] = .{ .key = s.key, .value = self.applied[i] };
            n += 1;
            if (s.alias) |alias| {
                buf[n] = .{ .key = alias, .value = null };
                n += 1;
            }
        }
        return buf[0..n];
    }

    /// `staged`, checked together, into the applied; they're unstaged.
    /// Nothing changes when they'd break a rule.
    pub fn apply(self: *State, gpa: Allocator, staged: *Staged) Allocator.Error!Outcome {
        var values = staged.values(self);
        if (settings.conflict(&values)) |conflict| return .{ .conflict = conflict };
        var applied: Applied = .initEmpty();
        for (&staged.edits, 0..) |*edit, i| {
            const change = edit.* orelse continue;
            try setOwned(gpa, &self.applied[i], change.text());
            applied.set(i);
            staged.unstage(gpa, i);
        }
        return .{ .applied = applied };
    }

    fn declares(d: *const service.Declared, i: usize) bool {
        return d.declares(all[i].key) or if (all[i].alias) |alias| d.set.contains(alias) else false;
    }
};

pub const Applied = std.StaticBitSet(all.len);

pub const Outcome = union(enum) {
    conflict: settings.Conflict,
    applied: Applied,
};

/// A viewer's changes, not yet applied.
pub const Staged = struct {
    edits: [all.len]?Edit = @splat(null),

    pub const Edit = union(enum) {
        unset,
        value: []u8,

        pub fn text(self: Edit) ?[]const u8 {
            return switch (self) {
                .unset => null,
                .value => |v| v,
            };
        }
    };

    pub fn deinit(self: *Staged, gpa: Allocator) void {
        for (0..all.len) |i| self.unstage(gpa, i);
    }

    /// A change of `i` to `value` (null: its default), unless it's in
    /// effect already or the installer's to set.
    pub fn stage(self: *Staged, gpa: Allocator, state: *const State, i: usize, value: ?[]const u8) Allocator.Error!void {
        self.unstage(gpa, i);
        if (all[i].effect == .fixed or inEffect(state, i, value)) return;
        self.edits[i] = if (value) |text| .{ .value = try gpa.dupe(u8, text) } else .unset;
    }

    pub fn unstage(self: *Staged, gpa: Allocator, i: usize) void {
        if (self.edits[i]) |edit| if (edit == .value) gpa.free(edit.value);
        self.edits[i] = null;
    }

    /// A staged change dropped; else an unsaved one's saved value staged.
    pub fn undo(self: *Staged, gpa: Allocator, state: *const State, i: usize) Allocator.Error!void {
        if (self.edits[i] != null) return self.unstage(gpa, i);
        try self.stage(gpa, state, i, state.saved[i]);
    }

    /// Those another viewer has applied since.
    pub fn prune(self: *Staged, gpa: Allocator, state: *const State) void {
        for (self.edits, 0..) |edit, i| {
            if (edit != null and inEffect(state, i, edit.?.text())) self.unstage(gpa, i);
        }
    }

    pub fn has(self: *const Staged, i: usize) bool {
        return self.edits[i] != null;
    }

    /// Setting `i` as it would be: staged, else applied.
    pub fn effective(self: *const Staged, state: *const State, i: usize) ?[]const u8 {
        return if (self.edits[i]) |edit| edit.text() else state.applied[i];
    }

    /// Each setting as it would be.
    pub fn values(self: *const Staged, state: *const State) Values {
        var out: Values = undefined;
        for (&out, 0..) |*value, i| value.* = self.effective(state, i);
        return out;
    }

    fn inEffect(state: *const State, i: usize, value: ?[]const u8) bool {
        const applied = state.applied[i];
        return same(value, applied) or (applied == null and same(value, all[i].default));
    }
};

/// The workers running, the reserve aside, as far as a change for workers
/// reaches them.
pub const Fleet = struct {
    oldest_spawn_ns: ?i64 = null,
    idle_stale: bool = false, // one spawned before the last change, idle and holding no session
};

/// What's changed, and where it stands.
pub const Pending = struct {
    staged: usize = 0,
    unsaved: usize = 0, // applied, not saved
    after: usize = 0, // unsaved once the staged are applied
    restart: usize = 0, // applied, read only as the conductor starts
    workers: usize = 0, // for workers to read as they start, which some running won't have
    retirable: bool = false, // an idle worker among those
    saving: bool, // whether there's a service to save to

    /// Whether quitting would lose something.
    pub fn asks(self: Pending) bool {
        return self.staged > 0 or (self.saving and self.unsaved > 0);
    }
};

pub fn pending(state: *const State, staged: *const Staged, fleet: Fleet, saving: bool) Pending {
    var p: Pending = .{ .saving = saving };
    for (0..all.len) |i| {
        if (staged.has(i)) p.staged += 1;
        if (state.isUnsaved(i)) p.unsaved += 1;
        if (!same(staged.effective(state, i), state.saved[i])) p.after += 1;
        if (all[i].effect == .restart and !same(state.applied[i], state.running[i])) p.restart += 1;
        const staged_for_workers = all[i].effect == .new_workers and staged.has(i) and fleet.oldest_spawn_ns != null;
        if (staged_for_workers or isMissed(state, fleet, i)) p.workers += 1;
    }
    p.retirable = p.workers > 0 and fleet.idle_stale;
    return p;
}

/// Whether setting `i` is applied, for workers to read as they start, and
/// one running started before.
pub fn isMissed(state: *const State, fleet: Fleet, i: usize) bool {
    if (all[i].effect != .new_workers or same(state.applied[i], state.running[i])) return false;
    const oldest = fleet.oldest_spawn_ns orelse return false;
    return oldest < state.workers_changed_ns;
}

pub fn same(a: ?[]const u8, b: ?[]const u8) bool {
    if (a == null or b == null) return a == null and b == null;
    return std.mem.eql(u8, a.?, b.?);
}

fn setOwned(gpa: Allocator, slot: *?[]const u8, value: ?[]const u8) Allocator.Error!void {
    const copy = if (value) |text| try gpa.dupe(u8, text) else null;
    if (slot.*) |old| gpa.free(old);
    slot.* = copy;
}

// --- Tests ---

const testing = std.testing;
const revise = settings.Setting.index("JULIA_DAEMON_REVISE");
const threads = settings.Setting.index("JULIA_NUM_THREADS");
const min_ttl = settings.Setting.index("JULIA_DAEMON_MIN_TTL");
const max_ttl = settings.Setting.index("JULIA_DAEMON_MAX_TTL");
const ping = settings.Setting.index("JULIA_DAEMON_PING_INTERVAL");
const project = settings.Setting.index("JULIA_DAEMON_WORKER_PROJECT");

// A conductor started with `env`, by a service declaring `service_env`.
fn started(env: []const [2][]const u8, service_env: []const [2][]const u8, unset: []const []const u8) !State {
    var map = Environ.Map.init(testing.allocator);
    defer map.deinit();
    for (env) |kv| try map.put(kv[0], kv[1]);
    var declared = service.Declared.init(testing.allocator);
    defer declared.deinit();
    for (service_env) |kv| try declared.set.put(kv[0], kv[1]);
    for (unset) |key| try declared.unset.insert(key);
    return State.init(testing.allocator, &map, &declared);
}

test "a setting reset and saved stays saved when the service is reread" {
    const gpa = testing.allocator;
    var state = try started(&.{.{ "JULIA_DAEMON_REVISE", "yes" }}, &.{.{ "JULIA_DAEMON_REVISE", "yes" }}, &.{});
    defer state.deinit(gpa);
    var staged: Staged = .{};
    defer staged.deinit(gpa);
    try staged.stage(gpa, &state, revise, null);
    try testing.expect((try state.apply(gpa, &staged)) == .applied);
    try testing.expect(state.isUnsaved(revise));
    try state.markSaved(gpa);
    // The service no longer sets it: a restart brings its default, as applied.
    var declared = service.Declared.init(gpa);
    defer declared.deinit();
    try state.reread(gpa, &declared);
    try testing.expect(!state.isUnsaved(revise));
}

test "what the service leaves undeclared is inherited, and an unset overrides it" {
    const gpa = testing.allocator;
    var state = try started(&.{.{ "JULIA_NUM_THREADS", "4" }}, &.{}, &.{});
    defer state.deinit(gpa);
    try testing.expectEqualStrings("4", state.saved[threads].?);
    try testing.expect(!state.isUnsaved(threads));
    var declared = service.Declared.init(gpa);
    defer declared.deinit();
    try declared.unset.insert("JULIA_NUM_THREADS");
    try state.reread(gpa, &declared);
    try testing.expect(state.saved[threads] == null);
    try testing.expect(state.isUnsaved(threads));
}

test "without a service to read, what the conductor started with is saved" {
    const gpa = testing.allocator;
    var map = Environ.Map.init(gpa);
    defer map.deinit();
    try map.put("JULIA_DAEMON_WORKER_TTL", "600"); // the deprecated name
    var state = try State.init(gpa, &map, null);
    defer state.deinit(gpa);
    try testing.expectEqualStrings("600", state.running[max_ttl].?);
    try testing.expectEqualStrings("600", state.saved[max_ttl].?);
    var buf: [2 * all.len]service.Change = undefined;
    try testing.expectEqual(@as(usize, 0), state.changesToSave(&buf).len);
}

test "staging what's in effect, or the installer's, stages nothing" {
    const gpa = testing.allocator;
    var state = try started(&.{.{ "JULIA_DAEMON_MAX_TTL", "7200" }}, &.{}, &.{});
    defer state.deinit(gpa);
    var staged: Staged = .{};
    defer staged.deinit(gpa);
    try staged.stage(gpa, &state, max_ttl, "7200");
    try staged.stage(gpa, &state, min_ttl, "120"); // unset, and its default
    try staged.stage(gpa, &state, project, "/elsewhere");
    try testing.expect(!staged.has(max_ttl) and !staged.has(min_ttl) and !staged.has(project));
    try staged.stage(gpa, &state, max_ttl, null); // the default, though alike, is a change: unset
    try testing.expect(staged.has(max_ttl));
}

test "undo drops a staged change, else stages the saved value" {
    const gpa = testing.allocator;
    var state = try started(&.{}, &.{}, &.{});
    defer state.deinit(gpa);
    var staged: Staged = .{};
    defer staged.deinit(gpa);
    try staged.stage(gpa, &state, max_ttl, "3600");
    try staged.undo(gpa, &state, max_ttl);
    try testing.expect(!staged.has(max_ttl));
    try staged.stage(gpa, &state, max_ttl, "3600");
    _ = try state.apply(gpa, &staged);
    try staged.undo(gpa, &state, max_ttl);
    try testing.expect(staged.has(max_ttl) and staged.edits[max_ttl].? == .unset);
    try staged.undo(gpa, &state, ping); // nothing to undo
    try testing.expect(!staged.has(ping));
}

test "applying is all or nothing, checked together" {
    const gpa = testing.allocator;
    var state = try started(&.{}, &.{}, &.{});
    defer state.deinit(gpa);
    var staged: Staged = .{};
    defer staged.deinit(gpa);
    try staged.stage(gpa, &state, min_ttl, "9000"); // above the max's default alone
    const refused = try state.apply(gpa, &staged);
    try testing.expectEqual(min_ttl, refused.conflict.ordered.below);
    try testing.expect(state.applied[min_ttl] == null and staged.has(min_ttl));
    try staged.stage(gpa, &state, max_ttl, "10000"); // together, fine
    const outcome = try state.apply(gpa, &staged);
    try testing.expect(outcome.applied.isSet(min_ttl) and outcome.applied.isSet(max_ttl));
    try testing.expectEqual(@as(usize, 2), outcome.applied.count());
    try testing.expectEqualStrings("9000", state.applied[min_ttl].?);
    try testing.expect(!staged.has(min_ttl) and !staged.has(max_ttl));
}

test "saving writes each unsaved setting, and drops a deprecated alias" {
    const gpa = testing.allocator;
    var state = try started(&.{.{ "JULIA_DAEMON_WORKER_TTL", "600" }}, &.{.{ "JULIA_DAEMON_WORKER_TTL", "600" }}, &.{});
    defer state.deinit(gpa);
    var staged: Staged = .{};
    defer staged.deinit(gpa);
    try staged.stage(gpa, &state, max_ttl, "3600");
    try staged.stage(gpa, &state, revise, "yes");
    _ = try state.apply(gpa, &staged);
    var buf: [2 * all.len]service.Change = undefined;
    const changes = state.changesToSave(&buf);
    try testing.expectEqual(@as(usize, 3), changes.len);
    try testing.expectEqualStrings("JULIA_DAEMON_REVISE", changes[0].key);
    try testing.expectEqualStrings("3600", changes[1].value.?);
    try testing.expectEqualStrings("JULIA_DAEMON_WORKER_TTL", changes[2].key);
    try testing.expect(changes[2].value == null);
    try state.markSaved(gpa);
    try testing.expectEqual(@as(usize, 0), state.changesToSave(&buf).len);
}

test "a viewer's staged change another applied is dropped" {
    const gpa = testing.allocator;
    var state = try started(&.{}, &.{}, &.{});
    defer state.deinit(gpa);
    var mine: Staged = .{};
    defer mine.deinit(gpa);
    var theirs: Staged = .{};
    defer theirs.deinit(gpa);
    try mine.stage(gpa, &state, revise, "yes");
    try mine.stage(gpa, &state, ping, "60");
    try theirs.stage(gpa, &state, revise, "yes");
    _ = try state.apply(gpa, &theirs);
    mine.prune(gpa, &state);
    try testing.expect(!mine.has(revise) and mine.has(ping));
}

test "changes for workers count while one running missed them" {
    const gpa = testing.allocator;
    var state = try started(&.{}, &.{}, &.{});
    defer state.deinit(gpa);
    var staged: Staged = .{};
    defer staged.deinit(gpa);
    try staged.stage(gpa, &state, revise, "yes");
    try staged.stage(gpa, &state, ping, "60");
    // Staged: counted while any worker runs, as none would have it.
    try testing.expectEqual(@as(usize, 0), pending(&state, &staged, .{}, true).workers);
    const before: Fleet = .{ .oldest_spawn_ns = 100, .idle_stale = true };
    var p = pending(&state, &staged, before, true);
    try testing.expectEqual(@as(usize, 1), p.workers);
    try testing.expectEqual(@as(usize, 2), p.staged);
    try testing.expect(p.asks());
    _ = try state.apply(gpa, &staged);
    state.workers_changed_ns = 200;
    p = pending(&state, &staged, before, true);
    try testing.expectEqual(@as(usize, 1), p.workers);
    try testing.expectEqual(@as(usize, 1), p.restart); // the ping interval
    try testing.expectEqual(@as(usize, 2), p.unsaved);
    try testing.expect(p.retirable and isMissed(&state, before, revise));
    // Once those running all started after it.
    const after: Fleet = .{ .oldest_spawn_ns = 300 };
    p = pending(&state, &staged, after, true);
    try testing.expectEqual(@as(usize, 0), p.workers);
    try testing.expect(!p.retirable and !isMissed(&state, after, revise));
    try testing.expect(!pending(&state, &staged, after, false).asks());
}
