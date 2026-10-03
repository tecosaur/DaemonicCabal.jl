// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0

const std = @import("std");
const Allocator = std.mem.Allocator;
const worker = @import("worker.zig");

const EnvVar = worker.EnvVar;

pub const EnvCache = struct {
    const MAX_ENTRIES = 5;

    entries: [MAX_ENTRIES]?Entry = @splat(null),
    access_counter: u64 = 0,
    allocator: Allocator,

    const Entry = struct {
        fingerprint: u64,
        env: []EnvVar,
        julia_project: ?[]const u8,
        access_time: u64,
    };

    pub fn init(allocator: Allocator) EnvCache {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *EnvCache) void {
        for (&self.entries) |*entry| {
            if (entry.*) |e| {
                worker.freeEnv(self.allocator, e.env);
                entry.* = null;
            }
        }
    }

    pub const LookupResult = struct {
        env: []const EnvVar,
        julia_project: ?[]const u8,
    };

    pub fn lookup(self: *EnvCache, fingerprint: u64) ?LookupResult {
        for (&self.entries) |*slot| {
            if (slot.*) |*e| {
                if (e.fingerprint == fingerprint) {
                    e.access_time = self.access_counter;
                    self.access_counter += 1;
                    return .{ .env = e.env, .julia_project = e.julia_project };
                }
            }
        }
        return null;
    }

    /// Takes ownership of `env` and its contents.
    pub fn insert(self: *EnvCache, fingerprint: u64, env: []EnvVar) LookupResult {
        var julia_project: ?[]const u8 = null;
        for (env) |e| {
            if (std.mem.eql(u8, e.key, "JULIA_PROJECT")) {
                julia_project = e.value;
                break;
            }
        }
        const slot = self.findEvictionSlot();
        if (self.entries[slot]) |old| worker.freeEnv(self.allocator, old.env);
        self.entries[slot] = .{
            .fingerprint = fingerprint,
            .env = env,
            .julia_project = julia_project,
            .access_time = self.access_counter,
        };
        self.access_counter += 1;
        return .{ .env = env, .julia_project = julia_project };
    }

    fn findEvictionSlot(self: *EnvCache) usize {
        var oldest_slot: usize = 0;
        var oldest_time: u64 = std.math.maxInt(u64);
        for (self.entries, 0..) |entry, i| {
            if (entry) |e| {
                if (e.access_time < oldest_time) {
                    oldest_time = e.access_time;
                    oldest_slot = i;
                }
            } else {
                return i;
            }
        }
        return oldest_slot;
    }
};
