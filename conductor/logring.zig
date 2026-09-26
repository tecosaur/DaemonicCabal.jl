// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0
//
// A worker's recent log, for `--status=live`: what it wrote to stderr and
// what the conductor said of it, a line each, the oldest dropped past
// `max_entries`.

const std = @import("std");

pub const max_entries = 200;
const max_line_bytes = 400;

pub const Source = enum { worker, conductor };

pub const Entry = struct {
    at: i64, // seconds, on the conductor's clock
    source: Source,
    text: []u8,
};

pub const LogRing = struct {
    entries: [max_entries]Entry = undefined, // a ring, `next` after the newest
    count: usize = 0,
    next: usize = 0,
    partial: std.ArrayList(u8) = .empty, // a stderr line not yet ended

    pub fn deinit(self: *LogRing, gpa: std.mem.Allocator) void {
        for (0..self.count) |i| gpa.free(self.at(i).text);
        self.partial.deinit(gpa);
    }

    /// A line, cut to `max_line_bytes`; a blank one is left out.
    pub fn add(self: *LogRing, gpa: std.mem.Allocator, when: i64, source: Source, line: []const u8) void {
        const text = std.mem.trimEnd(u8, line, "\r\n ");
        if (text.len == 0) return;
        const owned = gpa.dupe(u8, text[0..@min(text.len, max_line_bytes)]) catch return;
        if (self.count == max_entries) gpa.free(self.entries[self.next].text);
        self.entries[self.next] = .{ .at = when, .source = source, .text = owned };
        self.next = (self.next + 1) % max_entries;
        self.count = @min(self.count + 1, max_entries);
    }

    /// Stderr in whatever pieces it came, each line added once ended.
    pub fn feed(self: *LogRing, gpa: std.mem.Allocator, when: i64, bytes: []const u8) void {
        var rest = bytes;
        while (std.mem.indexOfScalar(u8, rest, '\n')) |nl| {
            if (self.partial.items.len > 0) {
                self.partial.appendSlice(gpa, rest[0..nl]) catch {};
                self.add(gpa, when, .worker, self.partial.items);
                self.partial.clearRetainingCapacity();
            } else {
                self.add(gpa, when, .worker, rest[0..nl]);
            }
            rest = rest[nl + 1 ..];
        }
        const room = max_line_bytes -| self.partial.items.len;
        self.partial.appendSlice(gpa, rest[0..@min(room, rest.len)]) catch {};
    }

    /// The `i`th entry kept, oldest first.
    pub fn at(self: *const LogRing, i: usize) Entry {
        return self.entries[(self.next + max_entries - self.count + i) % max_entries];
    }
};

test "lines split however stderr came, blanks left out" {
    const gpa = std.testing.allocator;
    var ring = LogRing{};
    defer ring.deinit(gpa);
    ring.feed(gpa, 1, "WARNING: Force thr");
    ring.feed(gpa, 2, "owing a SIGINT\n\nsecond\r\nthi");
    ring.add(gpa, 3, .conductor, "ping timed out");
    try std.testing.expectEqual(@as(usize, 3), ring.count);
    try std.testing.expectEqualStrings("WARNING: Force throwing a SIGINT", ring.at(0).text);
    try std.testing.expectEqualStrings("second", ring.at(1).text);
    try std.testing.expectEqual(Source.conductor, ring.at(2).source);
    try std.testing.expectEqual(@as(i64, 3), ring.at(2).at);
}

test "the oldest go past the limit" {
    const gpa = std.testing.allocator;
    var ring = LogRing{};
    defer ring.deinit(gpa);
    var buf: [16]u8 = undefined;
    for (0..max_entries + 5) |i| ring.add(gpa, @intCast(i), .worker, try std.fmt.bufPrint(&buf, "line {d}", .{i}));
    try std.testing.expectEqual(@as(usize, max_entries), ring.count);
    try std.testing.expectEqualStrings("line 5", ring.at(0).text);
    try std.testing.expectEqualStrings(try std.fmt.bufPrint(&buf, "line {d}", .{max_entries + 4}), ring.at(max_entries - 1).text);
}
