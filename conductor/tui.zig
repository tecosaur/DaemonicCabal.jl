// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0
//
// The `--status=live` view's pure parts: terminal keys, focus movement, and
// the framed pane. The conductor owns the state and the I/O (`main.zig`).

const std = @import("std");

pub const Key = union(enum) {
    up,
    down,
    page_up,
    page_down,
    home,
    end,
    enter,
    escape,
    interrupt, // ^C, which a raw client sends as a byte
    char: u8,
};

/// The keys in one chunk of terminal input. An ESC ending its chunk is the
/// Escape key: a terminal sends a whole sequence at once.
pub const KeyIterator = struct {
    bytes: []const u8,
    pos: usize = 0,

    pub fn next(self: *KeyIterator) ?Key {
        while (self.pos < self.bytes.len) {
            const byte = self.bytes[self.pos];
            self.pos += 1;
            switch (byte) {
                0x1b => return self.escape(),
                0x03 => return .interrupt,
                '\r', '\n' => return .enter,
                0x20...0x7e => return .{ .char = byte },
                else => {},
            }
        }
        return null;
    }

    // After an ESC: a CSI or SS3 sequence, else the Escape key alone.
    fn escape(self: *KeyIterator) ?Key {
        const rest = self.bytes[self.pos..];
        if (rest.len == 0 or (rest[0] != '[' and rest[0] != 'O')) return .escape;
        var i: usize = 1;
        var param: u16 = 0;
        while (i < rest.len and rest[i] >= 0x20 and rest[i] < 0x40) : (i += 1) {
            if (std.ascii.isDigit(rest[i])) param = param *| 10 +| (rest[i] - '0');
        }
        if (i == rest.len) {
            self.pos = self.bytes.len; // cut short: nothing to act on
            return self.next();
        }
        self.pos += i + 1;
        return switch (rest[i]) {
            'A' => .up,
            'B' => .down,
            'H' => .home,
            'F' => .end,
            '~' => switch (param) {
                1, 7 => .home,
                4, 8 => .end,
                5 => .page_up,
                6 => .page_down,
                else => self.next(),
            },
            else => self.next(),
        };
    }
};

/// The focus after `key` over `order`, the focusable clients top to bottom:
/// down from none takes the first, up from the first lets go.
pub fn moveFocus(order: []const u32, focus: ?u32, key: Key) ?u32 {
    const current = focus orelse return switch (key) {
        .down => if (order.len > 0) order[0] else null,
        else => null,
    };
    const i = std.mem.indexOfScalar(u32, order, current) orelse return null;
    return switch (key) {
        .down => order[@min(i + 1, order.len - 1)],
        .up => if (i == 0) null else order[i - 1],
        .escape => null,
        else => current,
    };
}

/// The focus once `order` has changed: kept while its client is listed, else
/// the client now at its row, else none.
pub fn keepFocus(order: []const u32, focus: ?u32, row: usize) ?u32 {
    const current = focus orelse return null;
    if (std.mem.indexOfScalar(u32, order, current) != null) return current;
    return if (order.len > 0) order[@min(row, order.len - 1)] else null;
}

pub const tab_width = 8;

/// A framed box of `height` rows, borders included, `width` columns wide.
/// `title` and `footer` sit in the borders; `body` fills the rows between,
/// from the top, cut to fit. Each character counts as one column, as in
/// the transcript's `TerminalText`.
pub const Pane = struct {
    title: []const u8,
    footer: []const u8,
    body: []const []const u8,
    dim_body: bool = false,
};

pub const min_pane_rows = 5; // three of body

pub fn writePane(out: *std.ArrayList(u8), gpa: std.mem.Allocator, styled: bool, pane: Pane, width: usize, height: usize) !void {
    const inner = width -| 4;
    const dim = if (styled) "\x1b[2m" else "";
    const reset = if (styled) "\x1b[0m" else "";
    try writeBorder(out, gpa, .{ dim, reset }, "╭─", "╮", pane.title, width);
    for (0..height -| 2) |row| {
        try out.print(gpa, "{s}│{s} ", .{ dim, reset });
        if (pane.dim_body) try out.appendSlice(gpa, dim);
        const text = if (row < pane.body.len) pane.body[row] else "";
        const used = try appendColumns(out, gpa, text, inner);
        if (pane.dim_body) try out.appendSlice(gpa, reset);
        try out.appendNTimes(gpa, ' ', inner - used);
        try out.print(gpa, " {s}│{s}\n", .{ dim, reset });
    }
    try writeBorder(out, gpa, .{ dim, reset }, "╰─", "╯", pane.footer, width);
}

// "╭─ label ────╮", the label cut to fit.
fn writeBorder(out: *std.ArrayList(u8), gpa: std.mem.Allocator, style: [2][]const u8, left: []const u8, right: []const u8, label: []const u8, width: usize) !void {
    try out.print(gpa, "{s}{s}", .{ style[0], left });
    var used: usize = 2;
    if (label.len > 0 and width > 6) {
        try out.append(gpa, ' ');
        used += 2 + try appendColumns(out, gpa, label, width - 6);
        try out.append(gpa, ' ');
    }
    for (used..width -| 1) |_| try out.appendSlice(gpa, "─");
    try out.print(gpa, "{s}{s}\n", .{ right, style[1] });
}

/// Appends `text` as at most `max` columns, controls dropped and tabs
/// expanded; returns the columns used. Invalid UTF-8 shows as U+FFFD.
pub fn appendColumns(out: *std.ArrayList(u8), gpa: std.mem.Allocator, text: []const u8, max: usize) !usize {
    var col: usize = 0;
    var i: usize = 0;
    while (i < text.len and col < max) {
        const len = std.unicode.utf8ByteSequenceLength(text[i]) catch 0;
        const decoded: ?u21 = if (len > 0 and i + len <= text.len)
            std.unicode.utf8Decode(text[i .. i + len]) catch null
        else
            null;
        const cp = decoded orelse {
            try out.appendSlice(gpa, "\u{fffd}");
            col += 1;
            i += 1;
            continue;
        };
        if (cp == '\t') {
            const stop = @min(max, (col / tab_width + 1) * tab_width);
            try out.appendNTimes(gpa, ' ', stop - col);
            col = stop;
        } else if (cp >= 0x20 and !(cp >= 0x7f and cp < 0xa0)) {
            try out.appendSlice(gpa, text[i .. i + len]);
            col += 1;
        }
        i += len;
    }
    return col;
}

test "keys: arrows, pages, enter, escape and characters" {
    var it = KeyIterator{ .bytes = "\x1b[A\x1bOB\x1b[5~\x1b[6~\rq\x03\x1b" };
    const expected = [_]Key{ .up, .down, .page_up, .page_down, .enter, .{ .char = 'q' }, .interrupt, .escape };
    for (expected) |key| try std.testing.expectEqual(key, it.next().?);
    try std.testing.expectEqual(@as(?Key, null), it.next());
}

test "keys: unknown and cut-short sequences leave nothing" {
    var it = KeyIterator{ .bytes = "\x1b[1;5Cx\x1b[99~\x1b[" };
    try std.testing.expectEqual(Key{ .char = 'x' }, it.next().?);
    try std.testing.expectEqual(@as(?Key, null), it.next());
    var alt = KeyIterator{ .bytes = "\x1bx" };
    try std.testing.expectEqual(Key.escape, alt.next().?);
    try std.testing.expectEqual(Key{ .char = 'x' }, alt.next().?);
}

test "focus moves down from none and lets go up from the first" {
    const order = [_]u32{ 7, 3, 9 };
    try std.testing.expectEqual(@as(?u32, 7), moveFocus(&order, null, .down));
    try std.testing.expectEqual(@as(?u32, null), moveFocus(&order, null, .up));
    try std.testing.expectEqual(@as(?u32, 3), moveFocus(&order, 7, .down));
    try std.testing.expectEqual(@as(?u32, 9), moveFocus(&order, 9, .down));
    try std.testing.expectEqual(@as(?u32, null), moveFocus(&order, 7, .up));
    try std.testing.expectEqual(@as(?u32, 7), moveFocus(&order, 3, .up));
    try std.testing.expectEqual(@as(?u32, null), moveFocus(&order, 3, .escape));
    try std.testing.expectEqual(@as(?u32, null), moveFocus(&.{}, null, .down));
}

test "a vanished focus passes to the client at its row" {
    const order = [_]u32{ 7, 9 };
    try std.testing.expectEqual(@as(?u32, 9), keepFocus(&order, 9, 1));
    try std.testing.expectEqual(@as(?u32, 9), keepFocus(&order, 3, 1));
    try std.testing.expectEqual(@as(?u32, 9), keepFocus(&order, 3, 5));
    try std.testing.expectEqual(@as(?u32, null), keepFocus(&.{}, 3, 0));
    try std.testing.expectEqual(@as(?u32, null), keepFocus(&order, null, 0));
}

test "columns: controls dropped, tabs expanded, cut at the width" {
    const gpa = std.testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    try std.testing.expectEqual(@as(usize, 14), try appendColumns(&out, gpa, "a\tb\x1b[1mé\xff", 20));
    try std.testing.expectEqualStrings("a       b[1mé\u{fffd}", out.items);
    out.clearRetainingCapacity();
    try std.testing.expectEqual(@as(usize, 3), try appendColumns(&out, gpa, "abcdef", 3));
    try std.testing.expectEqualStrings("abc", out.items);
}

test "pane: framed to its size, labels in the borders" {
    const gpa = std.testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    const pane = Pane{ .title = "title", .footer = "a footer too long to fit", .body = &.{ "one", "two", "three" } };
    try writePane(&out, gpa, false, pane, 20, 4);
    try std.testing.expectEqualStrings(
        \\╭─ title ──────────╮
        \\│ one              │
        \\│ two              │
        \\╰─ a footer too l ─╯
        \\
    , out.items);
}
