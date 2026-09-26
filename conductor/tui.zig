// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0
//
// The `--status=live` view's pure parts: terminal keys, focus movement, and
// the framed pane. The conductor owns the state and the I/O (`live.zig`).

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

/// The last lines of `text`, at most `out.len`, oldest first; a final
/// newline ends a line rather than starting one.
pub fn lastLines(text: []const u8, out: [][]const u8) [][]const u8 {
    if (text.len == 0) return out[0..0];
    var rest = if (text[text.len - 1] == '\n') text[0 .. text.len - 1] else text;
    var n: usize = 0;
    while (n < out.len) {
        const cut = std.mem.lastIndexOfScalar(u8, rest, '\n');
        out[out.len - 1 - n] = if (cut) |i| rest[i + 1 ..] else rest;
        n += 1;
        rest = if (cut) |i| rest[0..i] else break;
    }
    return out[out.len - n ..];
}

pub const tab_width = 8;

/// A framed box of `height` rows, borders included, `width` columns wide,
/// each row after a dim `gutter` (the top one after `branch`, as long).
/// `title` and `footer` sit in the borders, and `aside` at the top border's
/// end, its title cut first to make room; `body` fills the rows between,
/// from the top, cut to fit. Text keeps its colour (SGR) and loses other
/// escape sequences; each character counts as one column, as in the
/// transcript's `TerminalText`.
pub const Pane = struct {
    title: []const u8,
    aside: []const u8 = "",
    footer: []const u8,
    body: []const []const u8,
    dim_body: bool = false,
    cursor_last: bool = false, // the terminal's cursor is on `body`'s last line, marked there
    cursor_shown: bool = true, // its blink: marked now, else left blank
    cursor_sgr: []const u8 = "90", // its colour, as SGR parameters
    branch: []const []const u8 = &.{},
    gutter: []const []const u8 = &.{},
};

pub const min_pane_rows = 5; // three of body

pub fn writePane(out: *std.ArrayList(u8), gpa: std.mem.Allocator, styled: bool, pane: Pane, width: usize, height: usize) !void {
    const inner = width -| 4;
    const dim = if (styled) "\x1b[2m" else "";
    const reset = if (styled) "\x1b[0m" else "";
    try writeBorder(out, gpa, .{ dim, reset }, if (pane.branch.len > 0) pane.branch else pane.gutter, "╭─", "╮", pane.title, pane.aside, width);
    for (0..height -| 2) |row| {
        try out.appendSlice(gpa, dim);
        for (pane.gutter) |part| try out.appendSlice(gpa, part);
        try out.print(gpa, "│{s} ", .{reset});
        if (pane.dim_body) try out.appendSlice(gpa, dim);
        const text = if (row < pane.body.len) pane.body[row] else "";
        const cursor = pane.cursor_last and pane.cursor_shown and row + 1 == pane.body.len;
        const used = try appendLine(out, gpa, text, inner, styled, if (cursor) pane.cursor_sgr else null);
        if (styled) try out.appendSlice(gpa, reset);
        try out.appendNTimes(gpa, ' ', inner - used);
        try out.print(gpa, " {s}│{s}\n", .{ dim, reset });
    }
    try writeBorder(out, gpa, .{ dim, reset }, pane.gutter, "╰─", "╯", pane.footer, "", width);
}

// "╭─ label ──── aside ─╮", the label cut to fit.
fn writeBorder(out: *std.ArrayList(u8), gpa: std.mem.Allocator, style: [2][]const u8, gutter: []const []const u8, left: []const u8, right: []const u8, label: []const u8, aside: []const u8, width: usize) !void {
    const colour = style[0].len > 0;
    var drawn_aside: std.ArrayList(u8) = .empty;
    defer drawn_aside.deinit(gpa);
    const aside_cols = if (aside.len > 0) try appendColumns(&drawn_aside, gpa, aside, width -| 12, colour) else 0;
    try out.appendSlice(gpa, style[0]);
    for (gutter) |part| try out.appendSlice(gpa, part);
    try out.appendSlice(gpa, left);
    var used: usize = 2;
    if (label.len > 0 and width > 6) {
        try out.append(gpa, ' ');
        const room = width - 6 -| if (aside_cols > 0) aside_cols + 4 else 0;
        used += 2 + try appendColumns(out, gpa, label, room, colour);
        try out.print(gpa, "{s}{s} ", .{ style[1], style[0] });
    }
    const fill = width -| 1 -| used -| if (aside_cols > 0) aside_cols + 3 else 0;
    for (0..fill) |_| try out.appendSlice(gpa, "─");
    if (aside_cols > 0) try out.print(gpa, " {s}{s}{s} ─", .{ style[1], drawn_aside.items, style[0] });
    try out.print(gpa, "{s}{s}\n", .{ right, style[1] });
}

/// Appends one line of terminal output as the terminal would have drawn it,
/// at most `max` columns; returns the columns used. The line's own editing
/// is replayed: carriage return, backspace, tabs, cursor moves along the row
/// (CSI C, D, G) and erasing (CSI K, X). Colour (SGR) is kept when `colour`,
/// and other escape sequences leave nothing. Invalid UTF-8 shows as U+FFFD.
pub fn appendColumns(out: *std.ArrayList(u8), gpa: std.mem.Allocator, line: []const u8, max: usize, colour: bool) !usize {
    return appendLine(out, gpa, line, max, colour, null);
}

/// As `appendColumns`, with where the line leaves the cursor marked `▎`, in
/// `cursor`'s SGR colour, when given and nothing is drawn there: a prompt
/// awaiting input.
pub fn appendLine(out: *std.ArrayList(u8), gpa: std.mem.Allocator, line: []const u8, max: usize, colour: bool, cursor: ?[]const u8) !usize {
    var row = Row{};
    row.draw(line, @min(max, Row.max_cols));
    if (cursor) |sgr| row.markCursor(@min(max, Row.max_cols), sgr);
    var style: u8 = 0;
    for (row.cells[0..row.len]) |cell| {
        if (colour and cell.style != style) {
            try out.appendSlice(gpa, "\x1b[0m");
            try out.appendSlice(gpa, row.styles.get(cell.style));
            style = cell.style;
        }
        try out.appendSlice(gpa, cell.bytes[0..cell.n]);
    }
    if (style != 0) try out.appendSlice(gpa, "\x1b[0m");
    return row.len;
}

/// A terminal row being drawn: cells with the colour each was drawn in.
const Row = struct {
    const max_cols = 512;
    const Cell = struct { bytes: [4]u8 = .{ ' ', 0, 0, 0 }, n: u3 = 1, style: u8 = 0 };

    cells: [max_cols]Cell = undefined,
    len: usize = 0, // columns drawn
    col: usize = 0,
    styles: Styles = .{},
    style: u8 = 0,

    fn draw(self: *Row, text: []const u8, max: usize) void {
        var i: usize = 0;
        while (i < text.len) {
            const byte = text[i];
            if (byte == 0x1b) {
                const len = escapeLength(text[i..]);
                if (len > 2 and text[i + 1] == '[') self.csi(text[i + 2 .. i + len], max);
                i += len;
                continue;
            }
            switch (byte) {
                '\r' => self.col = 0,
                0x08 => self.col -|= 1,
                '\t' => self.col = @min(max, (self.col / tab_width + 1) * tab_width),
                0...0x07, 0x0a...0x0c, 0x0e...0x1a, 0x1c...0x1f, 0x7f => {},
                else => {
                    const len = std.unicode.utf8ByteSequenceLength(byte) catch 0;
                    const whole = len > 0 and i + len <= text.len and
                        if (std.unicode.utf8Decode(text[i .. i + len])) |cp| !(cp >= 0x80 and cp < 0xa0) else |_| false;
                    self.put(if (whole) text[i .. i + len] else "\u{fffd}", max);
                    i += if (whole) len else 1;
                    continue;
                },
            }
            i += 1;
        }
    }

    // Over a blank cell, or past the row's end, in `sgr`'s colour.
    fn markCursor(self: *Row, max: usize, sgr: []const u8) void {
        if (self.col >= max) return;
        const blank = self.col >= self.len or std.mem.eql(u8, self.cells[self.col].bytes[0..self.cells[self.col].n], " ");
        if (!blank) return;
        self.style = self.styles.apply(0, sgr);
        self.put("▎", max);
    }

    fn put(self: *Row, bytes: []const u8, max: usize) void {
        if (self.col >= max) return;
        if (self.col > self.len) @memset(self.cells[self.len..self.col], .{});
        var cell = Cell{ .n = @intCast(bytes.len), .style = self.style };
        @memcpy(cell.bytes[0..bytes.len], bytes);
        self.cells[self.col] = cell;
        self.col += 1;
        self.len = @max(self.len, self.col);
    }

    // `seq` is the sequence after `ESC [`, its final byte last.
    fn csi(self: *Row, seq: []const u8, max: usize) void {
        const final = seq[seq.len - 1];
        const params = seq[0 .. seq.len - 1];
        const n: usize = std.fmt.parseInt(usize, params, 10) catch 0;
        switch (final) {
            'm' => self.style = self.styles.apply(self.style, params),
            'C' => self.col = @min(max, self.col + @max(n, 1)),
            'D' => self.col -|= @max(n, 1),
            'G' => self.col = @min(max, @max(n, 1) - 1),
            'K' => switch (n) {
                0 => self.len = @min(self.len, self.col),
                1 => for (0..@min(self.col + 1, self.len)) |c| {
                    self.cells[c] = .{};
                },
                else => self.len = 0,
            },
            'X' => for (self.col..@min(self.col + @max(n, 1), self.len)) |c| {
                self.cells[c] = .{};
            },
            else => {},
        }
    }
};

/// The distinct colours of a row, as the SGR sequences that set them from a
/// reset; 0 is none. A row with more than fit keeps drawing in the last.
const Styles = struct {
    const max_styles = 32;
    const max_bytes = 48;

    bytes: [max_styles][max_bytes]u8 = undefined,
    lens: [max_styles]u8 = .{0} ** max_styles,
    count: u8 = 1,

    fn get(self: *const Styles, id: u8) []const u8 {
        return self.bytes[id][0..self.lens[id]];
    }

    // The style after `ESC [ params m` in style `from`.
    fn apply(self: *Styles, from: u8, params: []const u8) u8 {
        var reset = params.len == 0;
        var it = std.mem.splitAny(u8, params, ";:");
        while (it.next()) |p| {
            if (p.len == 0 or std.mem.eql(u8, p, "0")) reset = true;
        }
        var buf: [max_bytes]u8 = undefined;
        const base = if (reset) "" else self.get(from);
        const next = std.fmt.bufPrint(&buf, "{s}\x1b[{s}m", .{ base, params }) catch return from;
        const state = if (reset and std.mem.eql(u8, params, "0") or params.len == 0) "" else next;
        for (0..self.count) |id| {
            if (std.mem.eql(u8, self.get(@intCast(id)), state)) return @intCast(id);
        }
        if (self.count == max_styles) return from;
        const id = self.count;
        @memcpy(self.bytes[id][0..state.len], state);
        self.lens[id] = @intCast(state.len);
        self.count += 1;
        return id;
    }
};

/// Appends `text` with each run of spaces as one, escape sequences between
/// them kept but not breaking the run: a tree row's column alignment, as a
/// title.
pub fn appendCollapsed(out: *std.ArrayList(u8), gpa: std.mem.Allocator, text: []const u8) !void {
    var spaced = false;
    var i: usize = 0;
    while (i < text.len) {
        const len = if (text[i] == 0x1b) escapeLength(text[i..]) else 1;
        const space = len == 1 and text[i] == ' ';
        if (!(space and spaced)) try out.appendSlice(gpa, text[i .. i + len]);
        if (len == 1) spaced = space;
        i += len;
    }
}

// Of the escape sequence `text` starts with: CSI to its final byte, a string
// (OSC and the like) to its BEL or ST, else ESC and one byte.
fn escapeLength(text: []const u8) usize {
    if (text.len < 2) return text.len;
    switch (text[1]) {
        '[' => {
            var i: usize = 2;
            while (i < text.len and (text[i] < 0x40 or text[i] > 0x7e)) : (i += 1) {}
            return @min(i + 1, text.len);
        },
        ']', 'P', '_', '^', 'X' => {
            var i: usize = 2;
            while (i < text.len) : (i += 1) {
                if (text[i] == 0x07) return i + 1;
                if (text[i] == 0x1b and i + 1 < text.len and text[i + 1] == '\\') return i + 2;
            }
            return text.len;
        },
        else => return 2,
    }
}

test "collapsed: runs of spaces as one, escapes kept" {
    const gpa = std.testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    try appendCollapsed(&out, gpa, "#2 (t)   \x1b[2m up \x1b[0m   1m");
    try std.testing.expectEqualStrings("#2 (t) \x1b[2mup \x1b[0m1m", out.items);
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

test "last lines: the tail, blank lines kept" {
    var buf: [3][]const u8 = undefined;
    const lines = lastLines("a\nb\n\nc\n", &buf);
    try std.testing.expectEqual(@as(usize, 3), lines.len);
    try std.testing.expectEqualStrings("b", lines[0]);
    try std.testing.expectEqualStrings("", lines[1]);
    try std.testing.expectEqualStrings("c", lines[2]);
    try std.testing.expectEqual(@as(usize, 2), lastLines("x\npartial", &buf).len);
    try std.testing.expectEqual(@as(usize, 0), lastLines("", &buf).len);
}

test "columns: controls dropped, tabs expanded, cut at the width" {
    const gpa = std.testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    try std.testing.expectEqual(@as(usize, 11), try appendColumns(&out, gpa, "a\tb\x1b[1mé\xff\x07", 20, false));
    try std.testing.expectEqualStrings("a       bé\u{fffd}", out.items);
    out.clearRetainingCapacity();
    try std.testing.expectEqual(@as(usize, 1), try appendColumns(&out, gpa, "a\x1b[5Cb", 3, false));
    try std.testing.expectEqualStrings("a", out.items);
    out.clearRetainingCapacity();
    try std.testing.expectEqual(@as(usize, 3), try appendColumns(&out, gpa, "abcdef", 3, false));
    try std.testing.expectEqualStrings("abc", out.items);
}

test "columns: colour kept, other sequences dropped, redrawn lines last" {
    const gpa = std.testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    try std.testing.expectEqual(@as(usize, 7), try appendColumns(&out, gpa, "\x1b]0;title\x07\x1b[31mred\x1b[0m ok!\x1b[?25l", 20, true));
    try std.testing.expectEqualStrings("\x1b[0m\x1b[31mred\x1b[0m ok!", out.items);
    out.clearRetainingCapacity();
    try std.testing.expectEqual(@as(usize, 4), try appendColumns(&out, gpa, "50%...\r100%\x1b[K", 20, true));
    try std.testing.expectEqualStrings("100%", out.items);
}

test "cursor: marked where nothing is drawn, not over text" {
    const gpa = std.testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    _ = try appendLine(&out, gpa, "julia> ", 40, false, "90");
    try std.testing.expectEqualStrings("julia> ▎", out.items);
    out.clearRetainingCapacity();
    _ = try appendLine(&out, gpa, "julia> ", 40, true, "90");
    try std.testing.expectEqualStrings("julia> \x1b[0m\x1b[90m▎\x1b[0m", out.items);
    out.clearRetainingCapacity();
    _ = try appendLine(&out, gpa, "julia> 1+1\x1b[2D", 40, false, "90");
    try std.testing.expectEqualStrings("julia> 1+1", out.items);
    out.clearRetainingCapacity();
    _ = try appendLine(&out, gpa, "a b\x1b[2D", 40, false, "90");
    try std.testing.expectEqualStrings("a▎b", out.items);
    out.clearRetainingCapacity();
    _ = try appendLine(&out, gpa, "ab\x1b[3C", 40, false, "90");
    try std.testing.expectEqualStrings("ab   ▎", out.items);
}

test "columns: a REPL's line editing draws its prompt and input" {
    const gpa = std.testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    // As Julia's LineEdit redraws `julia> 1+1` a keystroke at a time.
    const drawn = "\r\x1b[0K\x1b[32m\x1b[1mjulia> \x1b[0m\r\x1b[7C1+\r\x1b[9C" ++
        "\r\x1b[0K\x1b[32m\x1b[1mjulia> \x1b[0m\r\x1b[7C1+1\r\x1b[10C";
    try std.testing.expectEqual(@as(usize, 10), try appendColumns(&out, gpa, drawn, 40, false));
    try std.testing.expectEqualStrings("julia> 1+1", out.items);
    out.clearRetainingCapacity();
    _ = try appendColumns(&out, gpa, drawn, 40, true);
    try std.testing.expectEqualStrings("\x1b[0m\x1b[32m\x1b[1mjulia> \x1b[0m1+1", out.items);
}

test "pane: an aside at the top border's end, the title cut for it" {
    const gpa = std.testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    const pane = Pane{ .title = "a long title", .aside = "mem ▃▅", .footer = "", .body = &.{} };
    try writePane(&out, gpa, false, pane, 24, 2);
    try std.testing.expectEqualStrings(
        \\╭─ a long t ── mem ▃▅ ─╮
        \\╰──────────────────────╯
        \\
    , out.items);
}

test "pane: framed to its size, labels in the borders" {
    const gpa = std.testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    const pane = Pane{ .title = "title", .footer = "a footer too long to fit", .body = &.{ "one", "two", "three" }, .branch = &.{ "╰", "─ " }, .gutter = &.{ "│", "  " } };
    try writePane(&out, gpa, false, pane, 20, 4);
    try std.testing.expectEqualStrings(
        \\╰─ ╭─ title ──────────╮
        \\│  │ one              │
        \\│  │ two              │
        \\│  ╰─ a footer too l ─╯
        \\
    , out.items);
}
