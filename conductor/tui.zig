// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0
//
// The `--status=live` view's pure parts: terminal keys, focus movement, and
// the framed pane. The conductor owns the state and the I/O (`live.zig`).

const std = @import("std");
const unicode = @import("unicode.zig");

pub const Key = union(enum) {
    up,
    down,
    left,
    right,
    tab,
    back_tab,
    backspace,
    delete,
    page_up,
    page_down,
    home,
    end,
    word_left, // Ctrl or Alt with an arrow, or Alt-b
    word_right, // likewise, or Alt-f
    kill_to_end, // ^K
    kill_to_start, // ^U
    enter,
    escape,
    interrupt, // ^C, which a raw client sends as a byte
    char: u8,
    text: []const u8, // a character past ASCII, as its UTF-8
};

/// The keys in one chunk of terminal input. An ESC ending its chunk is the
/// Escape key, and one before another key is Alt with it, which nothing
/// takes: a terminal sends a key's bytes at once, and a person presses keys
/// apart.
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
                // As readline takes them.
                0x01 => return .home,
                0x02 => return .left,
                0x05 => return .end,
                0x06 => return .right,
                0x0b => return .kill_to_end,
                0x15 => return .kill_to_start,
                '\r', '\n' => return .enter,
                '\t' => return .tab,
                0x7f, 0x08 => return .backspace,
                0x20...0x7e => return .{ .char = byte },
                0xc2...0xf4 => {
                    const len = std.unicode.utf8ByteSequenceLength(byte) catch continue;
                    const start = self.pos - 1;
                    if (start + len > self.bytes.len) return null; // cut short
                    const seq = self.bytes[start .. start + len];
                    if (!std.unicode.utf8ValidateSlice(seq)) continue;
                    self.pos = start + len;
                    return .{ .text = seq };
                },
                else => {},
            }
        }
        return null;
    }

    // After an ESC: the Escape key alone, a CSI or SS3 sequence, or Alt
    // with the key that follows (a character past ASCII whole), skipped
    // but for Alt-b and Alt-f.
    fn escape(self: *KeyIterator) ?Key {
        const rest = self.bytes[self.pos..];
        if (rest.len == 0) return .escape;
        if (rest[0] != '[' and rest[0] != 'O') {
            const len = @min(std.unicode.utf8ByteSequenceLength(rest[0]) catch 1, rest.len);
            self.pos += len;
            return switch (rest[0]) {
                'b' => .word_left,
                'f' => .word_right,
                else => self.next(),
            };
        }
        var i: usize = 1;
        var param: u16 = 0;
        // After a `;`, xterm's modifiers, 1 + (Shift 1, Alt 2, Ctrl 4).
        var modifiers: ?u16 = null;
        while (i < rest.len and rest[i] >= 0x20 and rest[i] < 0x40) : (i += 1) {
            if (rest[i] == ';') {
                modifiers = 0;
            } else if (std.ascii.isDigit(rest[i])) {
                if (modifiers) |*m| m.* = m.* *| 10 +| (rest[i] - '0') else param = param *| 10 +| (rest[i] - '0');
            }
        }
        if (i == rest.len) {
            self.pos = self.bytes.len; // cut short: nothing to act on
            return self.next();
        }
        self.pos += i + 1;
        // Alt or Ctrl (or both) with an arrow moves by word; nothing takes the rest.
        if (modifiers) |m| return if (m >= 3 and m <= 8 and (m - 1) & 0b110 != 0) switch (rest[i]) {
            'C' => .word_right,
            'D' => .word_left,
            else => self.next(),
        } else self.next();
        return switch (rest[i]) {
            'A' => .up,
            'B' => .down,
            'C' => .right,
            'D' => .left,
            'Z' => .back_tab,
            'H' => .home,
            'F' => .end,
            '~' => switch (param) {
                1, 7 => .home,
                3 => .delete,
                4, 8 => .end,
                5 => .page_up,
                6 => .page_down,
                else => self.next(),
            },
            else => self.next(),
        };
    }
};

/// Where the word before `at` in `text` starts, as readline's backward-word:
/// past what isn't a word's, then the word. A word is letters and digits,
/// any character past ASCII among them.
pub fn wordBefore(text: []const u8, at: usize) usize {
    var i = at;
    while (i > 0 and !isWordByte(text[i - 1])) i -= 1;
    while (i > 0 and isWordByte(text[i - 1])) i -= 1;
    return i;
}

/// Where the word from `at` in `text` ends, as readline's forward-word.
pub fn wordAfter(text: []const u8, at: usize) usize {
    var i = at;
    while (i < text.len and !isWordByte(text[i])) i += 1;
    while (i < text.len and isWordByte(text[i])) i += 1;
    return i;
}

fn isWordByte(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte) or byte >= 0x80;
}

/// The focus after `key` over `order`, the focusable clients top to bottom:
/// down from none takes the first, up from the first lets go.
pub fn moveFocus(order: []const u32, focus: ?u32, key: Key) ?u32 {
    const current = focus orelse return switch (key) {
        .down => if (order.len > 0) order[0] else null,
        else => null,
    };
    const i = std.mem.findScalar(u32, order, current) orelse return null;
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
    if (std.mem.findScalar(u32, order, current) != null) return current;
    return if (order.len > 0) order[@min(row, order.len - 1)] else null;
}

/// The last lines of `text`, at most `out.len`, oldest first; a final
/// newline ends a line rather than starting one.
pub fn lastLines(text: []const u8, out: [][]const u8) [][]const u8 {
    if (text.len == 0) return out[0..0];
    var rest = if (text[text.len - 1] == '\n') text[0 .. text.len - 1] else text;
    var n: usize = 0;
    while (n < out.len) {
        const cut = std.mem.findScalarLast(u8, rest, '\n');
        out[out.len - 1 - n] = if (cut) |i| rest[i + 1 ..] else rest;
        n += 1;
        rest = if (cut) |i| rest[0..i] else break;
    }
    return out[out.len - n ..];
}

/// The first of a frame's `total` lines to show in `height`, so that its
/// lines `keep_start..keep_end` show as far as they fit: the top, unless
/// they would fall below.
pub fn scrollTop(total: usize, height: usize, keep_start: usize, keep_end: usize) usize {
    if (total <= height) return 0;
    return @min(keep_start, keep_end -| height, total - height);
}

/// Lines `first..first + count` of `text`, each of whose lines ends in a
/// newline.
pub fn lineRange(text: []const u8, first: usize, count: usize) []const u8 {
    var start: usize = 0;
    for (0..first) |_| start = (std.mem.findScalarPos(u8, text, start, '\n') orelse return "") + 1;
    var end = start;
    for (0..count) |_| end = (std.mem.findScalarPos(u8, text, end, '\n') orelse return text[start..]) + 1;
    return text[start..end];
}

pub const tab_width = 8;

/// A framed box of `height` rows, borders included, `width` columns wide,
/// each row after a dim `gutter` (the top one after `branch`, as long).
/// `title` and `footer` sit in the borders, and `aside` at the top border's
/// end, its title cut first to make room; `body` fills the rows between,
/// from the top, cut to fit. Text keeps its colour (SGR) and loses other
/// escape sequences; each character takes the columns a terminal gives it
/// (`codepointWidth`).
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
    for (row.cells[0..row.len], 0..) |cell, k| {
        if (colour and cell.style != style) {
            var buf: [Sgr.max_bytes]u8 = undefined;
            try out.appendSlice(gpa, row.styles.get(cell.style).sequence(&buf));
            style = cell.style;
        }
        try out.appendSlice(gpa, row.shown(k));
    }
    if (style != 0) try out.appendSlice(gpa, "\x1b[0m");
    return row.len;
}

/// The columns `appendColumns` would draw `line` in, unbounded.
pub fn columns(line: []const u8) usize {
    var row = Row{};
    row.draw(line, Row.max_cols);
    return row.len;
}

/// The columns `text`, printable UTF-8, takes at a terminal; an invalid
/// byte takes one, as U+FFFD would.
pub fn textWidth(text: []const u8) usize {
    var cols: usize = 0;
    var i: usize = 0;
    while (i < text.len) {
        const char = decode(text[i..]);
        cols += if (char) |ch| codepointWidth(ch.cp) else 1;
        i += if (char) |ch| ch.len else 1;
    }
    return cols;
}

pub const decode = unicode.decode;
pub const codepointWidth = unicode.codepointWidth;

/// A terminal row being drawn: cells with the colour each was drawn in. A
/// wide character takes two, the second with no bytes of its own.
const Row = struct {
    const max_cols = 512;
    const Cell = struct {
        bytes: [16]u8 = .{' '} ++ @as([15]u8, @splat(0)), // room for combining marks
        n: u5 = 1, // 0: the second column of the wide character before
        wide: bool = false,
        style: u8 = 0,
    };

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
                    const char = decode(text[i..]) orelse {
                        self.put("\u{fffd}", 1, max);
                        i += 1;
                        continue;
                    };
                    // C1 controls are dropped as the rest.
                    if (char.cp < 0x80 or char.cp >= 0xa0) self.put(text[i .. i + char.len], codepointWidth(char.cp), max);
                    i += char.len;
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
        self.put("▎", 1, max);
    }

    // A wide character that doesn't fit ends the row, as the terminal
    // would wrap it.
    fn put(self: *Row, bytes: []const u8, width: u2, max: usize) void {
        if (width == 0) return self.combine(bytes);
        if (self.col >= max) return;
        if (self.col + width > max) {
            self.col = max;
            return;
        }
        if (self.col > self.len) @memset(self.cells[self.len..self.col], .{});
        var cell = Cell{ .n = @intCast(bytes.len), .wide = width == 2, .style = self.style };
        @memcpy(cell.bytes[0..bytes.len], bytes);
        self.cells[self.col] = cell;
        if (width == 2) self.cells[self.col + 1] = .{ .n = 0, .style = self.style };
        self.col += width;
        self.len = @max(self.len, self.col);
    }

    // Onto the character before, where its cell has room.
    fn combine(self: *Row, bytes: []const u8) void {
        var at = @min(self.col, self.len);
        if (at == 0) return;
        at -= 1;
        if (self.cells[at].n == 0 and at > 0) at -= 1;
        const cell = &self.cells[at];
        if (cell.n == 0 or @as(usize, cell.n) + bytes.len > cell.bytes.len) return;
        @memcpy(cell.bytes[cell.n..][0..bytes.len], bytes);
        cell.n += @intCast(bytes.len);
    }

    // Cell `k`'s bytes: a wide character's halves, one drawn over, blank.
    fn shown(self: *const Row, k: usize) []const u8 {
        const cell = &self.cells[k];
        if (cell.n == 0) return if (k > 0 and self.cells[k - 1].wide) "" else " ";
        const whole = !cell.wide or (k + 1 < self.len and self.cells[k + 1].n == 0);
        return if (whole) cell.bytes[0..cell.n] else " ";
    }

    // `seq` is the sequence after `ESC [`, its final byte last.
    fn csi(self: *Row, seq: []const u8, max: usize) void {
        const final = seq[seq.len - 1];
        const params = seq[0 .. seq.len - 1];
        const n: usize = std.fmt.parseInt(usize, params, 10) catch 0;
        switch (final) {
            'm' => self.style = self.styles.apply(self.style, params),
            'C' => self.col = @min(max, self.col +| @max(n, 1)),
            'D' => self.col -|= @max(n, 1),
            'G' => self.col = @min(max, @max(n, 1) - 1),
            'K' => switch (n) {
                0 => self.len = @min(self.len, self.col),
                1 => for (0..@min(self.col + 1, self.len)) |c| {
                    self.cells[c] = .{};
                },
                else => self.len = 0,
            },
            'X' => if (self.col < self.len) for (self.col..@min(self.col +| @max(n, 1), self.len)) |c| {
                self.cells[c] = .{};
            },
            else => {},
        }
    }
};

/// The distinct styles of a row, by id; 0 is the default. Past the last id,
/// a change keeps the style it was made in.
const Styles = struct {
    const max_styles = 256;

    states: [max_styles]Sgr = undefined,
    count: usize = 1,

    fn get(self: *const Styles, id: u8) Sgr {
        return if (id == 0) .{} else self.states[id];
    }

    // The style after `ESC [ params m` in style `from`.
    fn apply(self: *Styles, from: u8, params: []const u8) u8 {
        var state = self.get(from);
        state.apply(params);
        for (0..self.count) |id| {
            if (std.meta.eql(self.get(@intCast(id)), state)) return @intCast(id);
        }
        if (self.count == max_styles) return from;
        self.states[self.count] = state;
        self.count += 1;
        return @intCast(self.count - 1);
    }
};

/// What SGR sequences leave set, however many drew it: the attributes,
/// the foreground and background. Underline styles and colours are taken
/// as plain underline and dropped.
const Sgr = struct {
    const max_bytes = 64;
    const Colour = union(enum) { default, index: u8, rgb: [3]u8 };

    attributes: u9 = 0, // SGR 1 to 9, bit n - 1 for n
    fg: Colour = .default,
    bg: Colour = .default,

    fn apply(self: *Sgr, params: []const u8) void {
        var groups = std.mem.splitScalar(u8, params, ';');
        while (groups.next()) |group| {
            if (std.mem.findScalar(u8, group, ':') != null) {
                self.applyColon(group);
                continue;
            }
            const code = std.fmt.parseInt(u8, group, 10) catch if (group.len == 0) 0 else continue;
            switch (code) {
                38, 48 => {
                    const colour: ?Colour = switch (number(groups.next())) {
                        5 => .{ .index = number(groups.next()) },
                        2 => .{ .rgb = .{ number(groups.next()), number(groups.next()), number(groups.next()) } },
                        else => null,
                    };
                    if (colour) |c| if (code == 38) {
                        self.fg = c;
                    } else {
                        self.bg = c;
                    };
                },
                else => self.applyCode(code),
            }
        }
    }

    fn applyCode(self: *Sgr, code: u8) void {
        switch (code) {
            0 => self.* = .{},
            1...9 => self.attributes |= bit(code),
            21 => self.attributes |= bit(4),
            22 => self.attributes &= ~(bit(1) | bit(2)),
            23, 24 => self.attributes &= ~bit(code - 20),
            25 => self.attributes &= ~(bit(5) | bit(6)),
            27...29 => self.attributes &= ~bit(code - 20),
            30...37 => self.fg = .{ .index = code - 30 },
            39 => self.fg = .default,
            40...47 => self.bg = .{ .index = code - 40 },
            49 => self.bg = .default,
            90...97 => self.fg = .{ .index = code - 90 + 8 },
            100...107 => self.bg = .{ .index = code - 100 + 8 },
            else => {},
        }
    }

    // ITU T.416's form, `38:2:[space]:r:g:b` or `38:5:n`, and `4:n`
    // underline styles.
    fn applyColon(self: *Sgr, group: []const u8) void {
        var fields: [6]u8 = @splat(0);
        var n: usize = 0;
        var it = std.mem.splitScalar(u8, group, ':');
        while (it.next()) |field| : (n += 1) {
            if (n < fields.len) fields[n] = number(field);
        }
        switch (fields[0]) {
            4 => if (fields[1] == 0) self.applyCode(24) else self.applyCode(4),
            38, 48 => {
                const colour: Colour = switch (fields[1]) {
                    5 => .{ .index = fields[2] },
                    2 => .{ .rgb = if (n >= 6) fields[3..6].* else fields[2..5].* },
                    else => return,
                };
                if (fields[0] == 38) self.fg = colour else self.bg = colour;
            },
            else => {},
        }
    }

    // From a reset, so a cell's style never depends on the one before.
    fn sequence(self: Sgr, buf: *[max_bytes]u8) []const u8 {
        var w = std.Io.Writer.fixed(buf);
        w.writeAll("\x1b[0") catch unreachable;
        for (1..10) |code| if (self.attributes & bit(@intCast(code)) != 0) w.print(";{d}", .{code}) catch unreachable;
        for ([_]Colour{ self.fg, self.bg }, [_]u8{ 30, 40 }) |colour, base| switch (colour) {
            .default => {},
            .index => |i| if (i < 8)
                w.print(";{d}", .{base + i}) catch unreachable
            else if (i < 16)
                w.print(";{d}", .{base + 60 + i - 8}) catch unreachable
            else
                w.print(";{d};5;{d}", .{ base + 8, i }) catch unreachable,
            .rgb => |c| w.print(";{d};2;{d};{d};{d}", .{ base + 8, c[0], c[1], c[2] }) catch unreachable,
        };
        w.writeByte('m') catch unreachable;
        return w.buffered();
    }

    fn bit(code: u8) u9 {
        return @as(u9, 1) << @intCast(code - 1);
    }

    fn number(field: ?[]const u8) u8 {
        return std.fmt.parseInt(u8, field orelse return 0, 10) catch 0;
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

test "keys: editing a line" {
    var it = KeyIterator{ .bytes = "\x1b[D\x1b[C\t\x1b[Z\x7f\x08\x1b[3~" };
    const expected = [_]Key{ .left, .right, .tab, .back_tab, .backspace, .backspace, .delete };
    for (expected) |key| try std.testing.expectEqual(key, it.next().?);
    try std.testing.expectEqual(@as(?Key, null), it.next());
}

test "keys: characters past ASCII come whole, invalid ones not at all" {
    var it = KeyIterator{ .bytes = "é\xe2\x94x世\xf0\x9f" };
    try std.testing.expectEqualStrings("é", it.next().?.text);
    try std.testing.expectEqual(Key{ .char = 'x' }, it.next().?);
    try std.testing.expectEqualStrings("世", it.next().?.text);
    try std.testing.expectEqual(@as(?Key, null), it.next());
}

test "keys: as readline takes them" {
    var it = KeyIterator{ .bytes = "\x01\x02\x05\x06\x0b\x15\x1b[1;5D\x1b[1;5C\x1b[1;3D\x1b[1;3C\x1bb\x1bf" };
    const expected = [_]Key{ .home, .left, .end, .right, .kill_to_end, .kill_to_start, .word_left, .word_right, .word_left, .word_right, .word_left, .word_right };
    for (expected) |key| try std.testing.expectEqual(key, it.next().?);
    try std.testing.expectEqual(@as(?Key, null), it.next());
}

test "words: back and forward over what isn't a word's" {
    const text = "/usr/local/bin  julia-1.13";
    try std.testing.expectEqual(@as(usize, 11), wordBefore(text, 14));
    try std.testing.expectEqual(@as(usize, 11), wordBefore(text, 13));
    try std.testing.expectEqual(@as(usize, 0), wordBefore(text, 0));
    try std.testing.expectEqual(@as(usize, 1), wordBefore(text, 4));
    try std.testing.expectEqual(@as(usize, 4), wordAfter(text, 0));
    try std.testing.expectEqual(@as(usize, 21), wordAfter(text, 14));
    try std.testing.expectEqual(text.len, wordAfter(text, text.len));
    // A character past ASCII is a word's, whole.
    try std.testing.expectEqual(@as(usize, 0), wordBefore("世界", "世界".len));
    try std.testing.expectEqual(@as(usize, "世界".len), wordAfter("世界 x", 0));
}

test "keys: unknown and cut-short sequences leave nothing" {
    var it = KeyIterator{ .bytes = "\x1b[1;2Cx\x1b[1;5A\x1b[99~\x1b[" };
    try std.testing.expectEqual(Key{ .char = 'x' }, it.next().?);
    try std.testing.expectEqual(@as(?Key, null), it.next());
}

test "keys: an ESC before another key is Alt with it, skipped, not Escape" {
    var it = KeyIterator{ .bytes = "\x1bx\x1b\x7f\x1bé\x1b\x1bq\x1b" };
    try std.testing.expectEqual(Key{ .char = 'q' }, it.next().?);
    try std.testing.expectEqual(Key.escape, it.next().?);
    try std.testing.expectEqual(@as(?Key, null), it.next());
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

test "a frame taller than the screen scrolls only to keep the focus in view" {
    try std.testing.expectEqual(@as(usize, 0), scrollTop(10, 20, 15, 16));
    try std.testing.expectEqual(@as(usize, 0), scrollTop(30, 20, 5, 10));
    try std.testing.expectEqual(@as(usize, 6), scrollTop(30, 20, 20, 26));
    try std.testing.expectEqual(@as(usize, 10), scrollTop(30, 20, 28, 30));
    try std.testing.expectEqual(@as(usize, 22), scrollTop(40, 5, 22, 30)); // taller than the screen itself: its top
    const text = "a\nb\nc\nd\n";
    try std.testing.expectEqualStrings("b\nc\n", lineRange(text, 1, 2));
    try std.testing.expectEqualStrings("d\n", lineRange(text, 3, 5));
    try std.testing.expectEqualStrings("", lineRange(text, 6, 1));
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

test "columns: a count past any row's width moves or erases to its end" {
    const gpa = std.testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    try std.testing.expectEqual(@as(usize, 1), try appendColumns(&out, gpa, "a\x1b[18446744073709551615Cb", 8, false));
    try std.testing.expectEqualStrings("a", out.items);
    out.clearRetainingCapacity();
    try std.testing.expectEqual(@as(usize, 3), try appendColumns(&out, gpa, "abc\x1b[2D\x1b[18446744073709551615X", 8, false));
    try std.testing.expectEqualStrings("a  ", out.items);
}

test "columns: erasing past what is drawn erases nothing" {
    const gpa = std.testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    try std.testing.expectEqual(@as(usize, 0), try appendColumns(&out, gpa, "\x1b[5C\x1b[X", 80, false));
    try std.testing.expectEqual(@as(usize, 2), try appendColumns(&out, gpa, "ab\x1b[3C\x1b[4X\x1b[1K", 80, false));
    try std.testing.expectEqualStrings("  ", out.items);
    out.clearRetainingCapacity();
    try std.testing.expectEqual(@as(usize, 9), try appendColumns(&out, gpa, "ab\x1b[9C\x1b[X\x1b[3Dc", 80, false));
    try std.testing.expectEqualStrings("ab      c", out.items);
}

test "widths: wide characters take two columns, joining ones none" {
    try std.testing.expectEqual(@as(usize, 5), textWidth("a世界"));
    try std.testing.expectEqual(@as(usize, 1), textWidth("e\u{301}"));
    try std.testing.expectEqual(@as(usize, 2), textWidth("✅\u{fe0f}\u{200d}"));
    try std.testing.expectEqual(@as(usize, 4), textWidth("🎉ab"));
    try std.testing.expectEqual(@as(usize, 2), textWidth("\xffé"));
    try std.testing.expectEqual(@as(u2, 0), codepointWidth(0x1b));
    try std.testing.expectEqual(@as(u2, 1), codepointWidth('─'));
}

test "columns: a wide character's two columns, and a mark joining the one before" {
    const gpa = std.testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    try std.testing.expectEqual(@as(usize, 5), try appendColumns(&out, gpa, "世e\u{301}\x1b[Cx\u{85}", 20, false));
    try std.testing.expectEqualStrings("世e\u{301} x", out.items);
    // Drawn over, a wide character's other half is blank; one past the width isn't drawn.
    for ([_][2][]const u8{
        .{ "世界\x1b[3Gx", "世x " },
        .{ "世界\x1b[2Gx", " x界" },
        .{ "世界\x1b[3G\x1b[K", "世" },
        .{ "abc世", "abc" },
        .{ "abc世d", "abc" },
    }) |case| {
        out.clearRetainingCapacity();
        _ = try appendColumns(&out, gpa, case[0], 4, false);
        try std.testing.expectEqualStrings(case[1], out.items);
    }
}

test "columns: colour kept, other sequences dropped, redrawn lines last" {
    const gpa = std.testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    try std.testing.expectEqual(@as(usize, 7), try appendColumns(&out, gpa, "\x1b]0;title\x07\x1b[31mred\x1b[0m ok!\x1b[?25l", 20, true));
    try std.testing.expectEqualStrings("\x1b[0;31mred\x1b[0m ok!", out.items);
    try std.testing.expectEqual(@as(usize, 7), columns("\x1b]0;title\x07\x1b[31mred\x1b[0m ok!\x1b[?25l"));
    out.clearRetainingCapacity();
    try std.testing.expectEqual(@as(usize, 4), try appendColumns(&out, gpa, "50%...\r100%\x1b[K", 20, true));
    try std.testing.expectEqualStrings("100%", out.items);
}

test "colour: however many changes a line makes, each cell keeps its own" {
    const gpa = std.testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    var line: std.ArrayList(u8) = .empty;
    defer line.deinit(gpa);
    // Colours set without a reset between them, as a progress bar does.
    for (0..40) |i| try line.print(gpa, "\x1b[38;5;{d}m\x1b[1m#", .{i + 16});
    try line.appendSlice(gpa, "\x1b[22;38:2::1:2:3;48;2;4;5;6m$\x1b[4:3;7;49;39;27;24m%");
    _ = try appendColumns(&out, gpa, line.items, 80, true);
    try std.testing.expect(std.mem.find(u8, out.items, "\x1b[0;1;38;5;55m#") != null);
    try std.testing.expect(std.mem.endsWith(u8, out.items, "\x1b[0;38;2;1;2;3;48;2;4;5;6m$\x1b[0m%"));
}

test "cursor: marked where nothing is drawn, not over text" {
    const gpa = std.testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    _ = try appendLine(&out, gpa, "julia> ", 40, false, "90");
    try std.testing.expectEqualStrings("julia> ▎", out.items);
    out.clearRetainingCapacity();
    _ = try appendLine(&out, gpa, "julia> ", 40, true, "90");
    try std.testing.expectEqualStrings("julia> \x1b[0;90m▎\x1b[0m", out.items);
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
    try std.testing.expectEqualStrings("\x1b[0;1;32mjulia> \x1b[0m1+1", out.items);
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
