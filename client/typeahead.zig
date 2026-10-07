// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0
//
// Keys typed at a remote REPL's prompt, shown as they're typed rather than a
// round trip later: up to `cap` printable keys, backspaces and left and
// right moves, guessed at the cursor, taken back before each piece of the
// worker's output and shown again after it until its redraws show them.
// What's on screen beside them is followed in a `Row`, as the worker drew
// it; guessing stops wherever that can't be followed. A backspace or left
// move is guessed only within the input: after the line editor's
// `\e]133;B` mark, or, where it makes none (Julia before 1.14), within the
// typing guessed on the row. A right move is guessed only over what's known
// to be input, as at its end the line editor completes instead.

const std = @import("std");

/// The most keys guessed ahead of the worker's redraws.
pub const cap = 8;
/// The widest terminal followed; a wider one isn't guessed in.
const max_cols = 512;
/// Output at least this long is bulk, followed only from its last line.
const bulk = 4096;
/// Columns kept clear at the right edge, so a guess never wraps a row.
const margin = 2;
/// More than `Typeahead.frame` adds around the output it's given.
pub const frame_overhead = 128;
/// How long a key is assumed to take to be drawn, until a guess's has been timed.
const unmeasured_echo_ns = 500 * std.time.ns_per_ms;

// The keys guessed besides printable ones, as the line editor binds them.
const backspace = 0x7F;
const left = 0x02; // ^B, as an arrow is too
const right = 0x06; // ^F

/// What guessing depends on beyond the keys and output it's given.
pub const Context = struct {
    at_prompt: bool, // a line editor reads the keys: the terminal raw, no code running
    width: u16, // the terminal's columns, 0 if unknown
    now_ns: u64, // on a monotonic clock
};

/// Keys played on a row as the line editor would: its cells, cursor, and
/// the furthest each way the cursor has been, which is input.
const Sim = struct {
    cells: [max_cols]u8,
    col: u16,
    low: u16,
    reach: u16,
    inserts: u8 = 0,
    deleted: u8 = 0, // the last backspace's

    /// False where the line editor would do something else, or the result
    /// isn't known.
    fn apply(s: *Sim, key: u8) bool {
        switch (key) {
            backspace => {
                if (s.col == 0 or s.cells[s.col - 1] == 0) return false;
                s.col -= 1;
                s.deleted = s.cells[s.col];
                std.mem.copyForwards(u8, s.cells[s.col .. max_cols - 1], s.cells[s.col + 1 ..]);
                if (s.reach > s.col) s.reach -= 1;
            },
            left => s.col = std.math.sub(u16, s.col, 1) catch return false,
            right => s.col = if (s.col < s.reach) s.col + 1 else return false,
            else => {
                std.mem.copyBackwards(u8, s.cells[s.col + 1 ..], s.cells[s.col .. max_cols - 1]);
                s.cells[s.col] = key;
                if (s.reach >= s.col) s.reach += 1;
                s.col += 1;
                s.inserts += 1;
            },
        }
        s.low = @min(s.low, s.col);
        s.reach = @max(s.reach, s.col);
        return true;
    }
};

pub const Typeahead = struct {
    row: Row = .{},
    keys: [cap]u8 = undefined, // printable, or `backspace`, `left`, `right`
    sent_ns: [cap]u64 = undefined, // when each guess went to the worker
    guessed: u8 = 0,
    // The row as the worker drew it before the guesses, which they're played
    // on from `base_col`.
    base: [max_cols]u8 = undefined,
    base_col: u16 = 0,
    // How far the row is known to be input: as far as the guesses the
    // worker has drawn reached, until it may have changed.
    reach: ?u16 = null,
    // Without marks: where the typing guessed on the row began, which the
    // input's start can't be past.
    typed_from: ?u16 = null,
    moves: u32 = 0, // the row's, as `reach` and `typed_from` were known

    echo_ns: u64 = 0, // the slowest the worker has lately drawn a guess, 0 until it has
    // Keys went unguessed: none is guessed until the worker has surely drawn
    // them, as a guess drawn early would be in the wrong place.
    unguessed_until_ns: u64 = 0,

    /// Shows those of `keys` that can be guessed, into `w`; any other key
    /// takes the guesses back, and stops guessing until the worker has had
    /// time to draw it.
    pub fn onKeys(self: *Typeahead, keys: []const u8, ctx: Context, w: *std.Io.Writer) void {
        var i: usize = 0;
        while (i < keys.len) if (nextKey(keys, &i) == null) {
            self.drop(w);
            self.typed_from = null;
            return self.unguessed(ctx);
        };
        i = 0;
        while (i < keys.len) {
            const key = nextKey(keys, &i).?;
            if (!self.canGuess(key, ctx)) return self.unguessed(ctx);
            if (isPrintable(key) and self.typed_from == null) self.typed_from = self.base_col;
            self.keys[self.guessed] = key;
            self.sent_ns[self.guessed] = ctx.now_ns;
            self.guessed += 1;
            writeRuns(w, &.{key});
        }
    }

    /// Before the worker's `output`: the guesses taken off the screen, which
    /// is then as the worker drew it, until `afterOutput`; unless `output`
    /// clears them itself.
    pub fn beforeOutput(self: *const Typeahead, output: []const u8, w: *std.Io.Writer) void {
        if (!clearsRow(output)) self.takeBack(w);
    }

    fn takeBack(self: *const Typeahead, w: *std.Io.Writer) void {
        var buf: [cap]u8 = undefined;
        const keys = netKeys(self.keys[0..self.guessed], &buf);
        // Each undone, last first: a key typed by a backspace, a backspace by
        // typing back what it deleted, a move by the opposite one.
        var sim = self.played();
        var undo: [cap]u8 = undefined;
        for (keys, 0..) |key, i| {
            _ = sim.apply(key);
            undo[keys.len - 1 - i] = switch (key) {
                backspace => sim.deleted,
                left => right,
                right => left,
                else => backspace,
            };
        }
        writeRuns(w, undo[0..keys.len]);
    }

    /// After the worker's `output`: the guesses it has drawn let go, and the
    /// rest shown again, unless it drew something else.
    pub fn afterOutput(self: *Typeahead, output: []const u8, ctx: Context, w: *std.Io.Writer) void {
        self.row.feed(output, ctx.width);
        self.settle(ctx, w);
    }

    // `afterOutput`, its output followed already.
    fn settle(self: *Typeahead, ctx: Context, w: *std.Io.Writer) void {
        // Another row, or none known.
        if (self.row.cells == null or self.row.moves != self.moves) self.unknown();
        self.moves = self.row.moves;
        if (self.guessed == 0) return;
        if (self.row.marked and !self.row.input_open) return self.forget();
        const drawn = self.drawnGuesses() orelse {
            self.unknown();
            return self.forget();
        };
        if (drawn.keys > 0) {
            const n = drawn.keys;
            self.timeEcho(ctx.now_ns -| self.sent_ns[n - 1]);
            std.mem.copyForwards(u8, self.keys[0 .. self.guessed - n], self.keys[n..self.guessed]);
            std.mem.copyForwards(u64, self.sent_ns[0 .. self.guessed - n], self.sent_ns[n..self.guessed]);
            self.guessed -= n;
            self.base = self.row.cells.?;
            self.base_col = self.row.col.?;
            self.reach = drawn.reach;
        }
        if (self.guessed == 0) return;
        var sim = self.played();
        for (self.keys[0..self.guessed]) |key| if (!sim.apply(key)) return self.forget();
        if (!self.allows(&sim, ctx)) return self.forget();
        var buf: [cap]u8 = undefined;
        writeRuns(w, netKeys(self.keys[0..self.guessed], &buf));
    }

    /// The worker's `output` as one update to the terminal, into `w`, which
    /// has room for `frame_overhead` more: while there are guesses, they're
    /// taken back and shown again within a synchronized update (mode 2026),
    /// so the row is never painted without them.
    pub fn frame(self: *Typeahead, output: []const u8, ctx: Context, w: *std.Io.Writer) void {
        if (self.guessed == 0) {
            w.writeAll(output) catch {};
            return self.afterOutput(output, ctx, w);
        }
        // Followed once, to know how it ends before anything goes around it.
        var fed = self.row;
        fed.feed(output, ctx.width);
        // Nothing may be written into the middle of the worker's own escape
        // sequence or character, which the next piece ends.
        if (!endsBetween(&fed, output)) {
            self.beforeOutput(output, w);
            self.reach = null;
            self.forget();
            w.writeAll(output) catch {};
            self.row = fed;
            return self.settle(ctx, w);
        }
        w.writeAll("\x1b[?2026h") catch {};
        self.beforeOutput(output, w);
        w.writeAll(output) catch {};
        self.row = fed;
        self.settle(ctx, w);
        w.writeAll("\x1b[?2026l") catch {};
    }

    /// The guesses taken back, as the keys may now mean something else.
    pub fn drop(self: *Typeahead, w: *std.Io.Writer) void {
        self.takeBack(w);
        self.reach = null;
        self.forget();
    }

    /// The row lost track of, as the terminal reflows it on a resize: what's
    /// on screen is left for the worker's next redraw.
    pub fn resized(self: *Typeahead) void {
        self.row = .{};
        self.moves = 0;
        self.unknown();
        self.forget();
    }

    fn forget(self: *Typeahead) void {
        self.guessed = 0;
    }

    // What's known of the input's extent, given up.
    fn unknown(self: *Typeahead) void {
        self.typed_from = null;
        self.reach = null;
    }

    // A key sent without a guess: its redraw comes as late as the slowest
    // guess's has, and a half again; what it does to the row isn't known.
    fn unguessed(self: *Typeahead, ctx: Context) void {
        const echo_ns = if (self.echo_ns == 0) unmeasured_echo_ns else self.echo_ns;
        self.unguessed_until_ns = ctx.now_ns +| echo_ns +| echo_ns / 2;
        if (self.guessed == 0) self.reach = null;
    }

    // Up at once and down slowly, so that unguessed keys are waited on long
    // enough.
    fn timeEcho(self: *Typeahead, sample_ns: u64) void {
        self.echo_ns = if (sample_ns >= self.echo_ns) sample_ns else self.echo_ns - (self.echo_ns - sample_ns) / 8;
    }

    fn canGuess(self: *Typeahead, key: u8, ctx: Context) bool {
        if (!ctx.at_prompt or ctx.now_ns < self.unguessed_until_ns or self.guessed == cap) return false;
        if (self.row.parse != .ground) return false; // mid-sequence, as output last left it
        if (self.row.marked and !self.row.input_open) return false;
        if (self.guessed == 0) {
            self.base = self.row.cells orelse return false;
            self.base_col = self.row.col orelse return false;
        }
        var sim = self.played();
        for (self.keys[0..self.guessed]) |k| _ = sim.apply(k);
        return sim.apply(key) and self.allows(&sim, ctx);
    }

    // The base row, before any guess, to play them on.
    fn played(self: *const Typeahead) Sim {
        const reach = @max(self.base_col, self.reach orelse 0);
        return .{ .cells = self.base, .col = self.base_col, .low = self.base_col, .reach = reach };
    }

    // Whether the keys `sim` played can be shown: what they insert keeps the
    // row clear of the margin, what's after the cursor pushed along with
    // them, and the cursor stays within the input.
    fn allows(self: *const Typeahead, sim: *const Sim, ctx: Context) bool {
        if (ctx.width == 0 or ctx.width > max_cols) return false;
        const col = self.row.col orelse return false;
        const end = self.row.contentEnd() orelse return false;
        if (@max(end, col) + sim.inserts + margin > ctx.width) return false;
        if (sim.low >= self.base_col) return true;
        const floor = if (self.row.marked) self.row.input_col else self.typed_from;
        return sim.low >= (floor orelse return false);
    }

    // How many of the guesses the worker has drawn, the most it matches:
    // its cursor where they'd leave it, and its row as they'd leave it as
    // far as they reached. Null when it matches none. What's past that, such
    // as a completion hint, isn't guessed.
    fn drawnGuesses(self: *const Typeahead) ?struct { keys: u8, reach: u16 } {
        const col = self.row.col orelse return null;
        const cells = self.row.cells orelse return null;
        var sim = self.played();
        var found: ?u8 = null;
        var reach: u16 = 0;
        for (0..self.guessed + 1) |k| {
            if (k > 0) _ = sim.apply(self.keys[k - 1]);
            if (col == sim.col and std.mem.eql(u8, cells[0..sim.reach], sim.cells[0..sim.reach])) {
                found = @intCast(k);
                reach = sim.reach;
            }
        }
        return .{ .keys = found orelse return null, .reach = reach };
    }
};

// The next key in `keys`, past it, as guessed; null for one that isn't.
fn nextKey(keys: []const u8, i: *usize) ?u8 {
    const key = keys[i.*];
    i.* += 1;
    if (isPrintable(key) or key == left or key == right) return key;
    if (key == backspace or key == 0x08) return backspace;
    // An arrow, in either cursor-key mode.
    if (key != 0x1B or i.* + 1 >= keys.len or (keys[i.*] != '[' and keys[i.*] != 'O')) return null;
    i.* += 2;
    return switch (keys[i.* - 1]) {
        'D' => left,
        'C' => right,
        else => null,
    };
}

// `keys` as they show, each insert a backspace straight after it undoes
// left out, into `buf`.
fn netKeys(keys: []const u8, buf: *[cap]u8) []const u8 {
    var n: usize = 0;
    for (keys) |key| {
        if (key == backspace and n > 0 and isPrintable(buf[n - 1])) {
            n -= 1;
        } else {
            buf[n] = key;
            n += 1;
        }
    }
    return buf[0..n];
}

// What the terminal is sent to show `keys` played at the cursor, a run of
// one kind at a time.
fn writeRuns(w: *std.Io.Writer, keys: []const u8) void {
    var i: usize = 0;
    while (i < keys.len) {
        var end = i + 1;
        while (end < keys.len and sameKind(keys[i], keys[end])) end += 1;
        const n = end - i;
        switch (keys[i]) {
            backspace => {
                csi(w, n, 'D');
                csi(w, n, 'P');
            },
            left => csi(w, n, 'D'),
            right => csi(w, n, 'C'),
            else => {
                csi(w, n, '@');
                w.writeAll(keys[i..end]) catch {};
            },
        }
        i = end;
    }
}

fn sameKind(a: u8, b: u8) bool {
    return a == b or (isPrintable(a) and isPrintable(b));
}

// A cursor or editing sequence, its count left out at 1.
fn csi(w: *std.Io.Writer, n: usize, final: u8) void {
    if (n == 1) {
        w.print("\x1b[{c}", .{final}) catch {};
    } else {
        w.print("\x1b[{d}{c}", .{ n, final }) catch {};
    }
}

// Whether `output` starts by clearing the cursor's row from its start, as
// the line editor's redraws do: where the guesses are, and from wherever
// they left the cursor.
fn clearsRow(output: []const u8) bool {
    for ([_][]const u8{ "\r\x1b[K", "\r\x1b[0K", "\r\x1b[2K", "\x1b[2K\r" }) |start| {
        if (std.mem.startsWith(u8, output, start)) return true;
    }
    return false;
}

// Whether `output`, which `row` has just followed, ends between escape
// sequences and between UTF-8 characters.
fn endsBetween(row: *const Row, output: []const u8) bool {
    if (row.parse != .ground) return false;
    var i = output.len;
    while (i > 0 and output.len - i < 4) {
        i -= 1;
        if (output[i] < 0x80) return true;
        const len = std.unicode.utf8ByteSequenceLength(output[i]) catch continue; // a continuation byte
        return output.len - i >= len;
    }
    return true;
}

/// The cursor's row as the worker drew it: the cursor's column and what's
/// in each cell, each unknown once output does what isn't followed.
pub const Row = struct {
    col: ?u16 = null,
    cells: ?[max_cols]u8 = null, // ASCII, 0 where unknown
    parse: Parse = .ground,
    param: u16 = 0, // a CSI's first parameter
    params: u8 = 0, // how many digits or separators it has had
    private: bool = false, // a CSI's `?` or other private marker
    osc: [5]u8 = undefined, // an OSC's start, as far as a mark's
    osc_len: u8 = 0,
    // The line editor's `\e]133;` marks: seen at all, and the input they
    // place, from its start (B) to its command's (C).
    marked: bool = false,
    input_open: bool = false,
    // Where the input starts on the row, while it's known: forgotten as the
    // cursor leaves the row, or it's erased from its start.
    input_col: ?u16 = null,
    // The rows below the cursor's known cleared, as a line editor clears its
    // input's rows from the last up before redrawing them.
    blank_below: u8 = 0,
    // The cursor's moves to another row, counted.
    moves: u32 = 0,

    const Parse = enum { ground, escape, csi, osc, osc_escape };

    pub fn feed(self: *Row, bytes: []const u8, width: u16) void {
        if (width == 0 or width > max_cols) {
            self.* = .{};
            return;
        }
        var rest = bytes;
        // A sequence the last output left open, ended first.
        while (self.parse != .ground and rest.len > 0) {
            self.step(rest[0], width);
            rest = rest[1..];
        }
        // Bulk output, as running code writes, is followed from its last line:
        // a newline starts a row afresh, so of what's before it only the last
        // mark counts, as Enter's output comes, the end of the input. A
        // redraw, far shorter, is followed whole, for the rows it clears.
        if (rest.len >= bulk) if (std.mem.lastIndexOfScalar(u8, rest, '\n')) |nl| {
            if (std.mem.lastIndexOf(u8, rest[0..nl], "\x1b]133;")) |at| {
                for (rest[at..nl]) |byte| {
                    self.step(byte, width);
                    if (self.parse == .ground) break;
                }
                self.parse = .ground;
            }
            self.blank_below = 0;
            rest = rest[nl..];
        };
        for (rest) |byte| self.step(byte, width);
    }

    /// The column after the row's last non-blank cell, if the row is known.
    pub fn contentEnd(self: *const Row) ?u16 {
        const cells = self.cells orelse return null;
        var end: usize = max_cols;
        while (end > 0 and cells[end - 1] == ' ') end -= 1;
        if (end > 0 and std.mem.findScalar(u8, cells[0..end], 0) != null) return null;
        return @intCast(end);
    }

    fn step(self: *Row, byte: u8, width: u16) void {
        switch (self.parse) {
            .ground => self.ground(byte, width),
            .escape => switch (byte) {
                '[' => {
                    self.parse = .csi;
                    self.param = 0;
                    self.params = 0;
                    self.private = false;
                },
                ']' => {
                    self.parse = .osc;
                    self.osc_len = 0;
                },
                else => {
                    // Saved cursors, charsets and the like: not followed.
                    self.parse = .ground;
                    self.lost();
                },
            },
            .csi => switch (byte) {
                '0'...'9' => {
                    if (self.params == 0) self.param = self.param *| 10 +| (byte - '0');
                },
                ';' => self.params +|= 1,
                '<'...'?' => self.private = true,
                0x20...0x2F => {}, // intermediates
                0x40...0x7E => {
                    self.parse = .ground;
                    self.csi(byte, width);
                },
                else => {
                    self.parse = .ground;
                    self.lost();
                },
            },
            .osc => switch (byte) {
                0x07 => self.endOsc(),
                0x1B => self.parse = .osc_escape,
                else => if (self.osc_len < self.osc.len) {
                    self.osc[self.osc_len] = byte;
                    self.osc_len += 1;
                },
            },
            .osc_escape => if (byte == '\\') self.endOsc() else {
                self.parse = .osc;
            },
        }
    }

    fn ground(self: *Row, byte: u8, width: u16) void {
        switch (byte) {
            0x1B => self.parse = .escape,
            '\r' => self.col = 0,
            '\n' => {
                self.col = 0;
                self.down(1);
            },
            0x08 => if (self.col) |c| {
                self.col = c -| 1;
            },
            0x07 => {},
            0x20...0x7E => self.put(byte, width),
            else => self.lost(), // tabs, other controls, and what's past ASCII
        }
    }

    fn put(self: *Row, byte: u8, width: u16) void {
        const c = self.col orelse return;
        if (self.cells) |*cells| cells[c] = byte;
        // The last column leaves a wrap pending, which isn't followed.
        self.col = if (c + 1 < width) c + 1 else null;
    }

    fn csi(self: *Row, final: u8, width: u16) void {
        if (self.private) return; // modes such as bracketed paste: no movement
        const n = @max(self.param, 1);
        switch (final) {
            'm' => {},
            'K' => self.erase(self.param),
            'J' => {
                self.erase(self.param);
                if (self.param != 1) self.blank_below = std.math.maxInt(u8); // and below
            },
            'C' => if (self.col) |c| {
                self.col = @min(c +| n, width - 1);
            },
            'D' => if (self.col) |c| {
                self.col = c -| n;
            },
            'G' => self.col = @min(n - 1, width - 1),
            '@' => self.shift(n, .right, width),
            'P' => self.shift(n, .left, width),
            // Another row, its column kept: from a cleared row one up, that
            // row is known cleared below.
            'A' => {
                const cleared = n == 1 and self.contentEnd() == 0;
                self.blank_below = if (cleared) self.blank_below +| 1 else 0;
                self.onto(false);
            },
            'B' => self.down(n),
            else => self.lost(),
        }
    }

    // Erase in line: 0 from the cursor on, 1 up to it, 2 all; known blank as
    // far as the cursor's column is.
    fn erase(self: *Row, mode: u16) void {
        // The row redrawn from its start, prompt and all.
        if (mode == 2 or self.col == 0) self.input_col = null;
        if (mode == 2) {
            self.cells = @splat(' ');
            return;
        }
        const c = self.col orelse return;
        switch (mode) {
            0 => {
                if (c == 0) self.cells = @splat(' ');
                if (self.cells) |*cells| @memset(cells[c..], ' ');
            },
            1 => if (self.cells) |*cells| @memset(cells[0 .. c + 1], ' '),
            else => self.lost(),
        }
    }

    fn shift(self: *Row, n: u16, direction: enum { left, right }, width: u16) void {
        const c = self.col orelse return;
        const cells = if (self.cells) |*cells| cells[c..width] else return;
        const k = @min(n, cells.len);
        switch (direction) {
            .right => {
                std.mem.copyBackwards(u8, cells[k..], cells[0 .. cells.len - k]);
                @memset(cells[0..k], ' ');
            },
            .left => {
                std.mem.copyForwards(u8, cells[0 .. cells.len - k], cells[k..]);
                @memset(cells[cells.len - k ..], ' ');
            },
        }
    }

    fn lost(self: *Row) void {
        self.col = null;
        self.blank_below = 0;
        self.onto(false);
    }

    // `n` rows down, onto one known blank if it was cleared.
    fn down(self: *Row, n: u16) void {
        const cleared = n <= self.blank_below;
        self.blank_below = if (cleared) self.blank_below - @as(u8, @intCast(n)) else 0;
        self.onto(cleared);
    }

    fn onto(self: *Row, cleared: bool) void {
        self.cells = if (cleared) @splat(' ') else null;
        self.input_col = null;
        self.moves +%= 1;
    }

    fn endOsc(self: *Row) void {
        self.parse = .ground;
        const mark = self.osc[0..self.osc_len];
        if (mark.len < 5 or !std.mem.eql(u8, mark[0..4], "133;")) return;
        self.marked = true;
        switch (mark[4]) {
            'B' => {
                self.input_open = true;
                self.input_col = self.col;
            },
            'C', 'D' => {
                self.input_open = false;
                self.input_col = null;
            },
            else => {},
        }
    }
};

// --- The client's ---

const platform = @import("platform/main.zig");
const debuglog = @import("debuglog.zig");

var enabled = false;
// Keys may be read on a thread apart from the output's, which take turns.
var turn: platform.Lock = .{};
var state: Typeahead = .{};
var columns: u16 = 0;
// A resize, reported in a signal handler, which may land mid-turn: taken
// up with the next turn.
var resized_columns: std.atomic.Value(u32) = .init(no_resize);
const no_resize = std.math.maxInt(u32);
var stderr_on_screen = false;
// While guessing, output goes out in pieces this large, each with the
// guesses around it in one write.
const relay_piece = 1024;

/// Guesses from here on, before keys are read: for a remote worker, whose
/// redraws come a round trip after each key, given a terminal `cols` wide.
pub fn enable(cols: u16) void {
    enabled = true;
    columns = cols;
    stderr_on_screen = platform.isatty(platform.getStderrHandle());
    debuglog.event("typeahead: on", .{});
}

/// The terminal now `cols` wide; safe in a signal handler.
pub fn resize(cols: u16) void {
    if (enabled) resized_columns.store(cols, .release);
}

/// Each read of local input, before it goes to the worker.
pub fn typed(bytes: []const u8) void {
    if (!enabled) return;
    takeTurn();
    defer turn.release();
    var buf: [frame_overhead]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    const before = state.guessed;
    state.onKeys(bytes, context(), &w);
    show(w.buffered());
    if (state.guessed > before) debuglog.event("typeahead: guessed {d}, {d} pending", .{ state.guessed - before, state.guessed });
}

/// The worker's `data` to `dst`, around which guesses are taken back and
/// shown again; false once `dst` is gone, as `platform.writeOutput`.
pub fn relay(dst: std.posix.fd_t, data: []const u8) bool {
    if (!enabled or (dst != platform.getStdoutHandle() and !stderr_on_screen)) return platform.writeOutput(dst, data);
    takeTurn();
    defer turn.release();
    const ctx = context();
    var rest = data;
    while (rest.len > 0) {
        // With no guesses to frame it in, it's only followed, and goes as it came.
        if (state.guessed == 0) {
            var none: std.Io.Writer = .fixed(&.{});
            state.afterOutput(rest, ctx, &none);
            return platform.writeOutput(dst, rest);
        }
        const piece = rest[0..@min(rest.len, relay_piece)];
        rest = rest[piece.len..];
        var buf: [relay_piece + frame_overhead]u8 = undefined;
        var w: std.Io.Writer = .fixed(&buf);
        const pending = state.guessed;
        state.frame(piece, ctx, &w);
        if (pending > 0) debuglog.event("typeahead: {d} drawn, {d} pending", .{ pending -| state.guessed, state.guessed });
        if (!platform.writeOutput(dst, w.buffered())) return false;
    }
    return true;
}

/// The guesses taken back: the worker has left its prompt, or is going.
pub fn drop() void {
    if (!enabled) return;
    takeTurn();
    defer turn.release();
    var buf: [frame_overhead]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    state.drop(&w);
    show(w.buffered());
}

fn takeTurn() void {
    turn.acquire();
    const cols = resized_columns.swap(no_resize, .acquire);
    if (cols == no_resize) return;
    columns = @intCast(cols);
    state.resized();
}

fn context() Context {
    // Ctrl-C is a key exactly while a line editor reads them.
    return .{ .at_prompt = platform.ctrlCIsKey(), .width = columns, .now_ns = platform.monotonicNs() };
}

fn show(bytes: []const u8) void {
    if (bytes.len > 0) platform.writeFile(platform.getStdoutHandle(), bytes);
}

fn isPrintable(byte: u8) bool {
    return byte >= 0x20 and byte < 0x7F;
}

// --- Tests ---

const testing = std.testing;

const prompt_ctx: Context = .{ .at_prompt = true, .width = 80, .now_ns = 0 };

fn atMs(ms: u64) Context {
    return .{ .at_prompt = true, .width = 80, .now_ns = ms * std.time.ns_per_ms };
}

// The prompt, empty, then with `line` and the cursor after it, as Julia's
// line editor redraws them.
const empty_prompt = "\r\x1b[0K\x1b[32m\x1b[1mjulia> \x1b[0m\x1b[0m\r\x1b[7C\r\x1b[7C";

fn redraw(comptime line: []const u8) []const u8 {
    return std.fmt.comptimePrint("\r\x1b[0K\x1b[32m\x1b[1mjulia> \x1b[0m\x1b[0m\r\x1b[7C{s}\r\x1b[{d}C", .{ line, 7 + line.len });
}

// As Julia 1.14's line editor redraws them, its prompt marked.
fn marked(comptime line: []const u8) []const u8 {
    return std.fmt.comptimePrint("\r\x1b[0K\x1b]133;A\x07\x1b[32m\x1b[1mjulia> \x1b[0m\x1b[0m\x1b]133;B\x07\r\x1b[7C{s}\r\x1b[{d}C", .{ line, 7 + line.len });
}

/// A typeahead past a prompt, and what it wrote.
const Harness = struct {
    t: Typeahead = .{},
    buf: [256]u8 = undefined,
    last: [256]u8 = undefined,
    w: std.Io.Writer = undefined,

    fn init(self: *Harness, prompt: []const u8) void {
        self.w = .fixed(&self.buf);
        self.output(prompt, prompt_ctx);
        _ = self.written();
    }

    fn keys(self: *Harness, bytes: []const u8, ctx: Context) []const u8 {
        self.t.onKeys(bytes, ctx, &self.w);
        return self.written();
    }

    // What's written around `bytes`, which itself goes to the terminal as is.
    fn output(self: *Harness, bytes: []const u8, ctx: Context) void {
        self.t.beforeOutput(bytes, &self.w);
        self.w.writeAll("|") catch {};
        self.t.afterOutput(bytes, ctx, &self.w);
    }

    // Since the last call; good until the next.
    fn written(self: *Harness) []const u8 {
        const text = self.w.buffered();
        @memcpy(self.last[0..text.len], text);
        self.w = .fixed(&self.buf);
        return self.last[0..text.len];
    }
};

test "a row follows the line editor's redraw" {
    var row: Row = .{};
    row.feed(redraw("1+1"), 80);
    try testing.expectEqual(10, row.col.?);
    try testing.expectEqualStrings("julia> 1+1", row.cells.?[0..10]);
    try testing.expectEqual(10, row.contentEnd().?);
    // A completion hint after the cursor counts as the row's content.
    row.feed("\x1b[90mreads\x1b[39m\x1b[5D", 80);
    try testing.expectEqual(10, row.col.?);
    try testing.expectEqual(15, row.contentEnd().?);
}

test "a row follows what it can't, until the next redraw" {
    var row: Row = .{};
    row.feed(redraw("x"), 80);
    row.feed("\x1b7", 80); // a saved cursor
    try testing.expect(row.col == null and row.cells == null);
    row.feed(redraw("x"), 80);
    try testing.expectEqual(8, row.col.?);
    row.feed("é", 80);
    try testing.expect(row.col == null);
    row.feed("\n", 80);
    try testing.expect(row.col.? == 0 and row.cells == null);
    // Split mid-sequence, as output may be.
    row.feed("\r\x1b[0", 80);
    row.feed("K\x1b[3", 80);
    row.feed("2mab\x1b]0;title\x07\x1b[1D", 80);
    try testing.expectEqual(1, row.col.?);
    try testing.expectEqualStrings("ab", row.cells.?[0..2]);
}

test "a row reads the line editor's marks" {
    var row: Row = .{};
    row.feed(marked("1+1"), 80);
    try testing.expect(row.marked and row.input_open);
    try testing.expectEqual(7, row.input_col.?);
    try testing.expectEqual(10, row.col.?);
    // Redrawn from its start, the row's input is placed again.
    row.feed("\r\x1b[0K", 80);
    try testing.expect(row.input_col == null);
    row.feed("julia> \x1b]133;B\x1b\\", 80);
    try testing.expectEqual(7, row.input_col.?);
    row.feed("\x1b[0m\x1b]133;C\x07", 80);
    try testing.expect(!row.input_open and row.input_col == null);
}

test "a row follows only the line output ends on, and the last mark before it" {
    var row: Row = .{};
    row.feed(marked("1+1"), 80);
    row.feed("\x1b]133;C\x07\x1b[1m2\x1b[0m\n" ++ more_output ++ "ta\x1b[1mil", 80);
    try testing.expect(row.marked and !row.input_open);
    try testing.expectEqual(4, row.col.?);
    try testing.expect(row.cells == null);
    // A prompt's start, then its line run on: still open.
    row.feed("\r\x1b[0K\x1b]133;A\x07julia> \x1b]133;B\x07ab\ncd", 80);
    try testing.expect(row.input_open);
    try testing.expectEqual(2, row.col.?);
}

// Lines enough to be bulk.
const more_output = blk: {
    const line = "\x1b[31mmore output\n";
    var lines: [bulk / line.len * line.len + line.len]u8 = undefined;
    for (0..lines.len / line.len) |i| @memcpy(lines[i * line.len ..][0..line.len], line);
    break :blk lines;
};

// An input over two rows, `foo(` then `bc`, redrawn as Julia's line editor
// does with the cursor on its last: cleared from there up, then drawn down.
fn twoRows(comptime last: []const u8) []const u8 {
    return std.fmt.comptimePrint("\r\x1b[0K\x1b[1A\r\x1b[0K\x1b[32m\x1b[1mjulia> \x1b[0m\x1b[0m\r\x1b[7Cfoo(\n\r\x1b[7C{s}\r\x1b[{d}C", .{ last, 7 + last.len });
}

test "a row is known cleared once cleared above the cursor's, and moved onto" {
    var row: Row = .{};
    row.feed(twoRows("b"), 80);
    try testing.expectEqualStrings("       b ", row.cells.?[0..9]);
    try testing.expectEqual(8, row.col.?);
    // Moved onto a row not cleared, it isn't known.
    row.feed("\x1b[2B", 80);
    try testing.expect(row.cells == null);
    // Erased below, every row below is cleared.
    row.feed("\r\x1b[J\n", 80);
    try testing.expectEqual(0, row.contentEnd().?);
}

test "the last row of an input over several is guessed on, but not backspaced from" {
    var h: Harness = .{};
    h.init(empty_prompt);
    // A row new to the input isn't known until a redraw has cleared it.
    h.output("\r\x1b[0K\x1b[32m\x1b[1mjulia> \x1b[0m\x1b[0m\r\x1b[7Cfoo(\n\r\x1b[7C\r\x1b[7C", prompt_ctx);
    _ = h.written();
    try testing.expectEqualStrings("", h.keys("b", atMs(0)));
    h.output(twoRows("b"), atMs(100));
    _ = h.written();
    try testing.expectEqualStrings("\x1b[@c", h.keys("c", atMs(1000)));
    h.output(twoRows("bc"), atMs(1100));
    _ = h.written();
    try testing.expectEqual(0, h.t.guessed);
    // Where its line starts isn't known.
    try testing.expectEqualStrings("", h.keys("\x7f", atMs(1200)));
}

test "a key typed at the prompt is shown at once, and let go as the worker draws it" {
    var h: Harness = .{};
    h.init(empty_prompt);
    const shown = h.keys("a", prompt_ctx);
    try testing.expectEqualStrings("\x1b[@a", shown);
    h.output(redraw("a"), prompt_ctx);
    const around = h.written();
    // Cleared by the redraw itself, and nothing left to show after it.
    try testing.expectEqualStrings("|", around);
    try testing.expectEqual(0, h.t.guessed);
}

test "a guess is let go however the worker draws it: echoed, styled, or hinted after" {
    var h: Harness = .{};
    h.init(empty_prompt);
    _ = h.keys("ab", prompt_ctx);
    // Echoed alone, as a line editor without a full redraw does.
    h.output("a", prompt_ctx);
    try testing.expectEqualStrings("\x1b[2D\x1b[2P|\x1b[@b", h.written());
    h.output("\x1b[35mb\x1b[39m", prompt_ctx);
    _ = h.written();
    try testing.expectEqual(0, h.t.guessed);
    // Redrawn whole, its text styled differently from before.
    _ = h.keys("c", prompt_ctx);
    h.output("\r\x1b[0K\x1b[32m\x1b[1mjulia> \x1b[0m\x1b[0m\r\x1b[7C\x1b[35mabc\x1b[39m\r\x1b[10C", prompt_ctx);
    _ = h.written();
    try testing.expectEqual(0, h.t.guessed);
    // Echoed, then a completion hint after it, the cursor brought back.
    _ = h.keys("d", prompt_ctx);
    h.output("d\x1b[90mef\x1b[39m\x1b[2D", prompt_ctx);
    _ = h.written();
    try testing.expectEqual(0, h.t.guessed);
}

test "a rewritten line lets go of the guesses it holds, and keeps the rest" {
    var h: Harness = .{};
    h.init(redraw("t"));
    _ = h.keys("his", prompt_ctx);
    h.output(redraw("thi"), prompt_ctx);
    try testing.expectEqualStrings("|\x1b[@s", h.written());
    try testing.expectEqual(1, h.t.guessed);
    // The same, the rewrite split mid-line across reads.
    var s: Harness = .{};
    s.init(redraw("t"));
    _ = s.keys("his", prompt_ctx);
    const whole = redraw("thi");
    const cut = std.mem.find(u8, whole, "i\r").?;
    s.output(whole[0..cut], prompt_ctx);
    try testing.expectEqualStrings("|\x1b[2@is", s.written());
    s.output(whole[cut..], prompt_ctx);
    try testing.expectEqualStrings("\x1b[2D\x1b[2P|\x1b[@s", s.written());
    try testing.expectEqual(1, s.t.guessed);
}

test "guesses the worker hasn't drawn yet are shown again after its redraw" {
    var h: Harness = .{};
    h.init(empty_prompt);
    _ = h.keys("ab", prompt_ctx);
    h.output(redraw("a"), prompt_ctx);
    const around = h.written();
    try testing.expectEqualStrings("|\x1b[@b", around);
    try testing.expectEqual(1, h.t.guessed);
    // One redraw answering several keys lets them all go.
    _ = h.keys("c", prompt_ctx);
    h.output(redraw("abc"), prompt_ctx);
    _ = h.written();
    try testing.expectEqual(0, h.t.guessed);
}

test "a redraw split across chunks keeps the guesses until it ends" {
    var h: Harness = .{};
    h.init(empty_prompt);
    _ = h.keys("ab", prompt_ctx);
    const whole = redraw("a");
    const cut = std.mem.find(u8, whole, "a\r").?;
    h.output(whole[0..cut], prompt_ctx);
    const first = h.written();
    try testing.expectEqualStrings("|\x1b[2@ab", first);
    h.output(whole[cut..], prompt_ctx);
    const second = h.written();
    try testing.expectEqualStrings("\x1b[2D\x1b[2P|\x1b[@b", second);
}

test "a redraw that isn't the guesses lets them go" {
    var h: Harness = .{};
    h.init(empty_prompt);
    // `]` switches to the package prompt rather than inserting.
    _ = h.keys("]", prompt_ctx);
    h.output("\r\x1b[0K\x1b[34m\x1b[1m(@v1.13) pkg> \x1b[0m\r\x1b[14C", prompt_ctx);
    _ = h.written();
    try testing.expectEqual(0, h.t.guessed);
    // As does one drawing another character where the guess was.
    h.init(empty_prompt);
    _ = h.keys("a", prompt_ctx);
    h.output(redraw("b"), prompt_ctx);
    const around = h.written();
    try testing.expectEqualStrings("|", around);
    try testing.expectEqual(0, h.t.guessed);
}

test "no more than the cap is guessed, and none after a key that wasn't" {
    var h: Harness = .{};
    h.init(empty_prompt);
    const shown = h.keys("abcdefghi", prompt_ctx);
    try testing.expectEqualStrings("\x1b[@a\x1b[@b\x1b[@c\x1b[@d\x1b[@e\x1b[@f\x1b[@g\x1b[@h", shown);
    // Every guess drawn, but not yet the key that wasn't.
    h.output(redraw("abcdefgh"), atMs(1));
    _ = h.written();
    const blocked = h.keys("j", atMs(2));
    try testing.expectEqualStrings("", blocked);
}

test "another key takes the guesses back, and stops guessing until the worker draws" {
    var h: Harness = .{};
    h.init(empty_prompt);
    _ = h.keys("ab", prompt_ctx);
    const back = h.keys("\t", prompt_ctx); // a completion
    try testing.expectEqualStrings("\x1b[2D\x1b[2P", back);
    const none = h.keys("c", prompt_ctx);
    try testing.expectEqualStrings("", none);
    // The guesses' own echo, before the arrow's: still too soon.
    h.output(redraw("ab"), atMs(10));
    _ = h.written();
    const stale = h.keys("d", atMs(20));
    try testing.expectEqualStrings("", stale);
    // Long after, as no guess has yet been timed.
    h.output(comptime redraw("acdb") ++ "\x1b[3D", atMs(400));
    _ = h.written();
    const again = h.keys("e", atMs(800));
    try testing.expectEqualStrings("\x1b[@e", again);
}

test "keys unguessed are waited on as long as guesses take to be drawn" {
    var h: Harness = .{};
    h.init(empty_prompt);
    _ = h.keys("a", atMs(0));
    h.output(redraw("a"), atMs(40));
    _ = h.written();
    try testing.expectEqual(40 * std.time.ns_per_ms, h.t.echo_ns);
    // A completion asked at 100 ms is surely drawn by 160.
    _ = h.keys("\t", atMs(100));
    h.output(comptime redraw("a") ++ "\x1b[1D", atMs(140));
    _ = h.written();
    try testing.expectEqualStrings("", h.keys("b", atMs(150)));
    // The `b` went unguessed too, so it's waited on in turn.
    h.output(comptime redraw("ba") ++ "\x1b[1D", atMs(190));
    _ = h.written();
    try testing.expectEqualStrings("", h.keys("c", atMs(200)));
    try testing.expectEqualStrings("\x1b[@c", h.keys("c", atMs(260)));
    // A slower echo is waited for at once; a quicker one only by degrees.
    h.t.timeEcho(80 * std.time.ns_per_ms);
    try testing.expectEqual(80 * std.time.ns_per_ms, h.t.echo_ns);
    h.t.timeEcho(0);
    try testing.expectEqual(70 * std.time.ns_per_ms, h.t.echo_ns);
}

test "a backspace takes back a guess, and goes with it" {
    var h: Harness = .{};
    h.init(empty_prompt);
    _ = h.keys("ab", prompt_ctx);
    try testing.expectEqualStrings("\x1b[D\x1b[P", h.keys("\x7f", prompt_ctx));
    h.output(redraw("a"), prompt_ctx);
    try testing.expectEqualStrings("|", h.written());
    try testing.expectEqual(0, h.t.guessed);
}

test "unmarked, a backspace reaches back only over the typing guessed" {
    var h: Harness = .{};
    h.init(empty_prompt);
    _ = h.keys("ab", prompt_ctx);
    h.output(redraw("ab"), prompt_ctx);
    _ = h.written();
    try testing.expectEqualStrings("\x1b[D\x1b[P\x1b[D\x1b[P", h.keys("\x7f\x08", prompt_ctx));
    try testing.expectEqualStrings("", h.keys("\x7f", prompt_ctx));
    // A line the worker drew, as history recalls one, isn't backspaced over.
    var r: Harness = .{};
    r.init(empty_prompt);
    r.output(redraw("xyz"), prompt_ctx);
    _ = r.written();
    try testing.expectEqualStrings("", r.keys("\x7f", prompt_ctx));
}

test "marked, a backspace reaches back to the input's start" {
    var h: Harness = .{};
    h.init(marked("abc"));
    // Taken back before output the worker drew without it, by putting back what it deleted.
    try testing.expectEqualStrings("\x1b[D\x1b[P", h.keys("\x7f", prompt_ctx));
    h.output("\x1b[39m", prompt_ctx);
    try testing.expectEqualStrings("\x1b[@c|\x1b[D\x1b[P", h.written());
    h.output(marked("ab"), prompt_ctx);
    try testing.expectEqualStrings("|", h.written());
    try testing.expectEqual(0, h.t.guessed);
    try testing.expectEqualStrings("\x1b[D\x1b[P\x1b[D\x1b[P", h.keys("\x7f\x7f", prompt_ctx));
    try testing.expectEqualStrings("", h.keys("\x7f", prompt_ctx));
}

test "a left move is guessed, and keys after it inserted there" {
    var h: Harness = .{};
    h.init(empty_prompt);
    _ = h.keys("ab", prompt_ctx);
    try testing.expectEqualStrings("\x1b[D", h.keys("\x1b[D", prompt_ctx));
    try testing.expectEqualStrings("\x1b[@x", h.keys("x", prompt_ctx));
    // Taken back last first; the move and the `x` the redraw hasn't drawn shown again.
    h.output("ab", prompt_ctx);
    try testing.expectEqualStrings("\x1b[D\x1b[P\x1b[C\x1b[2D\x1b[2P|\x1b[D\x1b[@x", h.written());
    h.output(comptime redraw("axb") ++ "\x1b[1D", prompt_ctx);
    _ = h.written();
    try testing.expectEqual(0, h.t.guessed);
}

test "moves stay within the input, and right ones within what's known of it" {
    var h: Harness = .{};
    h.init(empty_prompt);
    _ = h.keys("ab", prompt_ctx);
    try testing.expectEqualStrings("\x1b[D\x1b[D", h.keys("\x1bOD\x02", prompt_ctx));
    try testing.expectEqualStrings("", h.keys("\x1b[D", atMs(1))); // past the typing
    var r: Harness = .{};
    r.init(empty_prompt);
    _ = r.keys("ab", prompt_ctx);
    _ = r.keys("\x1b[D\x1b[D", prompt_ctx);
    try testing.expectEqualStrings("\x1b[C\x1b[C", r.keys("\x1b[C\x06", prompt_ctx));
    // At the input's end, a right move completes instead.
    try testing.expectEqualStrings("", r.keys("\x1b[C", prompt_ctx));
    // Nor is a completion hint after the cursor input.
    var m: Harness = .{};
    m.init(comptime marked("ab") ++ "\x1b[90mcd\x1b[39m\x1b[2D");
    try testing.expectEqualStrings("", m.keys("\x1b[C", prompt_ctx));
}

test "what the worker has drawn of the guesses stays known to be input" {
    var h: Harness = .{};
    h.init(empty_prompt);
    _ = h.keys("abc", prompt_ctx);
    h.output(redraw("abc"), prompt_ctx);
    _ = h.keys("\x1b[D\x1b[D", prompt_ctx);
    h.output(comptime redraw("abc") ++ "\x1b[2D", prompt_ctx);
    _ = h.written();
    try testing.expectEqual(0, h.t.guessed);
    try testing.expectEqualStrings("\x1b[C", h.keys("\x1b[C", prompt_ctx));
}

test "the command's start, marked in the output, ends guessing" {
    var h: Harness = .{};
    h.init(marked("ab"));
    _ = h.keys("c", prompt_ctx);
    h.output("\x1b[0m\x1b]133;C\x07", prompt_ctx);
    try testing.expectEqualStrings("\x1b[D\x1b[P|", h.written());
    try testing.expectEqual(0, h.t.guessed);
    try testing.expectEqualStrings("", h.keys("d", prompt_ctx));
}

test "nothing is guessed away from the prompt, or near the right edge" {
    var h: Harness = .{};
    h.init(empty_prompt);
    const running = h.keys("a", .{ .at_prompt = false, .width = 80, .now_ns = 0 });
    try testing.expectEqualStrings("", running);
    // A 10-column terminal: "julia> " leaves room for one, the margin kept.
    var narrow: Harness = .{};
    narrow.w = .fixed(&narrow.buf);
    narrow.output(empty_prompt, .{ .at_prompt = true, .width = 10, .now_ns = 0 });
    _ = narrow.written();
    const shown = narrow.keys("ab", .{ .at_prompt = true, .width = 10, .now_ns = 0 });
    try testing.expectEqualStrings("\x1b[@a", shown);
}

test "a resize forgets the row, so guessing waits for a redraw" {
    var h: Harness = .{};
    h.init(empty_prompt);
    h.t.resized();
    const none = h.keys("a", prompt_ctx);
    try testing.expectEqualStrings("", none);
}

test "output around guesses goes out as one synchronized update" {
    var h: Harness = .{};
    h.init(empty_prompt);
    _ = h.keys("ab", prompt_ctx);
    const output = comptime redraw("a");
    h.t.frame(output, prompt_ctx, &h.w);
    const update = h.written();
    try testing.expectEqualStrings("\x1b[?2026h" ++ output ++ "\x1b[@b\x1b[?2026l", update);
    // Without guesses, output is passed as it is.
    _ = h.keys("c", prompt_ctx);
    h.t.frame(redraw("abc"), prompt_ctx, &h.w);
    _ = h.written();
    h.t.frame("x", prompt_ctx, &h.w);
    try testing.expectEqualStrings("x", h.written());
}

test "nothing goes into a sequence or character the worker's output splits" {
    var h: Harness = .{};
    h.init(empty_prompt);
    _ = h.keys("ab", prompt_ctx);
    h.t.frame("\x1b[3", prompt_ctx, &h.w);
    try testing.expectEqualStrings("\x1b[2D\x1b[2P\x1b[3", h.written());
    try testing.expectEqualStrings("", h.keys("c", prompt_ctx));
    h.t.frame("1mx", prompt_ctx, &h.w);
    try testing.expectEqualStrings("1mx", h.written());
    var u: Harness = .{};
    u.init(empty_prompt);
    _ = u.keys("ab", prompt_ctx);
    u.t.frame("\xc3", prompt_ctx, &u.w);
    try testing.expectEqualStrings("\x1b[2D\x1b[2P\xc3", u.written());
}

test "framing never adds more than its overhead" {
    var h: Harness = .{};
    h.init(empty_prompt);
    _ = h.keys("abcdefgh", prompt_ctx);
    h.t.frame(empty_prompt, prompt_ctx, &h.w);
    try testing.expect(h.written().len - empty_prompt.len <= frame_overhead);
    // Deletions put back, and taken again.
    var m: Harness = .{};
    m.init(marked("abcd"));
    _ = m.keys("\x7f\x7f\x7f\x7fwxyz", prompt_ctx);
    const output = comptime marked("abcd");
    m.t.frame(output, prompt_ctx, &m.w);
    try testing.expect(m.written().len - output.len <= frame_overhead);
}

test "a resize waits for the next turn, as a signal handler may land mid-turn" {
    enable(80);
    defer {
        enabled = false;
        state = .{};
    }
    state.row.feed(empty_prompt, 80);
    resize(100);
    try testing.expectEqual(80, columns);
    try testing.expectEqual(7, state.row.col.?);
    drop();
    try testing.expectEqual(100, columns);
    try testing.expect(state.row.col == null);
}
