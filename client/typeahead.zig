// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0
//
// Keys typed at a remote REPL's prompt, shown as they're typed rather than a
// round trip later: up to `cap` characters, backspaces, and moves left,
// right and home, guessed at the cursor, taken back before each piece of
// the worker's output and shown again after it until its redraws show them.
// What's on screen beside them is followed in a `Row`, as the worker drew
// it; guessing stops wherever that can't be followed. A backspace or move
// left is guessed only within the input's line: after the line editor's
// `\e]133;B` mark (Julia 1.14), where the redraw put a continuation line's
// text, or failing both, within the typing guessed on the row. A move right
// is guessed only over what's known to be input, as at its end the line
// editor completes instead, and home only where the line's start is known.

const std = @import("std");
const unicode = @import("unicode.zig");

/// The most keys guessed ahead of the worker's redraws.
pub const cap = 8;
/// The widest terminal followed; a wider one isn't guessed in.
const max_cols = 512;
/// Output at least this long is bulk, followed only from its last line.
const bulk = 4096;
/// Columns kept clear at the right edge, so a guess never wraps a row.
const margin = 2;
/// More than `Typeahead.frame` adds around the output it's given.
pub const frame_overhead = 160 + 2 * (hint_cap * 3 + 16);
/// The longest completion hint followed, in columns.
const hint_cap = 64;
/// How long a key is assumed to take to be drawn, until a guess's has been timed.
const unmeasured_echo_ns = 500 * std.time.ns_per_ms;

// The keys guessed besides characters, as the line editor binds them.
const backspace = 0x7F;
const left = 0x02; // ^B, as an arrow is too
const right = 0x06; // ^F
const line_start = 0x01; // ^A: the line's start, then on again the input's
const input_start = 0x1C; // Home: the input's start; a code no key sends

// A cell's contents: a character of the Basic Multilingual Plane, or, from
// the surrogates no character uses, one of these.
const unknown = 0;
const wide_tail = 0xDFFF; // the second column of a wide character
// A character with marks joined to it, which the line editor may edit one
// code point at a time, or past the BMP: known not blank, and moved over as
// the line editor's moves skip marks, but neither typed nor deleted.
const opaque_char = 0xDFFE;

const Cells = [max_cols]u16;

// What a cell holds of `char`.
fn cellOf(char: u21) u16 {
    return if (char <= 0xFFFF and (char < 0xD800 or char > 0xDFFF)) @intCast(char) else opaque_char;
}

/// What guessing depends on beyond the keys and output it's given.
pub const Context = struct {
    at_prompt: bool, // a line editor reads the keys: the terminal raw, no code running
    width: u16, // the terminal's columns, 0 if unknown
    now_ns: u64, // on a monotonic clock
};

/// What a key does to the row, as the terminal is told it.
const Effect = union(enum) {
    insert: u21,
    delete: u21,
    move: i16,

    fn undo(e: Effect) Effect {
        return switch (e) {
            .insert => |c| .{ .delete = c },
            .delete => |c| .{ .insert = c },
            .move => |n| .{ .move = -n },
        };
    }
};

/// Keys played on a row as the line editor would: its cells, cursor, and
/// the furthest each way the cursor has been, which is input.
const Sim = struct {
    cells: Cells,
    col: u16,
    low: u16,
    reach: u16,
    // Where the line, and the input, start on the row, where known.
    line_start: ?u16,
    input_start: ?u16,
    inserts: u16 = 0, // in columns

    /// Null where the line editor would do something else, or the result
    /// isn't known.
    fn apply(s: *Sim, key: u21) ?Effect {
        const effect: Effect = switch (key) {
            backspace => blk: {
                const n = s.charBefore() orelse return null;
                const char = s.cells[s.col - n];
                if (char == opaque_char) return null;
                s.col -= n;
                std.mem.copyForwards(u16, s.cells[s.col .. max_cols - n], s.cells[s.col + n ..]);
                if (s.reach > s.col) s.reach -= n;
                break :blk .{ .delete = char };
            },
            left => .{ .move = -@as(i16, @intCast(s.charBefore() orelse return null)) },
            right => blk: {
                const n: u16 = if (s.col + 1 < max_cols and s.cells[s.col + 1] == wide_tail) 2 else 1;
                if (s.col + n > s.reach) return null;
                break :blk .{ .move = @intCast(n) };
            },
            line_start, input_start => blk: {
                const start = (if (key == line_start) s.line_start else s.input_start) orelse return null;
                break :blk .{ .move = @as(i16, @intCast(start)) - @as(i16, @intCast(s.col)) };
            },
            else => blk: {
                const n: u16 = unicode.codepointWidth(key);
                if (s.col + n >= max_cols or cellOf(key) == opaque_char) return null;
                std.mem.copyBackwards(u16, s.cells[s.col + n ..], s.cells[s.col .. max_cols - n]);
                s.cells[s.col] = cellOf(key);
                if (n == 2) s.cells[s.col + 1] = wide_tail;
                if (s.reach >= s.col) s.reach += n;
                s.inserts += n;
                break :blk .{ .insert = key };
            },
        };
        if (effect == .move) s.col = @intCast(@as(i32, s.col) + effect.move);
        if (effect == .insert) s.col += unicode.codepointWidth(effect.insert);
        s.low = @min(s.low, s.col);
        s.reach = @max(s.reach, s.col);
        return effect;
    }

    // The columns of the character before the cursor, if it's known.
    fn charBefore(s: *const Sim) ?u16 {
        if (s.col == 0) return null;
        const n: u16 = if (s.cells[s.col - 1] == wide_tail) 2 else 1;
        if (n > s.col or s.cells[s.col - n] == unknown) return null;
        return n;
    }
};

/// What the terminal is sent for effects, a run of a kind at a time.
const Out = struct {
    w: *std.Io.Writer,
    kind: ?std.meta.Tag(Effect) = null,
    cols: i32 = 0,
    text: [cap * 4]u8 = undefined,
    len: usize = 0,

    fn add(o: *Out, e: Effect) void {
        if (o.kind != std.meta.activeTag(e)) o.flush();
        o.kind = std.meta.activeTag(e);
        switch (e) {
            .insert => |c| {
                o.cols += unicode.codepointWidth(c);
                o.len += std.unicode.utf8Encode(c, o.text[o.len..]) catch 0;
            },
            .delete => |c| o.cols += unicode.codepointWidth(c),
            .move => |n| o.cols += n,
        }
    }

    fn flush(o: *Out) void {
        const n: usize = @abs(o.cols);
        if (n > 0) switch (o.kind.?) {
            .insert => {
                csi(o.w, n, '@');
                o.w.writeAll(o.text[0..o.len]) catch {};
            },
            .delete => {
                csi(o.w, n, 'D');
                csi(o.w, n, 'P');
            },
            .move => csi(o.w, n, if (o.cols < 0) 'D' else 'C'),
        };
        o.* = .{ .w = o.w };
    }
};

pub const Typeahead = struct {
    row: Row = .{},
    keys: [cap]u21 = undefined, // characters, or `backspace`, a move
    sent_ns: [cap]u64 = undefined, // when each guess went to the worker
    guessed: u8 = 0,
    // The row as the worker drew it before the guesses, which they're played
    // on from `base_col`.
    base: Cells = undefined,
    base_col: u16 = 0,
    // Where the base row's line, and the input, start, where known.
    base_line: ?u16 = null,
    base_input: ?u16 = null,
    // How far the row is known to be input: as far as the guesses the
    // worker has drawn reached, until it may have changed.
    reach: ?u16 = null,
    // Without marks: where the typing guessed on the row began, which the
    // input's start can't be past.
    typed_from: ?u16 = null,
    moves: u32 = 0, // the row's, as `reach` and `typed_from` were known
    last_key: u21 = 0, // the last sent, guessed or not, as the line editor repeats
    // The completion hint the line editor last drew at the input's end, as
    // far as the typing since has kept to it: hidden under the guesses (put
    // back as they're taken back), and what's left of it after the typing
    // guessed drawn after the cursor, for the worker's next redraw to draw.
    hint: [hint_cap]u16 = undefined,
    hint_len: u16 = 0,
    hint_hidden: bool = false,
    tail_shown: u16 = 0,
    echo_ns: u64 = 0, // the slowest the worker has lately drawn a guess, 0 until it has
    // Keys went unguessed: none is guessed until the worker has surely drawn
    // them, as a guess drawn early would be in the wrong place.
    unguessed_until_ns: u64 = 0,

    /// Shows those of `keys` that can be guessed, into `w`; any other key
    /// takes the guesses back, and stops guessing until the worker has had
    /// time to draw it.
    pub fn onKeys(self: *Typeahead, keys: []const u8, ctx: Context, w: *std.Io.Writer) void {
        self.row.typed();
        var i: usize = 0;
        while (i < keys.len) if (nextKey(keys, &i) == null) {
            self.drop(w);
            self.typed_from = null;
            self.last_key = 0;
            return self.unguessed(ctx);
        };
        i = 0;
        while (i < keys.len) {
            const key = nextKey(keys, &i).?;
            defer self.last_key = key;
            const effect = self.guess(key, ctx) orelse {
                self.removeTail(w);
                return self.unguessed(ctx);
            };
            self.removeTail(w);
            if (self.guessed == 0) self.hideHint(w);
            if (effect == .insert and self.typed_from == null) self.typed_from = self.base_col;
            self.keys[self.guessed] = key;
            self.sent_ns[self.guessed] = ctx.now_ns;
            self.guessed += 1;
            var out: Out = .{ .w = w };
            out.add(effect);
            out.flush();
            self.showTail(ctx, w);
        }
    }

    /// Before the worker's `output`: the guesses taken off the screen, which
    /// is then as the worker drew it, until `afterOutput`; unless `output`
    /// clears them itself.
    pub fn beforeOutput(self: *Typeahead, output: []const u8, w: *std.Io.Writer) void {
        if (!clearsRow(output)) return self.takeBack(w);
        self.tail_shown = 0;
        self.hint_hidden = false;
    }

    // Each guess undone, the last first, and the hint they hid put back.
    fn takeBack(self: *Typeahead, w: *std.Io.Writer) void {
        self.removeTail(w);
        defer if (self.hint_hidden) {
            drawHint(self.hint[0..self.hint_len], w);
            self.hint_hidden = false;
        };
        var effects: [cap]Effect = undefined;
        const n = self.played(&effects);
        var out: Out = .{ .w = w };
        var i = n;
        while (i > 0) {
            i -= 1;
            out.add(effects[i].undo());
        }
        out.flush();
    }

    // The guesses' effects as they show, into `effects`: an insert a
    // backspace straight after undoes left out.
    fn played(self: *const Typeahead, effects: *[cap]Effect) usize {
        var sim = self.onBase();
        var n: usize = 0;
        for (self.keys[0..self.guessed]) |key| {
            const e = sim.apply(key) orelse break;
            if (e == .delete and n > 0 and effects[n - 1] == .insert) {
                n -= 1;
            } else {
                effects[n] = e;
                n += 1;
            }
        }
        return n;
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
        if (self.row.cells() == null or self.row.moves != self.moves) self.unknown();
        self.moves = self.row.moves;
        if (self.guessed == 0) {
            self.hint_len = 0; // what's left of a hint, the output after it shows
            return;
        }
        if (self.row.marked and !self.row.input_open) return self.forget();
        const drawn = self.drawnGuesses() orelse {
            self.unknown();
            return self.forget();
        };
        self.letGo(drawn, ctx);
        if (self.guessed == 0) return self.holdTail(ctx, w);
        const s = self.replayed() orelse return self.forget();
        if (!self.allows(&s, ctx)) return self.forget();
        self.hideHint(w);
        var effects: [cap]Effect = undefined;
        var out: Out = .{ .w = w };
        for (effects[0..self.played(&effects)]) |e| out.add(e);
        out.flush();
        self.showTail(ctx, w);
    }

    // The worker's hint at the cursor taken off the screen, for the guesses
    // to be drawn in its place, its text kept.
    fn hideHint(self: *Typeahead, w: *std.Io.Writer) void {
        const col = self.row.col orelse return;
        const text = self.row.hintAt(col) orelse return;
        if (text.len > hint_cap or std.mem.findScalar(u16, text, opaque_char) != null) return;
        w.writeAll("\x1b[K") catch {};
        @memcpy(self.hint[0..text.len], text);
        self.hint_len = @intCast(text.len);
        self.hint_hidden = true;
        @memset(self.base[col..][0..text.len], ' ');
    }

    // What's left of the hint after the guesses, if they're all typing that
    // keeps to its start.
    fn tail(self: *const Typeahead) ?[]const u16 {
        const at = hintKept(self.hint[0..self.hint_len], self.keys[0..self.guessed]) orelse return null;
        return if (at < self.hint_len) self.hint[at..self.hint_len] else null;
    }

    // What's left of the hint drawn after the cursor, where it fits.
    fn showTail(self: *Typeahead, ctx: Context, w: *std.Io.Writer) void {
        const rest = self.tail() orelse return;
        const cursor = (self.replayed() orelse return).col;
        if (cursor + rest.len + margin > ctx.width) return;
        drawHint(rest, w);
        self.tail_shown = @intCast(rest.len);
    }

    fn removeTail(self: *Typeahead, w: *std.Io.Writer) void {
        if (self.tail_shown == 0) return;
        w.writeAll("\x1b[K") catch {};
        self.tail_shown = 0;
    }

    // Typing a redraw has drawn, but not yet the hint it leaves: that shown,
    // as the hint the worker is likely to draw next, until its next output.
    fn holdTail(self: *Typeahead, ctx: Context, w: *std.Io.Writer) void {
        const col = self.row.col orelse return;
        if (self.row.hintAt(col) != null or self.row.contentEnd() != col) {
            self.hint_len = 0;
            return;
        }
        self.showTail(ctx, w);
    }

    // The first `drawn.keys` guesses, as the row now shows, let go.
    fn letGo(self: *Typeahead, drawn: Drawn, ctx: Context) void {
        const n = drawn.keys;
        if (n == 0) return;
        self.timeEcho(ctx.now_ns -| self.sent_ns[n - 1]);
        // What the drawn typing leaves of the hint, if it kept to it.
        const kept = hintKept(self.hint[0..self.hint_len], self.keys[0..n]) orelse 0;
        std.mem.copyForwards(u16, self.hint[0 .. self.hint_len - kept], self.hint[kept..self.hint_len]);
        self.hint_len = if (kept > 0) self.hint_len - kept else 0;
        std.mem.copyForwards(u21, self.keys[0 .. self.guessed - n], self.keys[n..self.guessed]);
        std.mem.copyForwards(u64, self.sent_ns[0 .. self.guessed - n], self.sent_ns[n..self.guessed]);
        self.guessed -= n;
        _ = self.rebase();
        self.reach = drawn.reach;
    }

    // The row as it now is, for the guesses to be played on; false where
    // it isn't known.
    fn rebase(self: *Typeahead) bool {
        self.base = (self.row.cells() orelse return false).*;
        self.base_col = self.row.col orelse return false;
        // A continuation line's start, else the input's own, which is the
        // start of its first line.
        const l = self.row.line();
        self.base_input = if (l.start == null and self.row.marked) l.input_col else null;
        self.base_line = l.start orelse self.base_input;
        return true;
    }

    /// The worker's `output` as one update to the terminal, into `w`, which
    /// has room for `frame_overhead` more: while there are guesses, they're
    /// taken back and shown again within a synchronized update (mode 2026),
    /// so the row is never painted without them.
    pub fn frame(self: *Typeahead, output: []const u8, ctx: Context, w: *std.Io.Writer) void {
        if (self.idle()) {
            w.writeAll(output) catch {};
            return self.afterOutput(output, ctx, w);
        }
        // Followed first, to know how it ends before anything goes around it:
        // what's taken back is played on the base, not the row.
        self.row.feed(output, ctx.width);
        // Nothing may be written into the middle of the worker's own escape
        // sequence or character, which the next piece ends.
        if (self.row.parse != .ground or self.row.pending_bytes > 0) {
            self.beforeOutput(output, w);
            self.reach = null;
            self.forget();
            w.writeAll(output) catch {};
            return self.settle(ctx, w);
        }
        if (self.echoed(output)) |shown| return self.echo(output, shown, ctx, w);
        w.writeAll("\x1b[?2026h") catch {};
        self.beforeOutput(output, w);
        w.writeAll(output) catch {};
        self.settle(ctx, w);
        w.writeAll("\x1b[?2026l") catch {};
    }

    // How many guesses `output` echoes, if it's nothing but the first of
    // them, typed at the end of the row, as a line editor without a redraw
    // draws them.
    fn echoed(self: *const Typeahead, output: []const u8) ?u8 {
        if (self.hint_hidden or self.tail_shown > 0) return null;
        for (self.keys[0..self.guessed]) |key| if (!isText(key)) return null;
        var i: usize = 0;
        var n: u8 = 0;
        while (i < output.len) : (n += 1) {
            const char = unicode.decode(output[i..]) orelse return null;
            if (n == self.guessed or char.cp != self.keys[n]) return null;
            i += char.len;
        }
        const drawn = self.drawnGuesses() orelse return null;
        return if (n > 0 and drawn.keys == n) n else null;
    }

    // The cursor back to where the worker draws, its echo drawn over the
    // guesses it shows, and on past those it doesn't yet: nothing taken off
    // the screen, or put back.
    fn echo(self: *Typeahead, output: []const u8, shown: u8, ctx: Context, w: *std.Io.Writer) void {
        var all: i16 = 0;
        for (self.keys[0..self.guessed]) |key| all += unicode.codepointWidth(key);
        var rest: i16 = 0;
        for (self.keys[shown..self.guessed]) |key| rest += unicode.codepointWidth(key);
        var out: Out = .{ .w = w };
        out.add(.{ .move = -all });
        out.flush();
        w.writeAll(output) catch {};
        out.add(.{ .move = rest });
        out.flush();
        const drawn = self.drawnGuesses().?;
        self.moves = self.row.moves;
        self.letGo(drawn, ctx);
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
        self.tail_shown = 0;
        self.hint_hidden = false;
        self.unknown();
        self.forget();
    }

    fn forget(self: *Typeahead) void {
        self.guessed = 0;
        self.hint_len = 0;
    }

    /// Whether nothing of its own is on screen: no guesses, nor a hint.
    pub fn idle(self: *const Typeahead) bool {
        return self.guessed == 0 and self.tail_shown == 0;
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

    // What `key` does, played after the guesses, if it can be guessed.
    fn guess(self: *Typeahead, key: u21, ctx: Context) ?Effect {
        if (!ctx.at_prompt or ctx.now_ns < self.unguessed_until_ns or self.guessed == cap) return null;
        if (self.row.parse != .ground) return null; // mid-sequence, as output last left it
        if (self.row.marked and !self.row.input_open) return null;
        // Again, it's the input's start, which may be another row.
        if (key == line_start and self.last_key == line_start and self.row.line().start != null) return null;
        if (self.guessed == 0 and !self.rebase()) return null;
        var sim = self.replayed() orelse return null;
        const effect = sim.apply(key) orelse return null;
        return if (self.allows(&sim, ctx)) effect else null;
    }

    // The guesses played on the row before them.
    fn replayed(self: *const Typeahead) ?Sim {
        var s = self.onBase();
        for (self.keys[0..self.guessed]) |key| _ = s.apply(key) orelse return null;
        return s;
    }

    fn onBase(self: *const Typeahead) Sim {
        return .{
            .cells = self.base,
            .col = self.base_col,
            .low = self.base_col,
            .reach = @max(self.base_col, self.reach orelse 0),
            .line_start = self.base_line,
            .input_start = self.base_input,
        };
    }

    // Whether the keys `sim` played can be shown: what they insert keeps the
    // row clear of the margin, what's after the cursor pushed along with
    // them, and the cursor stays within the input's line.
    fn allows(self: *const Typeahead, s: *const Sim, ctx: Context) bool {
        if (ctx.width == 0 or ctx.width > max_cols) return false;
        const col = self.row.col orelse return false;
        const end = self.row.contentEnd() orelse return false;
        if (@max(end, col) + s.inserts + margin > ctx.width) return false;
        if (s.low >= self.base_col) return true;
        return s.low >= (self.base_line orelse self.typed_from orelse return false);
    }

    const Drawn = struct { keys: u8, reach: u16 };

    // How many of the guesses the row shows, the most it matches: its
    // cursor where they'd leave it, and its cells as they'd leave them as
    // far as they reached. Null when it matches none. What's past that, such
    // as a completion hint, isn't guessed.
    fn drawnGuesses(self: *const Typeahead) ?Drawn {
        const col = self.row.col orelse return null;
        const cells = self.row.cells() orelse return null;
        var s = self.onBase();
        var found: ?Drawn = null;
        for (0..self.guessed + 1) |k| {
            if (k > 0) _ = s.apply(self.keys[k - 1]) orelse break;
            if (col == s.col and std.mem.eql(u16, cells[0..s.reach], s.cells[0..s.reach]))
                found = .{ .keys = @intCast(k), .reach = s.reach };
        }
        return found;
    }
};

// The columns of `hint` that `keys` type, if they're all typing that keeps
// to its start.
fn hintKept(hint: []const u16, keys: []const u21) ?u16 {
    var at: u16 = 0;
    for (keys) |key| {
        if (!isText(key) or at >= hint.len or hint[at] != cellOf(key)) return null;
        at += unicode.codepointWidth(key);
    }
    return at;
}

// `cells` drawn in light black as a completion hint is, the cursor left
// where it was.
fn drawHint(cells: []const u16, w: *std.Io.Writer) void {
    w.writeAll("\x1b[90m") catch {};
    for (cells) |c| if (c != wide_tail) {
        var buf: [4]u8 = undefined;
        w.writeAll(buf[0 .. std.unicode.utf8Encode(c, &buf) catch 0]) catch {};
    };
    w.writeAll("\x1b[39m") catch {};
    csi(w, cells.len, 'D');
}

// The next key in `keys`, past it, as guessed; null for one that isn't.
fn nextKey(keys: []const u8, i: *usize) ?u21 {
    const named = [_]struct { []const u8, u21 }{
        .{ "\x7f", backspace },  .{ "\x08", backspace },  .{ "\x02", left },      .{ "\x06", right },
        .{ "\x01", line_start }, .{ "\x1b[D", left },     .{ "\x1bOD", left },    .{ "\x1b[C", right },
        .{ "\x1bOC", right },    .{ "\x1b[H", input_start }, .{ "\x1bOH", input_start }, .{ "\x1b[1~", input_start },
        .{ "\x1b[7~", input_start },
    };
    for (named) |k| if (std.mem.startsWith(u8, keys[i.*..], k[0])) {
        i.* += k[0].len;
        return k[1];
    };
    const char = unicode.decode(keys[i.*..]) orelse return null;
    i.* += char.len;
    return if (isText(char.cp)) char.cp else null;
}

// A character a key types: one that takes columns.
fn isText(key: u21) bool {
    return unicode.codepointWidth(key) > 0;
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
// they left the cursor. Erasing on from the cursor first, as a hint is
// cleared before one, changes nothing of that.
fn clearsRow(output: []const u8) bool {
    var rest = output;
    while (true) {
        rest = std.mem.cutPrefix(u8, rest, "\x1b[K") orelse std.mem.cutPrefix(u8, rest, "\x1b[0K") orelse break;
    }
    for ([_][]const u8{ "\r\x1b[K", "\r\x1b[0K", "\r\x1b[2K", "\x1b[2K\r" }) |start| {
        if (std.mem.startsWith(u8, rest, start)) return true;
    }
    return false;
}

/// The cursor's row as the worker drew it: the cursor's column, what's in
/// each cell, and each unknown once output does what isn't followed.
pub const Row = struct {
    col: ?u16 = null,
    here: Line = .{},
    // Rows counted from where the cursor started, as it moves up and down.
    y: i32 = 0,
    // The row the cursor was on as a key was last typed, which a line editor
    // redraws its input around: drawn as it draws its input down from the
    // prompt, it's kept, for when it moves back up to the cursor, and the
    // rows either side, for a move to one.
    typed_y: i32 = 0,
    kept: [3]Line = @splat(.{}),
    kept_y: ?i32 = null, // the middle's
    parse: Parse = .ground,
    param: u16 = 0, // a CSI's first parameter
    params: u8 = 0, // how many digits or separators it has had
    private: bool = false, // a CSI's `?` or other private marker
    osc: [5]u8 = undefined, // an OSC's start, as far as a mark's
    osc_len: u8 = 0,
    // A UTF-8 character begun: its bits so far, and the bytes it still needs.
    pending_char: u21 = 0,
    pending_bytes: u2 = 0,
    // The line editor's `\e]133;` marks: seen at all, and the input they
    // place, from its start (B) to its command's (C).
    marked: bool = false,
    input_open: bool = false,
    hinting: bool = false, // drawing in light black, as a completion hint is
    fresh: bool = false, // moved onto a row cleared, nothing drawn on it yet
    // The rows below the cursor's known cleared, as a line editor clears its
    // input's rows from the last up before redrawing them.
    blank_below: u8 = 0,
    // The cursor's moves to another row, counted.
    moves: u32 = 0,

    const Parse = enum { ground, escape, csi, osc, osc_escape };

    pub const Line = struct {
        cells: Cells = undefined,
        known: bool = false,
        // Where the input starts on it, from the mark's B: forgotten as it's
        // erased from its start.
        input_col: ?u16 = null,
        // Where a continuation line's text starts: on a row moved onto
        // cleared, where its first character is drawn.
        start: ?u16 = null,
        // A completion hint: where it starts, and its columns.
        hint_at: ?u16 = null,
        hint_len: u16 = 0,
    };

    /// The completion hint drawn from column `col`, if one is: what a line
    /// editor draws in light black after the input's end.
    pub fn hintAt(self: *const Row, col: u16) ?[]const u16 {
        const l = self.line();
        if (!l.known or l.hint_at != col) return null;
        return l.cells[col..][0..l.hint_len];
    }

    pub fn line(self: *const Row) *const Line {
        return &self.here;
    }

    fn edited(self: *Row) *Line {
        return &self.here;
    }

    /// A key typed on the cursor's row, which the line editor's redraws are
    /// around.
    pub fn typed(self: *Row) void {
        self.typed_y = self.y;
    }

    /// The cursor's row's cells, if they're known.
    pub fn cells(self: *const Row) ?*const Cells {
        return if (self.line().known) &self.line().cells else null;
    }

    pub fn feed(self: *Row, bytes: []const u8, width: u16) void {
        if (width == 0 or width > max_cols) {
            self.* = .{};
            return;
        }
        var rest = bytes;
        // A sequence or character the last output left open, ended first.
        while ((self.parse != .ground or self.pending_bytes > 0) and rest.len > 0) {
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
            self.pending_bytes = 0;
            self.blank_below = 0;
            self.kept_y = null;
            rest = rest[nl..];
        };
        for (rest) |byte| self.step(byte, width);
    }

    /// The column after the row's last non-blank cell, if the row is known.
    pub fn contentEnd(self: *const Row) ?u16 {
        const c = self.cells() orelse return null;
        var end: usize = max_cols;
        while (end > 0 and c[end - 1] == ' ') end -= 1;
        if (end > 0 and std.mem.findScalar(u16, c[0..end], unknown) != null) return null;
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
        if (self.pending_bytes > 0) {
            if (byte & 0xC0 != 0x80) {
                self.pending_bytes = 0;
                self.lost();
                return self.ground(byte, width);
            }
            self.pending_char = self.pending_char << 6 | (byte & 0x3F);
            self.pending_bytes -= 1;
            if (self.pending_bytes == 0) self.put(self.pending_char, width);
            return;
        }
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
            0xC2...0xF4 => {
                const len = std.unicode.utf8ByteSequenceLength(byte) catch unreachable;
                self.pending_bytes = @intCast(len - 1);
                self.pending_char = byte & (@as(u8, 0x7F) >> len);
            },
            else => self.lost(), // tabs, other controls, invalid UTF-8
        }
    }

    // `char` drawn at the cursor; one that joins the one before makes it
    // opaque.
    fn put(self: *Row, char: u21, width: u16) void {
        const n = unicode.codepointWidth(char);
        const c = self.col orelse return;
        const l = self.edited();
        if (n == 0) {
            if (!l.known) return;
            const before = c -| @as(u16, if (c >= 2 and l.cells[c - 1] == wide_tail) 2 else 1);
            if (c == 0 or l.cells[before] == unknown) return self.lost();
            l.cells[before] = opaque_char;
            return;
        }
        if (c + n > width) return self.lost(); // wrapped
        if (self.fresh) l.start = c;
        self.fresh = false;
        if (self.hinting) {
            if (l.hint_at == null or c != l.hint_at.? + l.hint_len) {
                l.hint_at = c;
                l.hint_len = 0;
            }
            l.hint_len += n;
        } else if (l.hint_at) |at| {
            if (c < at + l.hint_len and c + n > at) l.hint_at = null; // drawn over
        }
        if (l.known) {
            // Drawn over, a wide character's other half is blank.
            if (l.cells[c] == wide_tail and c > 0) l.cells[c - 1] = ' ';
            if (c + n < max_cols and l.cells[c + n] == wide_tail) l.cells[c + n] = ' ';
            l.cells[c] = cellOf(char);
            if (n == 2) l.cells[c + 1] = wide_tail;
        }
        // The last column leaves a wrap pending, which isn't followed.
        self.col = if (c + n < width) c + n else null;
    }

    fn csi(self: *Row, final: u8, width: u16) void {
        if (self.private) return; // modes such as bracketed paste: no movement
        const n = @max(self.param, 1);
        switch (final) {
            'm' => self.hinting = self.param == 90 and self.params == 0,
            'K' => self.erase(self.param),
            'J' => {
                self.erase(self.param);
                if (self.param != 1) self.blank_below = std.math.maxInt(u8); // and below
                if (self.param != 0) self.kept_y = null; // and above
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
            'A' => self.up(n),
            'B' => self.down(n),
            else => self.lost(),
        }
    }

    // Erase in line: 0 from the cursor on, 1 up to it, 2 all; known blank as
    // far as the cursor's column is.
    fn erase(self: *Row, mode: u16) void {
        const l = self.edited();
        // A hint erased at all goes whole: none is followed cut short.
        if (l.hint_at) |at| if (mode != 0 or (self.col orelse 0) < at + l.hint_len) {
            l.hint_at = null;
        };
        // The row redrawn from its start, prompt and all.
        if (mode == 2 or self.col == 0) {
            l.input_col = null;
            l.start = null;
            self.fresh = false;
        }
        if (mode == 2) return self.blank();
        const c = self.col orelse return;
        switch (mode) {
            0 => {
                if (c == 0) return self.blank();
                if (l.known) @memset(l.cells[c..], ' ');
            },
            1 => if (l.known) @memset(l.cells[0 .. c + 1], ' '),
            else => self.lost(),
        }
    }

    fn blank(self: *Row) void {
        const l = self.edited();
        l.cells = @splat(' ');
        l.known = true;
    }

    fn shift(self: *Row, n: u16, direction: enum { left, right }, width: u16) void {
        const c = self.col orelse return;
        const l = self.edited();
        l.hint_at = null;
        if (!l.known) return;
        const row = l.cells[c..width];
        const k = @min(n, row.len);
        switch (direction) {
            .right => {
                std.mem.copyBackwards(u16, row[k..], row[0 .. row.len - k]);
                @memset(row[0..k], ' ');
            },
            .left => {
                std.mem.copyForwards(u16, row[0 .. row.len - k], row[k..]);
                @memset(row[row.len - k ..], ' ');
            },
        }
    }

    // Where the cursor is, and so every row, no longer known.
    fn lost(self: *Row) void {
        self.col = null;
        self.blank_below = 0;
        self.kept_y = null;
        self.here = .{};
        self.moves +%= 1;
    }

    // Row `y`'s place among those kept, if it's one.
    fn keptAt(self: *Row, y: i32) ?*Line {
        const middle = self.kept_y orelse return null;
        if (y < middle - 1 or y > middle + 1) return null;
        return &self.kept[@intCast(y - middle + 1)];
    }

    // `n` rows up, its column kept: from a cleared row one up, that row is
    // known cleared below; onto the one kept, it's known again.
    fn up(self: *Row, n: u16) void {
        const cleared = n == 1 and self.contentEnd() == 0;
        self.blank_below = if (cleared) self.blank_below +| 1 else 0;
        self.fresh = false;
        self.moves +%= 1;
        self.y -%= n;
        self.here = if (self.keptAt(self.y)) |kept| kept.* else .{};
    }

    // `n` rows down, onto one known blank if it was cleared; the row typed
    // on, kept as it's left.
    fn down(self: *Row, n: u16) void {
        if (self.here.known and @abs(self.y -% self.typed_y) <= 1) {
            if (self.kept_y != self.typed_y) {
                self.kept = @splat(.{});
                self.kept_y = self.typed_y;
            }
            self.keptAt(self.y).?.* = self.here;
        }
        const cleared = n <= self.blank_below;
        self.blank_below = if (cleared) self.blank_below - @as(u8, @intCast(n)) else 0;
        self.moves +%= 1;
        self.y +%= n;
        self.here = .{};
        if (cleared) self.blank();
        self.fresh = cleared;
    }

    fn endOsc(self: *Row) void {
        self.parse = .ground;
        const mark = self.osc[0..self.osc_len];
        if (mark.len < 5 or !std.mem.eql(u8, mark[0..4], "133;")) return;
        self.marked = true;
        switch (mark[4]) {
            'B' => {
                self.input_open = true;
                self.edited().input_col = self.col;
            },
            'C', 'D' => {
                self.input_open = false;
                self.edited().input_col = null;
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
        if (state.idle()) {
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

// --- Tests ---

const testing = std.testing;

// What `cells` show, as UTF-8, a wide character's second column left out.
fn textOf(cells: []const u16) []const u8 {
    const S = struct {
        var buf: [max_cols * 4]u8 = undefined;
    };
    var n: usize = 0;
    for (cells) |c| {
        if (c != wide_tail) n += std.unicode.utf8Encode(if (c == opaque_char) '?' else c, S.buf[n..]) catch 0;
    }
    return S.buf[0..n];
}

const prompt_ctx: Context = .{ .at_prompt = true, .width = 80, .now_ns = 0 };

fn atMs(ms: u64) Context {
    return .{ .at_prompt = true, .width = 80, .now_ns = ms * std.time.ns_per_ms };
}

// The prompt, empty, then with `line` and the cursor after it, as Julia's
// line editor redraws them.
const empty_prompt = "\r\x1b[0K\x1b[32m\x1b[1mjulia> \x1b[0m\x1b[0m\r\x1b[7C\r\x1b[7C";

fn redraw(comptime line: []const u8) []const u8 {
    return std.fmt.comptimePrint("\r\x1b[0K\x1b[32m\x1b[1mjulia> \x1b[0m\x1b[0m\r\x1b[7C{s}\r\x1b[{d}C", .{ line, 7 + comptime columnsOf(line) });
}

// The columns `line` takes, as the line editor counts them.
fn columnsOf(comptime line: []const u8) usize {
    var n: usize = 0;
    var i: usize = 0;
    while (i < line.len) {
        const char = unicode.decode(line[i..]).?;
        n += unicode.codepointWidth(char.cp);
        i += char.len;
    }
    return n;
}

// As Julia 1.14's line editor redraws them, its prompt marked.
fn marked(comptime line: []const u8) []const u8 {
    return std.fmt.comptimePrint("\r\x1b[0K\x1b]133;A\x07\x1b[32m\x1b[1mjulia> \x1b[0m\x1b[0m\x1b]133;B\x07\r\x1b[7C{s}\r\x1b[{d}C", .{ line, 7 + comptime columnsOf(line) });
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
    try testing.expectEqualStrings("julia> 1+1", textOf(row.cells().?[0..10]));
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
    try testing.expect(row.col == null and row.cells() == null);
    row.feed(redraw("x"), 80);
    try testing.expectEqual(8, row.col.?);
    row.feed("é", 80);
    try testing.expectEqual(9, row.col.?);
    row.feed("\t", 80);
    try testing.expect(row.col == null);
    row.feed("\n", 80);
    try testing.expect(row.col.? == 0 and row.cells() == null);
    // Split mid-sequence, as output may be.
    row.feed("\r\x1b[0", 80);
    row.feed("K\x1b[3", 80);
    row.feed("2mab\x1b]0;title\x07\x1b[1D", 80);
    try testing.expectEqual(1, row.col.?);
    try testing.expectEqualStrings("ab", textOf(row.cells().?[0..2]));
}

test "a row reads the line editor's marks" {
    var row: Row = .{};
    row.feed(marked("1+1"), 80);
    try testing.expect(row.marked and row.input_open);
    try testing.expectEqual(7, row.line().input_col.?);
    try testing.expectEqual(10, row.col.?);
    // Redrawn from its start, the row's input is placed again.
    row.feed("\r\x1b[0K", 80);
    try testing.expect(row.line().input_col == null);
    row.feed("julia> \x1b]133;B\x1b\\", 80);
    try testing.expectEqual(7, row.line().input_col.?);
    row.feed("\x1b[0m\x1b]133;C\x07", 80);
    try testing.expect(!row.input_open and row.line().input_col == null);
}

test "a row follows only the line output ends on, and the last mark before it" {
    var row: Row = .{};
    row.feed(marked("1+1"), 80);
    row.feed("\x1b]133;C\x07\x1b[1m2\x1b[0m\n" ++ more_output ++ "ta\x1b[1mil", 80);
    try testing.expect(row.marked and !row.input_open);
    try testing.expectEqual(4, row.col.?);
    try testing.expect(row.cells() == null);
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
    return std.fmt.comptimePrint("\r\x1b[0K\x1b[1A\r\x1b[0K\x1b[32m\x1b[1mjulia> \x1b[0m\x1b[0m\r\x1b[7Cfoo(\n\r\x1b[7C{s}\r\x1b[{d}C", .{ last, 7 + comptime columnsOf(last) });
}

test "a row is known cleared once cleared above the cursor's, and moved onto" {
    var row: Row = .{};
    row.feed(twoRows("b"), 80);
    try testing.expectEqualStrings("       b ", textOf(row.cells().?[0..9]));
    try testing.expectEqual(8, row.col.?);
    // Moved onto a row not cleared, it isn't known.
    row.feed("\x1b[2B", 80);
    try testing.expect(row.cells() == null);
    // Erased below, every row below is cleared.
    row.feed("\r\x1b[J\n", 80);
    try testing.expectEqual(0, row.contentEnd().?);
}

test "the last row of an input over several is guessed on, back to where its line starts" {
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
    // At its start, a backspace joins it to the line before.
    try testing.expectEqualStrings("\x1b[D\x1b[P\x1b[D\x1b[P", h.keys("\x7f\x7f", atMs(1200)));
    try testing.expectEqualStrings("", h.keys("\x7f", atMs(1200)));
}

// The same, its cursor on the first row, `col` columns in: drawn down from
// the prompt, then moved up to it.
fn onFirstRow(comptime first: []const u8, comptime col: usize) []const u8 {
    return std.fmt.comptimePrint("\x1b[1B\r\x1b[0K\x1b[1A\r\x1b[0K\x1b]133;A\x07\x1b[32m\x1b[1mjulia> \x1b[0m\x1b[0m\x1b]133;B\x07\r\x1b[7C{s}\n\r\x1b[7Cbc\x1b[1A\r\x1b[{d}C", .{ first, col });
}

test "a row drawn, then moved back up to, is known again" {
    var row: Row = .{};
    row.feed(onFirstRow("foo(", 10), 80);
    try testing.expectEqualStrings("julia> foo(", textOf(row.cells().?[0..11]));
    try testing.expectEqual(10, row.col.?);
    try testing.expectEqual(7, row.line().input_col.?);
    // Further up than it drew, it isn't.
    row.feed("\x1b[1A", 80);
    try testing.expect(row.cells() == null);
}

test "the cursor's row of an input over several is guessed on, wherever it is" {
    var h: Harness = .{};
    h.init(onFirstRow("foo(", 10));
    try testing.expectEqualStrings("\x1b[@x", h.keys("x", prompt_ctx));
    try testing.expectEqualStrings("\x1b[D\x1b[P", h.keys("\x7f", prompt_ctx));
    try testing.expectEqualStrings("\x1b[D\x1b[P", h.keys("\x7f", prompt_ctx));
    try testing.expectEqualStrings("\x1b[@y", h.keys("y", prompt_ctx));
    // Drawn by the worker: let go, each, so their echo timed.
    h.output(onFirstRow("foy(", 10), atMs(50));
    _ = h.written();
    try testing.expectEqual(0, h.t.guessed);
    try testing.expectEqual(50 * std.time.ns_per_ms, h.t.echo_ns);
    // Back to the input's start, but not past it.
    try testing.expectEqualStrings("\x1b[3D", h.keys("\x1b[H", atMs(60)));
    try testing.expectEqualStrings("", h.keys("\x1b[D", atMs(60)));
}

// An input over six rows, `l0` to `l5` but row `at` reading `text`, redrawn
// with its cursor moved from row `from` to row `at`, `col` columns in, as
// Julia's line editor does: down to the last row, cleared up to the
// prompt's, drawn down, then up.
fn sixRows(comptime from: usize, comptime at: usize, comptime text: []const u8, comptime col: usize) []const u8 {
    comptime {
        @setEvalBranchQuota(100_000);
        var out: []const u8 = "";
        if (from < 5) out = out ++ std.fmt.comptimePrint("\x1b[{d}B", .{5 - from});
        for (0..5) |_| out = out ++ "\r\x1b[0K\x1b[1A";
        out = out ++ "\r\x1b[0K\x1b[32m\x1b[1mjulia> \x1b[0m\x1b[0m";
        for (0..6) |i| {
            if (i > 0) out = out ++ "\n";
            out = out ++ "\r\x1b[7C" ++ (if (i == at) text else std.fmt.comptimePrint("l{d}", .{i}));
        }
        if (at < 5) out = out ++ std.fmt.comptimePrint("\x1b[{d}A", .{5 - at});
        return out ++ std.fmt.comptimePrint("\r\x1b[{d}C", .{col});
    }
}

test "the cursor's row of a long input is guessed on, and after a move a row up or down" {
    var h: Harness = .{};
    // Last typed on the second row from the top, four up from the last.
    h.t.row.y = 1;
    h.t.row.typed_y = 1;
    h.init(comptime sixRows(1, 1, "ab", 9));
    try testing.expectEqualStrings("\x1b[@c", h.keys("c", prompt_ctx));
    h.output(comptime sixRows(1, 1, "abc", 10), atMs(50));
    _ = h.written();
    try testing.expectEqual(0, h.t.guessed);
    try testing.expectEqual(50 * std.time.ns_per_ms, h.t.echo_ns);
    // Up a row, unguessed, onto one kept: typing goes on being guessed.
    try testing.expectEqualStrings("", h.keys("\x1b[A", atMs(100)));
    h.output(comptime sixRows(1, 0, "l0", 9), atMs(150));
    _ = h.written();
    try testing.expectEqualStrings("\x1b[@x", h.keys("x", atMs(1000)));
    // Two rows on, not kept: the next key's redraw keeps it, for the keys after.
    h.output(comptime sixRows(0, 0, "l0x", 10), atMs(1050));
    _ = h.written();
    _ = h.keys("\x1b[B\x1b[B", atMs(1100));
    h.output(comptime sixRows(0, 2, "l2", 9), atMs(1150));
    _ = h.written();
    try testing.expect(h.t.row.cells() == null);
    try testing.expectEqualStrings("", h.keys("z", atMs(2000)));
    h.output(comptime sixRows(2, 2, "l2z", 10), atMs(2050));
    _ = h.written();
    try testing.expectEqualStrings("\x1b[@y", h.keys("y", atMs(3000)));
}

// As Julia's line editor draws `line` with a completion hint after it: the
// old hint cleared, the line redrawn, the hint, and the cursor back.
fn hinted(comptime line: []const u8, comptime hint: []const u8) []const u8 {
    return std.fmt.comptimePrint("\x1b[0K{s}\x1b[90m{s}\x1b[39m\x1b[{d}D", .{ comptime redraw(line), hint, hint.len });
}

test "a row knows a completion hint drawn after the cursor" {
    var row: Row = .{};
    row.feed(comptime hinted("fun", "ction"), 80);
    try testing.expectEqualStrings("ction", textOf(row.hintAt(10).?));
    try testing.expect(row.hintAt(9) == null);
    // Erased, or drawn over, it's gone.
    row.feed("\x1b[0K", 80);
    try testing.expect(row.hintAt(10) == null);
}

test "typing that keeps to a hint shows what's left of it, until the worker's own" {
    var h: Harness = .{};
    h.init(redraw("fun"));
    try testing.expectEqualStrings("\x1b[@c", h.keys("c", prompt_ctx));
    // The hint for "fun" arrives after the "c": hidden, and what "c" leaves of it shown.
    h.output(comptime hinted("fun", "ction"), prompt_ctx);
    try testing.expectEqualStrings("|\x1b[K\x1b[@c\x1b[90mtion\x1b[39m\x1b[4D", h.written());
    // Drawn without a hint yet: what's left of it held, not blinking off.
    h.output(redraw("func"), prompt_ctx);
    try testing.expectEqualStrings("|\x1b[90mtion\x1b[39m\x1b[4D", h.written());
    try testing.expect(!h.t.idle());
    // The worker's own hint replaces it.
    h.output(comptime hinted("func", "tion"), prompt_ctx);
    try testing.expectEqualStrings("|", h.written());
    try testing.expect(h.t.idle());
    // Typed on, still keeping to it.
    try testing.expectEqualStrings("\x1b[K\x1b[@t\x1b[90mion\x1b[39m\x1b[3D", h.keys("t", prompt_ctx));
    try testing.expectEqualStrings("\x1b[K\x1b[@i\x1b[90mon\x1b[39m\x1b[2D", h.keys("i", prompt_ctx));
}

test "typing that leaves a hint hides it, and taken back, it's put back" {
    var h: Harness = .{};
    h.init(comptime hinted("fun", "ction"));
    try testing.expectEqualStrings("\x1b[K\x1b[@x", h.keys("x", prompt_ctx));
    h.output("\x1b[39m", prompt_ctx);
    try testing.expectEqualStrings("\x1b[D\x1b[P\x1b[90mction\x1b[39m\x1b[5D|\x1b[K\x1b[@x", h.written());
    // A key not guessed takes it all back.
    try testing.expectEqualStrings("\x1b[D\x1b[P\x1b[90mction\x1b[39m\x1b[5D", h.keys("\t", prompt_ctx));
    try testing.expect(h.t.idle());
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

test "a row follows characters past ASCII, wide ones over two columns" {
    var row: Row = .{};
    row.feed(redraw("é日b"), 80);
    try testing.expectEqual(11, row.col.?);
    try testing.expectEqualStrings("julia> é日b", textOf(row.cells().?[0..11]));
    // Drawn over, a wide character's other half goes blank.
    row.feed("\x1b[3Dx", 80);
    try testing.expectEqualStrings("julia> éx b", textOf(row.cells().?[0..11]));
}

test "characters past ASCII are guessed, and wide ones over two columns" {
    var h: Harness = .{};
    h.init(empty_prompt);
    try testing.expectEqualStrings("\x1b[@é", h.keys("é", prompt_ctx));
    try testing.expectEqualStrings("\x1b[2@日", h.keys("日", prompt_ctx));
    h.output(redraw("é日"), prompt_ctx);
    _ = h.written();
    try testing.expectEqual(0, h.t.guessed);
    try testing.expectEqualStrings("\x1b[2D", h.keys("\x1b[D", prompt_ctx));
    try testing.expectEqualStrings("\x1b[D\x1b[P", h.keys("\x7f", prompt_ctx));
    // Taken back: the wide character's move undone, the deleted one put back.
    h.output("\x1b[39m", prompt_ctx);
    try testing.expectEqualStrings("\x1b[@é\x1b[2C|\x1b[2D\x1b[D\x1b[P", h.written());
    // A character that joins the one before isn't guessed, and takes the rest back.
    try testing.expectEqualStrings("\x1b[@é\x1b[2C", h.keys("\u{301}", prompt_ctx));
    try testing.expectEqual(0, h.t.guessed);
}

test "characters with marks joined, or past the BMP, are moved over, but not deleted" {
    var h: Harness = .{};
    h.init(marked("x\u{302}y😀"));
    try testing.expectEqual(11, h.t.row.col.?);
    try testing.expectEqualStrings("\x1b[@z", h.keys("z", prompt_ctx));
    // Back over `z`, the emoji's two columns, `y`, and `x̂`; then on over it.
    try testing.expectEqualStrings("\x1b[D\x1b[2D\x1b[D\x1b[D", h.keys("\x1b[D\x1b[D\x1b[D\x1b[D", prompt_ctx));
    try testing.expectEqualStrings("\x1b[C", h.keys("\x1b[C", prompt_ctx));
    // A backspace there might delete only the mark.
    try testing.expectEqualStrings("", h.keys("\x7f", prompt_ctx));
}

test "home is guessed where the line's start is known" {
    var h: Harness = .{};
    h.init(marked("abc"));
    try testing.expectEqualStrings("\x1b[3D", h.keys("\x1b[H", prompt_ctx));
    try testing.expectEqualStrings("\x1b[@x", h.keys("x", prompt_ctx));
    h.output(comptime marked("xabc") ++ "\x1b[3D", prompt_ctx);
    _ = h.written();
    try testing.expectEqual(0, h.t.guessed);
    // Unmarked, the input's start isn't known.
    var u: Harness = .{};
    u.init(redraw("abc"));
    try testing.expectEqualStrings("", u.keys("\x01", prompt_ctx));
    // On a continuation line, ^A goes to its start, but again, the input's.
    var m: Harness = .{};
    m.init(twoRows("bc"));
    try testing.expectEqualStrings("\x1b[2D", m.keys("\x01", prompt_ctx));
    try testing.expectEqualStrings("", m.keys("\x01", prompt_ctx));
}

test "an echo of the first guesses is drawn over them, nothing taken off" {
    var h: Harness = .{};
    h.init(empty_prompt);
    _ = h.keys("ab日", prompt_ctx);
    h.t.frame("a", prompt_ctx, &h.w);
    try testing.expectEqualStrings("\x1b[4Da\x1b[3C", h.written());
    try testing.expectEqual(2, h.t.guessed);
    h.t.frame("b日", prompt_ctx, &h.w);
    try testing.expectEqualStrings("\x1b[3Db日", h.written());
    try testing.expectEqual(0, h.t.guessed);
    // Anything else around it goes the usual way.
    _ = h.keys("c", prompt_ctx);
    h.t.frame("c\x1b[90mde\x1b[39m\x1b[2D", prompt_ctx, &h.w);
    try testing.expectEqualStrings("\x1b[?2026h\x1b[D\x1b[Pc\x1b[90mde\x1b[39m\x1b[2D\x1b[?2026l", h.written());
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

test "a redraw after clearing a hint takes nothing back first" {
    var h: Harness = .{};
    h.init(empty_prompt);
    _ = h.keys("ab", prompt_ctx);
    h.output(comptime "\x1b[0K" ++ redraw("a"), prompt_ctx);
    try testing.expectEqualStrings("|\x1b[@b", h.written());
    // A lone erase, though, is the worker's cursor's.
    h.output("\x1b[0K", prompt_ctx);
    try testing.expectEqualStrings("\x1b[D\x1b[P|\x1b[@b", h.written());
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
