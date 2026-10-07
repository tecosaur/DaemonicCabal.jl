// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0
//
// Keys typed at a remote REPL's prompt, shown as they're typed rather than a
// round trip later: up to `cap` guesses, inserted at the cursor, taken back
// before each piece of the worker's output and shown again after it until
// its redraws show them. What's on screen beside them is followed in a `Row`,
// as the worker drew it; guessing stops wherever that can't be followed.

const std = @import("std");

/// The most keys guessed ahead of the worker's redraws.
pub const cap = 4;
/// The widest terminal followed; a wider one isn't guessed in.
const max_cols = 512;
/// Columns kept clear at the right edge, so a guess never wraps a row.
const margin = 2;
/// More than `Typeahead.frame` adds around the output it's given.
pub const frame_overhead = 64;
/// How long a key is assumed to take to be drawn, until a guess's has been timed.
const unmeasured_echo_ns = 500 * std.time.ns_per_ms;

/// What guessing depends on beyond the keys and output it's given.
pub const Context = struct {
    at_prompt: bool, // a line editor reads the keys: the terminal raw, no code running
    width: u16, // the terminal's columns, 0 if unknown
    now_ns: u64, // on a monotonic clock
};

pub const Typeahead = struct {
    row: Row = .{},
    guesses: [cap]u8 = undefined,
    sent_ns: [cap]u64 = undefined, // when each guess went to the worker
    guessed: u8 = 0,
    start: u16 = 0, // the column of the first guess, as the worker draws
    echo_ns: u64 = 0, // the slowest the worker has lately drawn a guess, 0 until it has
    // Keys went unguessed: none is guessed until the worker has surely drawn
    // them, as a guess drawn early would be in the wrong place.
    unguessed_until_ns: u64 = 0,

    /// Shows those of `keys` that can be guessed, into `w`; any other key
    /// takes the guesses back, and stops guessing until the worker has had
    /// time to draw it.
    pub fn onKeys(self: *Typeahead, keys: []const u8, ctx: Context, w: *std.Io.Writer) void {
        const printable = for (keys) |key| {
            if (!isPrintable(key)) break false;
        } else keys.len > 0;
        if (!printable) {
            self.drop(w);
            self.unguessed(ctx);
            return;
        }
        for (keys) |key| {
            if (!self.canGuess(ctx)) {
                self.unguessed(ctx);
                return;
            }
            if (self.guessed == 0) self.start = self.row.col.?;
            self.guesses[self.guessed] = key;
            self.sent_ns[self.guessed] = ctx.now_ns;
            self.guessed += 1;
            w.print("\x1b[@{c}", .{key}) catch {};
        }
    }

    /// Before the worker's output: the guesses taken off the screen, which
    /// is then as the worker drew it, until `afterOutput`.
    pub fn beforeOutput(self: *const Typeahead, w: *std.Io.Writer) void {
        if (self.guessed == 0) return;
        w.print("\x1b[{d}D\x1b[{d}P", .{ self.guessed, self.guessed }) catch {};
    }

    /// After the worker's `output`: the guesses it has drawn let go, and the
    /// rest shown again, unless it drew something else.
    pub fn afterOutput(self: *Typeahead, output: []const u8, ctx: Context, w: *std.Io.Writer) void {
        self.row.feed(output, ctx.width);
        if (self.guessed == 0) return;
        const drawn = self.drawnGuesses() orelse return self.forget();
        if (drawn > 0) self.timeEcho(ctx.now_ns -| self.sent_ns[drawn - 1]);
        std.mem.copyForwards(u8, self.guesses[0 .. self.guessed - drawn], self.guesses[drawn..self.guessed]);
        std.mem.copyForwards(u64, self.sent_ns[0 .. self.guessed - drawn], self.sent_ns[drawn..self.guessed]);
        self.guessed -= drawn;
        self.start += drawn;
        if (self.guessed == 0) return;
        if (!self.fits(ctx, self.guessed)) return self.forget();
        w.print("\x1b[{d}@{s}", .{ self.guessed, self.guesses[0..self.guessed] }) catch {};
    }

    /// The worker's `output` as one update to the terminal, into `w`, which
    /// has room for `frame_overhead` more: while there are guesses, they're
    /// taken back and shown again within a synchronized update (mode 2026),
    /// so the row is never painted without them.
    pub fn frame(self: *Typeahead, output: []const u8, ctx: Context, w: *std.Io.Writer) void {
        // Nothing may be written into the middle of the worker's own escape
        // sequence or character, which the next piece ends.
        if (self.guessed > 0 and !endsBetween(self.row, output, ctx.width)) {
            self.drop(w);
            w.writeAll(output) catch {};
            self.row.feed(output, ctx.width);
            return;
        }
        const guessing = self.guessed > 0;
        if (guessing) w.writeAll("\x1b[?2026h") catch {};
        self.beforeOutput(w);
        w.writeAll(output) catch {};
        self.afterOutput(output, ctx, w);
        if (guessing) w.writeAll("\x1b[?2026l") catch {};
    }

    /// The guesses taken back, as the keys may now mean something else.
    pub fn drop(self: *Typeahead, w: *std.Io.Writer) void {
        self.beforeOutput(w);
        self.forget();
    }

    /// The row lost track of, as the terminal reflows it on a resize: what's
    /// on screen is left for the worker's next redraw.
    pub fn resized(self: *Typeahead) void {
        self.row = .{};
        self.forget();
    }

    fn forget(self: *Typeahead) void {
        self.guessed = 0;
    }

    // A key sent without a guess: its redraw comes as late as the slowest
    // guess's has, and a half again.
    fn unguessed(self: *Typeahead, ctx: Context) void {
        const echo_ns = if (self.echo_ns == 0) unmeasured_echo_ns else self.echo_ns;
        self.unguessed_until_ns = ctx.now_ns +| echo_ns +| echo_ns / 2;
    }

    // Up at once and down slowly, so that unguessed keys are waited on long
    // enough.
    fn timeEcho(self: *Typeahead, sample_ns: u64) void {
        self.echo_ns = if (sample_ns >= self.echo_ns) sample_ns else self.echo_ns - (self.echo_ns - sample_ns) / 8;
    }

    fn canGuess(self: *const Typeahead, ctx: Context) bool {
        if (!ctx.at_prompt or ctx.now_ns < self.unguessed_until_ns or self.guessed == cap) return false;
        if (self.row.parse != .ground) return false; // mid-sequence, as output last left it
        return self.fits(ctx, self.guessed + 1);
    }

    // Whether `n` guesses at the cursor keep the row clear of the margin,
    // what's after the cursor pushed along with them.
    fn fits(self: *const Typeahead, ctx: Context, n: usize) bool {
        if (ctx.width == 0 or ctx.width > max_cols) return false;
        const col = self.row.col orelse return false;
        const end = self.row.contentEnd() orelse return false;
        return @max(end, col) + n + margin <= ctx.width;
    }

    // How many guesses the worker has drawn, if its cursor and row say.
    fn drawnGuesses(self: *const Typeahead) ?u8 {
        const col = self.row.col orelse return null;
        if (col < self.start or col - self.start > self.guessed) return null;
        const drawn: u8 = @intCast(col - self.start);
        const cells = self.row.cells orelse return null;
        if (!std.mem.eql(u8, cells[self.start..col], self.guesses[0..drawn])) return null;
        return drawn;
    }
};

// Whether `output`, following what `row` has seen, ends between escape
// sequences and between UTF-8 characters.
fn endsBetween(row: Row, output: []const u8, width: u16) bool {
    var probe = row;
    probe.feed(output, width);
    if (probe.parse != .ground) return false;
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

    const Parse = enum { ground, escape, csi, osc, osc_escape };

    pub fn feed(self: *Row, bytes: []const u8, width: u16) void {
        if (width == 0 or width > max_cols) {
            self.* = .{};
            return;
        }
        for (bytes) |byte| self.step(byte, width);
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
                ']' => self.parse = .osc,
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
                0x07 => self.parse = .ground,
                0x1B => self.parse = .osc_escape,
                else => {},
            },
            .osc_escape => self.parse = if (byte == '\\') .ground else .osc,
        }
    }

    fn ground(self: *Row, byte: u8, width: u16) void {
        switch (byte) {
            0x1B => self.parse = .escape,
            '\r' => self.col = 0,
            // Onto another row, whose cells aren't known.
            '\n' => {
                self.col = 0;
                self.cells = null;
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
            'J' => self.erase(if (self.param == 2) 2 else self.param),
            'C' => if (self.col) |c| {
                self.col = @min(c +| n, width - 1);
            },
            'D' => if (self.col) |c| {
                self.col = c -| n;
            },
            'G' => self.col = @min(n - 1, width - 1),
            '@' => self.shift(n, .right, width),
            'P' => self.shift(n, .left, width),
            'A', 'B' => self.cells = null, // another row, its column kept
            else => self.lost(),
        }
    }

    // Erase in line: 0 from the cursor on, 1 up to it, 2 all; known blank as
    // far as the cursor's column is.
    fn erase(self: *Row, mode: u16) void {
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
        self.cells = null;
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
// As much as a loop reads at once, so that each read goes out in one write.
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
    var buf: [cap * 8]u8 = undefined;
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
    var rest = data;
    while (rest.len > 0) {
        const piece = rest[0..@min(rest.len, relay_piece)];
        rest = rest[piece.len..];
        var buf: [relay_piece + frame_overhead]u8 = undefined;
        var w: std.Io.Writer = .fixed(&buf);
        const pending = state.guessed;
        state.frame(piece, context(), &w);
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
    var buf: [32]u8 = undefined;
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

/// A typeahead past the empty prompt, and what it wrote.
const Harness = struct {
    t: Typeahead = .{},
    buf: [256]u8 = undefined,
    last: [256]u8 = undefined,
    w: std.Io.Writer = undefined,

    fn init(self: *Harness) void {
        self.w = .fixed(&self.buf);
        self.output(empty_prompt, prompt_ctx);
        _ = self.written();
    }

    fn keys(self: *Harness, bytes: []const u8, ctx: Context) []const u8 {
        self.t.onKeys(bytes, ctx, &self.w);
        return self.written();
    }

    // What's written around `bytes`, which itself goes to the terminal as is.
    fn output(self: *Harness, bytes: []const u8, ctx: Context) void {
        self.t.beforeOutput(&self.w);
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

test "a key typed at the prompt is shown at once, and let go as the worker draws it" {
    var h: Harness = .{};
    h.init();
    const shown = h.keys("a", prompt_ctx);
    try testing.expectEqualStrings("\x1b[@a", shown);
    h.output(redraw("a"), prompt_ctx);
    const around = h.written();
    // Taken back before the redraw, and nothing left to show after it.
    try testing.expectEqualStrings("\x1b[1D\x1b[1P|", around);
    try testing.expectEqual(0, h.t.guessed);
}

test "guesses the worker hasn't drawn yet are shown again after its redraw" {
    var h: Harness = .{};
    h.init();
    _ = h.keys("ab", prompt_ctx);
    h.output(redraw("a"), prompt_ctx);
    const around = h.written();
    try testing.expectEqualStrings("\x1b[2D\x1b[2P|\x1b[1@b", around);
    try testing.expectEqual(1, h.t.guessed);
    // One redraw answering several keys lets them all go.
    _ = h.keys("c", prompt_ctx);
    h.output(redraw("abc"), prompt_ctx);
    _ = h.written();
    try testing.expectEqual(0, h.t.guessed);
}

test "a redraw split across chunks keeps the guesses until it ends" {
    var h: Harness = .{};
    h.init();
    _ = h.keys("ab", prompt_ctx);
    const whole = redraw("a");
    const cut = std.mem.find(u8, whole, "a\r").?;
    h.output(whole[0..cut], prompt_ctx);
    const first = h.written();
    try testing.expectEqualStrings("\x1b[2D\x1b[2P|\x1b[2@ab", first);
    h.output(whole[cut..], prompt_ctx);
    const second = h.written();
    try testing.expectEqualStrings("\x1b[2D\x1b[2P|\x1b[1@b", second);
}

test "a redraw that isn't the guesses lets them go" {
    var h: Harness = .{};
    h.init();
    // `]` switches to the package prompt rather than inserting.
    _ = h.keys("]", prompt_ctx);
    h.output("\r\x1b[0K\x1b[34m\x1b[1m(@v1.13) pkg> \x1b[0m\r\x1b[14C", prompt_ctx);
    _ = h.written();
    try testing.expectEqual(0, h.t.guessed);
    // As does one drawing another character where the guess was.
    h.init();
    _ = h.keys("a", prompt_ctx);
    h.output(redraw("b"), prompt_ctx);
    const around = h.written();
    try testing.expectEqualStrings("\x1b[1D\x1b[1P|", around);
    try testing.expectEqual(0, h.t.guessed);
}

test "no more than the cap is guessed, and none after a key that wasn't" {
    var h: Harness = .{};
    h.init();
    const shown = h.keys("abcde", prompt_ctx);
    try testing.expectEqualStrings("\x1b[@a\x1b[@b\x1b[@c\x1b[@d", shown);
    // Every guess drawn, but not yet the key that wasn't.
    h.output(redraw("abcd"), atMs(1));
    _ = h.written();
    const blocked = h.keys("f", atMs(2));
    try testing.expectEqualStrings("", blocked);
}

test "another key takes the guesses back, and stops guessing until the worker draws" {
    var h: Harness = .{};
    h.init();
    _ = h.keys("ab", prompt_ctx);
    const back = h.keys("\x1b[D", prompt_ctx); // a left arrow
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
    h.init();
    _ = h.keys("a", atMs(0));
    h.output(redraw("a"), atMs(40));
    _ = h.written();
    try testing.expectEqual(40 * std.time.ns_per_ms, h.t.echo_ns);
    // A left arrow at 100 ms is surely drawn by 160.
    _ = h.keys("\x1b[D", atMs(100));
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

test "nothing is guessed away from the prompt, or near the right edge" {
    var h: Harness = .{};
    h.init();
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
    h.init();
    h.t.resized();
    const none = h.keys("a", prompt_ctx);
    try testing.expectEqualStrings("", none);
}

test "output around guesses goes out as one synchronized update" {
    var h: Harness = .{};
    h.init();
    _ = h.keys("ab", prompt_ctx);
    const output = comptime redraw("a");
    h.t.frame(output, prompt_ctx, &h.w);
    const update = h.written();
    try testing.expectEqualStrings("\x1b[?2026h\x1b[2D\x1b[2P" ++ output ++ "\x1b[1@b\x1b[?2026l", update);
    // Without guesses, output is passed as it is.
    _ = h.keys("c", prompt_ctx);
    h.t.frame(redraw("abc"), prompt_ctx, &h.w);
    _ = h.written();
    h.t.frame("x", prompt_ctx, &h.w);
    try testing.expectEqualStrings("x", h.written());
}

test "nothing goes into a sequence or character the worker's output splits" {
    var h: Harness = .{};
    h.init();
    _ = h.keys("ab", prompt_ctx);
    h.t.frame("\x1b[3", prompt_ctx, &h.w);
    try testing.expectEqualStrings("\x1b[2D\x1b[2P\x1b[3", h.written());
    try testing.expectEqualStrings("", h.keys("c", prompt_ctx));
    h.t.frame("1mx", prompt_ctx, &h.w);
    try testing.expectEqualStrings("1mx", h.written());
    var u: Harness = .{};
    u.init();
    _ = u.keys("ab", prompt_ctx);
    u.t.frame("\xc3", prompt_ctx, &u.w);
    try testing.expectEqualStrings("\x1b[2D\x1b[2P\xc3", u.written());
}

test "framing never adds more than its overhead" {
    var h: Harness = .{};
    h.init();
    _ = h.keys("abcd", prompt_ctx);
    h.t.frame(empty_prompt, prompt_ctx, &h.w);
    try testing.expect(h.written().len - empty_prompt.len <= frame_overhead);
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
