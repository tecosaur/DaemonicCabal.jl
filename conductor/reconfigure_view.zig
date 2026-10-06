// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0
//
// `--reconfigure`'s frame, drawn from a `Scene`: tabs, the focused tab's
// settings as a tree (the focused one explained beneath it), then any
// message, what's pending, and the keys.

const std = @import("std");
const Allocator = std.mem.Allocator;
const settings = @import("settings.zig");
const changes = @import("changes.zig");
const pal = @import("palette.zig");
const terminal = @import("terminal.zig");
const tui = @import("tui.zig");

const Setting = settings.Setting;
const all = settings.all;
const tabs = settings.tabs;
const hints = terminal.hints;

const max_width = 100;
const max_items = 16; // a tab's rows, headings included
const status_offset = 34; // a row's status, past its value's column
const field_cols = 16; // an edited value's field, at least
const max_value_cols = 24; // past this, a value's note isn't aligned with the rest
const field_toward_fg = 0.12; // its background, from the terminal's
const tab_toward_fg = 0.07; // an inactive tab's background, likewise

const reset = "\x1b[0m";
const dim = "\x1b[2m";
const bold = "\x1b[1m";
const heading_colour = "\x1b[1;34m";
const focus_mark = "\x1b[1;34m❯" ++ reset;
const staged_colour = "\x1b[33m";
const unsaved_colour = "\x1b[36m";
const problem_colour = "\x1b[31m";
// After a path's value, when it may not do.
const flag = " " ++ bold ++ problem_colour ++ "!\x1b[39m\x1b[22m";
const flag_cols: usize = 2;
const warning_colour = "\x1b[33m";
const number_colour = "\x1b[35m";
const choice_colour = "\x1b[34m";
const on_colour = "\x1b[32m";
const off_colour = "\x1b[31m";
const apply_colour = "\x1b[34m";

/// Colours taken from the terminal's own, where it gave them.
pub const Styles = struct {
    muted: pal.Sgr, // grey, for what explains
    field: pal.Sgr, // an edited value's background
    tab_tint: pal.Sgr, // an inactive tab's background

    pub fn of(palette: ?pal.Palette) Styles {
        const fg = if (palette) |p| p.foreground else null;
        const bg = if (palette) |p| p.background else null;
        return .{
            .muted = .muted(palette),
            .field = .blended("48", bg, fg, field_toward_fg, "\x1b[100m"),
            .tab_tint = .blended("48", bg, fg, tab_toward_fg, ""),
        };
    }
};

/// How the editor's text stands: its form, why it can't be staged, or a
/// warning it may not do.
pub const Check = struct {
    tone: enum { fine, good, warning, problem } = .fine,
    bytes: [256]u8 = undefined,
    len: usize = 0,

    pub fn set(self: *Check, tone: @FieldType(Check, "tone"), comptime fmt: []const u8, fmt_args: anytype) void {
        self.tone = tone;
        self.len = if (std.mem.print(&self.bytes, fmt, fmt_args)) |t| t.len else |_| 0;
    }

    fn text(self: *const Check) []const u8 {
        return self.bytes[0..self.len];
    }
};

/// Everything a frame shows.
pub const Scene = struct {
    state: *const changes.State,
    staged: *const changes.Staged,
    fleet: changes.Fleet,
    saving: bool, // whether there's a service to save to
    tab: usize,
    focus: usize, // a setting's index, in `tab`
    /// `placeholder`, grey while `text` is empty: what an empty field leaves.
    editor: ?struct { text: []const u8, cursor: usize, check: *const Check, placeholder: []const u8 = "" } = null,
    message: ?struct { problem: bool, text: []const u8 } = null,
    asking: bool = false, // whether to save before quitting
    /// Paths that may not do (missing, say), marked by their values.
    flagged: std.StaticBitSet(all.len) = .empty,
    styles: *const Styles,
    cols: u16,
    rows: u16,
};

/// The frame (the cursor `from` lines below its top) erased, and `last` (a
/// line or more) left in its place.
pub fn clear(gpa: Allocator, out: *std.ArrayList(u8), from: usize, last: ?[]const u8) !void {
    if (from > 0) try out.print(gpa, "\x1b[{d}F", .{from}) else try out.append(gpa, '\r');
    try out.appendSlice(gpa, "\x1b[0J");
    const text = last orelse return;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| try out.print(gpa, "{s}\r\n", .{line});
}

/// `scene` drawn over the last frame, the cursor `from` lines below its top;
/// returns how far below its own top it leaves the cursor.
pub fn draw(gpa: Allocator, out: *std.ArrayList(u8), scene: *const Scene, from: usize) !usize {
    try out.appendSlice(gpa, "\x1b[?2026h\x1b[?25l");
    if (from > 0) try out.print(gpa, "\x1b[{d}F", .{from}) else try out.append(gpa, '\r');
    try out.appendSlice(gpa, "\x1b[0J");
    var composed: std.ArrayList(u8) = .empty;
    defer composed.deinit(gpa);
    var frame: Frame = .{ .gpa = gpa, .out = &composed, .scene = scene };
    try frame.compose();
    // Cut to the screen, scrolled to keep the focus in view.
    const total = frame.line();
    const height = @min(total, @as(usize, scene.rows) -| 1);
    const top = tui.scrollTop(total, height, frame.focus_lines[0], frame.focus_lines[1]);
    try out.appendSlice(gpa, tui.lineRange(composed.items, top, height));
    const at = frame.cursor orelse {
        try out.appendSlice(gpa, "\x1b[?2026l");
        return height;
    };
    const line = at.line - top;
    // A terminal reads a cursor-up of 0 as 1.
    if (height > line) try out.print(gpa, "\x1b[{d}A", .{height - line});
    try out.print(gpa, "\x1b[{d}G\x1b[?25h\x1b[?2026l", .{at.col + 1});
    return line;
}

/// The first setting of each tab: where its focus starts.
pub const first_settings: [tabs.len]usize = blk: {
    var first: [tabs.len]usize = undefined;
    for (tabs, &first) |tab, *f| f.* = for (all, 0..) |s, i| {
        if (s.tab == tab) break i;
    } else unreachable;
    break :blk first;
};

/// The next setting of `i`'s tab down (or up) that `values` leave in use,
/// else `i`.
pub fn moveFocus(i: usize, down: bool, values: settings.Values) usize {
    var j = i;
    while (if (down) j + 1 < all.len else j > 0) {
        j = if (down) j + 1 else j - 1;
        if (all[j].tab == all[i].tab and settings.isUsed(j, values)) return j;
    }
    return i;
}

/// `i`, if `values` leave it in use, else the setting it hangs on.
pub fn usableFocus(i: usize, values: settings.Values) usize {
    if (settings.isUsed(i, values)) return i;
    const up = moveFocus(i, false, values);
    return if (up != i) up else moveFocus(i, true, values);
}

// Where values start: past the widest row's label, in every tab alike.
const value_col = blk: {
    var widest = 0;
    for (all) |s| {
        widest = @max(widest, 2 * @as(usize, s.depth) + s.label.len);
        if (s.heading) |h| widest = @max(widest, 2 * @as(usize, s.depth - 1) + h.len);
    }
    break :blk widest + 4;
};

/// A tab's row: a setting, or a heading over those after it.
const Item = struct {
    depth: u8,
    setting: ?usize, // else a heading
    label: []const u8,
};

fn itemsOf(tab: settings.Tab, buf: *[max_items]Item) []Item {
    var items: std.ArrayList(Item) = .initBuffer(buf);
    for (all, 0..) |s, i| {
        if (s.tab != tab) continue;
        if (s.heading) |heading| items.appendAssumeCapacity(.{ .depth = s.depth - 1, .setting = null, .label = heading });
        items.appendAssumeCapacity(.{ .depth = s.depth, .setting = i, .label = s.label });
    }
    return items.items;
}

/// An item among its tab's.
const Row = struct {
    items: []const Item,
    k: usize,
    values: *const changes.Values, // as the viewer would have them
    value_cols: usize, // the tab's widest value, to align what follows

    fn item(self: Row) Item {
        return self.items[self.k];
    }

    // A heading is unused with the first row under it.
    fn used(self: Row) bool {
        return settings.isUsed(self.item().setting orelse self.items[self.k + 1].setting.?, self.values);
    }
};

/// A frame being written, and where in it the terminal's cursor goes.
const Frame = struct {
    gpa: Allocator,
    out: *std.ArrayList(u8),
    scene: *const Scene,
    cursor: ?struct { line: usize, col: usize } = null,
    focus_lines: [2]usize = .{ 0, 0 }, // the focused setting and what explains it

    fn line(self: *const Frame) usize {
        return std.mem.count(u8, self.out.items, "\n");
    }

    fn write(self: *Frame, bytes: []const u8) !void {
        try self.out.appendSlice(self.gpa, bytes);
    }

    fn print(self: *Frame, comptime fmt: []const u8, fmt_args: anytype) !void {
        try self.out.print(self.gpa, fmt, fmt_args);
    }

    fn pad(self: *Frame, n: usize) !void {
        try self.out.appendNTimes(self.gpa, ' ', n);
    }

    fn muted(self: *const Frame) []const u8 {
        return self.scene.styles.muted.get();
    }

    fn compose(self: *Frame) !void {
        const scene = self.scene;
        const width = @min(@as(usize, scene.cols), max_width);
        const values = scene.staged.values(scene.state);
        try self.writeTabs(width);
        try self.writeRule(width);
        var buf: [max_items]Item = undefined;
        const items = itemsOf(tabs[scene.tab], &buf);
        for (items, 0..) |item, k| {
            const row: Row = .{ .items = items, .k = k, .values = &values, .value_cols = valueCols(items, &values, scene.flagged) };
            const focused = item.setting == scene.focus;
            if (focused) self.focus_lines[0] = self.line();
            try self.writeRow(row);
            if (focused) {
                try self.writeInfo(row, width);
                self.focus_lines[1] = self.line();
            }
        }
        try self.writeRule(width);
        try self.writeFooter(width);
    }

    fn writeRule(self: *Frame, width: usize) !void {
        try self.write(dim);
        for (0..width) |_| try self.write("─");
        try self.write(reset ++ "\n");
    }

    // Each tab a cell of its own, faintly tinted, the active one in inverse
    // video (blue), starred for a change: yellow while staged, else cyan
    // while unsaved. Too narrow for them all, the active one alone, between
    // arrows.
    fn writeTabs(self: *Frame, width: usize) !void {
        const scene = self.scene;
        var cols: usize = 0;
        for (tabs) |tab| cols += tab.title().len + 4;
        const narrow = cols > width;
        if (narrow) try self.write("‹");
        for (tabs, 0..) |tab, t| {
            const active = t == scene.tab;
            if (narrow and !active) continue;
            try self.write(if (active) "\x1b[7;1;34m" else scene.styles.tab_tint.get());
            try self.print(" {s}", .{tab.title()});
            // The active tab's star is its text's colour, sure to show.
            try self.write(switch (tabMark(scene, tab)) {
                .none => " ",
                .staged => if (active) "*" else staged_colour ++ "*\x1b[39m",
                .unsaved => if (active) "*" else unsaved_colour ++ "*\x1b[39m",
            });
            try self.write(" " ++ reset ++ " ");
        }
        if (narrow) try self.print("› {s}{d}/{d}{s}", .{ dim, scene.tab + 1, tabs.len, reset });
        try self.write("\n");
    }

    // "❯ ├ label       value  default …        status"
    fn writeRow(self: *Frame, row: Row) !void {
        const scene = self.scene;
        const item = row.item();
        const used = row.used();
        const i = item.setting orelse {
            try self.write("  " ++ dim);
            for (1..item.depth + 1) |level| try self.write(guide(row.items, row.k, level));
            return self.print(reset ++ "{s}{s}{s}" ++ reset ++ "\n", .{ if (used) "" else dim, heading_colour, item.label });
        };
        const focused = i == scene.focus;
        try self.write(if (focused) focus_mark ++ " " ++ dim else "  " ++ dim);
        for (1..item.depth + 1) |level| try self.write(guide(row.items, row.k, level));
        try self.write(reset);
        if (!used) try self.write(dim);
        try self.print("{s}{s}\x1b[22m", .{ if (focused) bold else "", item.label });
        if (!used) try self.write(dim);
        try self.pad(value_col -| (2 + 2 * @as(usize, item.depth) + item.label.len));
        const cols = if (focused and scene.editor != null) try self.writeField(i) else try self.writeValue(row, i);
        try self.pad(@max(2, status_offset -| cols));
        try self.writeStatus(i, used);
        try self.write(reset ++ "\n");
    }

    // The value, coloured by its state or else its kind, then its default
    // and, staged, what it was, in grey. Returns the columns used.
    fn writeValue(self: *Frame, row: Row, i: usize) !usize {
        const scene = self.scene;
        const s = &all[i];
        const value = row.values[i];
        const staged = scene.staged.has(i);
        const applied = scene.state.applied[i];
        const used = row.used();
        var buf: [128]u8 = undefined;
        const shown = settings.display(s, value, &buf);
        const colour = if (!used)
            ""
        else if (staged)
            staged_colour
        else if (scene.state.isUnsaved(i))
            unsaved_colour
        else if (value == null and s.default == null)
            self.muted()
        else
            kindColour(s, value orelse s.default.?);
        try self.print("{s}{s}\x1b[39m", .{ colour, shown });
        const flagged = scene.flagged.isSet(i);
        if (flagged) try self.write(flag);
        const shown_cols = tui.textWidth(shown) + if (flagged) flag_cols else 0;
        const note_at = @max(shown_cols, row.value_cols);
        var note_buf: [192]u8 = undefined;
        var note = std.Io.Writer.fixed(&note_buf);
        const at_default = changes.alike(i, value, null);
        // Being the default is marked fainter than a default it differs from.
        const marked = s.effect != .fixed and at_default and s.default != null;
        // Staged away from the default, it was the default: "was default 1".
        const was_default = staged and !at_default and s.default != null and changes.alike(i, applied, null);
        if (staged and !was_default) {
            var was: [128]u8 = undefined;
            note.print("was {s} · ", .{settings.display(s, applied, &was)}) catch {};
        }
        if (s.effect == .fixed or marked) {} else if (s.default) |d| {
            var default_buf: [128]u8 = undefined;
            note.print("{s}default {s}", .{ if (was_default) "was " else "", settings.display(s, d, &default_buf) }) catch {};
        } else if (value != null) note.print("unset: {s}", .{s.unset}) catch {};
        const text = note.buffered();
        const cols = tui.textWidth(text) + if (marked) "default".len else 0;
        if (cols == 0) return shown_cols;
        try self.pad(note_at - shown_cols);
        try self.print("  {s}{s}{s}\x1b[39m", .{ if (used) self.muted() else "", text, if (marked) dim ++ "default\x1b[22m" else "" });
        if (!used) try self.write(dim);
        return note_at + 2 + cols;
    }

    // The value being typed on a faint background, red while it doesn't
    // parse, with the terminal's cursor in it. Returns the columns used.
    fn writeField(self: *Frame, i: usize) !usize {
        const e = self.scene.editor.?;
        var buf: [256]u8 = undefined;
        const valid = if (settings.normalise(&all[i], e.text, &buf)) |_| true else |_| false;
        const shown = if (e.text.len == 0) e.placeholder else e.text;
        // Padded a cell either side; the cursor past the end takes the right one.
        try self.print("{s} {s}{s}", .{ self.scene.styles.field.get(), if (e.text.len == 0) self.muted() else if (valid) "" else problem_colour, shown });
        const text_cols = 1 + tui.textWidth(shown);
        const cols = @max(field_cols, text_cols + 1);
        try self.pad(cols - text_cols);
        try self.write(reset);
        self.cursor = .{ .line = self.line(), .col = value_col + 1 + tui.textWidth(e.text[0..e.cursor]) };
        if (!settings.steps(all[i].kind)) return cols;
        try self.print("  " ++ bold ++ "↑↓\x1b[22m {s}adjust value" ++ reset, .{self.muted()});
        return cols + 2 + comptime tui.textWidth("↑↓ adjust value");
    }

    fn writeStatus(self: *Frame, i: usize, used: bool) !void {
        const scene = self.scene;
        const state = scene.state;
        var buf: [3][]const u8 = undefined;
        var parts: std.ArrayList([]const u8) = .initBuffer(&buf);
        if (scene.staged.has(i)) {
            parts.appendAssumeCapacity(staged_colour ++ "staged");
        } else if (state.isUnsaved(i)) {
            parts.appendAssumeCapacity(unsaved_colour ++ "unsaved");
        }
        if (state.awaitsRestart(i)) {
            parts.appendAssumeCapacity("on restart");
        } else if (changes.isMissed(state, scene.fleet, i)) {
            parts.appendAssumeCapacity("new workers");
        }
        if (!used) parts.appendAssumeCapacity("unused");
        for (parts.items, 0..) |part, p| {
            if (p > 0) try self.print("{s} · ", .{self.muted()});
            try self.print("{s}{s}" ++ reset, .{ self.muted(), part });
        }
    }

    // Beneath the focused setting, in grey, as its tree goes on: while it's
    // typed, how the value stands; what it does; and, unused, why.
    fn writeInfo(self: *Frame, row: Row, width: usize) !void {
        const item = row.item();
        const s = &all[item.setting.?];
        var indent_buf: [64]u8 = undefined;
        var indent = std.Io.Writer.fixed(&indent_buf);
        indent.writeAll("  " ++ dim) catch {};
        for (1..item.depth + 1) |level| indent.writeAll(if (moreAt(row.items, row.k, level)) "│ " else "  ") catch {};
        const children = row.k + 1 < row.items.len and row.items[row.k + 1].depth > item.depth;
        indent.writeAll(if (children) "│ " else "  ") catch {};
        indent.writeAll(reset) catch {};
        const indent_cols = 4 + 2 * @as(usize, item.depth);
        const text_width = width -| indent_cols;
        // Kept while editing, empty too, so the rows don't shift as it comes and goes.
        if (self.scene.editor) |e| if (e.check.len > 0) {
            const colour = switch (e.check.tone) {
                .fine => self.muted(),
                .good => on_colour,
                .warning => warning_colour,
                .problem => problem_colour,
            };
            if (indent_cols <= value_col and value_col + tui.textWidth(e.check.text()) <= width) {
                try self.write(indent.buffered());
                try self.pad(value_col - indent_cols);
                try self.print("{s}{s}" ++ reset ++ "\n", .{ colour, e.check.text() });
            } else try self.writeWrapped(e.check.text(), text_width, indent.buffered(), colour);
        } else try self.print("{s}" ++ reset ++ "\n", .{indent.buffered()});
        try self.writeWrapped(s.about, text_width, indent.buffered(), self.muted());
    }

    // Each line after `indent`, in `style`.
    fn writeWrapped(self: *Frame, text: []const u8, width: usize, indent: []const u8, style: []const u8) !void {
        var words = std.mem.tokenizeScalar(u8, text, ' ');
        var cols: usize = 0;
        while (words.next()) |word| {
            const len = tui.textWidth(word);
            if (cols > 0 and cols + 1 + len > width) {
                try self.write(reset ++ "\n");
                cols = 0;
            }
            if (cols == 0) try self.print("{s}{s}", .{ indent, style }) else try self.write(" ");
            try self.write(word);
            cols += len + @intFromBool(cols > 0);
        }
        try self.write(reset ++ "\n");
    }

    // A message, then what's pending, then the keys, or the question on
    // quitting.
    fn writeFooter(self: *Frame, width: usize) !void {
        const scene = self.scene;
        const p = changes.pending(scene.state, scene.staged, scene.fleet, scene.saving);
        if (scene.message) |message| {
            var it = std.mem.splitScalar(u8, message.text, '\n');
            while (it.next()) |line_text| try self.writeWrapped(line_text, width -| 2, "  ", if (message.problem) problem_colour else "");
        }
        if (p.staged + p.unsaved + p.restart + p.workers > 0) try self.writeCounts(p);
        try self.write("  ");
        if (scene.asking) {
            if (p.staged > 0) try self.print(apply_colour ++ "apply" ++ reset ++ " {d}{s}", .{ p.staged, if (p.saving) " and " else "? " });
            if (p.saving) try self.print("save {d}? ", .{p.after});
            try self.write("\x1b[1;32my" ++ reset ++ dim ++ "/" ++ reset ++ "\x1b[1;31mn" ++ reset ++ dim ++ " · " ++ comptime hints(&.{.{ "Esc", "stay" }}));
        } else if (scene.editor != null) {
            try self.write(comptime hints(&.{ .{ "⏎", "stage" }, .{ "Esc", "cancel" } }));
        } else {
            const i = scene.focus;
            const can = changes.actions(scene.state, scene.staged, p, i);
            try self.writeHints(&.{
                .{ .key = "←→", .action = "tab" },
                .{ .key = "↑↓", .action = "setting" },
                .{ .key = "⏎", .action = "edit", .applies = all[i].effect != .fixed },
                .{ .key = "d", .action = "default", .applies = can.default },
                .{ .key = "u", .action = "undo", .applies = can.undo },
                .{ .key = "a", .action = "apply", .applies = can.apply },
                .{ .key = "w", .action = "save", .applies = can.save },
                .{ .key = "q", .action = "quit" },
            });
        }
        try self.write(reset ++ "\n");
    }

    // "2 changes staged · 1 unsaved": the first count names what it counts.
    fn writeCounts(self: *Frame, p: changes.Pending) !void {
        try self.write("  ");
        const counts = [_]struct { usize, []const u8, []const u8 }{
            .{ p.staged, staged_colour, "staged" },
            .{ p.unsaved, unsaved_colour, "unsaved" },
            .{ p.restart, "", "awaiting restart" },
            .{ p.workers, "", "only for new workers" },
        };
        var first = true;
        for (counts) |count| {
            if (count[0] == 0) continue;
            if (!first) try self.write(dim ++ " · " ++ reset);
            const noun = if (!first) "" else if (count[0] == 1) " change" else " changes";
            first = false;
            try self.print("{s}{d}" ++ reset ++ "{s} {s}", .{ count[1], count[0], noun, count[2] });
        }
        if (p.retirable) try self.write(comptime dim ++ ": " ++ hints(&.{.{ "r", "retires the idle ones" }}) ++ reset);
        try self.write("\n");
    }

    const Hint = struct { key: []const u8, action: []const u8, applies: bool = true };

    // As `terminal.hints`, a key that doesn't apply now greyed like its action.
    fn writeHints(self: *Frame, pairs: []const Hint) !void {
        for (pairs, 0..) |hint, n| {
            if (n > 0) try self.write(reset ++ dim ++ " · ");
            if (hint.applies)
                try self.print(reset ++ bold ++ "{s}" ++ reset ++ dim ++ " {s}", .{ hint.key, hint.action })
            else
                try self.print(reset ++ dim ++ "{s}{s} {s}", .{ self.muted(), hint.key, hint.action });
        }
    }
};

fn tabMark(scene: *const Scene, tab: settings.Tab) enum { none, staged, unsaved } {
    var unsaved = false;
    for (all, 0..) |s, i| {
        if (s.tab != tab) continue;
        if (scene.staged.has(i)) return .staged;
        unsaved = unsaved or scene.state.isUnsaved(i);
    }
    return if (unsaved) .unsaved else .none;
}

// The widest value shown among `items`, those past `max_value_cols` aside.
fn valueCols(items: []const Item, values: *const changes.Values, flagged: std.StaticBitSet(all.len)) usize {
    var widest: usize = 0;
    for (items) |item| {
        const i = item.setting orelse continue;
        var buf: [128]u8 = undefined;
        const cols = tui.textWidth(settings.display(&all[i], values[i], &buf)) + if (flagged.isSet(i)) flag_cols else 0;
        if (cols <= max_value_cols) widest = @max(widest, cols);
    }
    return widest;
}

fn kindColour(s: *const Setting, value: []const u8) []const u8 {
    return switch (s.kind) {
        .count, .seconds, .bytes, .share, .percent, .ports, .threads => number_colour,
        .flag => if (settings.isOn(value)) on_colour else off_colour,
        // A yes or no is a flag in all but name.
        .choice => if (settings.parseFlag(value)) |on| (if (on) on_colour else off_colour) else choice_colour,
        .path, .text => "",
    };
}

// "├ " or "╰ " at the item's own level; above it, "│ " where an ancestor
// has more to come.
fn guide(items: []const Item, k: usize, level: usize) []const u8 {
    const own = level == items[k].depth;
    const more = moreAt(items, k, level);
    return if (own) (if (more) "├ " else "╰ ") else if (more) "│ " else "  ";
}

// Whether a later item sits at `level` before the tree leaves it.
fn moreAt(items: []const Item, k: usize, level: usize) bool {
    return for (items[k + 1 ..]) |later| {
        if (later.depth < level) break false;
        if (later.depth == level) break true;
    } else false;
}

// --- Tests ---

const testing = std.testing;

// The frame's text, its escape sequences left out.
fn drawnText(scene: *const Scene) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);
    _ = try draw(testing.allocator, &out, scene, 0);
    var plain: std.ArrayList(u8) = .empty;
    errdefer plain.deinit(testing.allocator);
    var i: usize = 0;
    while (i < out.items.len) {
        if (out.items[i] == 0x1b) {
            i += 1;
            while (i < out.items.len and !std.ascii.isAlphabetic(out.items[i])) i += 1;
            i += 1;
            continue;
        }
        try plain.append(testing.allocator, out.items[i]);
        i += 1;
    }
    return plain.toOwnedSlice(testing.allocator);
}

fn sceneOf(state: *const changes.State, staged: *const changes.Staged, styles: *const Styles, tab: usize, focus: usize) Scene {
    return .{ .state = state, .staged = staged, .fleet = .{}, .saving = true, .tab = tab, .focus = focus, .styles = styles, .cols = 100, .rows = 50 };
}

test "a staged change shows what it was, and the footer counts it" {
    const gpa = testing.allocator;
    var env = std.process.Environ.Map.init(gpa);
    defer env.deinit();
    var state = try changes.State.init(gpa, &env, null);
    defer state.deinit(gpa);
    var staged: changes.Staged = .{};
    defer staged.deinit(gpa);
    const revise = Setting.index("JULIA_DAEMON_REVISE");
    try staged.stage(gpa, &state, revise, "yes");
    const styles = Styles.of(null);
    const scene = sceneOf(&state, &staged, &styles, 1, revise);
    const text = try drawnText(&scene);
    defer gpa.free(text);
    try testing.expect(std.mem.find(u8, text, "❯ Revise") != null);
    try testing.expect(std.mem.find(u8, text, "yes") != null);
    try testing.expect(std.mem.find(u8, text, "was default no") != null);
    try testing.expect(std.mem.find(u8, text, "1 change staged") != null);
    try testing.expect(std.mem.find(u8, text, "Sessions*") != null);
}

test "keys that would do nothing are greyed" {
    const gpa = testing.allocator;
    var env = std.process.Environ.Map.init(gpa);
    defer env.deinit();
    var state = try changes.State.init(gpa, &env, null);
    defer state.deinit(gpa);
    var staged: changes.Staged = .{};
    defer staged.deinit(gpa);
    const styles = Styles.of(null);
    var scene = sceneOf(&state, &staged, &styles, 0, 0);
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    _ = try draw(gpa, &out, &scene, 0);
    // Nothing to apply or save: greyed, not bold.
    try testing.expect(std.mem.find(u8, out.items, bold ++ "a" ++ reset) == null);
    try testing.expect(std.mem.find(u8, out.items, "\x1b[90ma apply") != null);
    try staged.stage(gpa, &state, 0, "2");
    scene = sceneOf(&state, &staged, &styles, 0, 0);
    out.clearRetainingCapacity();
    _ = try draw(gpa, &out, &scene, 0);
    try testing.expect(std.mem.find(u8, out.items, bold ++ "a" ++ reset) != null);
}

test "a change workers missed is marked on its row" {
    const gpa = testing.allocator;
    var env = std.process.Environ.Map.init(gpa);
    defer env.deinit();
    var state = try changes.State.init(gpa, &env, null);
    defer state.deinit(gpa);
    var staged: changes.Staged = .{};
    defer staged.deinit(gpa);
    const revise = Setting.index("JULIA_DAEMON_REVISE");
    try staged.stage(gpa, &state, revise, "yes");
    _ = try state.apply(gpa, &staged);
    state.workers_changed_ns = 10;
    const styles = Styles.of(null);
    var scene = sceneOf(&state, &staged, &styles, 1, revise);
    scene.fleet = .{ .oldest_spawn_ns = 5, .idle_stale = true };
    const text = try drawnText(&scene);
    defer gpa.free(text);
    try testing.expect(std.mem.find(u8, text, "unsaved · new workers") != null);
    try testing.expect(std.mem.find(u8, text, "1 change unsaved · 1 only for new workers: r retires the idle ones") != null);
}

test "a frame taller than the terminal scrolls to keep its focus" {
    const gpa = testing.allocator;
    var env = std.process.Environ.Map.init(gpa);
    defer env.deinit();
    var state = try changes.State.init(gpa, &env, null);
    defer state.deinit(gpa);
    var staged: changes.Staged = .{};
    defer staged.deinit(gpa);
    const styles = Styles.of(null);
    const high = Setting.index("JULIA_DAEMON_MEMFREE_HIGH"); // the memory tab's last
    const check: Check = .{};
    var scene = sceneOf(&state, &staged, &styles, 3, high);
    scene.rows = 8;
    scene.editor = .{ .text = "20%", .cursor = 1, .check = &check };
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    const cursor_line = try draw(gpa, &out, &scene, 0);
    const text = try drawnText(&scene);
    defer gpa.free(text);
    try testing.expectEqual(@as(usize, 7), std.mem.count(u8, text, "\n"));
    try testing.expect(std.mem.find(u8, text, "❯") != null and std.mem.find(u8, text, "eased above") != null);
    // The cursor's line is the focused row's, among those shown.
    var lines = std.mem.splitScalar(u8, text, '\n');
    for (0..cursor_line) |_| _ = lines.next();
    try testing.expect(std.mem.find(u8, lines.next().?, "eased above") != null);
}

test "the editor's cursor is placed past wide characters' two columns" {
    const gpa = testing.allocator;
    var env = std.process.Environ.Map.init(gpa);
    defer env.deinit();
    var state = try changes.State.init(gpa, &env, null);
    defer state.deinit(gpa);
    var staged: changes.Staged = .{};
    defer staged.deinit(gpa);
    const styles = Styles.of(null);
    const args = Setting.index("JULIA_DAEMON_WORKER_ARGS");
    const check: Check = .{};
    var scene = sceneOf(&state, &staged, &styles, 0, args);
    scene.editor = .{ .text = "世界x", .cursor = "世界".len, .check = &check };
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    _ = try draw(gpa, &out, &scene, 0);
    var expected: [16]u8 = undefined;
    // Past the field's padding cell, then two columns each: column `value_col + 6`, 1-based.
    try testing.expect(std.mem.find(u8, out.items, try std.mem.print(&expected, "\x1b[{d}G", .{value_col + 6})) != null);
}

test "a field pads its text by a cell either side, however long" {
    const gpa = testing.allocator;
    var env = std.process.Environ.Map.init(gpa);
    defer env.deinit();
    var state = try changes.State.init(gpa, &env, null);
    defer state.deinit(gpa);
    var staged: changes.Staged = .{};
    defer staged.deinit(gpa);
    const styles = Styles.of(null);
    const args = Setting.index("JULIA_DAEMON_WORKER_ARGS");
    const check: Check = .{};
    var scene = sceneOf(&state, &staged, &styles, 0, args);
    const text = "--threads=4 --heap-size-hint=2G";
    scene.editor = .{ .text = text, .cursor = 0, .check = &check };
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    _ = try draw(gpa, &out, &scene, 0);
    try testing.expect(std.mem.find(u8, out.items, " " ++ text ++ " " ++ reset) != null);
}

test "a terminal a row high gets no cursor-up of 0, which moves one" {
    const gpa = testing.allocator;
    var env = std.process.Environ.Map.init(gpa);
    defer env.deinit();
    var state = try changes.State.init(gpa, &env, null);
    defer state.deinit(gpa);
    var staged: changes.Staged = .{};
    defer staged.deinit(gpa);
    const styles = Styles.of(null);
    const args = Setting.index("JULIA_DAEMON_WORKER_ARGS");
    const check: Check = .{};
    var scene = sceneOf(&state, &staged, &styles, 0, args);
    scene.rows = 1;
    scene.editor = .{ .text = "-O3", .cursor = 1, .check = &check };
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    try testing.expectEqual(@as(usize, 0), try draw(gpa, &out, &scene, 0));
    try testing.expect(std.mem.find(u8, out.items, "\x1b[0A") == null);
}

test "a flagged path is marked after its value" {
    const gpa = testing.allocator;
    var env = std.process.Environ.Map.init(gpa);
    defer env.deinit();
    var state = try changes.State.init(gpa, &env, null);
    defer state.deinit(gpa);
    var staged: changes.Staged = .{};
    defer staged.deinit(gpa);
    const executable = Setting.index("JULIA_DAEMON_WORKER_EXECUTABLE");
    try staged.stage(gpa, &state, executable, "/gone/julia");
    const styles = Styles.of(null);
    var scene = sceneOf(&state, &staged, &styles, @intFromEnum(all[executable].tab), executable);
    const unflagged = try drawnText(&scene);
    defer gpa.free(unflagged);
    try testing.expect(std.mem.find(u8, unflagged, "/gone/julia !") == null);
    scene.flagged.set(executable);
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    _ = try draw(gpa, &out, &scene, 0);
    try testing.expect(std.mem.find(u8, out.items, "/gone/julia" ++ "\x1b[39m" ++ flag) != null);
    const flagged = try drawnText(&scene);
    defer gpa.free(flagged);
    const at = std.mem.find(u8, flagged, "/gone/julia !").?;
    const line_end = std.mem.findScalarPos(u8, flagged, at, '\n').?;
    try testing.expect(std.mem.find(u8, flagged[at..line_end], "was default julia") != null);
}

test "an empty field shows, greyed, what it leaves" {
    const gpa = testing.allocator;
    var env = std.process.Environ.Map.init(gpa);
    defer env.deinit();
    var state = try changes.State.init(gpa, &env, null);
    defer state.deinit(gpa);
    var staged: changes.Staged = .{};
    defer staged.deinit(gpa);
    const limit = Setting.index("JULIA_DAEMON_SANDBOX_MAX_MEMORY");
    const styles = Styles.of(null);
    var check: Check = .{};
    var scene = sceneOf(&state, &staged, &styles, @intFromEnum(all[limit].tab), limit);
    scene.editor = .{ .text = "", .cursor = 0, .check = &check, .placeholder = "62G" };
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    _ = try draw(gpa, &out, &scene, 0);
    // A cell in, as typed text would be.
    const greyed = try std.mem.concat(gpa, u8, &.{ styles.field.get(), " ", styles.muted.get(), "62G" });
    defer gpa.free(greyed);
    try testing.expect(std.mem.find(u8, out.items, greyed) != null);
    // Typed over, it's gone.
    scene.editor = .{ .text = "4G", .cursor = 2, .check = &check, .placeholder = "62G" };
    out.clearRetainingCapacity();
    _ = try draw(gpa, &out, &scene, 0);
    try testing.expect(std.mem.find(u8, out.items, "62G") == null);
}

test "an editor's check line stays, empty or not" {
    const gpa = testing.allocator;
    var env = std.process.Environ.Map.init(gpa);
    defer env.deinit();
    var state = try changes.State.init(gpa, &env, null);
    defer state.deinit(gpa);
    var staged: changes.Staged = .{};
    defer staged.deinit(gpa);
    const limit = Setting.index("JULIA_DAEMON_SANDBOX_MAX_MEMORY");
    const styles = Styles.of(null);
    var scene = sceneOf(&state, &staged, &styles, @intFromEnum(all[limit].tab), limit);
    var said: Check = .{};
    said.set(.fine, "Unset: no limit.", .{});
    const silent: Check = .{};
    scene.editor = .{ .text = "", .cursor = 0, .check = &said };
    const with_check = try drawnText(&scene);
    defer gpa.free(with_check);
    scene.editor = .{ .text = "4G", .cursor = 2, .check = &silent };
    const without = try drawnText(&scene);
    defer gpa.free(without);
    try testing.expectEqual(std.mem.count(u8, with_check, "\n"), std.mem.count(u8, without, "\n"));
}

test "focus passes over the settings the others leave unused" {
    var values: [all.len]?[]const u8 = @splat(null);
    const server = Setting.index("JULIA_DAEMON_SERVER");
    const ports = Setting.index("JULIA_DAEMON_PORTS");
    const runtime = Setting.index("JULIA_DAEMON_RUNTIME");
    try testing.expectEqual(runtime, moveFocus(server, true, &values));
    try testing.expectEqual(server, moveFocus(runtime, false, &values));
    values[server] = "tcp://localhost:9345";
    try testing.expectEqual(ports, moveFocus(server, true, &values));
    try testing.expectEqual(ports, moveFocus(runtime, false, &values));
    // Pressure off, nothing below it in its tab is reachable.
    const pressure = Setting.index("JULIA_DAEMON_MEMORY_PRESSURE");
    values[pressure] = "0";
    try testing.expectEqual(pressure, moveFocus(pressure, true, &values));
}

test "focus on a setting left unused moves to the one it hangs on" {
    var values: [all.len]?[]const u8 = @splat(null);
    const server = Setting.index("JULIA_DAEMON_SERVER");
    const ports = Setting.index("JULIA_DAEMON_PORTS");
    try testing.expectEqual(server, usableFocus(ports, &values));
    try testing.expectEqual(server, usableFocus(server, &values));
    values[server] = "tcp://localhost:9345";
    try testing.expectEqual(ports, usableFocus(ports, &values));
    const pressure = Setting.index("JULIA_DAEMON_MEMORY_PRESSURE");
    values[pressure] = "0";
    try testing.expectEqual(pressure, usableFocus(Setting.index("JULIA_DAEMON_MEMFREE_HIGH"), &values));
}

test "every tab's first setting is used whatever the others hold" {
    for (first_settings) |i| try testing.expect(all[i].used == null);
}

test "an editor's check sits under its field when it fits, else wraps from the tree" {
    const gpa = testing.allocator;
    var env = std.process.Environ.Map.init(gpa);
    defer env.deinit();
    var state = try changes.State.init(gpa, &env, null);
    defer state.deinit(gpa);
    var staged: changes.Staged = .{};
    defer staged.deinit(gpa);
    const server = Setting.index("JULIA_DAEMON_SERVER");
    const styles = Styles.of(null);
    var scene = sceneOf(&state, &staged, &styles, @intFromEnum(all[server].tab), server);
    // The column `needle` starts at, on the line holding it.
    const columnOf = struct {
        fn of(text: []const u8, needle: []const u8) usize {
            const at = std.mem.find(u8, text, needle).?;
            const line_start = if (std.mem.findScalarLast(u8, text[0..at], '\n')) |nl| nl + 1 else 0;
            return tui.textWidth(text[line_start..at]);
        }
    }.of;
    var check: Check = .{};
    check.set(.warning, "Port 9591 is in use.", .{});
    scene.editor = .{ .text = "tcp://0.0.0.0:9591", .cursor = 0, .check = &check };
    const fits = try drawnText(&scene);
    defer gpa.free(fits);
    try testing.expectEqual(value_col, columnOf(fits, "Port 9591"));
    check.set(.warning, "This says rather more than the space beside the field could hold, so it wraps.", .{});
    const wraps = try drawnText(&scene);
    defer gpa.free(wraps);
    try testing.expectEqual(4, columnOf(wraps, "This says"));
}
