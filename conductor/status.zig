// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0
//
// `juliaclient --status` report: a tree of the conductor's worker pool grouped
// host → projects → workers → clients (plus sandboxed and reserve groups),
// rendered as styled text (color when the client is a TTY) or JSON.

const std = @import("std");
const main = @import("main.zig");
const platform = @import("platform/main.zig");
const config = @import("config.zig");
const worker = @import("worker.zig");
const argspec = @import("args.zig");
const pal = @import("palette.zig");

const Conductor = main.Conductor;
const Worker = worker.Worker;

// Minimal append-only sink over an owned byte buffer. Zig 0.16's ArrayList has
// no generic `.writer()`, so this adapter exposes the few writer methods the
// formatter needs while keeping `try w.print(...)` call sites unchanged.
const Writer = struct {
    list: *std.ArrayList(u8),
    gpa: std.mem.Allocator,
    fn writeAll(self: Writer, bytes: []const u8) !void {
        try self.list.appendSlice(self.gpa, bytes);
    }
    fn writeByte(self: Writer, byte: u8) !void {
        try self.list.append(self.gpa, byte);
    }
    fn writeByteNTimes(self: Writer, byte: u8, n: usize) !void {
        try self.list.appendNTimes(self.gpa, byte, n);
    }
    fn print(self: Writer, comptime fmt: []const u8, args: anytype) !void {
        try self.list.print(self.gpa, fmt, args);
    }
};

/// How to render a report. `format` is the `--status=<value>` argument ("json"
/// → machine output, else the styled tree); `tty` enables ANSI styling;
/// `palette`, when the client answered the colour probe, drives truecolor
/// gradients (else flat 8-color).
pub const Options = struct {
    format: ?[]const u8 = null,
    tty: bool = false,
    palette: ?*const pal.Palette = null,
};

/// A rendered report. `bytes` is caller-owned; `lines` counts newlines, for the
/// live view's cursor-up redraw.
pub const Report = struct {
    bytes: []u8,
    lines: usize,
};

/// Render the report at the current time. Caller owns `Report.bytes`.
pub fn render(c: *Conductor, opts: Options) !Report {
    return renderAt(c, opts, c.currentTime());
}

// Render against an explicit reference time; the standalone test harness has no
// live `Io` clock.
pub fn renderAt(c: *Conductor, opts: Options, now: i64) !Report {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(c.allocator);
    const w = Writer{ .list = &buf, .gpa = c.allocator };
    if (opts.format != null and std.mem.eql(u8, opts.format.?, "json")) {
        try renderJson(c, w, now);
    } else {
        const tints: ?Tints = if (opts.palette) |p| .{ .palette = p } else null;
        try renderTree(c, w, Style{ .enabled = opts.tty }, tints, now);
    }
    const lines = std.mem.count(u8, buf.items, "\n");
    return .{ .bytes = try buf.toOwnedSlice(c.allocator), .lines = lines };
}

// --- Styling -----------------------------------------------------------------

// 8-color ANSI so the user's terminal theme governs the exact hues.
const ansi = struct {
    const reset = "\x1b[0m";
    const bold = "\x1b[1m";
    const dim = "\x1b[2m";
    const red = "\x1b[31m";
    const green = "\x1b[32m";
    const yellow = "\x1b[33m";
    const blue = "\x1b[34m";
    const cyan = "\x1b[36m";
};

// A styling sink that emits ANSI codes only when enabled; otherwise the text
// passes through unstyled, so piped output stays plain but aligned.
const Style = struct {
    enabled: bool,
    fn open(self: Style, w: Writer, comptime codes: []const u8) !void {
        if (self.enabled) try w.writeAll(codes);
    }
    fn close(self: Style, w: Writer) !void {
        if (self.enabled) try w.writeAll(ansi.reset);
    }
    // Write `text` wrapped in `codes`, resetting after.
    fn wrap(self: Style, w: Writer, comptime codes: []const u8, text: []const u8) !void {
        try self.open(w, codes);
        try w.writeAll(text);
        try self.close(w);
    }
};

// --- Gradients ----------------------------------------------------------------

// Each stat ramps between two anchor colours as its value moves 0→1. An anchor
// is a palette role — an ANSI slot (resolved from the probed terminal palette,
// so it tracks the user's theme, with a muted fallback) or the default
// foreground. Stat → (t=0 anchor → t=1 anchor):
//   mem      green → red       (t = mem / memCeiling)
//   cpu      blue  → magenta   (t = cpu% / 100)
//   cull     fg    → yellow    (t = 1 − remaining/budget; near expiry → yellow)
//   activity fg   → cyan       (t = activity value in [0,1])
const Tint = enum { mem, cpu, cull, activity };

// A gradient anchor: a soft neutral (fg pulled toward bg, muted on any theme),
// or an ANSI slot with the fallback used when the terminal didn't report it.
const Anchor = union(enum) {
    muted,
    slot: struct { idx: usize, fallback: pal.Rgb },
};
const MUTED_TOWARD_BG = 0.45;
const FALLBACK_MUTED = pal.Rgb.init(0x80, 0x80, 0x80);
fn anslot(idx: usize, fb: pal.Rgb) Anchor {
    return .{ .slot = .{ .idx = idx, .fallback = fb } };
}
const red = anslot(1, pal.Rgb.init(0xc8, 0x3c, 0x3c));
const green = anslot(2, pal.Rgb.init(0x3c, 0xc8, 0x50));
const yellow = anslot(3, pal.Rgb.init(0xc8, 0xa0, 0x3c));
const blue = anslot(4, pal.Rgb.init(0x50, 0x78, 0xd0));
const magenta = anslot(5, pal.Rgb.init(0xc0, 0x50, 0xc0));
const cyan = anslot(6, pal.Rgb.init(0x40, 0xb0, 0xb8));
// The (t=0, t=1) anchor pair for each stat, indexed by Tint.
const anchors = std.enums.directEnumArray(Tint, [2]Anchor, 0, .{
    .mem = .{ green, red },
    .cpu = .{ blue, magenta },
    .cull = .{ .muted, yellow },
    .activity = .{ .muted, cyan },
});

// The probed palette for one render, used to resolve gradient anchors. Present
// only when the client is a truecolor TTY that answered the colour probe;
// otherwise null and stats fall back to the flat 8-color styling.
const Tints = struct {
    palette: *const pal.Palette,

    fn resolve(self: Tints, anchor: Anchor) pal.Rgb {
        return switch (anchor) {
            .muted => if (self.palette.foreground) |fg|
                if (self.palette.background) |bg| pal.blend(fg, bg, MUTED_TOWARD_BG) else fg
            else
                FALLBACK_MUTED,
            .slot => |a| pal.slot(self.palette, a.idx, a.fallback),
        };
    }

    // Open the truecolor fg SGR for `tint` at fraction `t`. Caller resets.
    fn open(self: Tints, w: Writer, tint: Tint, t: f64) !void {
        const a = anchors[@intFromEnum(tint)];
        var buf: [pal.sgr_fg_len]u8 = undefined;
        try w.writeAll(pal.sgrFg(pal.blend(self.resolve(a[0]), self.resolve(a[1]), t), &buf));
    }
};

// Per-render invariants threaded through the tree alongside (c, s, now): the
// resolved gradient anchors (null without a truecolor probe) and the footprint the
// gradient treats as fully "hot" — see memCeiling.
const Ctx = struct {
    tints: ?Tints,
    mem_ceiling: u64,
};

// The gradient anchors to use, present only when styling is on AND the terminal
// answered the colour probe. Sites that would otherwise emit a flat ANSI colour
// branch on this to decide between a truecolor ramp and their plain fallback.
fn gradientTints(s: Style, ctx: Ctx) ?Tints {
    return if (s.enabled) ctx.tints else null;
}

// --- Health ------------------------------------------------------------------

const Health = enum { healthy, pinging, unresponsive, inactive };

fn workerHealth(c: *Conductor, wk: *const Worker, now: i64) Health {
    if (wk.active_clients == 0) return .inactive;
    if (wk.ping_pending) {
        const waited: u64 = @intCast(@max(0, now - wk.last_pinged));
        return if (waited >= c.cfg.ping_timeout) .unresponsive else .pinging;
    }
    return .healthy;
}

// The leading "●"/"◌" dot, colored by health (solid for active, hollow grey for
// inactive). The glyph alone distinguishes states when styling is disabled.
fn writeHealthDot(s: Style, w: Writer, health: Health) !void {
    switch (health) {
        .healthy => try s.wrap(w, ansi.green, "●"),
        .pinging => try s.wrap(w, ansi.yellow, "●"),
        .unresponsive => try s.wrap(w, ansi.red, "●"),
        .inactive => try s.wrap(w, ansi.dim, "◌"),
    }
}

// --- Value formatting --------------------------------------------------------

fn writeBytes(w: Writer, bytes: u64) !void {
    const units = [_][]const u8{ "B", "K", "M", "G", "T" };
    var v: f64 = @floatFromInt(bytes);
    var u: usize = 0;
    while (v >= 1024 and u + 1 < units.len) : (u += 1) v /= 1024;
    if (u == 0)
        try w.print("{d}{s}", .{ bytes, units[u] })
    else
        try w.print("{d:.0}{s}", .{ v, units[u] });
}

// Compact duration: "8s", "41m", "2h14m", "3d2h".
fn writeDuration(w: Writer, total_seconds: i64) !void {
    var buf: [16]u8 = undefined;
    try w.writeAll(formatDuration(&buf, total_seconds));
}

// `writeDuration` left-padded to a fixed width (e.g. the uptime column), so the
// stats after it align. Over-width values print unpadded.
fn writeDurationPadded(w: Writer, total_seconds: i64, width: usize) !void {
    var buf: [16]u8 = undefined;
    const d = formatDuration(&buf, total_seconds);
    if (d.len < width) try w.writeByteNTimes(' ', width - d.len);
    try w.writeAll(d);
}

// Like formatDuration but second-precise under 10min, where a cull countdown's
// final minutes are worth watching tick down ("9m02s", "47s").
fn formatCountdown(buf: *[16]u8, total_seconds: i64) []const u8 {
    const s: u64 = @intCast(@max(0, total_seconds));
    if (s >= 600) return formatDuration(buf, total_seconds);
    return if (s < 60)
        std.fmt.bufPrint(buf, "{d}s", .{s}) catch unreachable
    else
        std.fmt.bufPrint(buf, "{d}m{d:0>2}s", .{ s / 60, s % 60 }) catch unreachable;
}

fn formatDuration(buf: *[16]u8, total_seconds: i64) []const u8 {
    const s: u64 = @intCast(@max(0, total_seconds));
    return if (s < 60)
        std.fmt.bufPrint(buf, "{d}s", .{s}) catch unreachable
    else if (s < 3600)
        std.fmt.bufPrint(buf, "{d}m", .{s / 60}) catch unreachable
    else if (s < 86400) blk: {
        const h = s / 3600;
        const m = (s % 3600) / 60;
        break :blk if (m == 0) std.fmt.bufPrint(buf, "{d}h", .{h}) catch unreachable else std.fmt.bufPrint(buf, "{d}h{d}m", .{ h, m }) catch unreachable;
    } else blk: {
        const d = s / 86400;
        const h = (s % 86400) / 3600;
        break :blk if (h == 0) std.fmt.bufPrint(buf, "{d}d", .{d}) catch unreachable else std.fmt.bufPrint(buf, "{d}d{d}h", .{ d, h }) catch unreachable;
    };
}

// Contract a leading home-directory prefix to "~".
fn contractHome(path: []const u8, home: []const u8) []const u8 {
    if (home.len == 0 or !std.mem.startsWith(u8, path, home)) return path;
    return path[home.len..]; // caller re-prepends "~"
}

// --- Tree rendering ----------------------------------------------------------

const indent = "  ";

fn renderTree(c: *Conductor, w: Writer, s: Style, tints: ?Tints, now: i64) !void {
    const ctx = Ctx{ .tints = tints, .mem_ceiling = memCeiling(c) };
    const have_sandboxed = anySandboxed(c);
    var printed_any = false;
    // Host group: real projects with non-sandboxed workers. The "host" header
    // only appears when there are also sandboxed workers to contrast against.
    if (have_sandboxed) try writeGroupHeader(w, s, "host");
    var it = c.workers.iterator();
    while (it.next()) |entry| {
        if (entry.value_ptr.items.len == 0) continue;
        if (entry.value_ptr.items[0].sandboxed) continue;
        if (printed_any) try w.writeByte('\n');
        try renderProject(c, w, s, ctx, entry.value_ptr.items, entry.key_ptr.*, now, have_sandboxed);
        printed_any = true;
    }
    // Sandboxed group: workers listed directly, no project sub-grouping.
    if (have_sandboxed) {
        try w.writeByte('\n');
        try writeGroupHeader(w, s, "◆ sandboxed");
        const total = countSandboxed(c);
        var seen: usize = 0;
        var sit = c.workers.iterator();
        while (sit.next()) |entry| {
            for (entry.value_ptr.items) |wk| {
                if (!wk.sandboxed) continue;
                seen += 1;
                try renderWorker(c, w, s, ctx, wk, entry.key_ptr.*, now, false, seen == total);
                printed_any = true;
            }
        }
    }
    // Reserve group: the warm spare, no project, no clients.
    if (c.reserve) |r| {
        try w.writeByte('\n');
        try writeGroupHeader(w, s, "◇ reserve");
        try renderWorker(c, w, s, ctx, r, null, now, false, true);
        printed_any = true;
    }
    if (!printed_any) {
        try s.wrap(w, ansi.dim, "No workers running.\n");
    }
    try renderFooter(c, w, s, now);
}

fn writeGroupHeader(w: Writer, s: Style, label: []const u8) !void {
    try w.writeAll(indent);
    try s.wrap(w, ansi.dim, label);
    try w.writeByte('\n');
}

// A project header: "  basename · parent/", with the basename in bold blue and
// the parent path dimmed. A pooled-RSS total is appended only when the project
// has multiple workers (with one worker its line already shows the figure).
// When the whole project is inactive the header is dimmed too. Without styling,
// the full path is printed plainly.
fn renderProject(c: *Conductor, w: Writer, s: Style, ctx: Ctx, workers: []const *Worker, key: []const u8, now: i64, nested: bool) !void {
    const all_inactive = for (workers) |wk| {
        if (wk.active_clients > 0) break false;
    } else true;
    const path = workers[0].project orelse "";
    const pad = if (nested) indent ++ indent else indent;
    try w.writeAll(pad);
    if (path.len == 0) {
        // No project: a worker running in the default (global) environment.
        try s.wrap(w, ansi.bold ++ ansi.blue, "@");
        try w.writeByte(' ');
        try s.wrap(w, ansi.dim, "(default environment)");
    } else if (s.enabled) {
        const shown = contractHome(path, c.cfg.host_home);
        const tilde = shown.ptr != path.ptr;
        const slash = std.mem.lastIndexOfScalar(u8, shown, '/');
        const basename = if (slash) |i| shown[i + 1 ..] else shown;
        const parent = if (slash) |i| shown[0 .. i + 1] else "";
        if (all_inactive)
            try s.wrap(w, ansi.dim, basename)
        else
            try s.wrap(w, ansi.bold ++ ansi.blue, basename);
        if (parent.len > 0 or tilde) {
            try s.open(w, ansi.dim);
            try w.writeAll(" · ");
            if (tilde) try w.writeByte('~');
            try w.writeAll(parent);
            try s.close(w);
        }
    } else {
        try w.writeAll(path);
    }
    if (workers.len > 1) {
        const pooled = groupMem(workers);
        if (pooled > 0) {
            try s.open(w, ansi.dim);
            try w.writeAll("  ");
            try writeBytes(w, pooled);
            try w.writeAll(" pooled");
            try s.close(w);
        }
    }
    try w.writeByte('\n');
    for (workers, 0..) |wk, i| {
        try renderWorker(c, w, s, ctx, wk, key, now, nested, i == workers.len - 1);
    }
}

// A worker line: "  ├─ ● #6  [label] v1.11 (interactive)  up 12m  490M  2%  <state>".
// Inactive workers (and the reserve) render entirely dim; the state slot shows
// the idle duration and the cull countdown.
// The identity+descriptor column is padded to this visible width so the stat
// columns (uptime, RSS, CPU) line up regardless of label/version/mode length.
const id_column_width = 26;

fn renderWorker(c: *Conductor, w: Writer, s: Style, ctx: Ctx, wk: *Worker, key: ?[]const u8, now: i64, nested: bool, is_last: bool) !void {
    const health = workerHealth(c, wk, now);
    const dim_line = health == .inactive;
    const pad = if (nested) indent ++ indent else indent;
    try w.writeAll(pad);
    try s.wrap(w, ansi.dim, if (is_last) "╰─ " else "├─ ");
    try writeHealthDot(s, w, health);
    try w.writeByte(' ');
    // Inactive workers render uniformly dim: a single dim span with no inner
    // resets. Active workers style each segment (id bold, label cyan, …).
    const id_text = idStr(wk.id);
    var col: usize = 1 + id_text.len; // visible width written so far in this column
    if (dim_line) {
        try s.open(w, ansi.dim);
        try w.print("#{s}", .{id_text});
        if (wk.session_label) |label| {
            try w.print(" [{s}]", .{label});
            col += 3 + label.len;
        }
    } else {
        try s.wrap(w, ansi.dim, "#");
        try s.wrap(w, ansi.bold, id_text);
        if (wk.session_label) |label| {
            try w.writeByte(' ');
            try s.wrap(w, ansi.dim, "[");
            try s.wrap(w, ansi.cyan, label);
            try s.wrap(w, ansi.dim, "]");
            col += 3 + label.len;
        }
    }
    if (wk.julia_channel) |ch| {
        try w.writeByte(' ');
        col += 1 + try writeChannel(w, ch);
    }
    if (wk.interactive) {
        try w.writeAll(" (interactive)");
        col += 14;
    }
    if (try argspec.renderThreads(c.allocator, wk.threads)) |t| {
        defer c.allocator.free(t);
        try w.print(" (threads={s})", .{t});
        col += 11 + t.len;
    }
    if (wk.sandboxed) {
        try w.writeAll(" (remote)");
        col += 9;
    }
    // Pad the identity column so the stats align, then uptime, RSS, CPU%.
    if (col < id_column_width) try w.writeByteNTimes(' ', id_column_width - col);
    if (!dim_line) try s.open(w, ansi.dim);
    try w.writeAll(" up ");
    if (!dim_line) try s.close(w);
    try writeDurationPadded(w, now - wk.created_at, 5);
    // Mem + CPU% gradients (green→red vs the pool's hottest, blue→magenta vs 100%);
    // dim/plain without a palette. mem==0 means unmeasured, so both are suppressed.
    if (wk.mem > 0) {
        try w.writeAll("  ");
        const t = if (ctx.mem_ceiling > 0)
            @as(f64, @floatFromInt(wk.mem)) / @as(f64, @floatFromInt(ctx.mem_ceiling))
        else
            0;
        const styled = try openStat(w, s, ctx, dim_line, .mem, t);
        try writeBytes(w, wk.mem);
        try closeStat(w, s, dim_line, styled);
        const pct = wk.cpu.util * 100;
        try w.writeAll("  ");
        const cpu_styled = try openStat(w, s, ctx, dim_line, .cpu, @min(1.0, wk.cpu.util));
        try w.print("{d:.0}%", .{pct});
        try closeStat(w, s, dim_line, cpu_styled);
    }
    // Activity (fg→cyan) sits right after CPU% on every worker — so the column
    // aligns across active and idle lines — shown only under pressure eviction.
    const showed_activity = c.pressure_monitor.active();
    if (showed_activity) try writeActivity(c, w, s, ctx, wk, key, now, dim_line);
    // State slot for inactive workers / reserve: idle + cull countdown.
    if (health == .inactive) try writeIdleState(c, w, s, ctx, wk, key, now, showed_activity);
    if (dim_line) try s.close(w);
    try w.writeByte('\n');
    if (health != .inactive) try renderClients(c, w, s, wk, now, nested, is_last);
}

// Open styling for a stat value (RSS/CPU); pair with `closeStat`. With a probed
// palette the value gets a truecolor ramp at `t_frac`, kept dim on an idle line
// so it reads as muted. Without a palette: an idle value inherits the line's dim
// span (returns false, no close needed); an active value is dimmed to mark it.
fn openStat(w: Writer, s: Style, ctx: Ctx, dim_line: bool, tint: Tint, t_frac: f64) !bool {
    if (gradientTints(s, ctx)) |t| {
        if (dim_line) try s.open(w, ansi.dim);
        try t.open(w, tint, t_frac);
        return true;
    }
    if (dim_line) return false; // inherit the worker line's dim span
    try s.open(w, ansi.dim);
    return true;
}

// Close an `openStat` span: reset, then restore the line's dim span if this was
// an idle worker (whose remaining segments still expect dim).
fn closeStat(w: Writer, s: Style, dim_line: bool, styled: bool) !void {
    if (!styled) return;
    try s.close(w);
    if (dim_line) try s.open(w, ansi.dim);
}

// "  idle 41m · culls in 1h19m" (activity, when shown, precedes this — see
// renderWorker). Within the line's dim span; the cull countdown breaks out for
// urgency (muted→yellow gradient, else amber/red steps) then restores dim. The
// reserve reads "ready"/"warming".
fn writeIdleState(c: *Conductor, w: Writer, s: Style, ctx: Ctx, wk: *const Worker, key: ?[]const u8, now: i64, after_activity: bool) !void {
    const is_reserve = c.reserve == wk;
    // " · " continues the activity segment; "   " starts a fresh column gap.
    try w.writeAll(if (after_activity) " · " else "   ");
    if (is_reserve) {
        // Reserve is TTL-exempt (findExpired skips it); no cull countdown.
        try w.writeAll(if (wk.ping_pending) "warming" else "ready");
        return;
    }
    try w.writeAll("idle ");
    try writeDuration(w, now - wk.last_active);
    // Countdown to the worker's activity-scaled budget, not a flat max_ttl.
    if (c.cfg.max_ttl > 0) {
        const budget: i64 = @intCast(c.idleBudget(wk, key orelse ""));
        try w.writeAll(" · culls in ");
        try writeCullCountdown(w, s, ctx, budget - (now - wk.last_active), @intCast(c.cfg.max_ttl));
    }
}

// " · activity 0.42", muted→cyan as it climbs. `in_dim` restores the worker
// line's dim span afterward (idle workers); active workers pass false.
fn writeActivity(c: *Conductor, w: Writer, s: Style, ctx: Ctx, wk: *const Worker, key: ?[]const u8, now: i64, in_dim: bool) !void {
    const activity = c.workerActivity(wk, key, now);
    try w.writeAll(" · activity ");
    if (gradientTints(s, ctx)) |t| {
        if (in_dim) try s.open(w, ansi.reset);
        // Ease-out: low activity still gains visible colour quickly.
        const warmth = 1.0 - (1.0 - activity) * (1.0 - activity);
        try t.open(w, .activity, warmth);
        try w.print("{d:.2}", .{activity});
        try s.close(w);
        if (in_dim) try s.open(w, ansi.dim);
    } else {
        try w.print("{d:.2}", .{activity});
    }
}

// The cull countdown, breaking out of and then restoring the line's dim span.
// With a palette it ramps muted→yellow against `color_budget` (max_ttl, so equal
// time-left reads alike across workers); else discrete amber/red. ≤60s bolds.
fn writeCullCountdown(w: Writer, s: Style, ctx: Ctx, remaining: i64, color_budget: i64) !void {
    var buf: [16]u8 = undefined;
    const text = formatCountdown(&buf, remaining);
    const imminent = remaining <= 60;
    if (gradientTints(s, ctx)) |t| {
        const frac = 1.0 - @as(f64, @floatFromInt(@max(0, remaining))) / @as(f64, @floatFromInt(@max(1, color_budget)));
        // Ease-in: hold neutral while there's time, sharpen toward yellow near cull.
        const warmth = 2.0 - @sqrt(4.0 - 3.0 * frac * frac);
        try s.open(w, ansi.reset);
        if (imminent) try s.open(w, ansi.bold);
        try t.open(w, .cull, warmth);
        try w.writeAll(text);
        try s.open(w, ansi.dim);
    } else if (imminent) {
        try s.open(w, ansi.reset ++ ansi.bold ++ ansi.red);
        try w.writeAll(text);
        try s.open(w, ansi.dim);
    } else if (remaining <= 300) {
        try s.open(w, ansi.reset ++ ansi.yellow);
        try w.writeAll(text);
        try s.open(w, ansi.dim);
    } else {
        try w.writeAll(text);
    }
}

// Client leaves under a worker. The branch carries a "│" down past the worker
// line when that worker has later siblings, so the tree stays connected.
fn renderClients(c: *Conductor, w: Writer, s: Style, wk: *const Worker, now: i64, nested: bool, worker_last: bool) !void {
    const base = if (nested) indent ++ indent else indent;
    const total = countClients(c, wk);
    var seen: usize = 0;
    var it = c.active_clients.iterator();
    while (it.next()) |entry| {
        if (entry.value_ptr.worker != wk) continue;
        const info = entry.value_ptr;
        seen += 1;
        try w.writeAll(base);
        try s.open(w, ansi.dim);
        try w.writeAll(if (worker_last) "   " else "│  ");
        try w.writeAll(if (seen == total) "   ╰─ " else "   ├─ ");
        try s.wrap(w, ansi.dim, "Client ");
        try w.print("{d}", .{entry.key_ptr.*});
        var name_buf: [64]u8 = undefined;
        if (platform.getParentName(@intCast(entry.key_ptr.*), &name_buf)) |name| {
            try w.print(" ({s})", .{name});
        }
        const attached_s = @divTrunc(now * 1_000_000 - info.start_time_us, 1_000_000);
        try s.open(w, ansi.dim);
        try w.writeAll(" · attached ");
        try writeDuration(w, attached_s);
        try s.close(w);
        try w.writeByte('\n');
    }
}

fn countClients(c: *Conductor, wk: *const Worker) usize {
    var n: usize = 0;
    var it = c.active_clients.iterator();
    while (it.next()) |entry| {
        if (entry.value_ptr.worker == wk) n += 1;
    }
    return n;
}

fn renderFooter(c: *Conductor, w: Writer, s: Style, now: i64) !void {
    _ = now;
    var active_workers: usize = 0;
    var total_clients: usize = 0;
    var total_mem: u64 = 0;
    var has_reserve = false;
    var it = c.workers.iterator();
    while (it.next()) |entry| {
        for (entry.value_ptr.items) |wk| {
            active_workers += 1;
            total_clients += wk.active_clients;
            total_mem += wk.mem;
        }
    }
    if (c.reserve) |r| {
        has_reserve = true;
        total_mem += r.mem;
    }
    try w.writeByte('\n');
    try s.open(w, ansi.dim);
    try w.writeAll(indent ++ ("─" ** 58) ++ "\n");
    try w.writeAll(indent);
    try w.print("{d} workers", .{active_workers});
    if (has_reserve) try w.writeAll(" · 1 reserve");
    try w.print(" · {d} clients", .{total_clients});
    if (total_mem > 0) {
        try w.writeAll(" · ");
        try writeBytes(w, total_mem);
    }
    try w.writeByte('\n');
    try w.writeAll(indent);
    try w.print("worker args  {s}\n", .{c.cfg.worker_args});
    try s.close(w);
}

// --- Helpers -----------------------------------------------------------------

fn anySandboxed(c: *Conductor) bool {
    var it = c.workers.iterator();
    while (it.next()) |entry| {
        for (entry.value_ptr.items) |wk| if (wk.sandboxed) return true;
    }
    return false;
}

fn countSandboxed(c: *Conductor) usize {
    var n: usize = 0;
    var it = c.workers.iterator();
    while (it.next()) |entry| {
        for (entry.value_ptr.items) |wk| if (wk.sandboxed) {
            n += 1;
        };
    }
    return n;
}

fn groupMem(workers: []const *Worker) u64 {
    var total: u64 = 0;
    for (workers) |wk| total += wk.mem;
    return total;
}

// The RSS the gradient paints as fully "hot" (red). Two anchors, whichever is
// larger:
//   - the heaviest worker in the pool, so the busiest worker always reads hot;
//   - each worker's padded fair share of system memory, total / (n + 8), so a
//     pool of uniform light workers spreads across the ramp instead of all
//     pegging red. The +8 keeps the slice sane when n is tiny (n=1 over 32G →
//     ~3.6G, not 32G).
// Zero only when nothing is measurable, which disables the RSS ramp.
fn memCeiling(c: *Conductor) u64 {
    var max_mem: u64 = 0;
    var n: u64 = 0;
    var it = c.workers.iterator();
    while (it.next()) |entry| {
        for (entry.value_ptr.items) |wk| {
            n += 1;
            max_mem = @max(max_mem, wk.mem);
        }
    }
    if (c.reserve) |r| {
        n += 1;
        max_mem = @max(max_mem, r.mem);
    }
    const fair_share: u64 = if (platform.readMemInfo()) |m| m.total / (n + 8) else 0;
    return @max(max_mem, fair_share);
}

// A juliaup channel ("+1.11", "+release") shown as a version ("v1.11") or a
// named channel in parentheses ("(release)"). Returns the visible width written.
fn writeChannel(w: Writer, channel: []const u8) !usize {
    const ch = if (channel.len > 0 and channel[0] == '+') channel[1..] else channel;
    if (ch.len > 0 and std.ascii.isDigit(ch[0])) {
        try w.print("v{s}", .{ch});
        return 1 + ch.len;
    }
    try w.print("({s})", .{ch});
    return 2 + ch.len;
}

threadlocal var id_buf: [16]u8 = undefined;
fn idStr(id: u32) []const u8 {
    return std.fmt.bufPrint(&id_buf, "{d}", .{id}) catch "?";
}

// --- JSON --------------------------------------------------------------------

fn renderJson(c: *Conductor, w: Writer, now: i64) !void {
    var total_clients: usize = 0;
    var total_mem: u64 = 0;
    var worker_count: usize = 0;
    try w.writeAll("{\"workers\":[");
    var first = true;
    var it = c.workers.iterator();
    while (it.next()) |entry| {
        for (entry.value_ptr.items) |wk| {
            if (!first) try w.writeByte(',');
            first = false;
            worker_count += 1;
            total_clients += wk.active_clients;
            total_mem += try writeWorkerJson(c, w, wk, entry.key_ptr.*, now);
        }
    }
    try w.writeAll("],\"reserve\":");
    if (c.reserve) |r| {
        total_mem += try writeWorkerJson(c, w, r, null, now);
    } else {
        try w.writeAll("null");
    }
    try w.print(",\"totals\":{{\"workers\":{d},\"reserve\":{d},\"clients\":{d},\"mem_bytes\":{d}}}", .{
        worker_count, @as(u8, if (c.reserve != null) 1 else 0), total_clients, total_mem,
    });
    try w.print(",\"max_ttl\":{d},\"min_ttl\":{d},\"label_ttl\":{d},\"worker_args\":", .{ c.cfg.max_ttl, c.cfg.min_ttl, c.cfg.label_ttl });
    try writeJsonString(w, c.cfg.worker_args);
    try w.print(",\"pressure\":{{\"source\":\"{s}\",\"under_pressure\":{}}}", .{ @tagName(c.pressure_monitor.source), c.pressure_monitor.under_pressure });
    try w.writeByte('}');
}

// Emit one worker object; returns its footprint so the caller can total it.
fn writeWorkerJson(c: *Conductor, w: Writer, wk: *const Worker, key: ?[]const u8, now: i64) !u64 {
    const pid = platform.getChildPid(wk.process);
    const stats = platform.getProcessStats(pid);
    const mem = if (stats) |st| st.mem_bytes else 0;
    try w.print("{{\"id\":{d},\"pid\":{d},\"project\":", .{ wk.id, pid });
    try writeJsonStringOrNull(w, wk.project);
    try w.writeAll(",\"channel\":");
    try writeJsonStringOrNull(w, wk.julia_channel);
    try w.writeAll(",\"session_label\":");
    try writeJsonStringOrNull(w, wk.session_label);
    try w.writeAll(",\"threads\":");
    const threads_str = try argspec.renderThreads(c.allocator, wk.threads);
    defer if (threads_str) |t| c.allocator.free(t);
    try writeJsonStringOrNull(w, threads_str);
    try w.print(",\"interactive\":{},\"sandboxed\":{}", .{ wk.interactive, wk.sandboxed });
    try w.print(",\"created_at\":{d},\"last_active\":{d},\"last_pinged\":{d}", .{ wk.created_at, wk.last_active, wk.last_pinged });
    try w.print(",\"ping_pending\":{},\"active_clients\":{d}", .{ wk.ping_pending, wk.active_clients });
    try w.print(",\"activity\":{d:.4},\"cull_budget_s\":{d}", .{ c.workerActivity(wk, key, now), c.idleBudget(wk, key orelse "") });
    if (stats) |st| {
        try w.print(",\"mem_bytes\":{d},\"cpu_seconds\":{d:.3}", .{ st.mem_bytes, st.cpu_seconds });
    } else {
        try w.writeAll(",\"mem_bytes\":null,\"cpu_seconds\":null");
    }
    try w.writeAll(",\"clients\":[");
    var first = true;
    var it = c.active_clients.iterator();
    while (it.next()) |entry| {
        if (entry.value_ptr.worker != wk) continue;
        if (!first) try w.writeByte(',');
        first = false;
        const attached_s = @divTrunc(now * 1_000_000 - entry.value_ptr.start_time_us, 1_000_000);
        try w.print("{{\"pid\":{d},\"client_num\":{d},\"attached_seconds\":{d}}}", .{
            entry.key_ptr.*, entry.value_ptr.client_num, attached_s,
        });
    }
    try w.writeAll("]}");
    return mem;
}

fn writeJsonStringOrNull(w: Writer, value: ?[]const u8) !void {
    if (value) |v| try writeJsonString(w, v) else try w.writeAll("null");
}

fn writeJsonString(w: Writer, value: []const u8) !void {
    try w.writeByte('"');
    for (value) |ch| switch (ch) {
        '"' => try w.writeAll("\\\""),
        '\\' => try w.writeAll("\\\\"),
        '\n' => try w.writeAll("\\n"),
        '\t' => try w.writeAll("\\t"),
        '\r' => try w.writeAll("\\r"),
        else => try w.writeByte(ch),
    };
    try w.writeByte('"');
}
