// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0
//
// `juliaclient --status` report: host → projects → workers → clients, plus
// sandboxed and reserve groups, as a styled tree or JSON.

const std = @import("std");
const main = @import("main.zig");
const platform = @import("platform/main.zig");
const config = @import("config.zig");
const worker = @import("worker.zig");
const argspec = @import("args.zig");
const pal = @import("palette.zig");

const Conductor = main.Conductor;
const Worker = worker.Worker;

// Zig 0.16's ArrayList has no generic `.writer()`.
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

/// Who asks: the host sees everything, a sandboxed client only its sandbox
/// (see `Conductor.isVisible`).
pub const Scope = union(enum) { host, remote_sandbox, mount_ns: u64 };

/// `format` is the `--status=<value>` argument; `palette` is set when the
/// client answered the colour probe.
pub const Options = struct {
    format: ?[]const u8 = null,
    tty: bool = false,
    palette: ?*const pal.Palette = null,
    scope: Scope = .host,
    focus: ?u32 = null, // a client id, marked in the tree
};

/// What one request sees, gathered once: the host every worker, a sandboxed
/// caller only its own sandbox's (`Conductor.isVisible`). The reserve is the host's.
const View = struct {
    workers: []const Placed, // pool by pool
    projects: []const Project, // the host's pools, as the tree groups them
    reserve: ?*Worker,
    starting: usize,

    const Placed = struct { key: []const u8, wk: *Worker };
    const Project = struct { key: []const u8, workers: []const *Worker };

    fn init(gpa: std.mem.Allocator, c: *Conductor, scope: Scope) !View {
        var workers: std.ArrayList(Placed) = .empty;
        errdefer workers.deinit(gpa);
        var projects: std.ArrayList(Project) = .empty;
        errdefer projects.deinit(gpa);
        var it = c.workers.iterator();
        while (it.next()) |entry| {
            const key = entry.key_ptr.*;
            const pool = entry.value_ptr.items;
            for (pool) |wk| if (Conductor.isVisible(scope, key, wk)) try workers.append(gpa, .{ .key = key, .wk = wk });
            if (pool.len > 0 and pool[0].launch == .direct and scope == .host)
                try projects.append(gpa, .{ .key = key, .workers = pool });
        }
        var starting: usize = 0;
        for (c.pending_spawns.items) |p| {
            const visible = switch (p.purpose) {
                .reserve => scope == .host,
                .client => |hold| Conductor.isVisible(scope, hold.worker_key, &p.spawn.worker),
            };
            if (visible) starting += 1;
        }
        return .{
            .workers = try workers.toOwnedSlice(gpa),
            .projects = try projects.toOwnedSlice(gpa),
            .reserve = if (scope == .host) c.reserve else null,
            .starting = starting,
        };
    }

    fn deinit(self: View, gpa: std.mem.Allocator) void {
        gpa.free(self.workers);
        gpa.free(self.projects);
    }
};

/// `lines` is for the live view's cursor-up redraw; `clients` are the tree's
/// focusable clients, top to bottom (none for JSON).
pub const Report = struct {
    bytes: []u8,
    lines: usize,
    clients: []u32,

    pub fn deinit(self: Report, gpa: std.mem.Allocator) void {
        gpa.free(self.bytes);
        gpa.free(self.clients);
    }
};

pub fn render(c: *Conductor, opts: Options) !Report {
    return renderAt(c, opts, c.currentTime());
}

// For the test harness, which has no live `Io` clock.
pub fn renderAt(c: *Conductor, opts: Options, now: i64) !Report {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(c.allocator);
    var clients: std.ArrayList(u32) = .empty;
    errdefer clients.deinit(c.allocator);
    const w = Writer{ .list = &buf, .gpa = c.allocator };
    const view = try View.init(c.allocator, c, opts.scope);
    defer view.deinit(c.allocator);
    if (opts.format != null and std.mem.eql(u8, opts.format.?, "json")) {
        try renderJson(c, w, view, now);
    } else {
        const tints: ?Tints = if (opts.palette) |p| .{ .palette = p } else null;
        const ctx = Ctx{ .tints = tints, .mem_ceiling = memCeiling(view), .focus = opts.focus, .clients = &clients };
        try renderTree(c, w, Style{ .enabled = opts.tty }, ctx, view, now);
    }
    const lines = std.mem.count(u8, buf.items, "\n");
    const bytes = try buf.toOwnedSlice(c.allocator);
    errdefer c.allocator.free(bytes);
    return .{ .bytes = bytes, .lines = lines, .clients = try clients.toOwnedSlice(c.allocator) };
}

// --- Styling -----------------------------------------------------------------

// 8-color, so the terminal theme governs the hues.
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

const Style = struct {
    enabled: bool,
    fn open(self: Style, w: Writer, comptime codes: []const u8) !void {
        if (self.enabled) try w.writeAll(codes);
    }
    fn close(self: Style, w: Writer) !void {
        if (self.enabled) try w.writeAll(ansi.reset);
    }
    fn wrap(self: Style, w: Writer, comptime codes: []const u8, text: []const u8) !void {
        try self.open(w, codes);
        try w.writeAll(text);
        try self.close(w);
    }
};

// --- Gradients ----------------------------------------------------------------

const Tint = enum { mem, cpu, cull, activity };

// `muted` is fg pulled toward bg, muted on any theme.
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
const anchors = std.enums.directEnumArray(Tint, [2]Anchor, 0, .{
    .mem = .{ green, red },
    .cpu = .{ blue, magenta },
    .cull = .{ .muted, yellow },
    .activity = .{ .muted, cyan },
});

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

    // Caller resets.
    fn open(self: Tints, w: Writer, tint: Tint, t: f64) !void {
        const a = anchors[@intFromEnum(tint)];
        var buf: [pal.sgr_fg_len]u8 = undefined;
        try w.writeAll(pal.sgrFg(pal.blend(self.resolve(a[0]), self.resolve(a[1]), t), &buf));
    }
};

const Ctx = struct {
    tints: ?Tints,
    mem_ceiling: u64,
    focus: ?u32,
    clients: *std.ArrayList(u32), // focusable, in drawing order
};

fn gradientTints(s: Style, ctx: Ctx) ?Tints {
    return if (s.enabled) ctx.tints else null;
}

// --- Health ------------------------------------------------------------------

const Health = enum { healthy, pinging, unresponsive, inactive };

fn workerHealth(c: *Conductor, wk: *const Worker, now: i64) Health {
    if (wk.busyClients() == 0) return .inactive;
    if (wk.ping_pending) {
        const waited: u64 = @intCast(@max(0, now - wk.last_pinged));
        return if (waited >= c.cfg.ping_timeout) .unresponsive else .pinging;
    }
    return .healthy;
}

// The glyph alone distinguishes states when styling is disabled.
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

// "8s", "41m", "2h14m", "3d2h".
fn writeDuration(w: Writer, total_seconds: i64) !void {
    var buf: [16]u8 = undefined;
    try w.writeAll(try formatDuration(&buf, total_seconds));
}

fn writeDurationPadded(w: Writer, total_seconds: i64, width: usize) !void {
    var buf: [16]u8 = undefined;
    const d = try formatDuration(&buf, total_seconds);
    if (d.len < width) try w.writeByteNTimes(' ', width - d.len);
    try w.writeAll(d);
}

// Second-precise under 10min, where a countdown is worth watching tick.
fn formatCountdown(buf: *[16]u8, total_seconds: i64) ![]const u8 {
    const s: u64 = @intCast(@max(0, total_seconds));
    if (s >= 600) return formatDuration(buf, total_seconds);
    if (s < 60) return std.fmt.bufPrint(buf, "{d}s", .{s});
    return std.fmt.bufPrint(buf, "{d}m{d:0>2}s", .{ s / 60, s % 60 });
}

// The two largest units, the smaller left off when zero.
fn formatDuration(buf: *[16]u8, total_seconds: i64) ![]const u8 {
    const s: u64 = @intCast(@max(0, total_seconds));
    if (s < 60) return std.fmt.bufPrint(buf, "{d}s", .{s});
    if (s < 3600) return std.fmt.bufPrint(buf, "{d}m", .{s / 60});
    const big, const small, const units: [2]u8 = if (s < 86400)
        .{ s / 3600, s % 3600 / 60, .{ 'h', 'm' } }
    else
        .{ s / 86400, s % 86400 / 3600, .{ 'd', 'h' } };
    if (small == 0) return std.fmt.bufPrint(buf, "{d}{c}", .{ big, units[0] });
    return std.fmt.bufPrint(buf, "{d}{c}{d}{c}", .{ big, units[0], small, units[1] });
}

fn contractHome(path: []const u8, home: []const u8) []const u8 {
    if (home.len == 0 or !std.mem.startsWith(u8, path, home)) return path;
    return path[home.len..]; // caller re-prepends "~"
}

// --- Tree rendering ----------------------------------------------------------

const indent = "  ";

fn renderTree(c: *Conductor, w: Writer, s: Style, ctx: Ctx, view: View, now: i64) !void {
    var sandboxed: usize = 0;
    for (view.workers) |p| {
        if (p.wk.launch != .direct) sandboxed += 1;
    }
    for (view.projects, 0..) |project, i| {
        if (i == 0 and sandboxed > 0) try writeGroupHeader(w, s, "host");
        if (i > 0) try w.writeByte('\n');
        try renderProject(c, w, s, ctx, project.workers, project.key, now, sandboxed > 0);
    }
    if (sandboxed > 0) {
        if (view.projects.len > 0) try w.writeByte('\n');
        try writeGroupHeader(w, s, "◆ sandboxed");
        var seen: usize = 0;
        for (view.workers) |p| if (p.wk.launch != .direct) {
            seen += 1;
            try renderWorker(c, w, s, ctx, p.wk, p.key, now, false, seen == sandboxed);
        };
    }
    if (view.reserve) |r| {
        try w.writeByte('\n');
        try writeGroupHeader(w, s, "◇ reserve");
        try renderWorker(c, w, s, ctx, r, null, now, false, true);
    }
    if (view.workers.len == 0 and view.reserve == null) {
        try s.wrap(w, ansi.dim, "No workers running.\n");
    }
    try renderFooter(c, w, s, view);
}

fn writeGroupHeader(w: Writer, s: Style, label: []const u8) !void {
    try w.writeAll(indent);
    try s.wrap(w, ansi.dim, label);
    try w.writeByte('\n');
}

// "  basename · parent/", with a pooled RSS for more than one worker.
fn renderProject(c: *Conductor, w: Writer, s: Style, ctx: Ctx, workers: []const *Worker, key: []const u8, now: i64, nested: bool) !void {
    const all_inactive = for (workers) |wk| {
        if (wk.busyClients() > 0) break false;
    } else true;
    const path = workers[0].project orelse "";
    const pad = if (nested) indent ++ indent else indent;
    try w.writeAll(pad);
    if (path.len == 0) {
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

// "  ├─ ● #6  [label] v1.11 (interactive)  up 12m  490M  2%  <state>"
const id_column_width = 26;

fn renderWorker(c: *Conductor, w: Writer, s: Style, ctx: Ctx, wk: *Worker, key: ?[]const u8, now: i64, nested: bool, is_last: bool) !void {
    const health = workerHealth(c, wk, now);
    const dim_line = health == .inactive;
    const pad = if (nested) indent ++ indent else indent;
    try w.writeAll(pad);
    try s.wrap(w, ansi.dim, if (is_last) "╰─ " else "├─ ");
    try writeHealthDot(s, w, health);
    try w.writeByte(' ');
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
    switch (wk.launch) {
        .direct => {},
        .sandboxed => {
            try w.writeAll(" (sandboxed)");
            col += 12;
        },
        .client => {
            try w.writeAll(" (client sandbox)");
            col += 17;
        },
    }
    if (col < id_column_width) try w.writeByteNTimes(' ', id_column_width - col);
    if (!dim_line) try s.open(w, ansi.dim);
    try w.writeAll(" up ");
    if (!dim_line) try s.close(w);
    try writeDurationPadded(w, now - wk.created_at, 5);
    // mem == 0 means unmeasured.
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
    const showed_activity = c.pressure_monitor.active();
    if (showed_activity) try writeActivity(c, w, s, ctx, wk, key, now, dim_line);
    if (health == .inactive) try writeIdleState(c, w, s, ctx, wk, key, now, showed_activity);
    if (dim_line) try s.close(w);
    try w.writeByte('\n');
    // Watchers show under an otherwise idle worker too.
    if (wk.active_clients > 0) try renderClients(c, w, s, ctx, wk, now, nested, is_last);
}

// Pair with `closeStat`. False when the value just inherits the line's dim.
fn openStat(w: Writer, s: Style, ctx: Ctx, dim_line: bool, tint: Tint, t_frac: f64) !bool {
    if (gradientTints(s, ctx)) |t| {
        if (dim_line) try s.open(w, ansi.dim);
        try t.open(w, tint, t_frac);
        return true;
    }
    if (dim_line) return false;
    try s.open(w, ansi.dim);
    return true;
}

fn closeStat(w: Writer, s: Style, dim_line: bool, styled: bool) !void {
    if (!styled) return;
    try s.close(w);
    if (dim_line) try s.open(w, ansi.dim);
}

// "  idle 41m · culls in 1h19m", within the line's dim span.
fn writeIdleState(c: *Conductor, w: Writer, s: Style, ctx: Ctx, wk: *const Worker, key: ?[]const u8, now: i64, after_activity: bool) !void {
    const is_reserve = c.reserve == wk;
    try w.writeAll(if (after_activity) " · " else "   ");
    if (is_reserve) {
        // The reserve is TTL-exempt.
        try w.writeAll(if (wk.ping_pending) "warming" else "ready");
        return;
    }
    try w.writeAll("idle ");
    try writeDuration(w, now - wk.last_active);
    if (c.cfg.max_ttl > 0) {
        const budget: i64 = @intCast(c.idleBudget(wk, key orelse ""));
        try w.writeAll(" · culls in ");
        try writeCullCountdown(w, s, ctx, budget - (now - wk.last_active), @intCast(c.cfg.max_ttl));
    }
}

// `in_dim` restores the line's dim span afterward.
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

// Coloured against `color_budget` (max_ttl), so equal time left reads alike
// across workers.
fn writeCullCountdown(w: Writer, s: Style, ctx: Ctx, remaining: i64, color_budget: i64) !void {
    var buf: [16]u8 = undefined;
    const text = try formatCountdown(&buf, remaining);
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

fn renderClients(c: *Conductor, w: Writer, s: Style, ctx: Ctx, wk: *const Worker, now: i64, nested: bool, worker_last: bool) !void {
    const base = if (nested) indent ++ indent else indent;
    const total = countClients(c, wk);
    var seen: usize = 0;
    // Clients first, then watchers.
    for ([_]bool{ false, true }) |watchers| {
        var it = c.active_clients.iterator();
        while (it.next()) |entry| {
            const info = entry.value_ptr;
            if (info.worker != wk or info.watcher != watchers or info.internal) continue;
            seen += 1;
            const focused = ctx.focus == entry.key_ptr.*;
            if (!watchers) try ctx.clients.append(w.gpa, entry.key_ptr.*);
            try w.writeAll(base);
            try s.open(w, ansi.dim);
            try w.writeAll(if (worker_last) "   " else "│  ");
            try w.writeAll(if (seen == total) "   ╰─ " else "   ├─ ");
            try s.wrap(w, ansi.dim, if (info.watcher) "Watcher " else "Client ");
            try w.print("{d}", .{info.pid});
            var name_buf: [64]u8 = undefined;
            if (platform.getParentName(info.pid, &name_buf)) |name| {
                try w.print(" ({s})", .{name});
            }
            const attached_s = @divTrunc(now * 1_000_000 - info.start_time_us, 1_000_000);
            try s.open(w, ansi.dim);
            try w.writeAll(" · attached ");
            try writeDuration(w, attached_s);
            try s.close(w);
            if (focused) try s.wrap(w, ansi.bold ++ ansi.cyan, "  ◀");
            try w.writeByte('\n');
        }
    }
}

fn countClients(c: *Conductor, wk: *const Worker) usize {
    var n: usize = 0;
    var it = c.active_clients.iterator();
    while (it.next()) |entry| {
        if (entry.value_ptr.worker == wk and !entry.value_ptr.internal) n += 1;
    }
    return n;
}

fn renderFooter(c: *Conductor, w: Writer, s: Style, view: View) !void {
    var total_clients: usize = 0;
    var total_mem: u64 = if (view.reserve) |r| r.mem else 0;
    for (view.workers) |p| {
        total_clients += p.wk.busyClients();
        total_mem += p.wk.mem;
    }
    try w.writeByte('\n');
    try s.open(w, ansi.dim);
    try w.writeAll(indent ++ ("─" ** 58) ++ "\n");
    try w.writeAll(indent);
    try w.print("{d} workers", .{view.workers.len});
    if (view.reserve != null) try w.writeAll(" · 1 reserve");
    if (view.starting > 0) try w.print(" · {d} starting", .{view.starting});
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

fn groupMem(workers: []const *Worker) u64 {
    var total: u64 = 0;
    for (workers) |wk| total += wk.mem;
    return total;
}

// The RSS painted fully hot: the heaviest worker, or a padded fair share of
// memory, total / (n + 8), so a pool of light workers doesn't all peg red.
fn memCeiling(view: View) u64 {
    var max_mem: u64 = if (view.reserve) |r| r.mem else 0;
    for (view.workers) |p| max_mem = @max(max_mem, p.wk.mem);
    const n: u64 = view.workers.len + @intFromBool(view.reserve != null);
    const fair_share: u64 = if (platform.readMemInfo()) |m| m.total / (n + 8) else 0;
    return @max(max_mem, fair_share);
}

// "+1.11" → "v1.11", "+release" → "(release)". Returns the visible width.
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

fn renderJson(c: *Conductor, w: Writer, view: View, now: i64) !void {
    var total_clients: usize = 0;
    var total_mem: u64 = 0;
    try w.writeAll("{\"workers\":[");
    for (view.workers, 0..) |p, i| {
        if (i > 0) try w.writeByte(',');
        total_clients += p.wk.busyClients();
        total_mem += try writeWorkerJson(c, w, p.wk, p.key, now);
    }
    try w.writeAll("],\"reserve\":");
    if (view.reserve) |r| {
        total_mem += try writeWorkerJson(c, w, r, null, now);
    } else {
        try w.writeAll("null");
    }
    try w.print(",\"totals\":{{\"workers\":{d},\"reserve\":{d},\"starting\":{d},\"clients\":{d},\"mem_bytes\":{d}}}", .{
        view.workers.len, @intFromBool(view.reserve != null), view.starting, total_clients, total_mem,
    });
    try w.print(",\"max_ttl\":{d},\"min_ttl\":{d},\"label_ttl\":{d},\"worker_args\":", .{ c.cfg.max_ttl, c.cfg.min_ttl, c.cfg.label_ttl });
    try writeJsonString(w, c.cfg.worker_args);
    try w.print(",\"pressure\":{{\"source\":\"{s}\",\"under_pressure\":{}}}", .{ @tagName(c.pressure_monitor.source), c.pressure_monitor.under_pressure });
    try w.writeByte('}');
}

// Returns the worker's footprint, for the caller's total.
fn writeWorkerJson(c: *Conductor, w: Writer, wk: *const Worker, key: ?[]const u8, now: i64) !u64 {
    const pid = platform.getChildPid(wk.process);
    const stats = if (wk.process.id) |id| platform.getProcessStats(id) else null;
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
    try w.print(",\"interactive\":{},\"launch\":\"{s}\"", .{ wk.interactive, @tagName(wk.launch) });
    try w.print(",\"created_at\":{d},\"last_active\":{d},\"last_pinged\":{d}", .{ wk.created_at, wk.last_active, wk.last_pinged });
    try w.print(",\"ping_pending\":{},\"active_clients\":{d},\"watchers\":{d}", .{ wk.ping_pending, wk.busyClients(), countClients(c, wk) - wk.busyClients() });
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
        if (entry.value_ptr.worker != wk or entry.value_ptr.internal) continue;
        if (!first) try w.writeByte(',');
        first = false;
        const attached_s = @divTrunc(now * 1_000_000 - entry.value_ptr.start_time_us, 1_000_000);
        try w.print("{{\"id\":{d},\"pid\":{d},\"watcher\":{},\"attached_seconds\":{d}}}", .{
            entry.key_ptr.*, entry.value_ptr.pid, entry.value_ptr.watcher, attached_s,
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
