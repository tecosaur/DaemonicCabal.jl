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

/// Render the full status report. `format` is the `--status=<value>` argument
/// ("json" selects machine output; anything else is the styled tree). `tty`
/// enables ANSI styling. Caller owns the returned slice.
pub fn render(c: *Conductor, format: ?[]const u8, tty: bool) ![]u8 {
    return renderAt(c, format, tty, c.currentTime());
}

// Render against an explicit reference time. Exposed for the standalone test
// harness, which builds a Conductor with no live `Io` clock.
pub fn renderAt(c: *Conductor, format: ?[]const u8, tty: bool, now: i64) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(c.allocator);
    const w = Writer{ .list = &buf, .gpa = c.allocator };
    if (format != null and std.mem.eql(u8, format.?, "json"))
        try renderJson(c, w, now)
    else
        try renderTree(c, w, Style{ .enabled = tty }, now);
    return buf.toOwnedSlice(c.allocator);
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
    const s: u64 = @intCast(@max(0, total_seconds));
    if (s < 60) {
        try w.print("{d}s", .{s});
    } else if (s < 3600) {
        try w.print("{d}m", .{s / 60});
    } else if (s < 86400) {
        const h = s / 3600;
        const m = (s % 3600) / 60;
        if (m == 0) try w.print("{d}h", .{h}) else try w.print("{d}h{d}m", .{ h, m });
    } else {
        const d = s / 86400;
        const h = (s % 86400) / 3600;
        if (h == 0) try w.print("{d}d", .{d}) else try w.print("{d}d{d}h", .{ d, h });
    }
}

// Contract a leading home-directory prefix to "~".
fn contractHome(path: []const u8, home: []const u8) []const u8 {
    if (home.len == 0 or !std.mem.startsWith(u8, path, home)) return path;
    return path[home.len..]; // caller re-prepends "~"
}

// --- Tree rendering ----------------------------------------------------------

const indent = "  ";

fn renderTree(c: *Conductor, w: Writer, s: Style, now: i64) !void {
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
        try renderProject(c, w, s, entry.value_ptr.items, now, have_sandboxed);
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
                try renderWorker(c, w, s, wk, now, false, seen == total);
                printed_any = true;
            }
        }
    }
    // Reserve group: the warm spare, no project, no clients.
    if (c.reserve) |r| {
        try w.writeByte('\n');
        try writeGroupHeader(w, s, "◇ reserve");
        try renderWorker(c, w, s, r, now, false, true);
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
fn renderProject(c: *Conductor, w: Writer, s: Style, workers: []const *Worker, now: i64, nested: bool) !void {
    const all_inactive = for (workers) |wk| {
        if (wk.active_clients > 0) break false;
    } else true;
    const path = workers[0].project orelse "";
    const pad = if (nested) indent ++ indent else indent;
    try w.writeAll(pad);
    if (path.len == 0) {
        // No project: a worker running in the default (global) environment.
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
        try s.open(w, ansi.dim);
        try w.writeAll("  ");
        try writeBytes(w, groupRss(workers));
        try w.writeAll(" pooled");
        try s.close(w);
    }
    try w.writeByte('\n');
    for (workers, 0..) |wk, i| {
        try renderWorker(c, w, s, wk, now, nested, i == workers.len - 1);
    }
}

// A worker line: "  ├─ ● #6  [label] v1.11 (interactive)  up 12m  490M  2%  <state>".
// Inactive workers (and the reserve) render entirely dim; the state slot shows
// the idle duration and the cull countdown.
// The identity+descriptor column is padded to this visible width so the stat
// columns (uptime, RSS, CPU) line up regardless of label/version/mode length.
const id_column_width = 26;

fn renderWorker(c: *Conductor, w: Writer, s: Style, wk: *const Worker, now: i64, nested: bool, is_last: bool) !void {
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
    if (wk.sandboxed) {
        try w.writeAll(" (remote)");
        col += 9;
    }
    // Pad the identity column so the stats align, then uptime, RSS, CPU%.
    if (col < id_column_width) try w.writeByteNTimes(' ', id_column_width - col);
    if (!dim_line) try s.open(w, ansi.dim);
    try w.writeAll(" up ");
    if (!dim_line) try s.close(w);
    try writeDuration(w, now - wk.created_at);
    const stats = platform.getProcessStats(platform.getChildPid(wk.process));
    try w.writeAll("  ");
    if (stats) |st| try writeBytes(w, st.rss_bytes) else try w.writeAll("n/a");
    if (stats) |st| {
        const uptime: f64 = @floatFromInt(@max(1, now - wk.created_at));
        const pct = st.cpu_seconds / uptime * 100;
        if (!dim_line) try s.open(w, ansi.dim);
        try w.print("  {d:.0}%", .{pct});
        if (!dim_line) try s.close(w);
    }
    // State slot for inactive workers / reserve: idle + cull countdown.
    if (health == .inactive) try writeIdleState(c, w, s, wk, now);
    if (dim_line) try s.close(w);
    try w.writeByte('\n');
    if (health != .inactive) try renderClients(c, w, s, wk, now, nested, is_last);
}

// "  idle 41m · culls in 1h19m". Called within the worker line's open dim span,
// so base text inherits dim; only an imminent cull breaks out to amber/red and
// then restores dim for the rest of the span. The reserve reads "ready"/"warming".
fn writeIdleState(c: *Conductor, w: Writer, s: Style, wk: *const Worker, now: i64) !void {
    const is_reserve = c.reserve == wk;
    try w.writeAll("   ");
    if (is_reserve) {
        try w.writeAll(if (wk.ping_pending) "warming" else "ready");
    } else {
        try w.writeAll("idle ");
        try writeDuration(w, now - wk.last_active);
    }
    if (c.cfg.worker_ttl > 0) {
        const remaining = @as(i64, @intCast(c.cfg.worker_ttl)) - (now - wk.last_active);
        try w.writeAll(" · culls in ");
        if (remaining <= 60) {
            try s.open(w, ansi.reset ++ ansi.bold ++ ansi.red);
            try writeDuration(w, remaining);
            try s.open(w, ansi.dim); // restore the line's dim span
        } else if (remaining <= 300) {
            try s.open(w, ansi.reset ++ ansi.yellow);
            try writeDuration(w, remaining);
            try s.open(w, ansi.dim);
        } else {
            try writeDuration(w, remaining);
        }
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
    var total_rss: u64 = 0;
    var has_reserve = false;
    var it = c.workers.iterator();
    while (it.next()) |entry| {
        for (entry.value_ptr.items) |wk| {
            active_workers += 1;
            total_clients += wk.active_clients;
            if (platform.getProcessStats(platform.getChildPid(wk.process))) |st| total_rss += st.rss_bytes;
        }
    }
    if (c.reserve) |r| {
        has_reserve = true;
        if (platform.getProcessStats(platform.getChildPid(r.process))) |st| total_rss += st.rss_bytes;
    }
    try w.writeByte('\n');
    try s.open(w, ansi.dim);
    try w.writeAll(indent ++ ("─" ** 58) ++ "\n");
    try w.writeAll(indent);
    try w.print("{d} workers", .{active_workers});
    if (has_reserve) try w.writeAll(" · 1 reserve");
    try w.print(" · {d} clients · ", .{total_clients});
    try writeBytes(w, total_rss);
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

fn groupRss(workers: []const *Worker) u64 {
    var total: u64 = 0;
    for (workers) |wk| {
        if (platform.getProcessStats(platform.getChildPid(wk.process))) |st| total += st.rss_bytes;
    }
    return total;
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
    var total_rss: u64 = 0;
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
            total_rss += try writeWorkerJson(c, w, wk, now);
        }
    }
    try w.writeAll("],\"reserve\":");
    if (c.reserve) |r| {
        total_rss += try writeWorkerJson(c, w, r, now);
    } else {
        try w.writeAll("null");
    }
    try w.print(",\"totals\":{{\"workers\":{d},\"reserve\":{d},\"clients\":{d},\"rss_bytes\":{d}}}", .{
        worker_count, @as(u8, if (c.reserve != null) 1 else 0), total_clients, total_rss,
    });
    try w.print(",\"worker_ttl\":{d},\"label_ttl\":{d},\"worker_args\":", .{ c.cfg.worker_ttl, c.cfg.label_ttl });
    try writeJsonString(w, c.cfg.worker_args);
    try w.writeByte('}');
}

// Emit one worker object; returns its RSS so the caller can total it.
fn writeWorkerJson(c: *Conductor, w: Writer, wk: *const Worker, now: i64) !u64 {
    const pid = platform.getChildPid(wk.process);
    const stats = platform.getProcessStats(pid);
    const rss = if (stats) |st| st.rss_bytes else 0;
    try w.print("{{\"id\":{d},\"pid\":{d},\"project\":", .{ wk.id, pid });
    try writeJsonStringOrNull(w, wk.project);
    try w.writeAll(",\"channel\":");
    try writeJsonStringOrNull(w, wk.julia_channel);
    try w.writeAll(",\"session_label\":");
    try writeJsonStringOrNull(w, wk.session_label);
    try w.print(",\"interactive\":{},\"sandboxed\":{}", .{ wk.interactive, wk.sandboxed });
    try w.print(",\"created_at\":{d},\"last_active\":{d},\"last_pinged\":{d}", .{ wk.created_at, wk.last_active, wk.last_pinged });
    try w.print(",\"ping_pending\":{},\"active_clients\":{d}", .{ wk.ping_pending, wk.active_clients });
    if (stats) |st| {
        try w.print(",\"rss_bytes\":{d},\"cpu_seconds\":{d:.3}", .{ st.rss_bytes, st.cpu_seconds });
    } else {
        try w.writeAll(",\"rss_bytes\":null,\"cpu_seconds\":null");
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
    return rss;
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
