// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0
//
// `--status` redrawn in place at a terminal: the styled one-shot, which waits
// a beat so its CPU meter resolves, and `--status=live`, a small TUI whose
// keys move a focus over the clients and act on it.
//
// A change with no timer armed repaints at once; a burst only sets `dirty`.
// Each fire re-arms fast if dirty, else at the heartbeat, until no
// subscriber remains. Output never blocks the conductor: what a terminal
// doesn't take is queued, and a subscriber too far behind is dropped.
//
// The focused client's transcript comes from the conductor watching its
// session, as `--watch` does, in colour: of a session already recorded for
// the pane, relayed whole for following it full-screen.

const std = @import("std");
const posix = std.posix;
const main = @import("main.zig");
const platform = @import("platform/main.zig");
const protocol = @import("protocol.zig");
const status = @import("status.zig");
const args = @import("args.zig");
const worker = @import("worker.zig");
const pal = @import("palette.zig");
const tui = @import("tui.zig");
const peek = @import("peek.zig");
const logring = @import("logring.zig");
const terminal = @import("terminal.zig");

const Conductor = main.Conductor;
const ClientStreams = Conductor.ClientStreams;

const debounce_ms = 100;
const heartbeat_ms = 1000;
const blink_ms = 500; // the redraw's pace while a cursor blinks, so its phase is kept
const cpu_half_life: f64 = 1.4; // tracks the 1s heartbeat
const probe_timeout_ms = 300; // a worker slower to answer is busy on thread 0
const max_tail_bytes = 64 << 10;
const max_pane_rows = 16; // a preview: ⏎ shows the whole
const note_s = 4; // how long an action's outcome stays in the pane's border
const resample_s = 5; // a snapshot still sampling is not asked for again sooner
const alternate_screen = "\x1b[?7h\x1b[?1049h\x1b[H\x1b[2J";
const main_screen = "\x1b[0m\x1b[?1049l\x1b[?7l";
const profile_follows = "The profile follows once the session yields.";

const Watch = terminal.Watch;

pub const Subscribers = struct {
    list: std.ArrayList(*Subscriber) = .empty,
    armed: bool = false,
    dirty: bool = false,
    snapshots: std.ArrayList(Snapshot) = .empty, // one per worker, the latest
    trends: std.AutoHashMapUnmanaged(u32, status.Trend) = .empty, // by worker id, while a live view is open
    trend_at: i64 = 0, // the second last sampled
};

/// A worker's stacks, from its stderr, and profile report, from the worker;
/// the report comes once the worker yields.
const Snapshot = struct {
    worker_id: u32,
    taken_at: i64,
    stacks: ?[]u8 = null,
    report: ?[]u8 = null,

    fn deinit(self: Snapshot, gpa: std.mem.Allocator) void {
        if (self.stacks) |b| gpa.free(b);
        if (self.report) |b| gpa.free(b);
    }
};

const Size = terminal.Size;

/// What the pane shows of the focused client.
const Preview = union(enum) {
    pending,
    unsessioned, // a plain client, which has no transcript
    busy: i64, // the worker didn't answer, as of then
    unrecorded: i64, // as of then: recording may yet start
    failed: i64, // the watch ended in error, as of then
    transcript, // `Subscriber.tail`
};

/// The conductor watching a session for a subscriber.
const Attachment = struct {
    id: u32, // the conductor's own watcher, as tracked
    follow: bool, // relayed whole, rather than kept for the pane
    sockets: [4]posix.socket_t, // stdin, stdout, stderr, signals
    output: Watch,
    signals: Watch,
    frames: terminal.SignalFrames = .{},
};

const Subscriber = struct {
    term: terminal.Terminal,
    scope: status.Scope,
    oneshot: bool, // draw one CPU-resolved frame, then disconnect
    // The live view's:
    focus: ?u32 = null, // a client id
    focus_row: usize = 0, // its place in the tree, for when it leaves
    order: []u32 = &.{}, // the focusable clients last drawn, top to bottom
    following: bool = false, // the focused session, full-screen
    target: ?u32 = null, // the client `preview` and `tail` are of
    preview: Preview = .pending,
    tail: std.ArrayList(u8) = .empty,
    attachment: ?*Attachment = null,
    confirming: ?u32 = null, // the client `t` would terminate, awaiting y/n
    note: Note = .{},
    view: View = .transcript, // what the pane shows of the focus
    output_ns: i64 = 0, // when the preview's session last wrote: its cursor blinks from then
    cursor_drawn: bool = false, // the last frame's pane marked a cursor
    paging: bool = false, // the view, full-screen
    scroll: usize = 0, // the pager's top line
    pager_top: ?usize = null, // the top line on screen, once drawn
    pager_shown: u64 = 0, // `pagerShown` as drawn

    fn owns(self: *const Subscriber, w: *const Watch) bool {
        if (w == &self.term.input or w == &self.term.signals) return true;
        const a = self.attachment orelse return false;
        return w == &a.output or w == &a.signals;
    }
};

/// What the pane shows: the focused session's transcript, its worker's
/// stacktrace, or its worker's recent log.
const View = enum { transcript, stacktrace, log };

/// An action's outcome, shown in the pane's border for `note_s`.
const Note = struct {
    bytes: [160]u8 = undefined,
    len: usize = 0,
    until: i64 = 0,

    fn set(self: *Note, now: i64, comptime fmt: []const u8, fmt_args: anytype) void {
        self.len = if (std.mem.print(&self.bytes, fmt, fmt_args)) |t| t.len else |_| 0;
        self.until = now + note_s;
    }

    fn text(self: *const Note, now: i64) ?[]const u8 {
        return if (now < self.until) self.bytes[0..self.len] else null;
    }
};

/// Takes `streams`. A live subscriber's first frame is drawn at once.
pub fn subscribe(c: *Conductor, streams: ClientStreams, palette: ?pal.Palette, scope: status.Scope, oneshot: bool) !void {
    const sub = try c.allocator.create(Subscriber);
    errdefer c.allocator.destroy(sub);
    sub.* = .{ .term = .{ .streams = streams, .palette = palette, .id = c.client_id }, .scope = scope, .oneshot = oneshot };
    try c.live.list.append(c.allocator, sub);
    if (oneshot) {
        c.refreshStats(null); // first reading; the deferred fire takes the second
        c.event_loop.armLiveTimer(debounce_ms);
        c.live.armed = true;
        return;
    }
    sub.term.open(c);
    repaint(c, sub);
    if (!c.live.armed) {
        c.event_loop.armLiveTimer(heartbeat_ms);
        c.live.armed = true;
    }
}

pub fn noteChange(c: *Conductor) void {
    if (c.live.list.items.len == 0) return;
    c.live.dirty = true;
    if (!c.live.armed) fire(c);
}

pub fn onTimer(c: *Conductor) void {
    c.live.armed = false;
    fire(c);
}

/// A client's exit or interrupt, when it is a subscriber's.
pub fn dropById(c: *Conductor, id: u32) bool {
    for (c.live.list.items) |sub| if (sub.term.id == id) {
        sub.term.gone = true;
        sweep(c);
        return true;
    };
    return false;
}

pub fn deinit(c: *Conductor) void {
    for (c.live.list.items) |sub| sub.term.gone = true;
    sweep(c);
    c.live.list.deinit(c.allocator);
    c.live.trends.deinit(c.allocator);
    for (c.live.snapshots.items) |snap| snap.deinit(c.allocator);
    c.live.snapshots.deinit(c.allocator);
}

/// The stacks a worker wrote on being asked for a snapshot; takes `stacks`.
pub fn onStacks(c: *Conductor, w: *const worker.Worker, stacks: []u8) void {
    const snap = snapshotOf(c, w.id) orelse return c.allocator.free(stacks);
    if (snap.stacks) |old| c.allocator.free(old);
    snap.stacks = stacks;
    noteChange(c);
}

/// The profile a worker reported; takes `report`.
pub fn onProfile(c: *Conductor, w: *const worker.Worker, report: []u8) void {
    const snap = snapshotOf(c, w.id) orelse return c.allocator.free(report);
    if (snap.report) |old| c.allocator.free(old);
    snap.report = report;
    noteChange(c);
}

// A worker's snapshot, begun here when it was asked for elsewhere.
fn snapshotOf(c: *Conductor, worker_id: u32) ?*Snapshot {
    if (findSnapshot(c, worker_id)) |snap| return snap;
    c.live.snapshots.append(c.allocator, .{ .worker_id = worker_id, .taken_at = c.currentTime() }) catch return null;
    return &c.live.snapshots.items[c.live.snapshots.items.len - 1];
}

fn findSnapshot(c: *Conductor, worker_id: u32) ?*Snapshot {
    for (c.live.snapshots.items) |*snap| if (snap.worker_id == worker_id) return snap;
    return null;
}

// Those of workers gone.
fn pruneSnapshots(c: *Conductor) void {
    var i: usize = 0;
    while (i < c.live.snapshots.items.len) {
        const snap = c.live.snapshots.items[i];
        if (c.findWorkerById(snap.worker_id) != null) {
            i += 1;
            continue;
        }
        snap.deinit(c.allocator);
        _ = c.live.snapshots.swapRemove(i);
    }
}

/// Stale watches, of a subscriber or attachment already gone, are ignored.
/// Reads never wait, so a stale readiness costs nothing.
pub fn onReadable(c: *Conductor, w: *Watch) void {
    const sub = for (c.live.list.items) |s| {
        if (s.owns(w)) break s;
    } else return;
    var buf: [16 << 10]u8 = undefined;
    const n = platform.recvNonBlocking(w.fd, &buf) orelse {
        switch (w.kind) {
            .input, .signals => sub.term.gone = true,
            .watch_output => {}, // the verdict comes on its signals
            .watch_signals => endAttachment(c, sub, null),
        }
        if (sub.term.gone) sweep(c);
        return;
    };
    const bytes = buf[0..n];
    switch (w.kind) {
        .input => onKeys(c, sub, bytes),
        .signals => sub.term.onSignals(bytes),
        .watch_output => onWatchOutput(c, sub, bytes),
        .watch_signals => onWatchSignals(c, sub, bytes),
    }
    if (sub.term.gone) return sweep(c);
    // Unless the reading ended what it watched.
    if (sub.owns(w)) watch(c, w);
}

// One-shots set util to the raw rate; any live view uses the EWMA.
fn fire(c: *Conductor) void {
    if (c.live.list.items.len == 0) return;
    const had_change = c.live.dirty;
    c.live.dirty = false;
    const all_oneshot = for (c.live.list.items) |sub| {
        if (!sub.oneshot) break false;
    } else true;
    c.refreshStats(if (all_oneshot) null else cpu_half_life);
    pruneSnapshots(c);
    if (!all_oneshot) recordTrends(c);
    var behind = false;
    var blinking = false;
    for (c.live.list.items) |sub| {
        if (!sub.oneshot) {
            platform.write(sub.term.streams.fd(.signals), &[_]u8{ protocol.signals.query_size, 0x00 });
            retarget(c, sub);
        }
        repaint(c, sub);
        if (sub.oneshot) sub.term.gone = true;
        behind = behind or sub.term.queued.items.len > 0;
        blinking = blinking or sub.cursor_drawn;
    }
    sweep(c);
    if (c.live.list.items.len == 0) return;
    c.event_loop.armLiveTimer(if (had_change or behind) debounce_ms else if (blinking) blink_ms else heartbeat_ms);
    c.live.armed = true;
}

// A subscriber still behind catches up first, skipping this frame; one
// following a session gets only its output.
fn repaint(c: *Conductor, sub: *Subscriber) void {
    if (sub.term.queued.items.len > 0) {
        _ = sub.term.flushQueued();
        return;
    }
    if (sub.following) return;
    if (sub.paging) return drawPager(c, sub);
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(c.allocator);
    const lines = composeFrame(c, sub, &out) catch |err| {
        std.debug.print("Status: render failed: {}\n", .{err});
        return;
    };
    sub.term.sendFrame(c.allocator, out.items);
    sub.term.lines_last_printed = lines;
}

// DEC 2026 synchronised update, so no tearing; ESC[<n>F returns to the
// frame's top and ESC[0J clears any tail. Returns the frame's lines.
fn composeFrame(c: *Conductor, sub: *Subscriber, out: *std.ArrayList(u8)) !usize {
    sub.cursor_drawn = false; // until a pane marks one
    const render = struct {
        fn f(conductor: *Conductor, s: *const Subscriber) !status.Report {
            return conductor.renderStatus("live", true, s.term.palette, s.scope, s.focus, focusedTrend(conductor, s), !s.oneshot and s.focus == null);
        }
    }.f;
    var report = try render(c, sub);
    const kept = tui.keepFocus(report.clients, sub.focus, sub.focus_row);
    if (kept != sub.focus) {
        sub.focus = kept;
        report.deinit(c.allocator);
        report = try render(c, sub);
    }
    defer report.deinit(c.allocator);
    try out.appendSlice(c.allocator, "\x1b[?2026h");
    if (sub.term.lines_last_printed > 0) try out.print(c.allocator, "\x1b[{d}F\x1b[0J", .{sub.term.lines_last_printed});
    var frame: std.ArrayList(u8) = .empty;
    defer frame.deinit(c.allocator);
    var lines = report.lines;
    const placed = if (sub.focus) |focus| placed: {
        sub.focus_row = std.mem.findScalar(u32, report.clients, focus) orelse 0;
        break :placed report.placement;
    } else null;
    // The pane encloses the focused row, its top border; the frame stays a
    // row short of the screen, so it never scrolls.
    const height = if (sub.oneshot) lines else @as(usize, sub.term.size.rows) -| 1;
    const full = sub.view != .transcript or (sub.preview == .transcript and sub.tail.items.len > 0);
    const wanted: usize = if (full) max_pane_rows else tui.min_pane_rows;
    const rows = @min(wanted, height -| lines +| 1);
    var focus_lines: [2]usize = .{ 0, 0 };
    if (placed) |at| {
        const line = std.mem.count(u8, report.bytes[0..at.start], "\n");
        const pane = rows >= tui.min_pane_rows;
        focus_lines = .{ line, line + if (pane) rows else 1 };
        try frame.appendSlice(c.allocator, report.bytes[0..at.start]);
        if (pane) try writePane(c, sub, sub.focus.?, &frame, at, report, rows) else try frame.appendSlice(c.allocator, report.bytes[at.start..at.end]);
        try frame.appendSlice(c.allocator, report.bytes[at.end..]);
        if (pane) lines += rows - 1;
    } else {
        try frame.appendSlice(c.allocator, report.bytes);
    }
    // Taller than the screen, the tree is cut to it, scrolled to the focus.
    const top = tui.scrollTop(lines, height, focus_lines[0], focus_lines[1]);
    const shown = @min(lines, height);
    try out.appendSlice(c.allocator, tui.lineRange(frame.items, top, shown));
    if (shown < lines) try out.appendSlice(c.allocator, "\x1b[0m"); // a style open across the cut
    try out.appendSlice(c.allocator, "\x1b[?2026l");
    c.allocator.free(sub.order);
    sub.order = report.clients;
    report.clients = &.{};
    return shown;
}

// The focused row, as the tree drew it at `at`, is the pane's title; a
// worker's charts, where they fit, stand at its end for the row's own
// memory and CPU.
fn writePane(c: *Conductor, sub: *Subscriber, focus: u32, out: *std.ArrayList(u8), at: status.Placement, report: status.Report, rows: usize) !void {
    const info = c.active_clients.get(focus) orelse return;
    // The tree's column alignment is no use in a title.
    var row: std.ArrayList(u8) = .empty;
    defer row.deinit(c.allocator);
    try tui.appendCollapsed(&row, c.allocator, report.bytes[at.label_start..at.label_end]);
    var joined: std.ArrayList(u8) = .empty;
    defer joined.deinit(c.allocator);
    try joined.appendSlice(c.allocator, report.bytes[at.label_start..at.stats[0]]);
    try joined.appendSlice(c.allocator, report.bytes[at.stats[1]..at.label_end]);
    var charted: std.ArrayList(u8) = .empty;
    defer charted.deinit(c.allocator);
    try tui.appendCollapsed(&charted, c.allocator, joined.items);
    const width = @as(usize, sub.term.size.cols) -| at.gutter_cols;
    const fits = report.aside.len > 0 and tui.columns(charted.items) + tui.columns(report.aside) + 10 <= width;
    var lines_buf: [256][]const u8 = undefined;
    var view_lines: std.ArrayList([]const u8) = .empty;
    defer view_lines.deinit(c.allocator);
    var view_text: std.ArrayList(u8) = .empty;
    defer view_text.deinit(c.allocator);
    const snap = if (sub.view == .stacktrace) findSnapshot(c, info.worker.id) else null;
    if (snap) |sn| try snapshotLines(c.allocator, sn, focus, &view_lines);
    if (sub.view == .log) try logLines(c, info.worker, rows - 2, &view_text, &view_lines);
    // Where the transcript can't be read, the latest the worker's log has.
    var hint_buf: [480]u8 = undefined;
    const hint = latestEntry(c, info.worker, &hint_buf);
    const body: []const []const u8 = if (sub.view != .transcript) view_lines.items else switch (sub.preview) {
        .pending => &.{},
        .unsessioned => &.{"Transcripts are only available in sessions."},
        .busy => &.{ "Its worker is busy, so the transcript waits until it yields.", hint },
        .unrecorded => &.{
            "This session isn't being recorded.",
            "⏎ expands it, recording it from then on; JULIA_DAEMON_RECORD records sessions from their start.",
        },
        .failed => &.{ "The transcript's watch ended in error; trying again.", hint },
        .transcript => if (sub.tail.items.len == 0)
            &.{"Nothing recorded yet."}
        else
            tui.lastLines(sub.tail.items, lines_buf[0..@min(lines_buf.len, rows - 2)]),
    };
    var footer_buf: [160]u8 = undefined;
    const cursor_sgr = pal.Sgr.muted(sub.term.palette); // the grey the tree dims with
    // Output mid-line, such as a prompt, leaves the cursor on its last.
    sub.cursor_drawn = sub.view == .transcript and sub.preview == .transcript and
        sub.tail.items.len > 0 and sub.tail.items[sub.tail.items.len - 1] != '\n';
    try tui.writePane(out, c.allocator, true, .{
        .title = if (fits) charted.items else row.items,
        .aside = if (fits) report.aside else "",
        .footer = paneFooter(c, sub, info, snap, &footer_buf),
        .body = body,
        .dim_body = sub.view == .transcript and (sub.preview != .transcript or sub.tail.items.len == 0),
        .cursor_last = sub.cursor_drawn,
        // Steady while the session writes, then a second off, a second on.
        .cursor_shown = @mod(@divTrunc(c.nowNs() - sub.output_ns, std.time.ns_per_s), 2) == 0,
        .cursor_sgr = cursor_sgr.params(),
        .branch = &at.branch,
        .gutter = &at.gutter,
    }, @as(usize, sub.term.size.cols) -| at.gutter_cols, rows);
}

// The pane's bottom border: the terminate prompt, an action's outcome, or
// the keys the pane's view takes.
fn paneFooter(c: *Conductor, sub: *const Subscriber, info: main.ActiveClientInfo, snap: ?*const Snapshot, buf: *[160]u8) []const u8 {
    if (sub.confirming) |id| {
        const whole = info.session and (info.sync or info.worker.session_label != null);
        return std.mem.print(buf, "terminate client {d}{s}? " ++ comptime hints(&.{ .{ "y", "" }, .{ "n", "" } }), .{
            if (c.active_clients.get(id)) |target| target.pid else id,
            if (whole) " and its session" else "",
        }) catch "terminate? " ++ comptime hints(&.{ .{ "y", "" }, .{ "n", "" } });
    }
    if (sub.note.text(c.currentTime())) |note| return note;
    if (snap) |sn| return if (sn.report == null)
        "sampling… · " ++ comptime hints(&.{ .{ "⏎", "expand" }, .{ "Esc", "transcript" }, .{ "q", "quit" } })
    else
        comptime hints(&.{ .{ "⏎", "expand" }, .{ "s", "again" }, .{ "Esc", "transcript" }, .{ "q", "quit" } });
    if (sub.view == .log) return comptime hints(&.{ .{ "⏎", "expand" }, .{ "Esc", "transcript" }, .{ "q", "quit" } });
    return if (info.session)
        comptime hints(&.{ .{ "↑↓", "focus" }, .{ "⏎", "expand" }, .{ "s", "stacktrace" }, .{ "l", "log" }, .{ "i", "interrupt" }, .{ "t", "terminate" }, .{ "q", "quit" } })
    else
        comptime hints(&.{ .{ "↑↓", "focus" }, .{ "s", "stacktrace" }, .{ "l", "log" }, .{ "i", "interrupt" }, .{ "t", "terminate" }, .{ "q", "quit" } });
}

fn onKeys(c: *Conductor, sub: *Subscriber, bytes: []const u8) void {
    var keys = tui.KeyIterator{ .bytes = bytes };
    while (keys.next()) |key| {
        if (key == .interrupt) {
            sub.term.gone = true;
            return;
        }
        if (sub.following) {
            const leave = key == .escape or (key == .char and key.char == 'q');
            if (leave) leaveFollow(c, sub);
            continue;
        }
        if (sub.paging) {
            pagerKey(c, sub, key);
            continue;
        }
        if (sub.confirming) |id| {
            sub.confirming = null;
            if (key == .char and key.char == 'y') terminate(c, sub, id);
            repaint(c, sub);
            continue;
        }
        switch (key) {
            .char => |ch| switch (ch) {
                'q' => {
                    sub.term.gone = true;
                    return;
                },
                'i' => if (sub.focus) |focus| interrupt(c, sub, focus),
                't' => if (sub.focus) |focus| {
                    sub.confirming = focus;
                    repaint(c, sub);
                },
                's' => if (sub.focus) |focus| takeSnapshot(c, sub, focus),
                'l' => if (sub.focus != null) {
                    sub.view = if (sub.view == .log) .transcript else .log;
                    repaint(c, sub);
                },
                else => {},
            },
            .escape => {
                if (sub.view != .transcript) {
                    sub.view = .transcript;
                } else {
                    sub.focus = null;
                    retarget(c, sub);
                }
                repaint(c, sub);
            },
            .up, .down => {
                sub.focus = tui.moveFocus(sub.order, sub.focus, key);
                if (sub.view == .stacktrace) sub.view = .transcript;
                retarget(c, sub);
                repaint(c, sub);
            },
            .enter => if (sub.view != .transcript) {
                sub.paging = true;
                sub.scroll = 0;
                sub.pager_top = null;
                sub.term.send(c.allocator, alternate_screen ++ "\x1b[?7l");
                repaint(c, sub);
            } else enterFollow(c, sub),
            else => {},
        }
    }
}

// As a client's Ctrl-C: from Julia 1.14 the worker cancels the focused
// client's code, and the SIGINT finds nothing; before, the SIGINT reaches
// whichever of its clients runs.
fn interrupt(c: *Conductor, sub: *Subscriber, focus: u32) void {
    const info = c.active_clients.get(focus) orelse return;
    const w = info.worker;
    w.cancelClient(focus, 0); // 0: whichever evaluation is current
    w.signal(platform.SIG.INT);
    const now = c.currentTime();
    if (w.busyClients() > 1)
        sub.note.set(now, "interrupted client {d}; before Julia 1.14, whichever of the worker's {d} runs", .{ info.pid, w.busyClients() })
    else
        sub.note.set(now, "interrupted client {d}", .{info.pid});
    repaint(c, sub);
}

// The focused client's run, or its whole session when the session is the
// worker's own (labelled or `--sync`), which then goes with its label.
fn terminate(c: *Conductor, sub: *Subscriber, focus: u32) void {
    const info = c.active_clients.get(focus) orelse return;
    const w = info.worker;
    const whole = info.session and (info.sync or w.session_label != null);
    var buf: [256]u32 = undefined;
    var ids: std.ArrayList(u32) = .initBuffer(&buf);
    var it = c.active_clients.iterator();
    while (it.next()) |entry| {
        const other = entry.value_ptr;
        const included = if (whole) other.worker == w and !other.internal else entry.key_ptr.* == focus;
        if (included) ids.appendBounded(entry.key_ptr.*) catch break;
    }
    const worker_id = w.id;
    const labelled = whole and w.session_label != null;
    const ending = c.endClients(w, ids.items);
    if (labelled and ending != .retired) c.clearLabel(w);
    const now = c.currentTime();
    switch (ending) {
        .ended => sub.note.set(now, "ended client {d}{s}", .{ info.pid, if (whole) " and its session" else "" }),
        .interrupted => sub.note.set(now, "ended client {d}, with a forced interrupt", .{info.pid}),
        .retired => sub.note.set(now, "retired worker #{d}: client {d} would not stop", .{ worker_id, info.pid }),
    }
    noteChange(c);
}

// Julia's runtime writes the stacks to stderr at once and samples a profile,
// whose report the worker sends once it yields. Where Julia takes no such
// signal, the worker is asked, and samples itself.
fn takeSnapshot(c: *Conductor, sub: *Subscriber, focus: u32) void {
    const w = (c.active_clients.get(focus) orelse return).worker;
    sub.view = .stacktrace;
    const now = c.currentTime();
    const snap = snapshotOf(c, w.id) orelse return;
    const sampling = snap.report == null and snap.stacks != null and now - snap.taken_at < resample_s;
    if (!sampling) {
        snap.deinit(c.allocator);
        snap.* = .{ .worker_id = w.id, .taken_at = now };
        if (platform.peek_signal) |sig| w.signal(sig) else w.startPeek();
    }
    repaint(c, sub);
}

// The focused client's part of the profile, or until it comes, a digest of
// the stacks; the whole view has both.
fn snapshotLines(gpa: std.mem.Allocator, snap: *const Snapshot, focus: u32, out: *std.ArrayList([]const u8)) !void {
    if (snap.report) |report| return appendLines(gpa, out, clientSection(report, focus));
    if (snap.stacks) |stacks| try peek.digest(gpa, stacks, 8, out) else try out.append(gpa, "Asking for the worker's stacks…");
    try out.append(gpa, "");
    try out.append(gpa, profile_follows);
}

// Each of `text`'s lines, a slice of it.
fn appendLines(gpa: std.mem.Allocator, out: *std.ArrayList([]const u8), text: []const u8) !void {
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| try out.append(gpa, line);
}

// The worker heads each client's part `── client <id> ──`; the whole report
// when this client has none.
fn clientSection(report: []const u8, client: u32) []const u8 {
    var buf: [48]u8 = undefined;
    const head = std.mem.print(&buf, "── client {d} ──", .{client}) catch return report;
    const start = std.mem.find(u8, report, head) orelse return report;
    const end = std.mem.findPos(u8, report, start + head.len, "\n── ") orelse report.len;
    return report[start..end];
}

// The whole snapshot: the report, then the raw stacks. Drawn only when it or
// the view changes; a scroll of less than a screen moves what is shown (in a
// scroll region, above the status line) and draws only the lines it brings in.
fn drawPager(c: *Conductor, sub: *Subscriber) void {
    const focus = sub.focus orelse return;
    const info = c.active_clients.get(focus) orelse return;
    var lines: std.ArrayList([]const u8) = .empty;
    defer lines.deinit(c.allocator);
    var text: std.ArrayList(u8) = .empty;
    defer text.deinit(c.allocator);
    const shown: u64 = switch (sub.view) {
        .log => shown: {
            logLines(c, info.worker, logring.max_entries, &text, &lines) catch return;
            break :shown logShown(&info.worker.recent, c.currentTime(), sub.term.size);
        },
        else => shown: {
            const snap = findSnapshot(c, info.worker.id) orelse return;
            pagerLines(c.allocator, snap, &lines) catch return;
            break :shown pagerShown(snap, sub.term.size);
        },
    };
    const rows = @as(usize, sub.term.size.rows) -| 1;
    sub.scroll = @min(sub.scroll, lines.items.len -| rows);
    const same = sub.pager_top != null and sub.pager_shown == shown;
    if (same and sub.pager_top.? == sub.scroll) return;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(c.allocator);
    const top = sub.scroll;
    const bottom = @min(lines.items.len, top + rows);
    writePager(c, sub, &out, lines.items, top, bottom, rows, if (same) sub.pager_top.? else null) catch return;
    out.print(c.allocator, "\x1b[{d};1H\x1b[2K\x1b[7m worker #{d} · lines {d}–{d} of {d} · \x1b[1m↑↓ PgUp PgDn g G\x1b[22m · \x1b[1mq\x1b[22m back \x1b[0m\x1b[?2026l", .{
        sub.term.size.rows, info.worker.id, top + 1, bottom, lines.items.len,
    }) catch return;
    sub.term.send(c.allocator, out.items);
    sub.pager_top = top;
    sub.pager_shown = shown;
}

// Lines `top..bottom` on screen: those new since the view's top was `was`,
// when that is less than a screen away, else all of them.
fn writePager(c: *Conductor, sub: *Subscriber, out: *std.ArrayList(u8), lines: []const []const u8, top: usize, bottom: usize, rows: usize, was: ?usize) !void {
    const gpa = c.allocator;
    try out.appendSlice(gpa, "\x1b[?2026h");
    const moved: isize = if (was) |w| @as(isize, @intCast(top)) - @as(isize, @intCast(w)) else 0;
    const distance: usize = @abs(moved);
    var first: usize = top;
    var last: usize = bottom;
    if (was != null and distance < rows) {
        // Within the region only, so the status line stays put.
        try out.print(gpa, "\x1b[1;{d}r", .{rows});
        // A line feed at the region's foot, or a reverse index at its head,
        // scrolls it: VT100's own, where not every terminal has SU and SD.
        if (moved > 0) {
            try out.print(gpa, "\x1b[{d};1H", .{rows});
            try out.appendNTimes(gpa, '\n', distance);
            first = @max(top, bottom -| distance);
        } else {
            try out.appendSlice(gpa, "\x1b[1;1H");
            for (0..distance) |_| try out.appendSlice(gpa, "\x1bM");
            last = @min(bottom, top + distance);
        }
        try out.appendSlice(gpa, "\x1b[r");
    } else {
        try out.appendSlice(gpa, "\x1b[H\x1b[2J");
    }
    for (first..last) |i| {
        try out.print(gpa, "\x1b[{d};1H\x1b[2K", .{i - top + 1});
        _ = try tui.appendColumns(out, gpa, lines[i], sub.term.size.cols, true);
    }
}

// What the pager shows, bar its scroll: its content and the terminal's size.
fn pagerShown(snap: *const Snapshot, size: Size) u64 {
    var h = std.hash.Wyhash.init(0);
    for ([_]?[]const u8{ snap.report, snap.stacks }) |part| {
        const bytes: []const u8 = part orelse &.{};
        h.update(std.mem.asBytes(&@intFromPtr(bytes.ptr)));
        h.update(std.mem.asBytes(&bytes.len));
    }
    h.update(std.mem.asBytes(&size));
    return h.final();
}

// As `pagerShown`, for a worker's log: its newest entry, and the second,
// as ages count up.
fn logShown(recent: *const logring.LogRing, now: i64, size: Size) u64 {
    var h = std.hash.Wyhash.init(1);
    h.update(std.mem.asBytes(&recent.count));
    if (recent.count > 0) h.update(std.mem.asBytes(&@intFromPtr(recent.at(recent.count - 1).text.ptr)));
    h.update(std.mem.asBytes(&now));
    h.update(std.mem.asBytes(&size));
    return h.final();
}

// The newest `last` of a worker's recent entries, oldest first, each after
// its age, the conductor's own dim; the lines are slices of `text`.
fn logLines(c: *Conductor, w: *const worker.Worker, last: usize, text: *std.ArrayList(u8), lines: *std.ArrayList([]const u8)) !void {
    const recent = &w.recent;
    if (recent.count == 0) return lines.append(c.allocator, "Nothing logged of this worker yet.");
    const now = c.currentTime();
    const first = recent.count -| last;
    var ends: std.ArrayList(usize) = .empty;
    defer ends.deinit(c.allocator);
    for (first..recent.count) |i| {
        const entry = recent.at(i);
        var age_buf: [16]u8 = undefined;
        try text.print(c.allocator, "\x1b[2m{s:>8}\x1b[0m  {s}{s}\x1b[0m", .{
            ageText(&age_buf, now - entry.at),
            if (entry.source == .conductor) "\x1b[2m" else "",
            entry.text,
        });
        try ends.append(c.allocator, text.items.len);
    }
    var start: usize = 0;
    for (ends.items) |end| {
        try lines.append(c.allocator, text.items[start..end]);
        start = end;
    }
}

// "latest in its log, 3s ago: WARNING: Force throwing a SIGINT", or "".
fn latestEntry(c: *Conductor, w: *const worker.Worker, buf: []u8) []const u8 {
    if (w.recent.count == 0) return "";
    const entry = w.recent.at(w.recent.count - 1);
    var age_buf: [16]u8 = undefined;
    return std.mem.print(buf, "Latest in its log (l), {s}: {s}", .{ ageText(&age_buf, c.currentTime() - entry.at), entry.text }) catch "";
}

fn ageText(buf: []u8, seconds: i64) []const u8 {
    const s: u64 = @intCast(@max(0, seconds));
    return (if (s < 60)
        std.mem.print(buf, "{d}s ago", .{s})
    else if (s < 3600)
        std.mem.print(buf, "{d}m ago", .{s / 60})
    else
        std.mem.print(buf, "{d}h ago", .{s / 3600})) catch "";
}

fn pagerLines(gpa: std.mem.Allocator, snap: *const Snapshot, out: *std.ArrayList([]const u8)) !void {
    if (snap.report) |report| try appendLines(gpa, out, report) else try out.append(gpa, profile_follows);
    try out.append(gpa, "");
    try appendLines(gpa, out, snap.stacks orelse "");
}

fn pagerKey(c: *Conductor, sub: *Subscriber, key: tui.Key) void {
    const page = @as(usize, sub.term.size.rows) -| 2;
    switch (key) {
        .up => sub.scroll -|= 1,
        .down => sub.scroll += 1,
        .page_up => sub.scroll -|= page,
        .page_down => sub.scroll += page,
        .home => sub.scroll = 0,
        .end => sub.scroll = std.math.maxInt(usize) / 2,
        .char => |ch| switch (ch) {
            'g' => sub.scroll = 0,
            'G' => sub.scroll = std.math.maxInt(usize) / 2,
            'q' => return leavePager(c, sub),
            else => return,
        },
        .escape => return leavePager(c, sub),
        else => return,
    }
    repaint(c, sub);
}

fn leavePager(c: *Conductor, sub: *Subscriber) void {
    sub.paging = false;
    sub.term.drawn = 0;
    sub.term.send(c.allocator, main_screen);
    repaint(c, sub);
}

// Sampled a second apart, only while a live view is open; a worker gone
// takes its trend with it.
fn recordTrends(c: *Conductor) void {
    const now = c.currentTime();
    if (now == c.live.trend_at) return;
    c.live.trend_at = now;
    var buf: [64]u32 = undefined;
    var gone: std.ArrayList(u32) = .initBuffer(&buf);
    var it = c.live.trends.keyIterator();
    while (it.next()) |id| if (c.findWorkerById(id.*) == null) gone.appendBounded(id.*) catch break;
    for (gone.items) |id| _ = c.live.trends.remove(id);
    var workers = c.workers.iterator();
    while (workers.next()) |entry| for (entry.value_ptr.items) |w| {
        const trend = c.live.trends.getOrPut(c.allocator, w.id) catch continue;
        if (!trend.found_existing) trend.value_ptr.* = .{};
        trend.value_ptr.record(w.mem, w.cpu.util);
    };
}

fn focusedTrend(c: *Conductor, sub: *const Subscriber) ?*const status.Trend {
    const focus = sub.focus orelse return null;
    const info = c.active_clients.get(focus) orelse return null;
    return c.live.trends.getPtr(info.worker.id);
}

// --- The focused client's session ---

/// Brings the pane's attachment in line with the focus: none without one, a
/// watch of a session client's session, asked again after a beat when
/// its worker was busy or its session unrecorded.
fn retarget(c: *Conductor, sub: *Subscriber) void {
    if (sub.following) return;
    if (sub.target != sub.focus) {
        detach(c, sub);
        sub.target = sub.focus;
        sub.preview = .pending;
        sub.tail.clearRetainingCapacity();
    }
    const focus = sub.focus orelse return;
    if (sub.attachment != null) return;
    const info = c.active_clients.get(focus) orelse return;
    switch (sub.preview) {
        .pending => {},
        .busy, .unrecorded, .failed => |since| if (c.currentTime() - since < 1) return,
        else => return,
    }
    sub.preview = if (info.session) attach(c, sub, info.worker, false) else .unsessioned;
}

fn enterFollow(c: *Conductor, sub: *Subscriber) void {
    const focus = sub.focus orelse return;
    const info = c.active_clients.get(focus) orelse return;
    if (!info.session) return;
    detach(c, sub);
    switch (attach(c, sub, info.worker, true)) {
        .transcript => {},
        else => |failed| {
            sub.preview = failed;
            return repaint(c, sub);
        },
    }
    sub.following = true;
    sub.term.drawn = 0;
    sub.term.send(c.allocator, alternate_screen);
}

// Back to the tree, which the main screen still shows.
fn leaveFollow(c: *Conductor, sub: *Subscriber) void {
    detach(c, sub);
    sub.following = false;
    sub.term.drawn = 0;
    sub.term.send(c.allocator, main_screen);
    sub.target = null;
    retarget(c, sub);
    repaint(c, sub);
}

/// `.transcript` once attached.
fn attach(c: *Conductor, sub: *Subscriber, w: *worker.Worker, follow: bool) Preview {
    if (w.ping_pending or !w.answersWithin(probe_timeout_ms)) return .{ .busy = c.currentTime() };
    const a = openAttachment(c, w, follow) catch |err| {
        std.debug.print("Status: watching worker {d}'s session failed: {}\n", .{ w.id, err });
        return .{ .failed = c.currentTime() };
    };
    sub.attachment = a;
    watch(c, &a.output);
    watch(c, &a.signals);
    return .transcript;
}

fn openAttachment(c: *Conductor, w: *worker.Worker, follow: bool) !*Attachment {
    const port_set = if (c.port_pool) |*pool| pool.allocate() orelse protocol.PortPool.none else protocol.PortPool.none;
    var tracked = false;
    errdefer if (!tracked) c.releasePortSet(port_set);
    c.client_counter += 1;
    const id = c.client_counter;
    const pid: u32 = @intCast(platform.getpid());
    const switches = [_]args.Switch{
        .{ .name = "--watch", .value = if (follow) "" else "recorded", .index = 0, .words = 1 },
        .{ .name = "--session", .value = w.session_label orelse "", .index = 1, .words = 1 },
    };
    const info = worker.ClientInfo{
        .tty = true,
        .color = true,
        .force = true,
        .id = id,
        .key = c.keyFor(.client, id),
        .ppid = 0,
        .cwd = "/",
        .env = &.{},
        .switches = &switches,
        .programfile = null,
        .args = &.{},
        .port_set = port_set,
    };
    const paths = w.runClient(c.allocator, &info, if (c.cfg.transport == .local) c.cfg.socket_dir else null) catch |err| {
        _ = c.handleRunClientError(w, err);
        return err;
    };
    defer paths.deinit(c.allocator);
    var sockets: [4]posix.socket_t = undefined;
    var opened: usize = 0;
    errdefer for (sockets[0..opened]) |s| platform.close(s);
    var key: [8]u8 = undefined;
    std.mem.writeInt(u64, &key, info.key, .little);
    for ([_][]const u8{ paths.stdin, paths.stdout, paths.stderr, paths.signals }) |path| {
        sockets[opened] = try dialWorker(c, path);
        opened += 1;
        platform.write(sockets[opened - 1], &key);
    }
    const a = try c.allocator.create(Attachment);
    errdefer c.allocator.destroy(a);
    try c.trackClient(id, .{ .worker = w, .pid = pid, .port_set = port_set, .watcher = true, .internal = true });
    tracked = true;
    a.* = .{
        .id = id,
        .follow = follow,
        .sockets = sockets,
        .output = .{ .kind = .watch_output, .fd = sockets[1] },
        .signals = .{ .kind = .watch_signals, .fd = sockets[3] },
    };
    return a;
}

// A worker's client socket: a local path, or `:port` on the host it binds.
fn dialWorker(c: *Conductor, address: []const u8) !posix.socket_t {
    if (address.len == 0 or address[0] != ':') return platform.connectLocalOnce(address);
    const bind = c.cfg.bind_address;
    const host = if (std.mem.eql(u8, bind, "0.0.0.0"))
        "127.0.0.1"
    else if (std.mem.eql(u8, bind, "::") or std.mem.eql(u8, bind, "[::]"))
        "[::1]"
    else
        bind;
    const bracketed = host.len > 0 and host[0] != '[' and std.mem.findScalar(u8, host, ':') != null;
    var buf: [300]u8 = undefined;
    const target = try std.mem.print(&buf, "{s}{s}{s}{s}", .{ if (bracketed) "[" else "", host, if (bracketed) "]" else "", address });
    return (try protocol.connectAddress(.tcp, target, protocol.connect_timeout_ms)).socket;
}

// Closing its signals ends the watch, and the worker reports it done.
fn detach(c: *Conductor, sub: *Subscriber) void {
    const a = sub.attachment orelse return;
    sub.attachment = null;
    unwatch(c, &a.output);
    unwatch(c, &a.signals);
    for (a.sockets) |s| platform.close(s);
    c.allocator.destroy(a);
}

fn onWatchOutput(c: *Conductor, sub: *Subscriber, bytes: []const u8) void {
    if (sub.following) return sub.term.send(c.allocator, bytes);
    sub.output_ns = c.nowNs();
    sub.tail.appendSlice(c.allocator, bytes) catch return;
    if (sub.tail.items.len > max_tail_bytes) {
        const over = sub.tail.items.len - max_tail_bytes;
        const cut = if (std.mem.findScalarPos(u8, sub.tail.items, over, '\n')) |i| i + 1 else over;
        sub.tail.replaceRangeAssumeCapacity(0, cut, &.{});
    }
    noteChange(c);
}

// The worker asks what it would ask a client, and says when the watch ends.
fn onWatchSignals(c: *Conductor, sub: *Subscriber, bytes: []const u8) void {
    const a = sub.attachment orelse return;
    for (bytes) |byte| {
        const msg = a.frames.feed(byte) orelse continue;
        switch (msg[0]) {
            protocol.signals.exit => return endAttachment(c, sub, if (msg[1] >= 1) msg[2] else 1),
            protocol.signals.raw_mode => platform.write(a.signals.fd, &[_]u8{ msg[0], 0 }),
            protocol.signals.query_size => {
                var reply = [_]u8{ msg[0], 4, 0, 0, 0, 0 };
                std.mem.writeInt(u16, reply[2..4], sub.term.size.rows, .little);
                std.mem.writeInt(u16, reply[4..6], sub.term.size.cols, .little);
                platform.write(a.signals.fd, &reply);
            },
            else => {},
        }
    }
}

// `code` is null when the worker went without saying: as a finished watch.
fn endAttachment(c: *Conductor, sub: *Subscriber, code: ?u8) void {
    const follow = if (sub.attachment) |a| a.follow else return;
    detach(c, sub);
    if (follow) return leaveFollow(c, sub);
    sub.preview = switch (code orelse 0) {
        0 => .transcript,
        2 => .{ .unrecorded = c.currentTime() },
        else => .{ .failed = c.currentTime() },
    };
    noteChange(c);
}

// --- I/O ---

const watch = terminal.watch;
const unwatch = terminal.unwatch;
const hints = terminal.hints;

// Ends the gone: the shell prompt lands under the last frame.
fn sweep(c: *Conductor) void {
    var i: usize = 0;
    while (i < c.live.list.items.len) {
        const sub = c.live.list.items[i];
        if (!sub.term.gone) {
            i += 1;
            continue;
        }
        _ = c.live.list.swapRemove(i);
        if (!sub.oneshot) detach(c, sub);
        const full_screen = sub.following or sub.paging;
        // A pager cut short may have left its scroll region.
        sub.term.close(c, if (sub.oneshot) null else if (full_screen) "\x1b[r" ++ main_screen ++ "\r\n" else "\r\n");
        sub.tail.deinit(c.allocator);
        c.allocator.free(sub.order);
        c.allocator.destroy(sub);
    }
    // The trends are kept only while a live view is open.
    const viewing = for (c.live.list.items) |sub| {
        if (!sub.oneshot) break true;
    } else false;
    if (!viewing) c.live.trends.clearAndFree(c.allocator);
}
