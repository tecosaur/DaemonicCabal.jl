// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0
//
// `--status` redrawn in place at a terminal: the styled one-shot, which waits
// a beat so its CPU meter resolves, and `--status=live`, a small TUI whose
// keys move a focus over the clients and act on it (`STATUS_TUI.md`).
//
// A change with no timer armed repaints at once; a burst only sets `dirty`.
// Each fire re-arms fast if dirty, else at the heartbeat, until no
// subscriber remains. Output never blocks the conductor: what a terminal
// doesn't take is queued, and a subscriber too far behind is dropped.
//
// The focused client's transcript comes from the conductor watching its
// session, as `--watch` does: a plain watch of a recorded session for the
// pane, a colour one relayed whole for following it full-screen.

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

const Conductor = main.Conductor;
const ClientStreams = Conductor.ClientStreams;

const debounce_ms = 100;
const heartbeat_ms = 1000;
const cpu_half_life: f64 = 1.4; // tracks the 1s heartbeat
const max_queued_bytes = 1 << 20;
const probe_timeout_ms = 300; // a worker slower to answer is busy on thread 0
const max_tail_bytes = 64 << 10;
const max_pane_rows = 16; // a preview: ⏎ shows the whole
const cursor_hide = "\x1b[?25l";
const cursor_show = "\x1b[?25h";
const alternate_screen = "\x1b[?1049h\x1b[H\x1b[2J";
const main_screen = "\x1b[0m\x1b[?1049l";

/// The low bits of an event-loop tag for a `Watch`, whose address it carries.
pub const tag: usize = 5;

/// A descriptor the event loop watches for a subscriber. Aligned so the
/// tag's low bits are free.
pub const Watch = struct {
    kind: enum { input, signals, watch_output, watch_signals } align(8),
    fd: posix.socket_t,
};

pub const Subscribers = struct {
    list: std.ArrayList(*Subscriber) = .empty,
    armed: bool = false,
    dirty: bool = false,
};

const Size = struct { rows: u16 = 24, cols: u16 = 80 };

/// What the pane shows of the focused client.
const Preview = union(enum) {
    pending,
    unsessioned, // a plain client: nothing of it is recorded
    busy: i64, // the worker didn't answer, as of then
    unrecorded: i64, // as of then: recording may yet start
    failed: u8, // the watch's exit code
    transcript, // `Subscriber.tail`
};

/// The conductor watching a session for a subscriber.
const Attachment = struct {
    id: u32, // the conductor's own watcher, as tracked
    follow: bool, // relayed whole, rather than kept for the pane
    sockets: [4]posix.socket_t, // stdin, stdout, stderr, signals
    output: Watch,
    signals: Watch,
    frames: SignalFrames = .{},
};

const Subscriber = struct {
    streams: ClientStreams, // held open across repaints
    palette: ?pal.Palette, // probed once at subscribe
    id: u32, // matched for teardown on exit/interrupt
    scope: status.Scope,
    oneshot: bool, // draw one CPU-resolved frame, then disconnect
    lines_last_printed: usize = 0, // for the cursor-up redraw
    queued: std.ArrayList(u8) = .empty, // output the terminal hasn't taken yet
    gone: bool = false,
    // The live view's:
    input: Watch = undefined,
    signals: Watch = undefined,
    frames: SignalFrames = .{},
    size: Size = .{},
    focus: ?u32 = null, // a client id
    focus_row: usize = 0, // its place in the tree, for when it leaves
    order: []u32 = &.{}, // the focusable clients last drawn, top to bottom
    following: bool = false, // the focused session, full-screen
    target: ?u32 = null, // the client `preview` and `tail` are of
    preview: Preview = .pending,
    tail: std.ArrayList(u8) = .empty,
    attachment: ?*Attachment = null,

    fn stdout(self: *const Subscriber) posix.socket_t {
        return self.streams.fd(.stdout);
    }
};

/// Messages framed `id len data`, as a signals socket carries them.
const SignalFrames = struct {
    bytes: [16]u8 = undefined,
    len: usize = 0,

    /// The message `byte` completes, if any.
    fn feed(self: *SignalFrames, byte: u8) ?[]const u8 {
        if (self.len == self.bytes.len) self.len = 0; // nothing sent is this long
        self.bytes[self.len] = byte;
        self.len += 1;
        const msg = self.bytes[0..self.len];
        if (msg.len < 2 or msg.len < 2 + msg[1]) return null;
        self.len = 0;
        return msg;
    }
};

/// Takes `streams`. A live subscriber's first frame is drawn at once.
pub fn subscribe(c: *Conductor, streams: ClientStreams, palette: ?pal.Palette, scope: status.Scope, oneshot: bool) !void {
    const sub = try c.allocator.create(Subscriber);
    errdefer c.allocator.destroy(sub);
    sub.* = .{ .streams = streams, .palette = palette, .id = c.client_counter, .scope = scope, .oneshot = oneshot };
    try c.live.list.append(c.allocator, sub);
    if (oneshot) {
        c.refreshStats(null); // first reading; the deferred fire takes the second
        c.event_loop.armLiveTimer(debounce_ms);
        c.live.armed = true;
        return;
    }
    // Raw, so keys arrive as they are pressed; the probe left it so already.
    const signals = streams.fd(.signals);
    platform.write(signals, &[_]u8{ protocol.signals.raw_mode, 0x01, 0x01 });
    platform.write(signals, &[_]u8{ protocol.signals.query_size, 0x00 });
    sub.input = .{ .kind = .input, .fd = streams.fd(.stdin) };
    sub.signals = .{ .kind = .signals, .fd = signals };
    watch(c, &sub.input);
    watch(c, &sub.signals);
    send(c, sub, cursor_hide);
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
    for (c.live.list.items) |sub| if (sub.id == id) {
        sub.gone = true;
        sweep(c);
        return true;
    };
    return false;
}

pub fn deinit(c: *Conductor) void {
    for (c.live.list.items) |sub| sub.gone = true;
    sweep(c);
    c.live.list.deinit(c.allocator);
}

/// Stale watches, of a subscriber or attachment already gone, are ignored.
/// Reads never wait, so a stale readiness costs nothing.
pub fn onReadable(c: *Conductor, w: *Watch) void {
    const sub = for (c.live.list.items) |s| {
        if (w == &s.input or w == &s.signals) break s;
        if (s.attachment) |a| if (w == &a.output or w == &a.signals) break s;
    } else return;
    var buf: [16 << 10]u8 = undefined;
    const n = platform.recvNonBlocking(w.fd, &buf) orelse {
        switch (w.kind) {
            .input, .signals => sub.gone = true,
            .watch_output => {}, // the verdict comes on its signals
            .watch_signals => endAttachment(c, sub, null),
        }
        if (sub.gone) sweep(c);
        return;
    };
    const bytes = buf[0..n];
    switch (w.kind) {
        .input => onKeys(c, sub, bytes),
        .signals => onClientSignals(sub, bytes),
        .watch_output => onWatchOutput(c, sub, bytes),
        .watch_signals => onWatchSignals(c, sub, bytes),
    }
    if (sub.gone) return sweep(c);
    // Unless the reading ended what it watched.
    const still = w == &sub.input or w == &sub.signals or
        if (sub.attachment) |a| w == &a.output or w == &a.signals else false;
    if (still) watch(c, w);
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
    var behind = false;
    for (c.live.list.items) |sub| {
        if (!sub.oneshot) {
            platform.write(sub.streams.fd(.signals), &[_]u8{ protocol.signals.query_size, 0x00 });
            retarget(c, sub);
        }
        repaint(c, sub);
        if (sub.oneshot) sub.gone = true;
        behind = behind or sub.queued.items.len > 0;
    }
    sweep(c);
    if (c.live.list.items.len == 0) return;
    c.event_loop.armLiveTimer(if (had_change or behind) debounce_ms else heartbeat_ms);
    c.live.armed = true;
}

// A subscriber still behind catches up first, skipping this frame; one
// following a session gets only its output.
fn repaint(c: *Conductor, sub: *Subscriber) void {
    if (sub.queued.items.len > 0) return flushQueued(sub);
    if (sub.following) return;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(c.allocator);
    const lines = composeFrame(c, sub, &out) catch |err| {
        std.debug.print("Status: render failed: {}\n", .{err});
        return;
    };
    send(c, sub, out.items);
    sub.lines_last_printed = lines;
}

// DEC 2026 synchronised update, so no tearing; ESC[<n>F returns to the
// frame's top and ESC[0J clears any tail. Returns the frame's lines.
fn composeFrame(c: *Conductor, sub: *Subscriber, out: *std.ArrayList(u8)) !usize {
    var report = try c.renderStatus("live", true, sub.palette, sub.scope, sub.focus);
    const kept = tui.keepFocus(report.clients, sub.focus, sub.focus_row);
    if (kept != sub.focus) {
        sub.focus = kept;
        const again = c.renderStatus("live", true, sub.palette, sub.scope, sub.focus) catch |err| {
            report.deinit(c.allocator);
            return err;
        };
        report.deinit(c.allocator);
        report = again;
    }
    defer report.deinit(c.allocator);
    try out.appendSlice(c.allocator, "\x1b[?2026h");
    if (sub.lines_last_printed > 0) try out.print(c.allocator, "\x1b[{d}F\x1b[0J", .{sub.lines_last_printed});
    var lines = report.lines;
    const placed = if (sub.focus) |focus| placed: {
        sub.focus_row = std.mem.indexOfScalar(u32, report.clients, focus) orelse 0;
        break :placed report.placement;
    } else null;
    // The pane goes under the focused row; the frame stays a row short of
    // the screen, so it never scrolls.
    const rows = @min(max_pane_rows, @as(usize, sub.size.rows) -| 1 -| lines);
    if (placed != null and rows >= tui.min_pane_rows) {
        const at = placed.?;
        try out.appendSlice(c.allocator, report.bytes[0..at.at]);
        try writePane(c, sub, sub.focus.?, out, at, rows);
        try out.appendSlice(c.allocator, report.bytes[at.at..]);
        lines += rows;
    } else {
        try out.appendSlice(c.allocator, report.bytes);
    }
    try out.appendSlice(c.allocator, "\x1b[?2026l");
    c.allocator.free(sub.order);
    sub.order = report.clients;
    report.clients = &.{};
    return lines;
}

fn writePane(c: *Conductor, sub: *Subscriber, focus: u32, out: *std.ArrayList(u8), at: status.Placement, rows: usize) !void {
    const info = c.active_clients.get(focus) orelse return;
    const label = info.worker.session_label;
    var title_buf: [256]u8 = undefined;
    const title = std.fmt.bufPrint(&title_buf, "Client {d}{s}{s}{s}{s}{s}", .{
        info.pid,
        if (!info.session) "" else if (info.sync) " · sync session" else " · session",
        if (label != null and info.session) " \"" else "",
        if (info.session) label orelse "" else "",
        if (label != null and info.session) "\"" else "",
        if (sub.preview == .transcript) " · transcript" else "",
    }) catch "Client";
    var lines_buf: [256][]const u8 = undefined;
    const body: []const []const u8 = switch (sub.preview) {
        .pending => &.{},
        .unsessioned => &.{"Not a --session client, so nothing of it is recorded."},
        .busy => &.{"Its worker is busy, so the transcript waits until it yields."},
        .unrecorded => &.{
            "This session isn't being recorded.",
            "⏎ follows it, recording from then on; JULIA_DAEMON_RECORD records sessions from their start.",
        },
        .failed => &.{"Its transcript is unavailable (see the conductor's log)."},
        .transcript => if (sub.tail.items.len == 0)
            &.{"Nothing recorded yet."}
        else
            tui.lastLines(sub.tail.items, lines_buf[0..@min(lines_buf.len, rows - 2)]),
    };
    try tui.writePane(out, c.allocator, true, .{
        .title = title,
        .footer = if (info.session) "↑↓ focus · ⏎ follow · q quit" else "↑↓ focus · q quit",
        .body = body,
        .dim_body = sub.preview != .transcript or sub.tail.items.len == 0,
        .gutter = &at.gutter,
    }, @as(usize, sub.size.cols) -| at.gutter_cols, rows);
}

fn onKeys(c: *Conductor, sub: *Subscriber, bytes: []const u8) void {
    var keys = tui.KeyIterator{ .bytes = bytes };
    while (keys.next()) |key| {
        if (key == .interrupt) {
            sub.gone = true;
            return;
        }
        if (sub.following) {
            const leave = key == .escape or (key == .char and key.char == 'q');
            if (leave) leaveFollow(c, sub);
            continue;
        }
        switch (key) {
            .char => |ch| if (ch == 'q') {
                sub.gone = true;
                return;
            },
            .up, .down, .escape => {
                sub.focus = tui.moveFocus(sub.order, sub.focus, key);
                retarget(c, sub);
                repaint(c, sub);
            },
            .enter => enterFollow(c, sub),
            else => {},
        }
    }
}

// The client's replies: a raw-mode ack, or the terminal's size.
fn onClientSignals(sub: *Subscriber, bytes: []const u8) void {
    for (bytes) |byte| {
        const msg = sub.frames.feed(byte) orelse continue;
        if (msg[0] == protocol.signals.query_size and msg[1] == 4) sub.size = .{
            .rows = std.mem.readInt(u16, msg[2..4], .little),
            .cols = std.mem.readInt(u16, msg[4..6], .little),
        };
    }
}

// --- The focused client's session ---

/// Brings the pane's attachment in line with the focus: none without one, a
/// plain watch of a session client's session, asked again after a beat when
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
        .busy, .unrecorded => |since| if (c.currentTime() - since < 1) return,
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
    send(c, sub, alternate_screen);
}

// Back to the tree, which the main screen still shows.
fn leaveFollow(c: *Conductor, sub: *Subscriber) void {
    detach(c, sub);
    sub.following = false;
    send(c, sub, main_screen ++ cursor_hide);
    sub.target = null;
    retarget(c, sub);
    repaint(c, sub);
}

/// `.transcript` once attached.
fn attach(c: *Conductor, sub: *Subscriber, w: *worker.Worker, follow: bool) Preview {
    if (w.ping_pending or !w.answersWithin(probe_timeout_ms)) return .{ .busy = c.currentTime() };
    const a = openAttachment(c, w, follow) catch |err| {
        std.debug.print("Status: watching worker {d}'s session failed: {}\n", .{ w.id, err });
        return .{ .failed = 1 };
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
        .tty = follow,
        .color = follow,
        .force = true,
        .id = id,
        .pid = pid,
        .host_pid = null,
        .ppid = 0,
        .cwd = "/",
        .env = &.{},
        .switches = &switches,
        .programfile = null,
        .args = &.{},
        .port_set = port_set,
    };
    const paths = w.runClient(c.allocator, &info) catch |err| {
        _ = c.handleRunClientError(w, err);
        return err;
    };
    defer for ([_][]const u8{ paths.stdin, paths.stdout, paths.stderr, paths.signals }) |p| c.allocator.free(p);
    var sockets: [4]posix.socket_t = undefined;
    var opened: usize = 0;
    errdefer for (sockets[0..opened]) |s| platform.close(s);
    for ([_][]const u8{ paths.stdin, paths.stdout, paths.stderr, paths.signals }) |path| {
        sockets[opened] = try dialWorker(c, path);
        opened += 1;
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
    const bracketed = host.len > 0 and host[0] != '[' and std.mem.indexOfScalar(u8, host, ':') != null;
    var buf: [300]u8 = undefined;
    const target = try std.fmt.bufPrint(&buf, "{s}{s}{s}{s}", .{ if (bracketed) "[" else "", host, if (bracketed) "]" else "", address });
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
    if (sub.following) return send(c, sub, bytes);
    sub.tail.appendSlice(c.allocator, bytes) catch return;
    if (sub.tail.items.len > max_tail_bytes) {
        const over = sub.tail.items.len - max_tail_bytes;
        const cut = if (std.mem.indexOfScalarPos(u8, sub.tail.items, over, '\n')) |i| i + 1 else over;
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
                std.mem.writeInt(u16, reply[2..4], sub.size.rows, .little);
                std.mem.writeInt(u16, reply[4..6], sub.size.cols, .little);
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
        else => |n| .{ .failed = n },
    };
    noteChange(c);
}

// --- I/O ---

fn watch(c: *Conductor, w: *Watch) void {
    c.event_loop.watchFd(@intFromPtr(w) | tag, w.fd);
}

fn unwatch(c: *Conductor, w: *Watch) void {
    c.event_loop.unwatchFd(@intFromPtr(w) | tag, w.fd);
}

fn send(c: *Conductor, sub: *Subscriber, bytes: []const u8) void {
    var rest = bytes;
    if (sub.queued.items.len == 0) {
        const n = platform.sendNonBlocking(sub.stdout(), rest) orelse {
            sub.gone = true;
            return;
        };
        rest = rest[n..];
    }
    if (rest.len == 0) return;
    sub.queued.appendSlice(c.allocator, rest) catch {
        sub.gone = true;
        return;
    };
    if (sub.queued.items.len > max_queued_bytes) sub.gone = true;
}

fn flushQueued(sub: *Subscriber) void {
    const n = platform.sendNonBlocking(sub.stdout(), sub.queued.items) orelse {
        sub.gone = true;
        return;
    };
    sub.queued.replaceRangeAssumeCapacity(0, n, &.{});
}

// Ends the gone: the shell prompt lands under the last frame.
fn sweep(c: *Conductor) void {
    var i: usize = 0;
    while (i < c.live.list.items.len) {
        const sub = c.live.list.items[i];
        if (!sub.gone) {
            i += 1;
            continue;
        }
        _ = c.live.list.swapRemove(i);
        if (!sub.oneshot) {
            detach(c, sub);
            unwatch(c, &sub.input);
            unwatch(c, &sub.signals);
            const leaving = if (sub.following) main_screen ++ "\r\n" ++ cursor_show else "\r\n" ++ cursor_show;
            _ = platform.sendNonBlocking(sub.stdout(), leaving);
        }
        sub.streams.closeForExit(0);
        sub.streams.deinit();
        sub.queued.deinit(c.allocator);
        sub.tail.deinit(c.allocator);
        c.allocator.free(sub.order);
        c.allocator.destroy(sub);
    }
}
