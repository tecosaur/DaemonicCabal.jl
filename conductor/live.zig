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

const std = @import("std");
const posix = std.posix;
const main = @import("main.zig");
const platform = @import("platform/main.zig");
const protocol = @import("protocol.zig");
const status = @import("status.zig");
const pal = @import("palette.zig");
const tui = @import("tui.zig");

const Conductor = main.Conductor;
const ClientStreams = Conductor.ClientStreams;

const debounce_ms = 100;
const heartbeat_ms = 1000;
const cpu_half_life: f64 = 1.4; // tracks the 1s heartbeat
const max_queued_bytes = 1 << 20;
const cursor_hide = "\x1b[?25l";
const cursor_show = "\x1b[?25h";

/// The low bits of an event-loop tag for a `Watch`, whose address it carries.
pub const tag: usize = 5;

/// A descriptor the event loop watches for a subscriber. Aligned so the
/// tag's low bits are free.
pub const Watch = struct {
    kind: enum { input, signals } align(8),
    fd: posix.socket_t,
};

pub const Subscribers = struct {
    list: std.ArrayList(*Subscriber) = .empty,
    armed: bool = false,
    dirty: bool = false,
};

const Size = struct { rows: u16 = 24, cols: u16 = 80 };

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
    signal_bytes: [16]u8 = undefined, // a partial message from the client
    signal_len: usize = 0,
    size: Size = .{},
    focus: ?u32 = null, // a client id
    focus_row: usize = 0, // its place in the tree, for when it leaves
    order: []u32 = &.{}, // the focusable clients last drawn, top to bottom

    fn stdout(self: *const Subscriber) posix.socket_t {
        return self.streams.fd(.stdout);
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

/// Stale watches, of a subscriber already gone, are ignored.
pub fn onReadable(c: *Conductor, w: *Watch) void {
    const sub = for (c.live.list.items) |s| {
        if (w == &s.input or w == &s.signals) break s;
    } else return;
    var buf: [512]u8 = undefined;
    const n = platform.socketRead(w.fd, &buf);
    if (n == 0) {
        sub.gone = true;
        return sweep(c);
    }
    switch (w.kind) {
        .input => onKeys(c, sub, buf[0..n]),
        .signals => onSignals(sub, buf[0..n]),
    }
    if (sub.gone) return sweep(c);
    watch(c, w);
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
        if (!sub.oneshot) platform.write(sub.streams.fd(.signals), &[_]u8{ protocol.signals.query_size, 0x00 });
        repaint(c, sub);
        if (sub.oneshot) sub.gone = true;
        behind = behind or sub.queued.items.len > 0;
    }
    sweep(c);
    if (c.live.list.items.len == 0) return;
    c.event_loop.armLiveTimer(if (had_change or behind) debounce_ms else heartbeat_ms);
    c.live.armed = true;
}

// A subscriber still behind catches up first, skipping this frame.
fn repaint(c: *Conductor, sub: *Subscriber) void {
    if (sub.queued.items.len > 0) return flushQueued(sub);
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
    try out.appendSlice(c.allocator, report.bytes);
    var lines = report.lines;
    if (sub.focus) |focus| {
        sub.focus_row = std.mem.indexOfScalar(u32, report.clients, focus) orelse 0;
        // The frame stays a row short of the screen, so it never scrolls.
        const rows = @as(usize, sub.size.rows) -| 1 -| lines;
        if (rows >= tui.min_pane_rows) {
            try writePane(c, sub, focus, out, rows);
            lines += rows;
        }
    }
    try out.appendSlice(c.allocator, "\x1b[?2026l");
    c.allocator.free(sub.order);
    sub.order = report.clients;
    report.clients = &.{};
    return lines;
}

fn writePane(c: *Conductor, sub: *Subscriber, focus: u32, out: *std.ArrayList(u8), rows: usize) !void {
    const info = c.active_clients.get(focus) orelse return;
    var title_buf: [256]u8 = undefined;
    const title = std.fmt.bufPrint(&title_buf, "Client {d}{s}{s}{s}", .{
        info.pid,
        if (info.session) (if (info.sync) " · sync session" else " · session") else "",
        if (info.session and info.worker.session_label != null) " " else "",
        if (info.session) info.worker.session_label orelse "" else "",
    }) catch "Client";
    const body: []const []const u8 = if (info.session)
        &.{"The transcript preview is not available yet."}
    else
        &.{"Not a --session client, so nothing is recorded."};
    try tui.writePane(out, c.allocator, true, .{
        .title = title,
        .footer = "↑↓ focus · q quit",
        .body = body,
        .dim_body = true,
    }, sub.size.cols, rows);
}

fn onKeys(c: *Conductor, sub: *Subscriber, bytes: []const u8) void {
    var keys = tui.KeyIterator{ .bytes = bytes };
    const before = sub.focus;
    while (keys.next()) |key| switch (key) {
        .interrupt => {
            sub.gone = true;
            return;
        },
        .char => |ch| if (ch == 'q') {
            sub.gone = true;
            return;
        },
        .up, .down, .escape => sub.focus = tui.moveFocus(sub.order, sub.focus, key),
        else => {},
    };
    if (sub.focus != before) repaint(c, sub);
}

// The client's replies: a raw-mode ack, or the terminal's size.
fn onSignals(sub: *Subscriber, bytes: []const u8) void {
    for (bytes) |byte| {
        if (sub.signal_len == sub.signal_bytes.len) sub.signal_len = 0; // nothing sent is this long
        sub.signal_bytes[sub.signal_len] = byte;
        sub.signal_len += 1;
        const msg = sub.signal_bytes[0..sub.signal_len];
        if (msg.len < 2 or msg.len < 2 + msg[1]) continue;
        if (msg[0] == protocol.signals.query_size and msg[1] == 4) {
            const rows = std.mem.readInt(u16, msg[2..4], .little);
            const cols = std.mem.readInt(u16, msg[4..6], .little);
            sub.size = .{ .rows = rows, .cols = cols };
        }
        sub.signal_len = 0;
    }
}

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
            unwatch(c, &sub.input);
            unwatch(c, &sub.signals);
            _ = platform.sendNonBlocking(sub.stdout(), "\r\n" ++ cursor_show);
        }
        sub.streams.closeForExit(0);
        sub.streams.deinit();
        sub.queued.deinit(c.allocator);
        c.allocator.free(sub.order);
        c.allocator.destroy(sub);
    }
}
