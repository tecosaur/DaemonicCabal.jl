// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0
//
// `--reconfigure`: the daemon's settings in tabs, changed in the running
// conductor and saved to its service (`RECONFIGURE.md`). This is the
// conductor's side: viewers, their keys, and what applying and saving do.
// The changes themselves are `changes.zig`'s; the frame, `reconfigure_view.zig`'s.
//
// Applying a setting read as workers start puts it in the environment they
// inherit, and replaces the reserve worker; one read only as the conductor
// starts waits for its restart.

const std = @import("std");
const Allocator = std.mem.Allocator;
const main = @import("main.zig");
const settings = @import("settings.zig");
const changes = @import("changes.zig");
const service = @import("service.zig");
const terminal = @import("terminal.zig");
const tui = @import("tui.zig");
const view = @import("reconfigure_view.zig");
const platform = @import("platform/main.zig");
const protocol = @import("protocol.zig");
const pal = @import("palette.zig");

const Conductor = main.Conductor;
const all = settings.all;
const tabs = settings.tabs;

const settle_ns = 700 * std.time.ns_per_ms; // unchanged this long, a typed path is checked whole
const reload_timeout_ns = 10 * std.time.ns_per_s; // the service manager's reread, before it's given up on
const reserve_key = settings.Setting.index("JULIA_DAEMON_RESERVE_WORKER");

/// The settings as the conductor holds them, the service that saves them,
/// and the views of them open.
pub const Settings = struct {
    model: changes.State,
    service: ?service.Service,
    viewers: std.ArrayList(*Viewer) = .empty,
    reloading: ?Reload = null,

    /// The service's file, when named, is read now for what it declares:
    /// the rest of the environment was inherited from what started it.
    pub fn init(gpa: Allocator, io: std.Io, env: *const std.process.Environ.Map) !Settings {
        const svc = if (env.get("JULIA_DAEMON_SERVICE")) |spec| service.Service.parse(spec) else null;
        var declared = service.Declared.init(gpa);
        defer declared.deinit();
        const read = if (svc) |s| if (service.load(gpa, io, s, &declared)) |_| true else |err| blk: {
            std.debug.print("Settings: couldn't read {s}: {}; taking the environment as its\n", .{ s.path, err });
            break :blk false;
        } else false;
        return .{ .model = try .init(gpa, env, if (read) &declared else null), .service = svc };
    }

    pub fn deinit(self: *Settings, gpa: Allocator) void {
        self.model.deinit(gpa);
        self.viewers.deinit(gpa);
    }
};

/// The service manager rereading a save, run apart so it can't hold the
/// conductor up.
const Reload = struct {
    child: std.process.Child,
    started_ns: i64,
};

const Viewer = struct {
    term: terminal.Terminal,
    styles: view.Styles,
    tab: usize = 0,
    focus: [tabs.len]usize = view.first_settings, // a setting's index, per tab
    staged: changes.Staged = .{},
    applied: changes.Applied = .initEmpty(), // by this viewer, for its farewell
    editor: ?Editor = null, // the focused setting's value, being typed
    message: Message = .{}, // until the next key
    asking: bool = false, // whether to save before quitting
    cursor_line: usize = 0, // the frame's line the terminal's cursor is on

    fn deinit(self: *Viewer, gpa: Allocator) void {
        self.staged.deinit(gpa);
        if (self.editor) |*e| e.deinit(gpa);
    }
};

const Editor = struct {
    text: std.ArrayList(u8) = .empty,
    cursor: usize = 0, // a byte offset, at a character's start
    origin: std.ArrayList(u8) = .empty, // what stepping began from, until typed over
    stepping: bool = false,
    changed_ns: i64 = 0, // as the text last changed
    settled: bool = true, // unchanged for `settle_ns` since
    check: view.Check = .{},

    fn deinit(self: *Editor, gpa: Allocator) void {
        self.text.deinit(gpa);
        self.origin.deinit(gpa);
    }
};

/// A line or more for the viewer: what an action did, or why it didn't.
const Message = struct {
    kind: enum { none, note, problem } = .none,
    bytes: [1024]u8 = undefined,
    len: usize = 0,

    fn set(self: *Message, kind: @FieldType(Message, "kind"), comptime fmt: []const u8, fmt_args: anytype) void {
        self.kind = kind;
        self.len = if (std.fmt.bufPrint(&self.bytes, fmt, fmt_args)) |t| t.len else |_| self.bytes.len;
    }
};

/// Takes `streams`, the terminal of a client allowed to reconfigure, and
/// its `palette` when it answered for one.
pub fn subscribe(c: *Conductor, streams: Conductor.ClientStreams, palette: ?pal.Palette) !void {
    const v = try c.allocator.create(Viewer);
    errdefer c.allocator.destroy(v);
    v.* = .{ .term = .{ .streams = streams, .palette = palette, .id = c.client_counter }, .styles = .of(palette) };
    try c.settings.viewers.append(c.allocator, v);
    if (c.settings.viewers.items.len == 1) rereadService(c, v);
    v.term.open(c);
    v.term.send(c.allocator, view.view_start);
    repaint(c, v);
}

/// The settings, one `KEY=value` a line: for a client that isn't a terminal.
pub fn listing(gpa: Allocator, s: *const Settings) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    for (tabs) |tab| {
        try out.print(gpa, "# {s}\n", .{tab.title()});
        for (all, 0..) |setting, i| {
            if (setting.tab != tab) continue;
            if (s.model.applied[i] orelse setting.default) |value|
                try out.print(gpa, "{s}={s}\n", .{ setting.key, value })
            else
                try out.print(gpa, "# {s} unset: {s}\n", .{ setting.key, setting.unset });
        }
    }
    return out.toOwnedSlice(gpa);
}

/// A watch that isn't one of its viewers' is left alone.
pub fn onReadable(c: *Conductor, w: *terminal.Watch) void {
    const v = for (c.settings.viewers.items) |v| {
        if (w == &v.term.input or w == &v.term.signals) break v;
    } else return;
    var buf: [4096]u8 = undefined;
    const n = platform.recvNonBlocking(w.fd, &buf) orelse {
        v.term.gone = true;
        return sweep(c);
    };
    switch (w.kind) {
        .input => onKeys(c, v, buf[0..n]),
        .signals => {
            const was = v.term.size;
            v.term.onSignals(buf[0..n]);
            if (!std.meta.eql(was, v.term.size)) repaint(c, v);
        },
        .watch_output, .watch_signals => {},
    }
    if (v.term.gone) return sweep(c);
    terminal.watch(c, w);
}

/// A second's tick: a path typed and left alone is checked whole, and the
/// service manager's reread is waited on. Returns whether either still is.
pub fn onTick(c: *Conductor) bool {
    const now = c.nowNs();
    var waiting = false;
    for (c.settings.viewers.items) |v| {
        const e = if (v.editor) |*e| e else continue;
        if (e.settled) continue;
        if (now - e.changed_ns < settle_ns) {
            waiting = true;
            continue;
        }
        e.settled = true;
        checkEditor(c, v);
        repaint(c, v);
    }
    if (c.settings.reloading != null) waiting = !pollReload(c, now) or waiting;
    sweep(c);
    return waiting;
}

/// A client's exit or interrupt, when it is a viewer's.
pub fn dropById(c: *Conductor, id: u32) bool {
    for (c.settings.viewers.items) |v| if (v.term.id == id) {
        v.term.gone = true;
        sweep(c);
        return true;
    };
    return false;
}

pub fn deinit(c: *Conductor) void {
    for (c.settings.viewers.items) |v| v.term.gone = true;
    sweep(c);
    if (c.settings.reloading) |*r| {
        _ = platform.kill(r.child.id.?, platform.SIG.KILL);
        platform.waitForExit(r.child.id.?);
    }
    c.settings.deinit(c.allocator);
}

// What the service declares, read afresh as the first view opens.
fn rereadService(c: *Conductor, v: *Viewer) void {
    const svc = c.settings.service orelse return;
    var declared = service.Declared.init(c.allocator);
    defer declared.deinit();
    service.load(c.allocator, c.io, svc, &declared) catch |err| {
        v.message.set(.problem, "Couldn't read {s}: {s}", .{ svc.path, reason(err) });
        return;
    };
    c.settings.model.reread(c.allocator, &declared) catch {};
}

// --- Keys ---

fn onKeys(c: *Conductor, v: *Viewer, bytes: []const u8) void {
    var keys = tui.KeyIterator{ .bytes = bytes };
    while (keys.next()) |key| {
        if (key == .interrupt) {
            v.term.gone = true;
            return;
        }
        v.message.kind = .none;
        if (v.asking) {
            v.asking = false;
            switch (key) {
                .char => |ch| if (ch == 'y') {
                    if (apply(c, v) and (c.settings.service == null or save(c, v))) v.term.gone = true;
                } else if (ch == 'n') {
                    v.term.gone = true;
                },
                else => {},
            }
        } else if (v.editor != null) {
            editKey(c, v, key);
        } else {
            browseKey(c, v, key);
        }
        if (v.term.gone) return;
    }
    v.term.querySize(); // a resize redraws as it's answered
    repaint(c, v);
}

fn browseKey(c: *Conductor, v: *Viewer, key: tui.Key) void {
    const model = &c.settings.model;
    const i = v.focus[v.tab];
    switch (key) {
        .left, .back_tab => v.tab = (v.tab + tabs.len - 1) % tabs.len,
        .right, .tab => v.tab = (v.tab + 1) % tabs.len,
        .up, .down => v.focus[v.tab] = moveFocus(tabs[v.tab], i, key == .down),
        .escape => quit(c, v),
        .enter => edit(c, v, i),
        .char => |ch| switch (ch) {
            ' ' => edit(c, v, i),
            'd' => v.staged.stage(c.allocator, model, i, null) catch {},
            'u' => v.staged.undo(c.allocator, model, i) catch {},
            'a' => _ = apply(c, v),
            'w' => if (apply(c, v)) {
                _ = save(c, v);
            },
            'r' => if (pendingOf(c, v).retirable) {
                const n = c.retireIdleWorkers(model.workers_changed_ns);
                v.message.set(.note, "Retired {d} idle worker{s} with the old settings: those that follow have the new.", .{ n, if (n == 1) "" else "s" });
            },
            'q' => quit(c, v),
            else => {},
        },
        else => {},
    }
}

// Asking first when that would lose something.
fn quit(c: *const Conductor, v: *Viewer) void {
    if (pendingOf(c, v).asks()) v.asking = true else v.term.gone = true;
}

// A choice cycles; anything else opens the editor on its value as shown.
fn edit(c: *Conductor, v: *Viewer, i: usize) void {
    const s = &all[i];
    if (s.effect == .fixed) return v.message.set(.note, "DaemonicCabal.install() sets this.", .{});
    const value = v.staged.effective(&c.settings.model, i);
    const cycled: ?[]const u8 = switch (s.kind) {
        .flag => if (settings.isOn(value orelse s.default.?)) "0" else "1",
        .choice => |options| blk: {
            const now = value orelse s.default.?;
            const at = for (options, 0..) |option, k| {
                if (std.mem.eql(u8, option, now)) break k;
            } else options.len - 1;
            break :blk options[(at + 1) % options.len];
        },
        else => null,
    };
    if (cycled) |next| return v.staged.stage(c.allocator, &c.settings.model, i, next) catch {};
    var editor: Editor = .{};
    var buf: [128]u8 = undefined;
    const shown = if (value != null or s.default != null) settings.display(s, value, &buf) else "";
    editor.text.appendSlice(c.allocator, shown) catch return;
    editor.cursor = shown.len;
    v.editor = editor;
    checkEditor(c, v);
}

fn editKey(c: *Conductor, v: *Viewer, key: tui.Key) void {
    const e = &v.editor.?;
    const i = v.focus[v.tab];
    const before = std.hash.Wyhash.hash(0, e.text.items);
    defer if (v.editor) |*after| if (std.hash.Wyhash.hash(0, after.text.items) != before) {
        after.changed_ns = c.nowNs();
        after.settled = false;
        c.event_loop.armTick();
        checkEditor(c, v);
    };
    // Typing over a stepped value starts stepping afresh from what's typed.
    switch (key) {
        .backspace, .delete, .char, .text => e.stepping = false,
        else => {},
    }
    switch (key) {
        .escape => closeEditor(c, v),
        .enter => {
            var buf: [256]u8 = undefined;
            const value = settings.normalise(&all[i], e.text.items, &buf) catch return; // its row says why
            closeEditor(c, v);
            v.staged.stage(c.allocator, &c.settings.model, i, value) catch {};
        },
        .up, .down => {
            if (!e.stepping) {
                e.origin.clearRetainingCapacity();
                e.origin.appendSlice(c.allocator, e.text.items) catch return;
                e.stepping = true;
            }
            var buf: [64]u8 = undefined;
            const next = settings.step(&all[i], e.text.items, key == .up, e.origin.items, &buf) orelse return;
            e.text.clearRetainingCapacity();
            e.text.appendSlice(c.allocator, next) catch return;
            e.cursor = next.len;
        },
        .left => e.cursor = charBefore(e.text.items, e.cursor),
        .right => e.cursor = charAfter(e.text.items, e.cursor),
        .home => e.cursor = 0,
        .end => e.cursor = e.text.items.len,
        .backspace => if (e.cursor > 0) {
            const start = charBefore(e.text.items, e.cursor);
            e.text.replaceRangeAssumeCapacity(start, e.cursor - start, &.{});
            e.cursor = start;
        },
        .delete => if (e.cursor < e.text.items.len) {
            e.text.replaceRangeAssumeCapacity(e.cursor, charAfter(e.text.items, e.cursor) - e.cursor, &.{});
        },
        .char => |ch| insert(c.allocator, e, &.{ch}),
        .text => |bytes| insert(c.allocator, e, bytes),
        else => {},
    }
}

fn insert(gpa: Allocator, e: *Editor, bytes: []const u8) void {
    if (e.text.items.len + bytes.len > 200) return;
    e.text.insertSlice(gpa, e.cursor, bytes) catch return;
    e.cursor += bytes.len;
}

// The start of the character before, or after, byte `at`.
fn charBefore(text: []const u8, at: usize) usize {
    var i = at -| 1;
    while (i > 0 and text[i] & 0xc0 == 0x80) i -= 1;
    return i;
}

fn charAfter(text: []const u8, at: usize) usize {
    var i = @min(at + 1, text.len);
    while (i < text.len and text[i] & 0xc0 == 0x80) i += 1;
    return i;
}

fn closeEditor(c: *Conductor, v: *Viewer) void {
    v.editor.?.deinit(c.allocator);
    v.editor = null;
}

// The next setting of `tab` down (or up) from `i`, else `i`.
fn moveFocus(tab: settings.Tab, i: usize, down: bool) usize {
    var j = i;
    while (if (down) j + 1 < all.len else j > 0) {
        j = if (down) j + 1 else j - 1;
        if (all[j].tab == tab) return j;
    }
    return i;
}

// --- Applying and saving ---

/// The staged changes into the conductor, if they break no rule together.
fn apply(c: *Conductor, v: *Viewer) bool {
    const s = &c.settings;
    const outcome = s.model.apply(c.allocator, &v.staged) catch {
        v.message.set(.problem, "Not applied: out of memory.", .{});
        return false;
    };
    const applied = switch (outcome) {
        .conflict => |conflict| {
            const values = v.staged.values(&s.model);
            var buf: [2][64]u8 = undefined;
            switch (conflict) {
                .positive => |i| v.message.set(.problem, "Not applied: {s} must be above 0.", .{all[i].label}),
                .ordered => |o| v.message.set(.problem, "Not applied: {s} ({s}) must be below {s} ({s}).", .{
                    all[o.below].label, settings.display(&all[o.below], values[o.below], &buf[0]),
                    all[o.above].label, settings.display(&all[o.above], values[o.above], &buf[1]),
                }),
            }
            return false;
        },
        .applied => |applied| applied,
    };
    const count = applied.count();
    if (count == 0) return true;
    v.applied.setUnion(applied);
    var renew = false;
    var it = applied.iterator(.{});
    while (it.next()) |i| {
        const key = all[i].key;
        const value = s.model.applied[i];
        if (all[i].effect != .restart) {
            if (value) |text| c.environ_map.put(key, text) catch |err| {
                std.debug.print("Settings: {s} not passed to new workers: {}\n", .{ key, err });
            } else _ = c.environ_map.swapRemove(key);
            if (all[i].alias) |alias| _ = c.environ_map.swapRemove(alias);
        }
        std.debug.print("Settings: {s}={s} applied\n", .{ key, value orelse "(unset)" });
        renew = renew or all[i].effect == .new_workers or i == reserve_key;
    }
    c.cfg.reload(c.environ_map) catch |err| std.debug.print("Settings: rereading them failed: {}\n", .{err});
    if (renew) {
        s.model.workers_changed_ns = c.nowNs();
        c.renewReserve();
    }
    v.message.set(.note, "Applied {d} change{s}.", .{ count, if (count == 1) "" else "s" });
    for (s.viewers.items) |other| if (other != v) {
        other.staged.prune(c.allocator, &s.model);
        repaint(c, other);
    };
    return true;
}

/// The applied changes to the service; without one, how to keep them.
fn save(c: *Conductor, v: *Viewer) bool {
    const s = &c.settings;
    var buf: [2 * all.len]service.Change = undefined;
    const to_save = s.model.changesToSave(&buf);
    if (to_save.len == 0) {
        v.message.set(.note, "Nothing to save.", .{});
        return true;
    }
    const svc = s.service orelse {
        noServiceMessage(&v.message, to_save);
        return false;
    };
    var target_buf: [std.fs.max_path_bytes]u8 = undefined;
    const target = svc.target(&target_buf);
    var shown_buf: [std.fs.max_path_bytes]u8 = undefined;
    const shown = homeRelative(c, target, &shown_buf);
    service.save(c.allocator, c.io, svc, to_save) catch |err| {
        std.debug.print("Settings: saving to {s} failed: {}\n", .{ target, err });
        v.message.set(.problem, "Couldn't save to {s}: {s}.", .{ shown, reason(err) });
        return false;
    };
    s.model.markSaved(c.allocator) catch {};
    std.debug.print("Settings: saved to {s}\n", .{target});
    if (svc.kind.rereadNote()) |note|
        v.message.set(.note, "Saved to {s}; {s}.", .{ shown, note })
    else
        v.message.set(.note, "Saved to {s}.", .{shown});
    if (svc.kind.reloadCommand()) |argv| startReload(c, argv);
    for (s.viewers.items) |other| if (other != v) repaint(c, other);
    return true;
}

// Run apart; `onTick` waits on it.
fn startReload(c: *Conductor, argv: []const []const u8) void {
    const s = &c.settings;
    if (s.reloading != null) return; // it rereads everything saved so far
    const child = std.process.spawn(c.io, .{ .argv = argv, .stdin = .ignore, .stdout = .ignore, .stderr = .ignore }) catch |err| {
        return reloadFailed(c, err);
    };
    s.reloading = .{ .child = child, .started_ns = c.nowNs() };
    c.event_loop.armTick();
}

// Whether it's done with.
fn pollReload(c: *Conductor, now: i64) bool {
    const r = &c.settings.reloading.?;
    const pid = r.child.id.?;
    const ok = platform.pollExit(pid) orelse {
        if (now - r.started_ns < reload_timeout_ns) return false;
        _ = platform.kill(pid, platform.SIG.KILL);
        platform.waitForExit(pid);
        c.settings.reloading = null;
        reloadFailed(c, error.Timeout);
        return true;
    };
    c.settings.reloading = null;
    if (!ok) reloadFailed(c, error.Failed);
    return true;
}

fn reloadFailed(c: *Conductor, err: anyerror) void {
    std.debug.print("Settings: systemctl --user daemon-reload failed: {}\n", .{err});
    for (c.settings.viewers.items) |v| {
        v.message.set(.problem, "Saved, but systemctl --user daemon-reload failed: run it before restarting.", .{});
        repaint(c, v);
    }
}

// "~/…" for a path within the home directory.
fn homeRelative(c: *const Conductor, path: []const u8, buf: []u8) []const u8 {
    const home = c.cfg.host_home;
    const within = home.len > 0 and path.len > home.len and std.mem.startsWith(u8, path, home) and path[home.len] == '/';
    if (!within) return path;
    return std.fmt.bufPrint(buf, "~{s}", .{path[home.len..]}) catch path;
}

fn noServiceMessage(message: *Message, to_save: []const service.Change) void {
    var w = std.Io.Writer.fixed(&message.bytes);
    w.writeAll("No service started the conductor, so nothing can save these. Set them where it starts:") catch {};
    for (to_save) |change| {
        if (change.value) |value| w.print("\n{s}={s}", .{ change.key, value }) catch {} else w.print("\nunset {s}", .{change.key}) catch {};
    }
    message.kind = .problem;
    message.len = w.end;
}

fn reason(err: anyerror) []const u8 {
    return switch (err) {
        error.FileNotFound => "it isn't there",
        error.AccessDenied, error.PermissionDenied => "permission denied",
        error.Unrecognised => "it isn't as DaemonicCabal.install() wrote it",
        error.Unwritable => "a value holds a line break",
        else => @errorName(err),
    };
}

// --- The editor's check ---

// How the editor's text stands for the focused setting: its form (shown
// when not as typed), why it can't be staged, the rule it would break, or,
// for a path, why it may not do.
fn checkEditor(c: *const Conductor, v: *Viewer) void {
    const e = &v.editor.?;
    const i = v.focus[v.tab];
    const s = &all[i];
    const check = &e.check;
    var form_buf: [256]u8 = undefined;
    const form = settings.normalise(s, e.text.items, &form_buf) catch
        return check.set(.problem, "Expected {s}.", .{settings.expected(s.kind)});
    var values = v.staged.values(&c.settings.model);
    values[i] = form;
    if (settings.conflict(&values)) |conflict| if (conflict.involves(i)) {
        var other_buf: [128]u8 = undefined;
        return switch (conflict) {
            .positive => check.set(.problem, "Must be above 0.", .{}),
            .ordered => |o| if (o.below == i)
                check.set(.problem, "Must be below {s} ({s}).", .{ all[o.above].label, settings.display(&all[o.above], values[o.above], &other_buf) })
            else
                check.set(.problem, "Must be above {s} ({s}).", .{ all[o.below].label, settings.display(&all[o.below], values[o.below], &other_buf) }),
        };
    };
    if (s.kind == .path) if (form) |path| {
        var why_buf: [256]u8 = undefined;
        if (pathWarning(c, s.kind.path, path, e.settled, &why_buf)) |why| return check.set(.warning, "{s}", .{why});
    };
    var shown_buf: [128]u8 = undefined;
    const shown = settings.display(s, form, &shown_buf);
    if (std.mem.eql(u8, std.mem.trim(u8, e.text.items, " \t"), shown)) return check.set(.fine, "", .{});
    check.set(.fine, "As {s}.", .{shown});
}

// Why `path` may not do, if it may not: its directory missing, or, once
// it's `whole` (no longer being typed), the path itself. A bare
// executable's name is looked for on the daemon's PATH.
fn pathWarning(c: *const Conductor, kind: settings.Path, path: []const u8, whole: bool, buf: []u8) ?[]const u8 {
    const cwd = std.Io.Dir.cwd();
    if (kind == .socket) {
        const address = protocol.parseAddress(path) catch return null;
        if (address.mode == .tcp) return null;
    }
    const bare = std.mem.indexOfAny(u8, path, "/\\") == null;
    if (kind == .executable and bare) {
        if (!whole or onPath(c, path)) return null;
        return std.fmt.bufPrint(buf, "{s} isn't on the daemon's PATH.", .{path}) catch null;
    }
    if (std.fs.path.dirname(path)) |dir| {
        const stat = cwd.statFile(c.io, dir, .{}) catch
            return std.fmt.bufPrint(buf, "{s} doesn't exist.", .{dir}) catch null;
        if (stat.kind != .directory) return std.fmt.bufPrint(buf, "{s} isn't a directory.", .{dir}) catch null;
    }
    if (!whole) return null;
    const stat = cwd.statFile(c.io, path, .{}) catch |err| return switch (err) {
        error.FileNotFound => if (kind == .executable) std.fmt.bufPrint(buf, "{s} doesn't exist.", .{path}) catch null else null,
        else => std.fmt.bufPrint(buf, "{s} can't be read: {s}.", .{ path, @errorName(err) }) catch null,
    };
    return switch (kind) {
        .executable => if (stat.kind == .directory)
            std.fmt.bufPrint(buf, "{s} is a directory.", .{path}) catch null
        else if (cwd.access(c.io, path, .{ .execute = true })) |_| null else |_| std.fmt.bufPrint(buf, "{s} isn't executable.", .{path}) catch null,
        .directory => if (stat.kind != .directory) std.fmt.bufPrint(buf, "{s} isn't a directory.", .{path}) catch null else null,
        .socket => null,
    };
}

fn onPath(c: *const Conductor, name: []const u8) bool {
    const path_env = c.environ_map.get("PATH") orelse return false;
    var dirs = std.mem.tokenizeScalar(u8, path_env, std.fs.path.delimiter);
    while (dirs.next()) |dir| {
        for ([_][]const u8{ "", ".exe" }) |suffix| {
            var buf: [std.fs.max_path_bytes]u8 = undefined;
            const candidate = std.fmt.bufPrint(&buf, "{s}{c}{s}{s}", .{ dir, std.fs.path.sep, name, suffix }) catch continue;
            if (std.Io.Dir.cwd().access(c.io, candidate, .{ .execute = true })) |_| return true else |_| {}
        }
    }
    return false;
}

// --- Workers ---

// Those running, the reserve aside, as far as a change for workers reaches them.
fn fleetOf(c: *const Conductor) changes.Fleet {
    var fleet: changes.Fleet = .{};
    var it = c.workers.valueIterator();
    while (it.next()) |list| for (list.items) |w| {
        fleet.oldest_spawn_ns = @min(fleet.oldest_spawn_ns orelse w.spawned_ns, w.spawned_ns);
        fleet.idle_stale = fleet.idle_stale or Conductor.isRetirable(w, c.settings.model.workers_changed_ns);
    };
    return fleet;
}

fn pendingOf(c: *const Conductor, v: *const Viewer) changes.Pending {
    return changes.pending(&c.settings.model, &v.staged, fleetOf(c), c.settings.service != null);
}

// --- Drawing ---

fn repaint(c: *Conductor, v: *Viewer) void {
    if (v.term.queued.items.len > 0 and !v.term.flushQueued()) return;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(c.allocator);
    const scene: view.Scene = .{
        .state = &c.settings.model,
        .staged = &v.staged,
        .fleet = fleetOf(c),
        .saving = c.settings.service != null,
        .tab = v.tab,
        .focus = v.focus[v.tab],
        .editor = if (v.editor) |*e| .{ .text = e.text.items, .cursor = e.cursor, .check = &e.check } else null,
        .message = if (v.message.kind == .none) null else .{ .problem = v.message.kind == .problem, .text = v.message.bytes[0..v.message.len] },
        .asking = v.asking,
        .styles = &v.styles,
        .cols = v.term.size.cols,
    };
    v.cursor_line = view.draw(c.allocator, &out, &scene, v.cursor_line) catch |err| {
        std.debug.print("Settings: drawing failed: {}\n", .{err});
        return;
    };
    v.term.sendFrame(c.allocator, out.items);
}

// What the viewer did, to leave in the frame's place: after a problem
// with its last action, what that was.
fn farewell(c: *const Conductor, v: *const Viewer, buf: []u8) []const u8 {
    const model = &c.settings.model;
    var w = std.Io.Writer.fixed(buf);
    if (v.message.kind == .problem) w.print("{s}\n", .{v.message.bytes[0..v.message.len]}) catch {};
    const n = v.applied.count();
    if (n == 0) {
        w.writeAll("No settings changed.") catch {};
        return w.buffered();
    }
    var unsaved: usize = 0;
    var restart: usize = 0;
    var it = v.applied.iterator(.{});
    while (it.next()) |i| {
        if (model.isUnsaved(i)) unsaved += 1;
        if (all[i].effect == .restart and !changes.same(model.applied[i], model.running[i])) restart += 1;
    }
    w.print("Applied {d} change{s}", .{ n, if (n == 1) "" else "s" }) catch {};
    const svc = c.settings.service;
    if (unsaved == 0) {
        var target_buf: [std.fs.max_path_bytes]u8 = undefined;
        var shown_buf: [std.fs.max_path_bytes]u8 = undefined;
        if (svc) |s| w.print(", saved to {s}", .{homeRelative(c, s.target(&target_buf), &shown_buf)}) catch {};
    } else if (svc == null) {
        w.writeAll(" (no service to save them to)") catch {};
    } else if (unsaved == n) {
        w.writeAll(" (unsaved)") catch {};
    } else {
        w.print(" ({d} unsaved)", .{unsaved}) catch {};
    }
    if (unsaved < n) if (svc) |s| if (s.kind.rereadNote()) |note| w.print("; {s}", .{note}) catch {};
    if (restart > 0) w.print("; {d} take{s} effect on restart", .{ restart, if (restart == 1) "s" else "" }) catch {};
    w.writeAll(".") catch {};
    return w.buffered();
}

// Ends the gone, their frame erased, but for a word on what they did.
fn sweep(c: *Conductor) void {
    const viewers = &c.settings.viewers;
    var i: usize = 0;
    while (i < viewers.items.len) {
        const v = viewers.items[i];
        if (!v.term.gone) {
            i += 1;
            continue;
        }
        _ = viewers.swapRemove(i);
        var leaving: std.ArrayList(u8) = .empty;
        defer leaving.deinit(c.allocator);
        var buf: [1536]u8 = undefined;
        view.clear(c.allocator, &leaving, v.cursor_line, farewell(c, v, &buf)) catch {};
        v.term.close(c, leaving.items);
        v.deinit(c.allocator);
        c.allocator.destroy(v);
    }
}
