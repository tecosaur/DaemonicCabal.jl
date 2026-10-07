// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0
//
// Replies the conductor makes itself, over a client's own four
// streams: strings, --status and its live view, --reconfigure.

const std = @import("std");
const posix = std.posix;
const platform = @import("platform/main.zig");
const protocol = @import("protocol.zig");
const status = @import("status.zig");
const live = @import("live.zig");
const reconfigure = @import("reconfigure.zig");
const pal = @import("palette.zig");

const main = @import("main.zig");
const Conductor = main.Conductor;
const worker = main.worker;
const ClientStreams = Conductor.ClientStreams;
const palette_probe_timeout_s = Conductor.palette_probe_timeout_s;
const reply_accept_timeout_ms = Conductor.reply_accept_timeout_ms;
const assign = @import("assign.zig");

// On failure everything partial is released first.
pub fn openClientStreams(c: *Conductor, client_socket: posix.socket_t, keyed: bool) !ClientStreams {
    const mode = c.cfg.transport;
    const bind = c.cfg.bind_address;
    var port_set_idx: u16 = protocol.PortPool.none;
    var ports: ?[4]u16 = null;
    if (c.port_pool) |*pool| {
        if (pool.allocate()) |idx| {
            port_set_idx = idx;
            ports = pool.portsForIndex(idx);
        }
    }
    errdefer assign.releasePortSet(c, port_set_idx);
    const suffixes = [_][]const u8{ "stdin.sock", "stdout.sock", "stderr.sock", "signals.sock" };
    var listeners: [4]protocol.Listener = undefined;
    var created: usize = 0;
    errdefer for (listeners[0..created]) |*l| l.close(c.io);
    for (0..4) |i| {
        listeners[i] = if (ports) |p|
            try protocol.listenTcp(c.io, bind, p[i])
        else
            try protocol.createListener(c.io, mode, c.cfg.socket_dir, suffixes[i], bind);
        created += 1;
    }
    sendSocketPaths(c, client_socket, .{
        .stdin = listeners[0].addr(), .stdout = listeners[1].addr(),
        .stderr = listeners[2].addr(), .signals = listeners[3].addr(),
    });
    var conns: [4]posix.socket_t = undefined;
    var accepted: usize = 0;
    errdefer for (conns[0..accepted]) |conn| platform.close(conn);
    for (0..4) |i| {
        // A client that gave up waiting must not wedge us in a bare accept.
        conns[i] = (try listeners[i].acceptTimeout(c.io, reply_accept_timeout_ms)) orelse return error.ClientGone;
        accepted += 1;
        if (keyed) {
            var key: [8]u8 = undefined;
            try protocol.readExactWithin(c.io, conns[i], &key, reply_accept_timeout_ms);
            if (std.mem.readInt(u64, &key, .little) != c.keyFor(.client, c.client_id)) return error.WrongKey;
        }
    }
    return .{ .c = c, .listeners = listeners, .conns = conns, .port_set_idx = port_set_idx };
}

pub fn serveString(c: *Conductor, client_socket: posix.socket_t, content: []const u8, exit_code: u8) !void {
    var streams = try openClientStreams(c, client_socket, true);
    defer streams.deinit();
    streams.finish(content, exit_code);
}

// Only the conductor's own user, at a local socket, may change it.
pub fn serveReconfigure(c: *Conductor, client_socket: posix.socket_t, tty: bool, size: protocol.TerminalSize, allowed: bool) !void {
    if (!allowed) {
        std.debug.print("Client {d}: --reconfigure refused (not a local, unsandboxed client)\n", .{c.client_id});
        return serveString(c, client_socket, "--reconfigure needs a local, unsandboxed client of the conductor's own user.\n", 1);
    }
    if (!tty) {
        const text = try reconfigure.listing(c.allocator, &c.settings);
        defer c.allocator.free(text);
        return serveString(c, client_socket, text, 0);
    }
    var streams = try openClientStreams(c, client_socket, true);
    std.debug.print("Client {d}: --reconfigure\n", .{c.client_id});
    try reconfigure.subscribe(c, streams, probePalette(c, &streams), size);
}

// A TTY client is colour-probed first; a non-answering terminal gets the flat report.
// A styled TTY one-shot waits a beat so its CPU meter resolves.
pub fn serveStatus(c: *Conductor, client_socket: posix.socket_t, switch_value: ?[]const u8, tty: bool, size: protocol.TerminalSize, scope: status.Scope) !void {
    // A bare `--status` has an empty value.
    const format = if (switch_value) |v| (if (v.len > 0) v else null) else null;
    var streams = try openClientStreams(c, client_socket, true);
    var held = false;
    defer if (!held) streams.deinit();
    const is_live = tty and format != null and std.mem.eql(u8, format.?, "live");
    const palette: ?pal.Palette = if (tty and (format == null or is_live)) probePalette(c, &streams) else null;
    if (is_live or (tty and format == null)) {
        try live.subscribe(c, streams, palette, size, scope, !is_live);
        held = true;
        return;
    }
    const report = renderStatus(c, format, tty, palette, scope, null, null, false) catch |err| {
        std.debug.print("Status: render failed: {}\n", .{err});
        streams.finish("Failed to generate status report.\n", 1);
        return;
    };
    defer report.deinit(c.allocator);
    streams.finish(report.bytes, 0);
}

pub fn renderStatus(c: *Conductor, format: ?[]const u8, tty: bool, palette: ?pal.Palette, scope: status.Scope, focus: ?u32, trend: ?*const status.Trend, hint: bool) !status.Report {
    return status.render(c, .{
        .format = format,
        .tty = tty,
        .scope = scope,
        .palette = if (palette) |*p| p else null,
        .focus = focus,
        .trend = trend,
        .hint = hint,
    });
}

// Read until the CSI 5n sentinel or a byte cap; a view's client is raw from
// the start, so the replies come unechoed.
pub fn probePalette(c: *Conductor, streams: *ClientStreams) ?pal.Palette {
    const stdin = streams.fd(.stdin);
    platform.write(streams.fd(.stdout), pal.queries);
    // This read blocks the event loop, so is bounded as a whole.
    const deadline = c.nowNs() + palette_probe_timeout_s * std.time.ns_per_s;
    var buf: [4096]u8 = undefined;
    var len: usize = 0;
    while (len < buf.len) {
        const left_ms = @divTrunc(deadline - c.nowNs(), std.time.ns_per_ms);
        if (left_ms <= 0 or !platform.waitReadable(stdin, @intCast(left_ms))) break;
        len += platform.recvNonBlocking(stdin, buf[len..]) orelse break;
        if (std.mem.find(u8, buf[0..len], pal.sentinel) != null) break;
    }
    var palette: pal.Palette = .{};
    pal.parse(buf[0..len], &palette);
    return if (palette.isPopulated()) palette else null;
}

/// Each path is at most `protocol.max_socket_path` long, as `runClient`
/// and `createListener` ensure.
pub fn sendSocketPaths(c: *Conductor, socket: posix.socket_t, paths: worker.Worker.SocketPaths) void {
    var buf: [1 + 4 + 4 * (2 + protocol.max_socket_path) + 8]u8 = undefined;
    var w = protocol.BufWriter{ .buf = &buf };
    w.writeInt(u8, protocol.client.socket_paths);
    w.writeInt(u32, c.client_id);
    // TCP: the client pairs the port with the conductor's host.
    const all = [_][]const u8{ paths.stdin, paths.stdout, paths.stderr, paths.signals };
    for (all) |path| {
        if (c.cfg.transport == .tcp) {
            const colon = std.mem.findScalarLast(u8, path, ':') orelse path.len;
            w.writeLenPrefixed(u16, path[colon..]);
        } else {
            w.writeLenPrefixed(u16, path);
        }
    }
    w.writeInt(u64, c.keyFor(.client, c.client_id));
    platform.write(socket, w.written());
}
