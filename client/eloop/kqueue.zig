// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0
//
// BSD/macOS kqueue-based event loop for the client.

const std = @import("std");
const c = std.c;
const posix = std.posix;

const platform = @import("../platform/main.zig");
const cooked = @import("../cooked.zig");
const bsd = @import("../platform/bsd.zig");

const EV_EOF = bsd.EV_EOF;
const EV_ERROR = bsd.EV_ERROR;
const makeKevent = bsd.makeKevent;
const keventCall = bsd.keventCall;

const UDATA_STDIN: usize = 0;
const UDATA_STDOUT: usize = 1;
const UDATA_STDERR: usize = 2;
const UDATA_SIGNALS: usize = 3;

/// Returns the worker's exit code.
pub fn run(
    stdin_fd: posix.fd_t,
    stdout_fd: posix.fd_t,
    stderr_fd: posix.fd_t,
    signals_fd: posix.fd_t,
    signal_parser: anytype,
    sync_mode: bool,
) !u8 {
    const kq = c.kqueue();
    if (kq == -1) return error.KqueueCreateFailed;
    defer _ = c.close(kq);
    var changes: [3]c.Kevent = .{
        makeKevent(@intCast(stdout_fd), c.EVFILT.READ, c.EV.ADD, 0, 0, UDATA_STDOUT),
        makeKevent(@intCast(stderr_fd), c.EVFILT.READ, c.EV.ADD, 0, 0, UDATA_STDERR),
        makeKevent(@intCast(signals_fd), c.EVFILT.READ, c.EV.ADD, 0, 0, UDATA_SIGNALS),
    };
    var no_events: [0]c.Kevent = undefined;
    if (keventCall(kq, &changes, &no_events, null) < 0) {
        return error.KqueueRegisterFailed;
    }
    // Regular files never report EV_EOF and /dev/null fails registration.
    const stdin_polled = blk: {
        var st: c.Stat = undefined;
        if (c.fstat(posix.STDIN_FILENO, &st) == 0 and c.S.ISREG(@as(u32, st.mode))) break :blk false;
        var stdin_change = [1]c.Kevent{makeKevent(@intCast(posix.STDIN_FILENO), c.EVFILT.READ, c.EV.ADD, 0, 0, UDATA_STDIN)};
        break :blk keventCall(kq, &stdin_change, &no_events, null) >= 0;
    };
    const buf_size = 1024;
    var out_buf: [buf_size]u8 = undefined;
    var stdin_buf: [buf_size]u8 = undefined;
    var signals_buf: [buf_size]u8 = undefined;
    var stdin_fwd = cooked.StdinForwarder{ .dst = stdin_fd, .sync_mode = sync_mode, .wants_raw = &signal_parser.worker_wants_raw };
    var exit_code: ?u8 = null;
    var stdout_eof = false;
    var stderr_eof = false;
    var stdin_closed = false;
    var events: [8]c.Kevent = undefined;
    var no_changes: [0]c.Kevent = undefined;
    const zero_ts = c.timespec{ .sec = 0, .nsec = 0 };
    while (true) {
        const draining_stdin = !stdin_polled and !stdin_closed and exit_code == null;
        const nevents = keventCall(kq, &no_changes, &events, if (draining_stdin) &zero_ts else null);
        if (nevents < 0) {
            const err: posix.E = @enumFromInt(c._errno().*);
            if (err == .INTR) continue;
            return error.KqueueWaitFailed;
        }
        const event_count: usize = @intCast(nevents);
        for (events[0..event_count]) |ev| {
            if ((ev.flags & EV_ERROR) != 0) continue;
            // kqueue can deliver data and EOF in one event: drain before EOF.
            switch (ev.udata) {
                UDATA_STDOUT => if (relay(stdout_fd, posix.STDOUT_FILENO, &out_buf, ev)) {
                    stdout_eof = true;
                    unwatch(kq, stdout_fd);
                },
                UDATA_STDERR => if (relay(stderr_fd, posix.STDERR_FILENO, &out_buf, ev)) {
                    stderr_eof = true;
                    unwatch(kq, stderr_fd);
                },
                UDATA_STDIN => {
                    if (exit_code != null or stdin_closed) continue;
                    var remaining: usize = @intCast(ev.data);
                    while (remaining > 0) {
                        const want = @min(remaining, stdin_buf.len);
                        const n = posix.read(posix.STDIN_FILENO, stdin_buf[0..want]) catch 0;
                        if (n == 0) break;
                        stdin_fwd.forward(stdin_buf[0..n]);
                        remaining -= n;
                    }
                    if ((ev.flags & EV_EOF) != 0) {
                        platform.sendEof(stdin_fd);
                        stdin_closed = true;
                        unwatch(kq, posix.STDIN_FILENO);
                    }
                },
                UDATA_SIGNALS => {
                    var remaining: usize = @intCast(ev.data);
                    while (remaining > 0) {
                        const want = @min(remaining, signals_buf.len);
                        const n = posix.read(signals_fd, signals_buf[0..want]) catch {
                            if (exit_code == null) exit_code = 1;
                            break;
                        };
                        if (n == 0) break;
                        switch (signal_parser.feed(signals_buf[0..n], signals_fd)) {
                            .exit => |code| exit_code = code,
                            .none => {},
                        }
                        remaining -= n;
                    }
                    if ((ev.flags & EV_EOF) != 0) {
                        if (exit_code == null) exit_code = 1;
                    }
                    // No longer read, so unwatched: they would stay ready.
                    if (exit_code != null) {
                        unwatch(kq, signals_fd);
                        if (stdin_polled) unwatch(kq, posix.STDIN_FILENO);
                    }
                },
                else => {},
            }
        }
        // Drain non-pollable stdin directly; read()==0 is EOF.
        if (!stdin_polled and !stdin_closed and exit_code == null) {
            const n = posix.read(posix.STDIN_FILENO, &stdin_buf) catch 0;
            if (n == 0) {
                platform.sendEof(stdin_fd);
                stdin_closed = true;
            } else {
                stdin_fwd.forward(stdin_buf[0..n]);
            }
        }
        if (exit_code != null and stdout_eof and stderr_eof) {
            return exit_code.?;
        }
    }
}

/// Level-triggered, a registration left at an end reports it forever.
fn unwatch(kq: posix.fd_t, fd: posix.fd_t) void {
    var change = [1]c.Kevent{makeKevent(@intCast(fd), c.EVFILT.READ, c.EV.DELETE, 0, 0, 0)};
    var no_events: [0]c.Kevent = undefined;
    _ = keventCall(kq, &change, &no_events, null);
}
/// Passes on what `ev` reports `src` holds; returns whether `src` has ended.
fn relay(src: posix.fd_t, dst: posix.fd_t, buf: []u8, ev: c.Kevent) bool {
    var remaining: usize = @intCast(ev.data);
    while (remaining > 0) {
        const n = posix.read(src, buf[0..@min(remaining, buf.len)]) catch return true;
        if (n == 0) return true;
        if (!platform.writeOutput(dst, buf[0..n])) {
            platform.close(src);
            return true;
        }
        remaining -= n;
    }
    return (ev.flags & EV_EOF) != 0 or ev.data == 0;
}
