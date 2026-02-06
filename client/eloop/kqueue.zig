// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0
//
// BSD/macOS kqueue-based event loop for the client.
// Multiplexes stdin, stdout (from worker), and signals socket.

const std = @import("std");
const c = std.c;
const posix = std.posix;

const platform = @import("../platform/main.zig");
const protocol = @import("../protocol.zig");

// EV flags - some BSD variants have gaps in Zig's bindings
const EV_EOF: u16 = if (@hasDecl(c.EV, "EOF")) c.EV.EOF else 0x8000;
const EV_ERROR: u16 = if (@hasDecl(c.EV, "ERROR")) c.EV.ERROR else 0x4000;

// Event identifiers stored in udata
const UDATA_STDIN: usize = 0;
const UDATA_STDOUT: usize = 1;
const UDATA_SIGNALS: usize = 2;

/// Run the client I/O loop using kqueue.
/// Returns exit code when complete.
pub fn run(
    stdio_fd: posix.fd_t,
    signals_fd: posix.fd_t,
    signal_parser: anytype,
) !u8 {
    const kq = c.kqueue();
    if (kq == -1) return error.KqueueCreateFailed;
    defer _ = c.close(kq);
    // Register reads on worker stdout and signals (required)
    var changes: [2]c.Kevent = .{
        makeKevent(@intCast(stdio_fd), c.EVFILT.READ, c.EV.ADD, 0, 0, UDATA_STDOUT),
        makeKevent(@intCast(signals_fd), c.EVFILT.READ, c.EV.ADD, 0, 0, UDATA_SIGNALS),
    };
    var no_changes: [0]c.Kevent = undefined;
    if (keventCall(kq, &changes, &no_changes) < 0) {
        return error.KqueueRegisterFailed;
    }
    // Register stdin separately: may fail on macOS when stdin is a device
    // file like /dev/null (kqueue returns EINVAL for non-pollable fds).
    var stdin_change = [1]c.Kevent{makeKevent(@intCast(posix.STDIN_FILENO), c.EVFILT.READ, c.EV.ADD, 0, 0, UDATA_STDIN)};
    _ = keventCall(kq, &stdin_change, &no_changes);
    // Buffers
    const buf_size = 1024;
    var stdout_buf: [buf_size]u8 = undefined;
    var stdin_buf: [buf_size]u8 = undefined;
    var signals_buf: [buf_size]u8 = undefined;
    // State
    var exit_code: ?u8 = null;
    var stdout_eof = false;
    var stdin_eof = false;
    // Event buffer
    var events: [8]c.Kevent = undefined;
    while (true) {
        const nevents = keventCall(kq, &no_changes, &events);
        if (nevents < 0) {
            const err: posix.E = @enumFromInt(c._errno().*);
            if (err == .INTR) continue;
            return error.KqueueWaitFailed;
        }
        const event_count: usize = @intCast(nevents);
        for (events[0..event_count]) |ev| {
            if ((ev.flags & EV_ERROR) != 0) continue;
            switch (udataInt(ev)) {
                UDATA_STDOUT => {
                    if (stdout_eof) continue;
                    // Read available data first
                    if (ev.data > 0) {
                        const n = posix.read(stdio_fd, &stdout_buf) catch {
                            stdout_eof = true;
                            continue;
                        };
                        if (n > 0) platform.write(posix.STDOUT_FILENO, stdout_buf[0..n]);
                    }
                    // Check for EOF and unregister to prevent busy loop
                    if ((ev.flags & EV_EOF) != 0 or ev.data == 0) {
                        stdout_eof = true;
                        var del = [1]c.Kevent{makeKevent(@intCast(stdio_fd), c.EVFILT.READ, c.EV.DELETE, 0, 0, UDATA_STDOUT)};
                        _ = keventCall(kq, &del, &no_changes);
                    }
                },
                UDATA_STDIN => {
                    if (stdin_eof or exit_code != null) continue;
                    // For pipes, EV_EOF is set immediately but data may still be available.
                    // Read any pending data, then unregister to stop busy-looping.
                    if (ev.data > 0) {
                        const n = posix.read(posix.STDIN_FILENO, &stdin_buf) catch continue;
                        if (n > 0) platform.write(stdio_fd, stdin_buf[0..n]);
                    }
                    if ((ev.flags & EV_EOF) != 0) {
                        stdin_eof = true;
                        // Unregister stdin from kqueue to prevent busy loop
                        var del = [1]c.Kevent{makeKevent(@intCast(posix.STDIN_FILENO), c.EVFILT.READ, c.EV.DELETE, 0, 0, UDATA_STDIN)};
                        _ = keventCall(kq, &del, &no_changes);
                    }
                },
                UDATA_SIGNALS => {
                    if ((ev.flags & EV_EOF) != 0) {
                        if (exit_code == null) exit_code = 1;
                        continue;
                    }
                    const n = posix.read(signals_fd, &signals_buf) catch {
                        if (exit_code == null) exit_code = 1;
                        continue;
                    };
                    if (n == 0) {
                        if (exit_code == null) exit_code = 1;
                        continue;
                    }
                    switch (signal_parser.feed(signals_buf[0..n], signals_fd)) {
                        .exit => |code| exit_code = code,
                        .none => {},
                    }
                },
                else => {},
            }
        }
        // Exit only when we have both exit code AND stdout is drained
        if (exit_code != null and stdout_eof) {
            return exit_code.?;
        }
    }
}

fn makeKevent(
    ident: usize,
    filter: i16,
    flags: u16,
    fflags: u32,
    data: isize,
    udata: usize,
) c.Kevent {
    return .{
        .ident = ident,
        .filter = filter,
        .flags = flags,
        .fflags = fflags,
        .data = data,
        .udata = udata,
    };
}
fn udataInt(ev: c.Kevent) usize {
    return ev.udata;
}
/// Wrapper for kevent syscall using slices
fn keventCall(kq: posix.fd_t, changelist: []const c.Kevent, eventlist: []c.Kevent) c_int {
    return c.kevent(kq, changelist.ptr, @intCast(changelist.len), eventlist.ptr, @intCast(eventlist.len), null);
}
