// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0
//
// BSD/macOS kqueue-based event loop for the client.
// Multiplexes stdin, stdout (from worker), and signals socket.

const std = @import("std");
const builtin = @import("builtin");
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
    // Register reads on all three sources
    var changes: [3]c.Kevent = .{
        makeKevent(@intCast(posix.STDIN_FILENO), c.EVFILT.READ, c.EV.ADD, 0, 0, UDATA_STDIN),
        makeKevent(@intCast(stdio_fd), c.EVFILT.READ, c.EV.ADD, 0, 0, UDATA_STDOUT),
        makeKevent(@intCast(signals_fd), c.EVFILT.READ, c.EV.ADD, 0, 0, UDATA_SIGNALS),
    };
    var dummy: [1]c.Kevent = undefined;
    if (c.kevent(kq, &changes, 3, &dummy, 0, null) < 0) {
        const err: posix.E = @enumFromInt(c._errno().*);
        std.debug.print("kevent register failed: {} (fds: stdin={}, stdio={}, signals={})\n", .{
            err, posix.STDIN_FILENO, stdio_fd, signals_fd,
        });
        return error.KqueueRegisterFailed;
    }
    // Buffers
    const buf_size = 1024;
    var stdout_buf: [buf_size]u8 = undefined;
    var stdin_buf: [buf_size]u8 = undefined;
    var signals_buf: [buf_size]u8 = undefined;
    // State
    var exit_code: ?u8 = null;
    var stdout_eof = false;
    var stdin_active = true;
    // Event buffer
    var events: [8]c.Kevent = undefined;
    var no_changes: [1]c.Kevent = undefined;
    while (true) {
        const nevents = c.kevent(kq, &no_changes, 0, &events, events.len, null);
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
                    // Check for EOF (EV_EOF flag or data == 0)
                    if ((ev.flags & EV_EOF) != 0 or ev.data == 0) {
                        stdout_eof = true;
                        continue;
                    }
                    // Read available data
                    const n = posix.read(stdio_fd, &stdout_buf) catch {
                        stdout_eof = true;
                        continue;
                    };
                    if (n == 0) {
                        stdout_eof = true;
                        continue;
                    }
                    _ = platform.write(posix.STDOUT_FILENO, stdout_buf[0..n]);
                },
                UDATA_STDIN => {
                    if (!stdin_active or exit_code != null) continue;
                    if ((ev.flags & EV_EOF) != 0) {
                        stdin_active = false;
                        deleteEvent(kq, posix.STDIN_FILENO);
                        continue;
                    }
                    const n = posix.read(posix.STDIN_FILENO, &stdin_buf) catch {
                        stdin_active = false;
                        deleteEvent(kq, posix.STDIN_FILENO);
                        continue;
                    };
                    if (n == 0) {
                        stdin_active = false;
                        deleteEvent(kq, posix.STDIN_FILENO);
                        continue;
                    }
                    _ = platform.write(stdio_fd, stdin_buf[0..n]);
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

const Udata = @TypeOf(@as(c.Kevent, undefined).udata);
const udata_is_ptr = @typeInfo(Udata) == .pointer;

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
        .udata = if (udata_is_ptr) @ptrFromInt(udata) else udata,
    };
}
fn udataInt(ev: c.Kevent) usize {
    return if (udata_is_ptr) @intFromPtr(ev.udata) else ev.udata;
}
/// Remove a read event registration from kqueue
fn deleteEvent(kq: posix.fd_t, fd: posix.fd_t) void {
    var change = makeKevent(@intCast(fd), c.EVFILT.READ, c.EV.DELETE, 0, 0, 0);
    var dummy: [1]c.Kevent = undefined;
    _ = c.kevent(kq, @ptrCast(&change), 1, &dummy, 0, null);
}
