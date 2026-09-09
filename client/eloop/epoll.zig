// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0
//
// Linux epoll-based event loop for the client.
// Multiplexes local stdin, worker stdout, worker stderr, and signals socket.

const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;

const platform = @import("../platform/main.zig");
const cooked = @import("../cooked.zig");

const UDATA_STDIN: u64 = 0;
const UDATA_STDOUT: u64 = 1;
const UDATA_STDERR: u64 = 2;
const UDATA_SIGNALS: u64 = 3;

pub fn run(
    stdin_fd: posix.fd_t,
    stdout_fd: posix.fd_t,
    stderr_fd: posix.fd_t,
    signals_fd: posix.fd_t,
    signal_parser: anytype,
    sync_mode: bool,
) !u8 {
    const epfd = try fdFromRc(linux.epoll_create1(linux.EPOLL.CLOEXEC));
    defer _ = linux.close(epfd);

    try ctlAdd(epfd, stdout_fd, UDATA_STDOUT, linux.EPOLL.IN);
    try ctlAdd(epfd, stderr_fd, UDATA_STDERR, linux.EPOLL.IN);
    try ctlAdd(epfd, signals_fd, UDATA_SIGNALS, linux.EPOLL.IN);
    // Regular files never report HUP/IN the way sockets do; /dev/null can fail
    // registration. Drain those stdin sources directly in the loop.
    const stdin_polled = if (ctlAdd(epfd, posix.STDIN_FILENO, UDATA_STDIN, linux.EPOLL.IN)) |_| true else |_| false;

    const buf_size = 1024;
    var stdout_buf: [buf_size]u8 = undefined;
    var stderr_buf: [buf_size]u8 = undefined;
    var stdin_buf: [buf_size]u8 = undefined;
    var signals_buf: [buf_size]u8 = undefined;
    var cooked_state = cooked.CookedState{};

    var exit_code: ?u8 = null;
    var stdout_eof = false;
    var stderr_eof = false;
    var stdin_closed = false;
    var events: [8]linux.epoll_event = undefined;

    while (true) {
        const draining_stdin = !stdin_polled and !stdin_closed and exit_code == null;
        const timeout: i32 = if (draining_stdin) 0 else -1;
        const n = linux.epoll_wait(epfd, &events, @intCast(events.len), timeout);
        switch (linux.errno(n)) {
            .SUCCESS => {},
            .INTR => continue,
            else => return error.EpollWaitFailed,
        }
        const event_count: usize = @intCast(n);
        for (events[0..event_count]) |ev| {
            const hung_up = (ev.events & (linux.EPOLL.HUP | linux.EPOLL.ERR | linux.EPOLL.RDHUP)) != 0;
            switch (ev.data.u64) {
                UDATA_STDOUT => {
                    if (!drainTo(posix.STDOUT_FILENO, stdout_fd, &stdout_buf, &stdout_eof) or hung_up)
                        stdout_eof = true;
                },
                UDATA_STDERR => {
                    if (!drainTo(posix.STDERR_FILENO, stderr_fd, &stderr_buf, &stderr_eof) or hung_up)
                        stderr_eof = true;
                },
                UDATA_STDIN => {
                    if (exit_code != null or stdin_closed) continue;
                    const nread = posix.read(posix.STDIN_FILENO, &stdin_buf) catch 0;
                    if (nread == 0 or hung_up) {
                        platform.close(stdin_fd);
                        stdin_closed = true;
                    } else if (sync_mode and !signal_parser.worker_wants_raw) {
                        for (stdin_buf[0..nread]) |byte| cooked_state.process(byte, stdin_fd);
                    } else {
                        platform.write(stdin_fd, stdin_buf[0..nread]);
                    }
                },
                UDATA_SIGNALS => {
                    const nread = posix.read(signals_fd, &signals_buf) catch {
                        if (exit_code == null) exit_code = 1;
                        continue;
                    };
                    // IN|HUP is common after write+shutdown: consume the payload
                    // before treating hangup as a missing exit code.
                    if (nread > 0) {
                        switch (signal_parser.feed(signals_buf[0..nread], signals_fd)) {
                            .exit => |code| exit_code = code,
                            .none => {},
                        }
                    }
                    if ((nread == 0 or hung_up) and exit_code == null) {
                        exit_code = 1;
                    }
                },
                else => {},
            }
        }
        if (!stdin_polled and !stdin_closed and exit_code == null) {
            const nread = posix.read(posix.STDIN_FILENO, &stdin_buf) catch 0;
            if (nread == 0) {
                platform.close(stdin_fd);
                stdin_closed = true;
            } else if (sync_mode and !signal_parser.worker_wants_raw) {
                for (stdin_buf[0..nread]) |byte| cooked_state.process(byte, stdin_fd);
            } else {
                platform.write(stdin_fd, stdin_buf[0..nread]);
            }
        }
        if (exit_code != null and stdout_eof and stderr_eof) {
            return exit_code.?;
        }
    }
}

fn drainTo(dst: posix.fd_t, src: posix.fd_t, buf: []u8, eof: *bool) bool {
    while (true) {
        const n = posix.read(src, buf) catch {
            eof.* = true;
            return false;
        };
        if (n == 0) {
            eof.* = true;
            return false;
        }
        platform.write(dst, buf[0..n]);
        if (n < buf.len) return true;
    }
}

fn ctlAdd(epfd: i32, fd: i32, udata: u64, events: u32) !void {
    var ev = linux.epoll_event{
        .events = events,
        .data = .{ .u64 = udata },
    };
    switch (linux.errno(linux.epoll_ctl(epfd, linux.EPOLL.CTL_ADD, fd, &ev))) {
        .SUCCESS => {},
        else => return error.EpollCtlFailed,
    }
}

fn fdFromRc(rc: usize) !i32 {
    return switch (linux.errno(rc)) {
        .SUCCESS => @intCast(rc),
        else => error.SyscallFailed,
    };
}
