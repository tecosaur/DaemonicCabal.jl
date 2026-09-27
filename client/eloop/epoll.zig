// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0
//
// Linux epoll-based event loop for the client, where io_uring is unavailable.

const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;

const platform = @import("../platform/main.zig");
const cooked = @import("../cooked.zig");

const Location = enum(u64) {
    local_stdin,
    worker_stdout,
    worker_stderr,
    signals,
};

/// Returns the worker's exit code.
pub fn run(
    stdin_fd: posix.fd_t,
    stdout_fd: posix.fd_t,
    stderr_fd: posix.fd_t,
    signals_fd: posix.fd_t,
    signal_parser: anytype,
    sync_mode: bool,
) !u8 {
    const rc = linux.epoll_create1(linux.EPOLL.CLOEXEC);
    if (linux.errno(rc) != .SUCCESS) return error.EpollCreateFailed;
    const epfd: i32 = @intCast(rc);
    defer _ = linux.close(epfd);
    try watch(epfd, stdout_fd, .worker_stdout);
    try watch(epfd, stderr_fd, .worker_stderr);
    try watch(epfd, signals_fd, .signals);
    // Regular files and /dev/null can't be polled, but never block: they're read each round.
    const stdin_polled = if (watch(epfd, posix.STDIN_FILENO, .local_stdin)) true else |_| false;
    var buf: [1024]u8 = undefined;
    var stdin_fwd = cooked.StdinForwarder{ .dst = stdin_fd, .sync_mode = sync_mode, .wants_raw = &signal_parser.worker_wants_raw };
    // Signals EOF without an exit code means the worker crashed.
    var exit_code: ?u8 = null;
    var stdout_eof = false;
    var stderr_eof = false;
    var stdin_eof = false;
    var events: [5]linux.epoll_event = undefined;
    while (exit_code == null or !stdout_eof or !stderr_eof) {
        const draining_stdin = !stdin_polled and !stdin_eof and exit_code == null;
        const wait_rc = linux.epoll_wait(epfd, &events, 4, if (draining_stdin) 0 else -1);
        switch (linux.errno(wait_rc)) {
            .SUCCESS => {},
            .INTR => continue,
            else => return error.EpollWaitFailed,
        }
        var count: usize = @intCast(wait_rc);
        if (draining_stdin) {
            events[count] = .{ .events = linux.EPOLL.IN, .data = .{ .u64 = @intFromEnum(Location.local_stdin) } };
            count += 1;
        }
        for (events[0..count]) |ev| switch (@as(Location, @enumFromInt(ev.data.u64))) {
            .worker_stdout => stdout_eof = !relay(epfd, stdout_fd, posix.STDOUT_FILENO, &buf),
            .worker_stderr => stderr_eof = !relay(epfd, stderr_fd, posix.STDERR_FILENO, &buf),
            .local_stdin => {
                if (exit_code != null) continue;
                if (readSome(epfd, posix.STDIN_FILENO, &buf)) |data| {
                    stdin_fwd.forward(data);
                } else {
                    platform.sendEof(stdin_fd);
                    stdin_eof = true;
                }
            },
            .signals => {
                if (exit_code != null) continue;
                exit_code = if (readSome(epfd, signals_fd, &buf)) |data| switch (signal_parser.feed(data, signals_fd)) {
                    .exit => |code| code,
                    .none => continue,
                } else 1;
                // No longer read, so unwatched: they would stay ready.
                unwatch(epfd, signals_fd);
                unwatch(epfd, posix.STDIN_FILENO);
            },
        };
    }
    return exit_code.?;
}

/// Passes on what `src` holds; returns whether it goes on.
fn relay(epfd: i32, src: posix.fd_t, dst: posix.fd_t, buf: []u8) bool {
    const data = readSome(epfd, src, buf) orelse return false;
    if (platform.writeOutput(dst, data)) return true;
    unwatch(epfd, src);
    platform.close(src);
    return false;
}

fn watch(epfd: i32, fd: posix.fd_t, location: Location) !void {
    var ev = linux.epoll_event{ .events = linux.EPOLL.IN, .data = .{ .u64 = @intFromEnum(location) } };
    if (linux.errno(linux.epoll_ctl(epfd, linux.EPOLL.CTL_ADD, fd, &ev)) != .SUCCESS) return error.EpollCtlFailed;
}

fn unwatch(epfd: i32, fd: posix.fd_t) void {
    _ = linux.epoll_ctl(epfd, linux.EPOLL.CTL_DEL, fd, null);
}

/// Null at the end of `fd`, which is then unwatched: a hung-up fd stays ready.
fn readSome(epfd: i32, fd: posix.fd_t, buf: []u8) ?[]u8 {
    const n = posix.read(fd, buf) catch |err| switch (err) {
        error.WouldBlock => return buf[0..0],
        else => 0,
    };
    if (n > 0) return buf[0..n];
    unwatch(epfd, fd);
    return null;
}
