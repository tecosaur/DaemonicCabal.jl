// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0
//
// Linux client event loop: io_uring when available, epoll otherwise.

// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0
//
// Linux client event loop: io_uring when available, epoll otherwise.

const posix = @import("std").posix;

const iouring = @import("iouring.zig");
const epoll = @import("epoll.zig");

pub fn run(
    stdin_fd: posix.fd_t,
    stdout_fd: posix.fd_t,
    stderr_fd: posix.fd_t,
    signals_fd: posix.fd_t,
    signal_parser: anytype,
    sync_mode: bool,
) !u8 {
    return iouring.run(stdin_fd, stdout_fd, stderr_fd, signals_fd, signal_parser, sync_mode) catch |err| switch (err) {
        error.SystemOutdated, error.PermissionDenied => epoll.run(stdin_fd, stdout_fd, stderr_fd, signals_fd, signal_parser, sync_mode),
        else => err,
    };
}
