// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0
//
// Linux event loop for the client: io_uring, or epoll where the kernel
// lacks it (before 5.6, for our operations) or has it disabled.

const posix = @import("std").posix;

const platform_linux = @import("../platform/linux.zig");
const iouring = @import("iouring.zig");
const epoll = @import("epoll.zig");

/// Returns the worker's exit code.
pub fn run(
    stdin_fd: posix.fd_t,
    stdout_fd: posix.fd_t,
    stderr_fd: posix.fd_t,
    signals_fd: posix.fd_t,
    signal_parser: anytype,
    sync_mode: bool,
) !u8 {
    var ring = platform_linux.initIoUring(8) catch |err| switch (err) {
        error.SystemOutdated, error.PermissionDenied, error.SystemResources => return epoll.run(stdin_fd, stdout_fd, stderr_fd, signals_fd, signal_parser, sync_mode),
        else => return err,
    };
    defer ring.deinit();
    return iouring.run(&ring, stdin_fd, stdout_fd, stderr_fd, signals_fd, signal_parser, sync_mode);
}
