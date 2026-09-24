// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0
//
// Signals reach the POSIX conductor loops through a self-pipe.

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const Io = std.Io;
const platform = @import("../platform/main.zig");

pub const SIGNAL_SHUTDOWN: u8 = 'S';
pub const SIGNAL_RECREATE: u8 = 'R';

pub var signal_pipe: [2]posix.fd_t = .{ -1, -1 };

/// Async-signal-safe, unlike platform.write's logging.
fn rawWrite(fd: posix.fd_t, buf: [*]const u8, len: usize) void {
    if (builtin.os.tag == .linux) {
        _ = std.os.linux.write(fd, buf, len);
    } else {
        _ = std.c.write(fd, buf, len);
    }
}

fn handleShutdown(_: posix.SIG) callconv(.c) void {
    rawWrite(signal_pipe[1], @ptrCast(&SIGNAL_SHUTDOWN), 1);
}

fn handleUsr1(_: posix.SIG) callconv(.c) void {
    rawWrite(signal_pipe[1], @ptrCast(&SIGNAL_RECREATE), 1);
}

pub fn installSignalHandlers() !void {
    signal_pipe = Io.Threaded.pipe2(.{ .NONBLOCK = true, .CLOEXEC = true }) catch return error.PipeCreationFailed;
    const shutdown_sigact = posix.Sigaction{
        .handler = .{ .handler = @ptrCast(&handleShutdown) },
        .mask = std.mem.zeroes(posix.sigset_t),
        .flags = 0,
    };
    posix.sigaction(posix.SIG.TERM, &shutdown_sigact, null);
    posix.sigaction(posix.SIG.INT, &shutdown_sigact, null);
    const usr1_sigact = posix.Sigaction{
        .handler = .{ .handler = @ptrCast(&handleUsr1) },
        .mask = std.mem.zeroes(posix.sigset_t),
        .flags = 0,
    };
    posix.sigaction(posix.SIG.USR1, &usr1_sigact, null);
    // A write to a vanished client must not kill the daemon; io_uring masks
    // SIGPIPE, but macOS c.write does not.
    const pipe_sigact = posix.Sigaction{
        .handler = .{ .handler = posix.SIG.IGN },
        .mask = std.mem.zeroes(posix.sigset_t),
        .flags = 0,
    };
    posix.sigaction(posix.SIG.PIPE, &pipe_sigact, null);
}

pub fn cleanupSignalHandlers() void {
    if (signal_pipe[0] != -1) platform.close(signal_pipe[0]);
    if (signal_pipe[1] != -1) platform.close(signal_pipe[1]);
    signal_pipe = .{ -1, -1 };
}
