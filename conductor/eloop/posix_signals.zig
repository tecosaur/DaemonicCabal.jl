// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0
//
// Shared POSIX signal handling for conductor event loops (Linux + BSD/macOS).
// Converts Unix signals to event loop events via a self-pipe.

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const Io = std.Io;

pub const SIGNAL_SHUTDOWN: u8 = 'S';
pub const SIGNAL_RECREATE: u8 = 'R';

/// Signal pipe for converting async signals to event loop events
pub var signal_pipe: [2]posix.fd_t = .{ -1, -1 };

/// Raw write bypassing platform.write debug logging (async-signal-safe).
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

/// Create signal pipe and install signal handlers. Call before running event loop.
pub fn installSignalHandlers() !void {
    signal_pipe = Io.Threaded.pipe2(.{ .NONBLOCK = true }) catch return error.PipeCreationFailed;
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
}

/// Close signal pipe. Call after event loop exits.
pub fn cleanupSignalHandlers() void {
    if (signal_pipe[0] != -1) posix.close(signal_pipe[0]);
    if (signal_pipe[1] != -1) posix.close(signal_pipe[1]);
    signal_pipe = .{ -1, -1 };
}
