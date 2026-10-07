// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0
//
// Signals reach the POSIX conductor loops through a self-pipe.

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const Io = std.Io;
const platform = @import("../platform/main.zig");
const protocol = @import("../protocol.zig");
const Conductor = @import("../main.zig").Conductor;

const SIGNAL_SHUTDOWN: u8 = 'S';
const SIGNAL_RECREATE: u8 = 'R';

pub var signal_pipe: [2]posix.fd_t = .{ -1, -1 };

/// Async-signal-safe, unlike platform.write's logging.
fn rawWrite(fd: posix.fd_t, buf: [*]const u8, len: usize) void {
    if (builtin.target.os.tag == .linux) {
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
    // Writes are plain write(2) on every loop, so one to a vanished peer
    // raises SIGPIPE, which must not kill the daemon.
    const pipe_sigact = posix.Sigaction{
        .handler = .{ .handler = posix.SIG.IGN },
        .mask = std.mem.zeroes(posix.sigset_t),
        .flags = 0,
    };
    posix.sigaction(posix.SIG.PIPE, &pipe_sigact, null);
}

/// Acts on signals read from the pipe, recreating the listener between
/// `loop`'s `stopAccepting` and `startAccepting`; true once shutdown was
/// requested.
pub fn handle(conductor: *Conductor, loop: anytype, listener: *protocol.Listener, signals: []const u8) bool {
    for (signals) |sig| switch (sig) {
        SIGNAL_SHUTDOWN => {
            std.debug.print("\nShutdown requested, stopping workers...\n", .{});
            conductor.gracefulShutdown();
            return true;
        },
        SIGNAL_RECREATE => {
            // A local client's, finding no socket, while ours is a TCP listener.
            if (conductor.cfg.transport != .local) continue;
            std.debug.print("Recreating socket due to SIGUSR1\n", .{});
            // A failed recreate leaves it closed, marked so.
            if (listener.fd() != platform.no_socket) {
                loop.stopAccepting(listener);
                listener.close(conductor.io);
                listener.server.socket.handle = platform.no_socket;
            }
            listener.* = conductor.createServer() catch |err| {
                std.debug.print("Failed to recreate socket: {}\n", .{err});
                continue;
            };
            loop.startAccepting(listener);
        },
        else => {},
    };
    return false;
}

/// `handle`, for the signals the pipe holds.
pub fn drain(conductor: *Conductor, loop: anytype, listener: *protocol.Listener) bool {
    var buf: [16]u8 = undefined;
    const n = posix.read(signal_pipe[0], &buf) catch |err| {
        std.debug.print("Signal pipe read error: {}\n", .{err});
        return false;
    };
    return handle(conductor, loop, listener, buf[0..n]);
}

pub fn cleanupSignalHandlers() void {
    if (signal_pipe[0] != -1) platform.close(signal_pipe[0]);
    if (signal_pipe[1] != -1) platform.close(signal_pipe[1]);
    signal_pipe = .{ -1, -1 };
}
