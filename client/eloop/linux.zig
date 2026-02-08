// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0
//
// Linux io_uring-based event loop for the client.
// Multiplexes local stdin, worker stdout, worker stderr, and signals socket.

const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;

const platform = @import("../platform/main.zig");
const protocol = @import("../protocol.zig");

const Location = enum(u64) {
    local_stdin,
    worker_stdout,
    worker_stderr,
    signals,
};

/// Run the client I/O loop using io_uring.
/// Returns exit code when complete.
pub fn run(
    stdin_fd: posix.fd_t,
    stdout_fd: posix.fd_t,
    stderr_fd: posix.fd_t,
    signals_fd: posix.fd_t,
    signal_parser: anytype,
) !u8 {
    const buf_size = 1024;
    var ring = try linux.IoUring.init(8, 0);
    defer ring.deinit();
    var local_stdin_buf: [buf_size]u8 = undefined;
    var worker_stdout_buf: [buf_size]u8 = undefined;
    var worker_stderr_buf: [buf_size]u8 = undefined;
    var signals_buf: [buf_size]u8 = undefined;
    // Queue initial reads
    _ = try ring.read(@intFromEnum(Location.local_stdin), posix.STDIN_FILENO, .{ .buffer = &local_stdin_buf }, 0);
    _ = try ring.read(@intFromEnum(Location.worker_stdout), stdout_fd, .{ .buffer = &worker_stdout_buf }, 0);
    _ = try ring.read(@intFromEnum(Location.worker_stderr), stderr_fd, .{ .buffer = &worker_stderr_buf }, 0);
    _ = try ring.read(@intFromEnum(Location.signals), signals_fd, .{ .buffer = &signals_buf }, 0);
    // Wait for: stdout+stderr EOF (guarantees output flushed) and exit code (from signals socket).
    // If signals EOF arrives without exit code, worker crashed - use exit code 1.
    var exit_code: ?u8 = null;
    var stdout_eof = false;
    var stderr_eof = false;
    while (true) {
        _ = try ring.submit_and_wait(1);
        while (ring.cq_ready() > 0) {
            const cqe = try ring.copy_cqe();
            const len: usize = @intCast(@max(0, cqe.res));
            switch (cqe.user_data) {
                @intFromEnum(Location.worker_stdout) => {
                    if (cqe.res <= 0) {
                        stdout_eof = true;
                        continue;
                    }
                    platform.write(posix.STDOUT_FILENO, worker_stdout_buf[0..len]);
                    _ = try ring.read(@intFromEnum(Location.worker_stdout), stdout_fd, .{ .buffer = &worker_stdout_buf }, 0);
                },
                @intFromEnum(Location.worker_stderr) => {
                    if (cqe.res <= 0) {
                        stderr_eof = true;
                        continue;
                    }
                    platform.write(posix.STDERR_FILENO, worker_stderr_buf[0..len]);
                    _ = try ring.read(@intFromEnum(Location.worker_stderr), stderr_fd, .{ .buffer = &worker_stderr_buf }, 0);
                },
                @intFromEnum(Location.local_stdin) => {
                    if (cqe.res <= 0) {
                        posix.close(stdin_fd);
                        continue;
                    }
                    if (exit_code != null) continue;
                    platform.write(stdin_fd, local_stdin_buf[0..len]);
                    _ = try ring.read(@intFromEnum(Location.local_stdin), posix.STDIN_FILENO, .{ .buffer = &local_stdin_buf }, 0);
                },
                @intFromEnum(Location.signals) => {
                    if (cqe.res <= 0) {
                        if (exit_code == null) exit_code = 1;
                        continue;
                    }
                    switch (signal_parser.feed(signals_buf[0..len], signals_fd)) {
                        .exit => |code| {
                            exit_code = code;
                        },
                        .none => _ = try ring.read(@intFromEnum(Location.signals), signals_fd, .{ .buffer = &signals_buf }, 0),
                    }
                },
                else => {},
            }
        }
        // Exit only when we have exit code AND both output streams are drained
        if (exit_code != null and stdout_eof and stderr_eof) {
            return exit_code.?;
        }
    }
}
