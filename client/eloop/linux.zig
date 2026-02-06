// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0
//
// Linux io_uring-based event loop for the client.
// Multiplexes stdin, stdout (from worker), and signals socket.

const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;

const platform = @import("../platform/main.zig");
const protocol = @import("../protocol.zig");

const Location = enum(u64) {
    stdin,
    stdout,
    signals,
};

/// Run the client I/O loop using io_uring.
/// Returns exit code when complete.
pub fn run(
    stdio_fd: posix.fd_t,
    signals_fd: posix.fd_t,
    signal_parser: anytype,
) !u8 {
    const buf_size = 1024;
    var ring = try linux.IoUring.init(4, 0);
    defer ring.deinit();
    var stdout_buf: [buf_size]u8 = undefined;
    var stdin_buf: [buf_size]u8 = undefined;
    var signals_buf: [buf_size]u8 = undefined;
    // Queue initial reads
    _ = try ring.read(@intFromEnum(Location.stdout), stdio_fd, .{ .buffer = &stdout_buf }, 0);
    _ = try ring.read(@intFromEnum(Location.stdin), posix.STDIN_FILENO, .{ .buffer = &stdin_buf }, 0);
    _ = try ring.read(@intFromEnum(Location.signals), signals_fd, .{ .buffer = &signals_buf }, 0);
    // Wait for both: stdout EOF (guarantees output flushed) and exit code (from signals socket).
    // If signals EOF arrives without exit code, worker crashed - use exit code 1.
    var exit_code: ?u8 = null;
    var stdout_eof = false;
    while (true) {
        _ = try ring.submit_and_wait(1);
        while (ring.cq_ready() > 0) {
            const cqe = try ring.copy_cqe();
            const len: usize = @intCast(@max(0, cqe.res));
            switch (cqe.user_data) {
                @intFromEnum(Location.stdout) => {
                    // Treat errors (e.g., ECONNRESET) same as EOF
                    if (cqe.res <= 0) {
                        stdout_eof = true;
                        continue;
                    }
                    platform.write(posix.STDOUT_FILENO, stdout_buf[0..len]);
                    _ = try ring.read(@intFromEnum(Location.stdout), stdio_fd, .{ .buffer = &stdout_buf }, 0);
                },
                @intFromEnum(Location.stdin) => {
                    if (cqe.res <= 0 or exit_code != null) continue; // EOF/error or exiting
                    platform.write(stdio_fd, stdin_buf[0..len]);
                    _ = try ring.read(@intFromEnum(Location.stdin), posix.STDIN_FILENO, .{ .buffer = &stdin_buf }, 0);
                },
                @intFromEnum(Location.signals) => {
                    // Treat errors same as EOF - worker may have crashed or closed connection
                    if (cqe.res <= 0) {
                        if (exit_code == null) exit_code = 1;
                        continue;
                    }
                    switch (signal_parser.feed(signals_buf[0..len], signals_fd)) {
                        .exit => |code| exit_code = code,
                        .none => _ = try ring.read(@intFromEnum(Location.signals), signals_fd, .{ .buffer = &signals_buf }, 0),
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
