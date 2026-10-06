// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0
//
// Linux io_uring-based event loop for the client.

const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;

const platform = @import("../platform/main.zig");
const cooked = @import("../cooked.zig");
const debuglog = @import("../debuglog.zig");
const typeahead = @import("../typeahead.zig");

const Location = enum(u64) {
    local_stdin,
    worker_stdout,
    worker_stderr,
    signals,
    /// The worker's stdin, which has room again for what waits to be sent.
    worker_stdin,
};

// A regular-file stdin must read on from its position, not from offset 0 forever.
const at_file_position: u64 = std.math.maxInt(u64);

/// Returns the worker's exit code.
pub fn run(
    ring: *linux.IoUring,
    stdin_fd: posix.fd_t,
    stdout_fd: posix.fd_t,
    stderr_fd: posix.fd_t,
    signals_fd: posix.fd_t,
    signal_parser: anytype,
    sync_mode: bool,
) !u8 {
    // Each indexed by its Location.
    const srcs = [4]posix.fd_t{ posix.STDIN_FILENO, stdout_fd, stderr_fd, signals_fd };
    var bufs: [4][cooked.StdinForwarder.max_read]u8 = undefined;
    var ended = [4]bool{ false, false, false, false };
    var stdin_fwd = cooked.StdinForwarder{ .dst = stdin_fd, .sync_mode = sync_mode, .wants_raw = &signal_parser.worker_wants_raw };
    for (0..srcs.len) |i| try queueRead(ring, @enumFromInt(i), srcs[i], &bufs[i]);
    // Signals EOF without an exit code means the worker crashed.
    var exit_code: ?u8 = null;
    while (true) {
        _ = ring.submit_and_wait(1) catch |err| switch (err) {
            error.SignalInterrupt => continue,
            else => return err,
        };
        while (ring.cq_ready() > 0) {
            const cqe = try ring.copy_cqe();
            const loc = std.enums.fromInt(Location, cqe.user_data) orelse continue;
            const i = @intFromEnum(loc);
            // A poll's result is its events, not data.
            const data: []u8 = if (loc == .worker_stdin) &.{} else bufs[i][0..@intCast(@max(0, cqe.res))];
            switch (loc) {
                .worker_stdout, .worker_stderr => {
                    if (cqe.res <= 0) {
                        ended[i] = true;
                        continue;
                    }
                    debuglog.event("{s}: {d} B {f}", .{ if (loc == .worker_stdout) "stdout" else "stderr", data.len, debuglog.preview(data) });
                    if (!typeahead.relay(if (loc == .worker_stdout) posix.STDOUT_FILENO else posix.STDERR_FILENO, data)) {
                        platform.close(srcs[i]);
                        ended[i] = true;
                        continue;
                    }
                },
                .local_stdin, .worker_stdin => {
                    if (exit_code != null) continue;
                    if (loc == .local_stdin) {
                        if (cqe.res <= 0) _ = stdin_fwd.end() else stdin_fwd.forward(data);
                    }
                    if (!stdin_fwd.flush()) {
                        _ = try ring.poll_add(@intFromEnum(Location.worker_stdin), stdin_fd, posix.POLL.OUT);
                    } else if (!stdin_fwd.ended) {
                        try queueRead(ring, .local_stdin, srcs[0], &bufs[0]);
                    }
                    continue;
                },
                .signals => {
                    if (cqe.res <= 0) {
                        if (exit_code == null) exit_code = 1;
                        continue;
                    }
                    switch (signal_parser.feed(data, signals_fd)) {
                        .exit => |code| {
                            exit_code = code;
                            continue;
                        },
                        .none => {},
                    }
                },
            }
            try queueRead(ring, loc, srcs[i], &bufs[i]);
        }
        const worker_stdout = @intFromEnum(Location.worker_stdout);
        const worker_stderr = @intFromEnum(Location.worker_stderr);
        if (exit_code != null and ended[worker_stdout] and ended[worker_stderr]) return exit_code.?;
    }
}

fn queueRead(ring: *linux.IoUring, loc: Location, fd: posix.fd_t, buf: []u8) !void {
    const offset = if (loc == .local_stdin) at_file_position else 0;
    _ = try ring.read(@intFromEnum(loc), fd, .{ .buffer = buf }, offset);
}
