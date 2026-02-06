// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0
//
// Linux io_uring-based event loop for the conductor.

const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const Io = std.Io;

const main = @import("../main.zig");
const Conductor = main.Conductor;
const platform = @import("../platform/main.zig");
const protocol = @import("../protocol.zig");
const worker = @import("../worker.zig");

const EventLocation = protocol.EventLocation;
const posix_signals = @import("posix_signals.zig");

pub const installSignalHandlers = posix_signals.installSignalHandlers;
pub const cleanupSignalHandlers = posix_signals.cleanupSignalHandlers;
const signal_pipe = &posix_signals.signal_pipe;
const SIGNAL_SHUTDOWN = posix_signals.SIGNAL_SHUTDOWN;
const SIGNAL_RECREATE = posix_signals.SIGNAL_RECREATE;

// EventLoop (wraps io_uring + health check state)
pub const EventLoop = struct {
    ring: linux.IoUring,
    health_check_ts: linux.kernel_timespec,

    pub fn init(entries: u13) !EventLoop {
        return .{
            .ring = try linux.IoUring.init(entries, 0),
            .health_check_ts = .{ .sec = 1, .nsec = 0 },
        };
    }

    pub fn deinit(self: *EventLoop) void {
        self.ring.deinit();
    }

    /// Schedule a health check for a worker after a short delay.
    pub fn scheduleHealthCheck(self: *EventLoop, w: *worker.Worker) void {
        _ = self.ring.timeout(@intFromPtr(w) | 1, &self.health_check_ts, 0, 0) catch {};
    }

    /// Cancel pending async ping read and drain the pong response.
    pub fn cancelPendingPing(self: *EventLoop, w: *worker.Worker) void {
        if (!w.ping_pending) return;
        _ = self.ring.cancel(@intFromEnum(EventLocation.ignored), @intFromPtr(w), 0) catch {};
        _ = self.ring.submit() catch {};
        var buf: [7]u8 = undefined;
        protocol.readExact(w.socket, &buf) catch {};
        w.ping_pending = false;
    }
};

// Main event loop
pub fn run(conductor: *Conductor, server: *Io.net.Server) void {
    const ring = &conductor.event_loop.ring;
    var signal_buf: [16]u8 = undefined;
    var pong_buf: [7]u8 = undefined;
    var client_addr: posix.sockaddr = undefined;
    var client_addr_len: posix.socklen_t = @sizeOf(posix.sockaddr);
    var server_fd = server.socket.handle;
    var ping_timer = linux.kernel_timespec{ .sec = @intCast(conductor.cfg.ping_interval), .nsec = 0 };
    var ping_timeout_ts = linux.kernel_timespec{ .sec = @intCast(conductor.cfg.ping_timeout), .nsec = 0 };
    // Queue initial operations
    _ = ring.accept(@intFromEnum(EventLocation.accept), server_fd, &client_addr, &client_addr_len, 0) catch |err| {
        std.debug.print("Fatal: failed to queue initial accept: {}\n", .{err});
        return;
    };
    _ = ring.read(@intFromEnum(EventLocation.signal), signal_pipe[0], .{ .buffer = &signal_buf }, 0) catch |err| {
        std.debug.print("Fatal: failed to queue signal read: {}\n", .{err});
        return;
    };
    _ = ring.timeout(@intFromEnum(EventLocation.ping_timer), &ping_timer, 0, 0) catch |err| {
        std.debug.print("Fatal: failed to queue ping timer: {}\n", .{err});
        return;
    };
    while (true) {
        _ = ring.submit_and_wait(1) catch |err| {
            if (err == error.SignalInterrupt) continue;
            std.debug.print("Fatal: io_uring submit_and_wait failed: {}\n", .{err});
            return;
        };
        var need_rearm_accept = false;
        var need_rearm_ping_timer = false;
        while (ring.cq_ready() > 0) {
            const cqe = ring.copy_cqe() catch |err| {
                std.debug.print("Fatal: io_uring copy_cqe failed: {}\n", .{err});
                return;
            };
            const user_data = cqe.user_data;
            // Worker events (user_data >= 0x1000, bit 0: 0=pong, 1=health check timeout)
            if (user_data >= 0x1000) {
                const w: *worker.Worker = @ptrFromInt(user_data & ~@as(u64, 1));
                if ((user_data & 1) != 0) {
                    const recently_pinged = (conductor.currentTime() - w.last_pinged) < 2;
                    if (w.active_clients == 0 and !w.ping_pending and !recently_pinged) {
                        queuePing(ring, w, &pong_buf, &ping_timeout_ts);
                    }
                } else {
                    handlePongResponse(conductor, w, cqe.res, &pong_buf);
                }
                continue;
            }
            switch (@as(EventLocation, @enumFromInt(user_data))) {
                .accept => {
                    if (cqe.res >= 0) {
                        const client_fd: posix.fd_t = @intCast(cqe.res);
                        conductor.handleConnectionFd(client_fd) catch |err| {
                            std.debug.print("Client handling failed: {}\n", .{err});
                        };
                        posix.close(client_fd);
                    } else {
                        const err_code: u32 = @intCast(-cqe.res);
                        if (err_code != @intFromEnum(posix.E.BADF)) {
                            std.debug.print("Accept error: {d}\n", .{cqe.res});
                        }
                    }
                    need_rearm_accept = true;
                },
                .signal => {
                    if (cqe.res > 0) {
                        const len: usize = @intCast(cqe.res);
                        for (signal_buf[0..len]) |sig| {
                            switch (sig) {
                                SIGNAL_SHUTDOWN => {
                                    std.debug.print("\nShutdown requested, stopping workers...\n", .{});
                                    conductor.gracefulShutdown();
                                    return;
                                },
                                SIGNAL_RECREATE => {
                                    std.debug.print("Recreating socket due to SIGUSR1\n", .{});
                                    server.deinit(conductor.io);
                                    Io.Dir.deleteFileAbsolute(conductor.io, conductor.cfg.socket_path) catch {};
                                    server.* = conductor.createServer() catch |err| {
                                        std.debug.print("Failed to recreate socket: {}\n", .{err});
                                        continue;
                                    };
                                    server_fd = server.socket.handle;
                                    need_rearm_accept = true;
                                },
                                else => {},
                            }
                        }
                    }
                    _ = ring.read(@intFromEnum(EventLocation.signal), signal_pipe[0], .{ .buffer = &signal_buf }, 0) catch |err| {
                        std.debug.print("Fatal: failed to requeue signal read: {}\n", .{err});
                        return;
                    };
                },
                .ping_timer => {
                    queueWorkerPings(conductor, ring, &pong_buf, &ping_timeout_ts);
                    need_rearm_ping_timer = true;
                },
                .ignored, _ => {},
            }
        }
        if (need_rearm_accept) {
            client_addr_len = @sizeOf(posix.sockaddr);
            _ = ring.accept(@intFromEnum(EventLocation.accept), server_fd, &client_addr, &client_addr_len, 0) catch |err| {
                std.debug.print("Fatal: failed to requeue accept: {}\n", .{err});
                return;
            };
        }
        if (need_rearm_ping_timer) {
            _ = ring.timeout(@intFromEnum(EventLocation.ping_timer), &ping_timer, 0, 0) catch |err| {
                std.debug.print("Fatal: failed to requeue ping timer: {}\n", .{err});
                return;
            };
        }
    }
}

// Health checking
fn queueWorkerPings(conductor: *Conductor, ring: *linux.IoUring, pong_buf: *[7]u8, timeout_ts: *linux.kernel_timespec) void {
    const now = conductor.currentTime();
    var it = conductor.workers.iterator();
    while (it.next()) |entry| {
        for (entry.value_ptr.items) |w| {
            maybeQueuePing(conductor, ring, w, pong_buf, timeout_ts, now);
        }
    }
    if (conductor.reserve) |r| maybeQueuePing(conductor, ring, r, pong_buf, timeout_ts, now);
}

fn maybeQueuePing(conductor: *Conductor, ring: *linux.IoUring, w: *worker.Worker, pong_buf: *[7]u8, timeout_ts: *linux.kernel_timespec, now: i64) void {
    if (w.ping_pending) return;
    if (w.active_clients > 0) return;
    if (now - w.last_pinged < @as(i64, @intCast(conductor.cfg.ping_interval))) return;
    queuePing(ring, w, pong_buf, timeout_ts);
}

fn queuePing(ring: *linux.IoUring, w: *worker.Worker, pong_buf: *[7]u8, timeout_ts: *linux.kernel_timespec) void {
    w.sendPing();
    const sqe = ring.read(@intFromPtr(w), w.socket, .{ .buffer = pong_buf }, 0) catch {
        w.ping_pending = false;
        return;
    };
    sqe.flags |= linux.IOSQE_IO_LINK;
    _ = ring.link_timeout(@intFromEnum(EventLocation.ignored), timeout_ts, 0) catch {};
}

fn handlePongResponse(conductor: *Conductor, w: *worker.Worker, cqe_res: i32, pong_buf: *[7]u8) void {
    if (cqe_res == -@as(i32, @intFromEnum(linux.E.CANCELED))) {
        if (w.ping_pending) {
            w.ping_pending = false;
            std.debug.print("Worker {d}: ping timed out\n", .{w.id});
            conductor.killUnresponsiveWorker(w);
        }
        return;
    }
    w.ping_pending = false;
    if (cqe_res <= 0) {
        std.debug.print("Worker {d}: ping failed (res={d})\n", .{ w.id, cqe_res });
        conductor.killUnresponsiveWorker(w);
        return;
    }
    const bytes_read: usize = @intCast(cqe_res);
    if (bytes_read < 7) {
        protocol.readExact(w.socket, pong_buf[bytes_read..]) catch {
            std.debug.print("Worker {d}: pong short read\n", .{w.id});
            conductor.killUnresponsiveWorker(w);
            return;
        };
    }
    w.last_pinged = conductor.currentTime();
    const worker_count = std.mem.readInt(u16, pong_buf[5..7], .little);
    if (worker_count != w.active_clients) {
        std.debug.print("Worker {d}: client count mismatch (worker={d}, conductor={d}), syncing\n", .{ w.id, worker_count, w.active_clients });
        conductor.syncWorkerClients(w);
    }
}
