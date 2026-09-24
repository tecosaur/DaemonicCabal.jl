// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0
//
// Linux io_uring-based event loop for the conductor.

const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;

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

// EventLoop
pub const EventLoop = struct {
    ring: linux.IoUring,
    health_check_ts: linux.kernel_timespec,
    ping_timeout_ts: linux.kernel_timespec = .{ .sec = 0, .nsec = 0 },
    live_ts: linux.kernel_timespec = .{ .sec = 0, .nsec = 0 },
    tick_ts: linux.kernel_timespec = .{ .sec = 1, .nsec = 0 },
    tick_armed: bool = false,

    pub fn init(entries: u13) !EventLoop {
        return .{
            .ring = try linux.IoUring.init(entries, 0),
            .health_check_ts = .{ .sec = 1, .nsec = 0 },
        };
    }

    pub fn deinit(self: *EventLoop) void {
        self.ring.deinit();
    }

    pub fn armLiveTimer(self: *EventLoop, delay_ms: u64) void {
        self.live_ts = .{ .sec = @intCast(delay_ms / 1000), .nsec = @intCast((delay_ms % 1000) * std.time.ns_per_ms) };
        _ = self.ring.timeout(@intFromEnum(EventLocation.live_timer), &self.live_ts, 0, 0) catch {};
    }

    pub fn scheduleHealthCheck(self: *EventLoop, w: *worker.Worker) void {
        _ = self.ring.timeout(@intFromPtr(w) | 1, &self.health_check_ts, 0, 0) catch {};
    }

    /// The pong read is linked to a timeout, which cancels it on expiry.
    pub fn awaitPong(self: *EventLoop, w: *worker.Worker, timeout_ms: u64) void {
        w.ping_pending = true;
        self.ping_timeout_ts = .{ .sec = @intCast(timeout_ms / 1000), .nsec = @intCast((timeout_ms % 1000) * std.time.ns_per_ms) };
        const sqe = self.ring.read(@intFromPtr(w), w.socket, .{ .buffer = &w.pong_buf }, 0) catch {
            w.ping_pending = false;
            return;
        };
        sqe.flags |= linux.IOSQE_IO_LINK;
        _ = self.ring.link_timeout(@intFromEnum(EventLocation.ignored), &self.ping_timeout_ts, 0) catch {};
    }

    /// One-shot. `tag` is a pending record's pointer, its low bits naming what.
    pub fn watchFd(self: *EventLoop, tag: usize, fd: posix.fd_t) void {
        _ = self.ring.poll_add(tag, fd, posix.POLL.IN) catch {};
    }

    /// A completion that still arrives is negative (cancelled) and ignored.
    pub fn unwatchFd(self: *EventLoop, tag: usize, _: posix.fd_t) void {
        _ = self.ring.cancel(@intFromEnum(EventLocation.ignored), tag, 0) catch {};
    }

    pub fn armTick(self: *EventLoop) void {
        if (self.tick_armed) return;
        _ = self.ring.timeout(@intFromEnum(EventLocation.tick_timer), &self.tick_ts, 0, 0) catch return;
        self.tick_armed = true;
    }

    /// Any completion that still arrives is rejected by isLiveWorker.
    pub fn cancelPendingPing(self: *EventLoop, w: *worker.Worker) void {
        _ = self.ring.cancel(@intFromEnum(EventLocation.ignored), @intFromPtr(w) | 1, 0) catch {};
        if (w.ping_pending) {
            _ = self.ring.cancel(@intFromEnum(EventLocation.ignored), @intFromPtr(w), 0) catch {};
            _ = self.ring.submit() catch {};
            var buf: [5]u8 = undefined;
            protocol.readExact(w.socket, &buf) catch {};
            w.ping_pending = false;
        } else {
            _ = self.ring.submit() catch {};
        }
    }
};

// Main event loop
pub fn run(conductor: *Conductor, listener: *protocol.Listener) void {
    const ring = &conductor.event_loop.ring;
    var signal_buf: [16]u8 = undefined;
    var client_addr: std.Io.Threaded.PosixAddress = undefined;
    var client_addr_len: posix.socklen_t = @sizeOf(std.Io.Threaded.PosixAddress);
    var server_fd = listener.fd();
    var ping_timer = linux.kernel_timespec{ .sec = @intCast(conductor.cfg.ping_interval), .nsec = 0 };
    const pressure_active = conductor.pressure_monitor.active();
    var pressure_timer = linux.kernel_timespec{ .sec = @intCast(conductor.pressureIntervalS()), .nsec = 0 };
    _ = ring.accept(@intFromEnum(EventLocation.accept), server_fd, &client_addr.any, &client_addr_len, posix.SOCK.CLOEXEC) catch |err| {
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
    if (pressure_active) {
        _ = ring.timeout(@intFromEnum(EventLocation.pressure_timer), &pressure_timer, 0, 0) catch |err| {
            std.debug.print("Fatal: failed to queue pressure timer: {}\n", .{err});
            return;
        };
    }
    while (true) {
        _ = ring.submit_and_wait(1) catch |err| {
            if (err == error.SignalInterrupt) continue;
            std.debug.print("Fatal: io_uring submit_and_wait failed: {}\n", .{err});
            return;
        };
        var need_rearm_accept = false;
        var need_rearm_ping_timer = false;
        var need_rearm_pressure_timer = false;
        // Whether a live `--status` view needs a repaint, once per batch.
        var pool_changed = false;
        while (ring.cq_ready() > 0) {
            const cqe = ring.copy_cqe() catch |err| {
                std.debug.print("Fatal: io_uring copy_cqe failed: {}\n", .{err});
                return;
            };
            const user_data = cqe.user_data;
            // Pointers: bits 1-2 set is a pending record, else a worker (bit 0:
            // health check timeout).
            if (user_data >= 0x1000 and (user_data & 6) != 0) {
                if (cqe.res >= 0) conductor.onReadable(@intCast(user_data));
                pool_changed = true;
                continue;
            }
            if (user_data >= 0x1000) {
                const w: *worker.Worker = @ptrFromInt(user_data & ~@as(u64, 1));
                if (!conductor.isLiveWorker(w)) continue;
                if ((user_data & 1) != 0) {
                    conductor.onHealthCheck(w);
                } else if (cqe.res == -@as(i32, @intFromEnum(linux.E.CANCELED))) {
                    conductor.onPongTimeout(w);
                } else {
                    conductor.onPong(w, if (cqe.res > 0) @intCast(cqe.res) else 0);
                }
                pool_changed = true;
                continue;
            }
            switch (@as(EventLocation, @enumFromInt(user_data))) {
                .accept => {
                    if (cqe.res >= 0) {
                        const client_fd: posix.fd_t = @intCast(cqe.res);
                        const peer = main.PeerInfo.fromSockaddr(&client_addr);
                        conductor.admitConnection(client_fd, &peer);
                    } else {
                        const err_code: u32 = @intCast(-cqe.res);
                        if (err_code != @intFromEnum(posix.E.BADF)) {
                            std.debug.print("Accept error: {d}\n", .{cqe.res});
                        }
                    }
                    need_rearm_accept = true;
                    pool_changed = true;
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
                                    listener.close(conductor.io);
                                    listener.* = conductor.createServer() catch |err| {
                                        std.debug.print("Failed to recreate socket: {}\n", .{err});
                                        continue;
                                    };
                                    server_fd = listener.fd();
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
                    conductor.onPingTimer();
                    need_rearm_ping_timer = true;
                    pool_changed = true;
                },
                .pressure_timer => {
                    conductor.onPressureTimer();
                    need_rearm_pressure_timer = true;
                    pool_changed = true;
                },
                .live_timer => conductor.onLiveTimer(),
                .tick_timer => {
                    conductor.event_loop.tick_armed = false;
                    if (conductor.tick()) conductor.event_loop.armTick();
                    pool_changed = true;
                },
                .ignored, _ => {},
            }
        }
        if (pool_changed) conductor.noteLiveChange();
        if (need_rearm_accept) {
            client_addr_len = @sizeOf(std.Io.Threaded.PosixAddress);
            _ = ring.accept(@intFromEnum(EventLocation.accept), server_fd, &client_addr.any, &client_addr_len, posix.SOCK.CLOEXEC) catch |err| {
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
        if (need_rearm_pressure_timer) {
            _ = ring.timeout(@intFromEnum(EventLocation.pressure_timer), &pressure_timer, 0, 0) catch |err| {
                std.debug.print("Fatal: failed to requeue pressure timer: {}\n", .{err});
                return;
            };
        }
    }
}
