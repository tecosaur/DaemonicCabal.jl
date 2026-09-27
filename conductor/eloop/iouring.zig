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
const platform_linux = @import("../platform/linux.zig");
const protocol = @import("../protocol.zig");
const worker = @import("../worker.zig");

const EventLocation = protocol.EventLocation;
const posix_signals = @import("posix_signals.zig");

const signal_pipe = &posix_signals.signal_pipe;
const SIGNAL_SHUTDOWN = posix_signals.SIGNAL_SHUTDOWN;
const SIGNAL_RECREATE = posix_signals.SIGNAL_RECREATE;
// A timeout's result on expiry; cancelled, it gives -ECANCELED.
const etime: i32 = @intFromEnum(linux.E.TIME);

/// A pong poll's user data: a worker's pointer alone could name a poll
/// cancelled since, whose completion is still to come.
const PongPoll = struct { w: *worker.Worker };

// EventLoop
pub const EventLoop = struct {
    ring: linux.IoUring,
    health_check_ts: linux.kernel_timespec,
    ping_timeout_ts: linux.kernel_timespec = .{ .sec = 0, .nsec = 0 },
    live_ts: linux.kernel_timespec = .{ .sec = 0, .nsec = 0 },
    tick_ts: linux.kernel_timespec = .{ .sec = 1, .nsec = 0 },
    tick_armed: bool = false,
    /// The poll each worker's pong is awaited by; any other is stale.
    pong_polls: std.AutoHashMapUnmanaged(*worker.Worker, *PongPoll) = .empty,
    pong_pool: std.heap.MemoryPool(PongPoll) = .empty,

    pub fn init(entries: u13) !EventLoop {
        return .{
            .ring = try platform_linux.initIoUring(entries),
            .health_check_ts = .{ .sec = 1, .nsec = 0 },
        };
    }

    pub fn deinit(self: *EventLoop) void {
        self.ring.deinit();
        self.pong_polls.deinit(std.heap.page_allocator);
        self.pong_pool.deinit(std.heap.page_allocator);
    }

    pub fn logResolution(_: *const EventLoop) void {
        std.debug.print(" - Event loop: io_uring\n", .{});
    }

    /// Replaces the pending one, which then completes cancelled.
    pub fn armLiveTimer(self: *EventLoop, delay_ms: u64) void {
        const tag = @intFromEnum(EventLocation.live_timer);
        self.live_ts = .{ .sec = @intCast(delay_ms / 1000), .nsec = @intCast((delay_ms % 1000) * std.time.ns_per_ms) };
        const ring = self.room(2) catch |err| return std.debug.print("io_uring: live timer not queued: {}\n", .{err});
        _ = ring.timeout_remove(@intFromEnum(EventLocation.ignored), tag, 0) catch unreachable;
        _ = ring.timeout(tag, &self.live_ts, 0, 0) catch unreachable;
    }

    pub fn scheduleHealthCheck(self: *EventLoop, w: *worker.Worker) void {
        self.queueTimeout(@intFromPtr(w) | 1, &self.health_check_ts) catch |err|
            w.log("health check not queued: {}", .{err});
    }

    /// The pong is polled for, not read, so it stays for `onPong` or
    /// `cancelPendingPing` to read; the poll is linked to a timeout, which
    /// cancels it on expiry. Unqueued, the ping stays pending, for
    /// `cancelPendingPing`.
    pub fn awaitPong(self: *EventLoop, w: *worker.Worker, timeout_ms: u64) void {
        w.ping_pending = true;
        self.ping_timeout_ts = .{ .sec = @intCast(timeout_ms / 1000), .nsec = @intCast((timeout_ms % 1000) * std.time.ns_per_ms) };
        self.queuePongPoll(w) catch |err| w.log("pong poll not queued: {}", .{err});
    }

    /// One-shot. `tag` is a pending record's pointer, its low bits naming what.
    pub fn watchFd(self: *EventLoop, tag: usize, fd: posix.fd_t) void {
        const ring = self.room(1) catch |err| return std.debug.print("io_uring: fd {d} not watched: {}\n", .{ fd, err });
        _ = ring.poll_add(tag, fd, posix.POLL.IN) catch unreachable;
    }

    /// A completion that still arrives is negative (cancelled) and ignored.
    pub fn unwatchFd(self: *EventLoop, tag: usize, fd: posix.fd_t) void {
        self.queueCancel(tag) catch |err| std.debug.print("io_uring: fd {d} not unwatched: {}\n", .{ fd, err });
    }

    pub fn armTick(self: *EventLoop) void {
        if (self.tick_armed) return;
        self.queueTimeout(@intFromEnum(EventLocation.tick_timer), &self.tick_ts) catch |err|
            return std.debug.print("io_uring: tick not queued: {}\n", .{err});
        self.tick_armed = true;
    }

    /// The pong poll's completion, should it still arrive, is stale.
    pub fn cancelPendingPing(self: *EventLoop, w: *worker.Worker) void {
        self.queueCancel(@intFromPtr(w) | 1) catch |err| w.log("health check not cancelled: {}", .{err});
        if (self.pong_polls.fetchRemove(w)) |kv|
            self.queueCancel(@intFromPtr(kv.value)) catch |err| w.log("pong poll not cancelled: {}", .{err});
        if (!w.ping_pending) return;
        var buf: [protocol.worker.pong_size]u8 = undefined;
        protocol.readExact(w.socket, &buf) catch {};
        w.ping_pending = false;
    }

    fn queuePongPoll(self: *EventLoop, w: *worker.Worker) !void {
        const ring = try self.room(2);
        const poll = try self.pong_pool.create(std.heap.page_allocator);
        errdefer self.pong_pool.destroy(poll);
        poll.* = .{ .w = w };
        try self.pong_polls.put(std.heap.page_allocator, w, poll);
        const sqe = ring.poll_add(@intFromPtr(poll), w.socket, posix.POLL.IN) catch unreachable;
        sqe.flags |= linux.IOSQE_IO_LINK;
        _ = ring.link_timeout(@intFromEnum(EventLocation.ignored), &self.ping_timeout_ts, 0) catch unreachable;
    }

    /// Frees `poll`, returning its worker unless it was stale.
    fn takePongPoll(self: *EventLoop, poll: *PongPoll) ?*worker.Worker {
        defer self.pong_pool.destroy(poll);
        const w = poll.w;
        if (self.pong_polls.get(w) != poll) return null;
        _ = self.pong_polls.remove(w);
        return w;
    }

    /// The ring, with room for `n` more SQEs: those queued are submitted when
    /// they would not fit, so a linked pair never straddles a submit.
    fn room(self: *EventLoop, n: u32) !*linux.IoUring {
        const ring = &self.ring;
        if (ring.sq.sqes.len - ring.sq_ready() < n) _ = try ring.submit();
        if (ring.sq.sqes.len - ring.sq_ready() < n) return error.SubmissionQueueFull;
        return ring;
    }

    fn queueTimeout(self: *EventLoop, user_data: u64, ts: *const linux.kernel_timespec) !void {
        _ = (try self.room(1)).timeout(user_data, ts, 0, 0) catch unreachable;
    }

    fn queueCancel(self: *EventLoop, target: u64) !void {
        _ = (try self.room(1)).cancel(@intFromEnum(EventLocation.ignored), target, 0) catch unreachable;
    }
};

// Main event loop
pub fn run(conductor: *Conductor, loop: *EventLoop, listener: *protocol.Listener) void {
    const ring = &loop.ring;
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
            // Pointers: bits 1-2 set is a pending record, bit 0 a worker's
            // health check timeout, else a pong poll.
            if (user_data >= 0x1000 and (user_data & 6) != 0) {
                if (cqe.res >= 0) conductor.onReadable(@intCast(user_data));
                pool_changed = true;
                continue;
            }
            if (user_data >= 0x1000 and (user_data & 1) != 0) {
                const w: *worker.Worker = @ptrFromInt(user_data & ~@as(u64, 1));
                if (cqe.res != -etime or !conductor.isLiveWorker(w)) continue;
                conductor.onHealthCheck(w);
                pool_changed = true;
                continue;
            }
            if (user_data >= 0x1000) {
                const w = loop.takePongPoll(@ptrFromInt(user_data)) orelse continue;
                if (!conductor.isLiveWorker(w)) continue;
                // Negative: cancelled by its timeout, or failed.
                if (cqe.res > 0) conductor.onPong(w, null) else conductor.onPongTimeout(w);
                pool_changed = true;
                continue;
            }
            switch (@as(EventLocation, @enumFromInt(user_data))) {
                .accept => {
                    if (cqe.res >= 0) {
                        const client_fd: posix.fd_t = @intCast(cqe.res);
                        const peer = main.PeerInfo.fromSockaddr(&client_addr);
                        conductor.admitConnection(client_fd, &peer);
                    } else switch (@as(linux.E, @enumFromInt(@as(u16, @intCast(-cqe.res))))) {
                        .BADF, .CANCELED => {},
                        else => |err| std.debug.print("Accept error: {t}\n", .{err}),
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
                                    // The pending accept holds the old socket open, so it
                                    // goes first; its completion rearms on the new one.
                                    loop.queueCancel(@intFromEnum(EventLocation.accept)) catch |err|
                                        std.debug.print("io_uring: accept not cancelled: {}\n", .{err});
                                    _ = ring.submit() catch {};
                                    listener.close(conductor.io);
                                    server_fd = -1;
                                    listener.* = conductor.createServer() catch |err| {
                                        std.debug.print("Failed to recreate socket: {}\n", .{err});
                                        continue;
                                    };
                                    server_fd = listener.fd();
                                },
                                else => {},
                            }
                        }
                    }
                    const signal_ring = loop.room(1) catch |err| {
                        std.debug.print("Fatal: failed to requeue signal read: {}\n", .{err});
                        return;
                    };
                    _ = signal_ring.read(@intFromEnum(EventLocation.signal), signal_pipe[0], .{ .buffer = &signal_buf }, 0) catch unreachable;
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
                .live_timer => if (cqe.res == -etime) conductor.onLiveTimer(),
                .tick_timer => {
                    loop.tick_armed = false;
                    if (conductor.tick()) loop.armTick();
                    pool_changed = true;
                },
                .ignored, _ => {},
            }
        }
        if (pool_changed) conductor.noteLiveChange();
        if (need_rearm_accept and server_fd >= 0) {
            client_addr_len = @sizeOf(std.Io.Threaded.PosixAddress);
            const accept_ring = loop.room(1) catch |err| {
                std.debug.print("Fatal: failed to requeue accept: {}\n", .{err});
                return;
            };
            _ = accept_ring.accept(@intFromEnum(EventLocation.accept), server_fd, &client_addr.any, &client_addr_len, posix.SOCK.CLOEXEC) catch unreachable;
        }
        if (need_rearm_ping_timer) {
            loop.queueTimeout(@intFromEnum(EventLocation.ping_timer), &ping_timer) catch |err| {
                std.debug.print("Fatal: failed to requeue ping timer: {}\n", .{err});
                return;
            };
        }
        if (need_rearm_pressure_timer) {
            loop.queueTimeout(@intFromEnum(EventLocation.pressure_timer), &pressure_timer) catch |err| {
                std.debug.print("Fatal: failed to requeue pressure timer: {}\n", .{err});
                return;
            };
        }
    }
}
