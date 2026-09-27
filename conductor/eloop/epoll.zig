// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0
//
// Linux epoll-based event loop for the conductor, where io_uring is
// unavailable. Timers are deadlines the loop keeps, bounding each wait; a
// ping's read and timeout race, settled by whichever clears `ping_pending`.

const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;

const main = @import("../main.zig");
const Conductor = main.Conductor;
const protocol = @import("../protocol.zig");
const worker = @import("../worker.zig");

const EventLocation = protocol.EventLocation;
const posix_signals = @import("posix_signals.zig");

const signal_pipe = &posix_signals.signal_pipe;
const SIGNAL_SHUTDOWN = posix_signals.SIGNAL_SHUTDOWN;
const SIGNAL_RECREATE = posix_signals.SIGNAL_RECREATE;

// Tags are an EventLocation, or a pointer (>= 0x1000): to a worker (as a
// timer, bit 0 marks a health check), or with bits 1-2 set a pending record.
const Timer = struct { tag: usize, due_ms: i64 };

// EventLoop
pub const EventLoop = struct {
    epfd: posix.fd_t,
    io_uring_error: anyerror,
    timers: std.ArrayList(Timer) = .empty,
    tick_armed: bool = false,

    pub fn init(io_uring_error: anyerror) !EventLoop {
        const rc = linux.epoll_create1(linux.EPOLL.CLOEXEC);
        if (linux.errno(rc) != .SUCCESS) return error.EpollCreateFailed;
        return .{ .epfd = @intCast(rc), .io_uring_error = io_uring_error };
    }

    pub fn deinit(self: *EventLoop) void {
        _ = linux.close(self.epfd);
        self.timers.deinit(std.heap.page_allocator);
    }

    pub fn logResolution(self: *const EventLoop) void {
        std.debug.print(" - Event loop: epoll (io_uring: {t})\n", .{self.io_uring_error});
    }

    pub fn armLiveTimer(self: *EventLoop, delay_ms: u64) void {
        self.arm(@intFromEnum(EventLocation.live_timer), delay_ms);
    }

    pub fn scheduleHealthCheck(self: *EventLoop, w: *worker.Worker) void {
        self.arm(@intFromPtr(w) | 1, 1000);
    }

    pub fn awaitPong(self: *EventLoop, w: *worker.Worker, timeout_ms: u64) void {
        self.watch(@intFromPtr(w), w.socket, linux.EPOLL.IN | linux.EPOLL.ONESHOT) catch return;
        w.ping_pending = true;
        self.arm(@intFromPtr(w), timeout_ms);
    }

    pub fn watchFd(self: *EventLoop, tag: usize, fd: posix.fd_t) void {
        self.watch(tag, fd, linux.EPOLL.IN | linux.EPOLL.ONESHOT) catch {};
    }

    pub fn unwatchFd(self: *EventLoop, _: usize, fd: posix.fd_t) void {
        _ = linux.epoll_ctl(self.epfd, linux.EPOLL.CTL_DEL, fd, null);
    }

    pub fn armTick(self: *EventLoop) void {
        if (self.tick_armed) return;
        self.arm(@intFromEnum(EventLocation.tick_timer), 1000);
        self.tick_armed = true;
    }

    /// isLiveWorker rejects any stale event.
    pub fn cancelPendingPing(self: *EventLoop, w: *worker.Worker) void {
        self.disarm(@intFromPtr(w) | 1);
        if (!w.ping_pending) return;
        self.unwatchFd(@intFromPtr(w), w.socket);
        self.disarm(@intFromPtr(w));
        var buf: [protocol.worker.pong_size]u8 = undefined;
        protocol.readExact(w.socket, &buf) catch {};
        w.ping_pending = false;
    }

    /// A one-shot watch stays registered once fired, so rewatching modifies it.
    fn watch(self: *EventLoop, tag: usize, fd: posix.fd_t, events: u32) !void {
        var ev = linux.epoll_event{ .events = events, .data = .{ .u64 = tag } };
        const errno = switch (linux.errno(linux.epoll_ctl(self.epfd, linux.EPOLL.CTL_ADD, fd, &ev))) {
            .EXIST => linux.errno(linux.epoll_ctl(self.epfd, linux.EPOLL.CTL_MOD, fd, &ev)),
            else => |e| e,
        };
        if (errno != .SUCCESS) {
            std.debug.print("epoll: failed to watch fd {d}: {t}\n", .{ fd, errno });
            return error.EpollCtlFailed;
        }
    }

    /// Replaces the timer of the same tag.
    fn arm(self: *EventLoop, tag: usize, delay_ms: u64) void {
        self.disarm(tag);
        const due_ms = nowMs() + @as(i64, @intCast(delay_ms));
        self.timers.append(std.heap.page_allocator, .{ .tag = tag, .due_ms = due_ms }) catch
            std.debug.print("epoll: out of memory arming a timer (tag {x})\n", .{tag});
    }

    fn disarm(self: *EventLoop, tag: usize) void {
        for (self.timers.items, 0..) |t, i| if (t.tag == tag) {
            _ = self.timers.swapRemove(i);
            return;
        };
    }

    /// Removes and returns a timer due by `now_ms`.
    fn takeDue(self: *EventLoop, now_ms: i64) ?usize {
        for (self.timers.items, 0..) |t, i| if (t.due_ms <= now_ms) {
            _ = self.timers.swapRemove(i);
            return t.tag;
        };
        return null;
    }

    /// Until the next timer is due, or indefinitely (-1).
    fn waitMs(self: *const EventLoop) i32 {
        if (self.timers.items.len == 0) return -1;
        var due_ms: i64 = std.math.maxInt(i64);
        for (self.timers.items) |t| due_ms = @min(due_ms, t.due_ms);
        return @intCast(std.math.clamp(due_ms - nowMs(), 0, std.math.maxInt(i32)));
    }
};

// Main event loop
pub fn run(conductor: *Conductor, loop: *EventLoop, listener: *protocol.Listener) void {
    var server_fd = listener.fd();
    loop.watch(@intFromEnum(EventLocation.accept), server_fd, linux.EPOLL.IN) catch return;
    loop.watch(@intFromEnum(EventLocation.signal), signal_pipe[0], linux.EPOLL.IN) catch return;
    const ping_interval_ms = conductor.cfg.ping_interval * 1000;
    const pressure_interval_ms = conductor.pressureIntervalS() * 1000;
    loop.arm(@intFromEnum(EventLocation.ping_timer), ping_interval_ms);
    if (conductor.pressure_monitor.active()) loop.arm(@intFromEnum(EventLocation.pressure_timer), pressure_interval_ms);
    var signal_buf: [16]u8 = undefined;
    var events: [32]linux.epoll_event = undefined;
    while (true) {
        const rc = linux.epoll_wait(loop.epfd, &events, events.len, loop.waitMs());
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            .INTR => continue,
            else => |err| {
                std.debug.print("Fatal: epoll_wait failed: {t}\n", .{err});
                return;
            },
        }
        // Whether a live `--status` view needs a repaint, once per batch.
        var pool_changed = false;
        // Readiness
        for (events[0..rc]) |ev| {
            const tag: usize = @intCast(ev.data.u64);
            if (tag >= 0x1000) {
                pool_changed = true;
                if ((tag & 6) != 0) {
                    conductor.onReadable(tag);
                    continue;
                }
                const w: *worker.Worker = @ptrFromInt(tag);
                if (!conductor.isLiveWorker(w)) continue;
                loop.disarm(tag);
                conductor.onPong(w);
                continue;
            }
            switch (@as(EventLocation, @enumFromInt(tag))) {
                .accept => {
                    handleAccept(conductor, server_fd);
                    pool_changed = true;
                },
                .signal => {
                    if (handleSignal(conductor, loop, listener, &server_fd, &signal_buf)) return;
                    pool_changed = true;
                },
                else => {},
            }
        }
        // Timers
        const now_ms = nowMs();
        while (loop.takeDue(now_ms)) |tag| {
            if (tag >= 0x1000) {
                const w: *worker.Worker = @ptrFromInt(tag & ~@as(usize, 1));
                if (!conductor.isLiveWorker(w)) continue;
                if ((tag & 1) != 0) {
                    conductor.onHealthCheck(w);
                } else {
                    loop.unwatchFd(tag, w.socket);
                    conductor.onPongTimeout(w);
                }
                pool_changed = true;
                continue;
            }
            switch (@as(EventLocation, @enumFromInt(tag))) {
                .ping_timer => {
                    conductor.onPingTimer();
                    loop.arm(tag, ping_interval_ms);
                    pool_changed = true;
                },
                .pressure_timer => {
                    conductor.onPressureTimer();
                    loop.arm(tag, pressure_interval_ms);
                    pool_changed = true;
                },
                .live_timer => conductor.onLiveTimer(),
                .tick_timer => {
                    loop.tick_armed = false;
                    if (conductor.tick()) loop.armTick();
                    pool_changed = true;
                },
                else => {},
            }
        }
        if (pool_changed) conductor.noteLiveChange();
    }
}

// Event handlers

fn handleAccept(conductor: *Conductor, server_fd: posix.fd_t) void {
    // Level-triggered, so never re-armed.
    var client_addr: std.Io.Threaded.PosixAddress = undefined;
    var client_addr_len: posix.socklen_t = @sizeOf(std.Io.Threaded.PosixAddress);
    const rc = linux.accept4(server_fd, &client_addr.any, &client_addr_len, posix.SOCK.CLOEXEC);
    switch (linux.errno(rc)) {
        .SUCCESS => {},
        .INTR, .AGAIN, .CONNABORTED => return,
        else => |err| {
            std.debug.print("Accept error: {t}\n", .{err});
            return;
        },
    }
    const peer = main.PeerInfo.fromSockaddr(&client_addr);
    conductor.admitConnection(@intCast(rc), &peer);
}

/// True when shutdown was requested.
fn handleSignal(
    conductor: *Conductor,
    loop: *EventLoop,
    listener: *protocol.Listener,
    server_fd: *posix.fd_t,
    signal_buf: *[16]u8,
) bool {
    const n = posix.read(signal_pipe[0], signal_buf) catch |err| {
        std.debug.print("Signal pipe read error: {}\n", .{err});
        return false;
    };
    for (signal_buf[0..n]) |sig| {
        switch (sig) {
            SIGNAL_SHUTDOWN => {
                std.debug.print("\nShutdown requested, stopping workers...\n", .{});
                conductor.gracefulShutdown();
                return true;
            },
            SIGNAL_RECREATE => {
                std.debug.print("Recreating socket due to SIGUSR1\n", .{});
                loop.unwatchFd(@intFromEnum(EventLocation.accept), server_fd.*);
                listener.close(conductor.io);
                listener.* = conductor.createServer() catch |err| {
                    std.debug.print("Failed to recreate socket: {}\n", .{err});
                    continue;
                };
                server_fd.* = listener.fd();
                loop.watch(@intFromEnum(EventLocation.accept), server_fd.*, linux.EPOLL.IN) catch {};
            },
            else => {},
        }
    }
    return false;
}

// Helpers

fn nowMs() i64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.MONOTONIC, &ts);
    return @as(i64, ts.sec) * std.time.ms_per_s + @divTrunc(ts.nsec, std.time.ns_per_ms);
}
