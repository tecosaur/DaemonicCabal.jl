// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0
//
// Linux epoll+timerfd event loop for the conductor.
//
// Mirrors the kqueue backend: accept, signal pipe, periodic ping/pressure
// timers, and per-worker ping (socket read + timeout) / health-check timers.
// Used when io_uring is unavailable (kernel < 5.1, or disabled).

const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const Io = std.Io;

const main = @import("../main.zig");
const Conductor = main.Conductor;
const platform = @import("../platform/main.zig");
const protocol = @import("../protocol.zig");
const worker = @import("../worker.zig");

const posix_signals = @import("posix_signals.zig");

pub const installSignalHandlers = posix_signals.installSignalHandlers;
pub const cleanupSignalHandlers = posix_signals.cleanupSignalHandlers;
const signal_pipe = &posix_signals.signal_pipe;
const SIGNAL_SHUTDOWN = posix_signals.SIGNAL_SHUTDOWN;
const SIGNAL_RECREATE = posix_signals.SIGNAL_RECREATE;

const UDATA_ACCEPT: u64 = 0;
const UDATA_SIGNAL: u64 = 1;
const UDATA_PING_TIMER: u64 = 2;
const UDATA_PRESSURE_TIMER: u64 = 4;
const UDATA_LIVE_TIMER: u64 = 5;

// Worker udata: pointer (8-byte aligned) with tag in the low bits.
//   bit0 = health-check timer, bit1 = ping-timeout timer, both clear = socket.
const WORKER_TAG_MASK: u64 = 0b11;
const TAG_PONG: u64 = 0;
const TAG_HEALTH: u64 = 1;
const TAG_PING_TIMEOUT: u64 = 2;

pub const EventLoop = struct {
    epfd: i32,
    ping_timer_fd: i32,
    pressure_timer_fd: i32,
    live_timer_fd: i32,
    ping_interval_ms: i64 = 1000,
    ping_timeout_ms: i64 = 5000,

    pub fn init(_: u13) !EventLoop {
        const epfd = try fdFromRc(linux.epoll_create1(linux.EPOLL.CLOEXEC));
        errdefer _ = linux.close(epfd);
        const ping_timer_fd = try createTimerFd();
        errdefer _ = linux.close(ping_timer_fd);
        const pressure_timer_fd = try createTimerFd();
        errdefer _ = linux.close(pressure_timer_fd);
        const live_timer_fd = try createTimerFd();
        errdefer _ = linux.close(live_timer_fd);
        try ctlAdd(epfd, ping_timer_fd, UDATA_PING_TIMER, linux.EPOLL.IN);
        try ctlAdd(epfd, pressure_timer_fd, UDATA_PRESSURE_TIMER, linux.EPOLL.IN);
        try ctlAdd(epfd, live_timer_fd, UDATA_LIVE_TIMER, linux.EPOLL.IN);
        return .{
            .epfd = epfd,
            .ping_timer_fd = ping_timer_fd,
            .pressure_timer_fd = pressure_timer_fd,
            .live_timer_fd = live_timer_fd,
        };
    }

    pub fn deinit(self: *EventLoop) void {
        _ = linux.close(self.ping_timer_fd);
        _ = linux.close(self.pressure_timer_fd);
        _ = linux.close(self.live_timer_fd);
        _ = linux.close(self.epfd);
    }

    pub fn armLiveTimer(self: *EventLoop, delay_ms: u64) void {
        armTimer(self.live_timer_fd, delay_ms, 0);
    }

    pub fn scheduleHealthCheck(self: *EventLoop, w: *worker.Worker) void {
        closeWorkerFd(self.epfd, &w.epoll_health_tfd);
        const fd = createTimerFd() catch return;
        ctlAdd(self.epfd, fd, @intFromPtr(w) | TAG_HEALTH, linux.EPOLL.IN) catch {
            _ = linux.close(fd);
            return;
        };
        w.epoll_health_tfd = fd;
        armTimer(fd, 1000, 0);
    }

    pub fn cancelPendingPing(self: *EventLoop, w: *worker.Worker) void {
        closeWorkerFd(self.epfd, &w.epoll_health_tfd);
        if (!w.ping_pending) return;
        _ = linux.epoll_ctl(self.epfd, linux.EPOLL.CTL_DEL, w.socket, null);
        closeWorkerFd(self.epfd, &w.epoll_ping_tfd);
        var buf: [5]u8 = undefined;
        protocol.readExact(w.socket, &buf) catch {};
        w.ping_pending = false;
    }
};

pub fn run(conductor: *Conductor, server: *Io.net.Server) void {
    const loop = &conductor.event_loop.epoll;
    var server_fd: posix.fd_t = server.socket.handle;
    loop.ping_interval_ms = @intCast(conductor.cfg.ping_interval * 1000);
    loop.ping_timeout_ms = @intCast(conductor.cfg.ping_timeout * 1000);

    ctlAdd(loop.epfd, server_fd, UDATA_ACCEPT, linux.EPOLL.IN) catch {
        std.debug.print("Fatal: failed to register accept fd\n", .{});
        return;
    };
    ctlAdd(loop.epfd, signal_pipe[0], UDATA_SIGNAL, linux.EPOLL.IN) catch {
        std.debug.print("Fatal: failed to register signal pipe\n", .{});
        return;
    };
    armTimer(loop.ping_timer_fd, @intCast(loop.ping_interval_ms), @intCast(loop.ping_interval_ms));
    const pressure_active = conductor.pressure_monitor.active();
    if (pressure_active) {
        const interval_s: u64 = @min(@as(u64, 5), conductor.cfg.ping_interval);
        const interval_ms: u64 = interval_s * 1000;
        armTimer(loop.pressure_timer_fd, interval_ms, interval_ms);
    }

    var signal_buf: [16]u8 = undefined;
    var events: [32]linux.epoll_event = undefined;
    while (true) {
        const n = linux.epoll_wait(loop.epfd, &events, @intCast(events.len), -1);
        switch (linux.errno(n)) {
            .SUCCESS => {},
            .INTR => continue,
            else => |e| {
                std.debug.print("Fatal: epoll_wait failed: {}\n", .{e});
                return;
            },
        }
        const event_count: usize = @intCast(n);
        var pool_changed = false;
        for (events[0..event_count]) |ev| {
            const udata = ev.data.u64;
            switch (udata) {
                UDATA_ACCEPT => {
                    handleAccept(conductor, server_fd);
                    pool_changed = true;
                },
                UDATA_SIGNAL => {
                    if (handleSignal(conductor, server, &server_fd, loop.epfd, &signal_buf)) return;
                    pool_changed = true;
                },
                UDATA_PING_TIMER => {
                    consumeTimer(loop.ping_timer_fd);
                    if (!pressure_active) conductor.sweepPendingKills();
                    conductor.enforceMaxTtl();
                    queueWorkerPings(conductor, loop);
                    pool_changed = true;
                },
                UDATA_PRESSURE_TIMER => {
                    consumeTimer(loop.pressure_timer_fd);
                    conductor.sweepPendingKills();
                    conductor.runEvictionEpisode();
                    pool_changed = true;
                },
                UDATA_LIVE_TIMER => {
                    consumeTimer(loop.live_timer_fd);
                    conductor.onLiveTimer();
                },
                else => {
                    const tag = udata & WORKER_TAG_MASK;
                    const w: *worker.Worker = @ptrFromInt(udata & ~WORKER_TAG_MASK);
                    if (!conductor.isLiveWorker(w)) continue;
                    switch (tag) {
                        TAG_HEALTH => handleHealthCheck(conductor, loop, w),
                        TAG_PING_TIMEOUT => handlePongTimeout(conductor, loop, w),
                        else => handlePongReady(conductor, loop, w),
                    }
                    pool_changed = true;
                },
            }
        }
        if (pool_changed) conductor.noteLiveChange();
    }
}

fn handleAccept(conductor: *Conductor, server_fd: posix.fd_t) void {
    var client_addr: posix.sockaddr = undefined;
    var client_addr_len: posix.socklen_t = @sizeOf(posix.sockaddr);
    const rc = linux.accept(server_fd, &client_addr, &client_addr_len);
    switch (linux.errno(rc)) {
        .SUCCESS => {},
        .AGAIN, .INTR => return,
        else => |e| {
            std.debug.print("Accept error: {}\n", .{e});
            return;
        },
    }
    const client_fd: posix.fd_t = @intCast(rc);
    defer platform.close(client_fd);
    if (conductor.cfg.transport == .tcp) protocol.setTcpNodelay(client_fd);
    const peer = main.PeerInfo{ .addr = client_addr, .len = client_addr_len };
    conductor.handleConnectionFd(client_fd, &peer) catch |err| {
        std.debug.print("Client handling failed: {}\n", .{err});
    };
}

fn handleSignal(
    conductor: *Conductor,
    server: *Io.net.Server,
    server_fd: *posix.fd_t,
    epfd: i32,
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
                _ = linux.epoll_ctl(epfd, linux.EPOLL.CTL_DEL, server_fd.*, null);
                server.deinit(conductor.io);
                Io.Dir.deleteFileAbsolute(conductor.io, conductor.cfg.socket_path) catch {};
                server.* = conductor.createServer() catch |err| {
                    std.debug.print("Failed to recreate socket: {}\n", .{err});
                    continue;
                };
                server_fd.* = server.socket.handle;
                ctlAdd(epfd, server_fd.*, UDATA_ACCEPT, linux.EPOLL.IN) catch {
                    std.debug.print("Failed to re-register accept fd\n", .{});
                };
            },
            else => {},
        }
    }
    return false;
}

fn queueWorkerPings(conductor: *Conductor, loop: *EventLoop) void {
    const now = conductor.currentTime();
    var it = conductor.workers.iterator();
    while (it.next()) |entry| {
        for (entry.value_ptr.items) |w| {
            maybeQueuePing(conductor, loop, w, now);
        }
    }
    if (conductor.reserve) |r| maybeQueuePing(conductor, loop, r, now);
}

fn maybeQueuePing(conductor: *Conductor, loop: *EventLoop, w: *worker.Worker, now: i64) void {
    conductor.refreshIdleMemIfStale(w, now);
    if (!w.shouldPing(now, conductor.cfg.ping_interval)) return;
    queuePing(loop, w);
}

fn queuePing(loop: *EventLoop, w: *worker.Worker) void {
    // EPOLLONESHOT disables the fd but leaves it registered; the next ping
    // must MOD (ADD fails with EEXIST). Arm before sendPing so a failed arm
    // cannot leave an unread pong on the socket.
    const events = linux.EPOLL.IN | linux.EPOLL.ONESHOT;
    ctlArm(loop.epfd, w.socket, @intFromPtr(w) | TAG_PONG, events) catch {
        w.ping_pending = false;
        return;
    };
    w.sendPing();
    closeWorkerFd(loop.epfd, &w.epoll_ping_tfd);
    const tfd = createTimerFd() catch {
        _ = linux.epoll_ctl(loop.epfd, linux.EPOLL.CTL_DEL, w.socket, null);
        w.ping_pending = false;
        return;
    };
    ctlAdd(loop.epfd, tfd, @intFromPtr(w) | TAG_PING_TIMEOUT, linux.EPOLL.IN) catch {
        _ = linux.close(tfd);
        _ = linux.epoll_ctl(loop.epfd, linux.EPOLL.CTL_DEL, w.socket, null);
        w.ping_pending = false;
        return;
    };
    w.epoll_ping_tfd = tfd;
    armTimer(tfd, @intCast(loop.ping_timeout_ms), 0);
}

fn handleHealthCheck(conductor: *Conductor, loop: *EventLoop, w: *worker.Worker) void {
    consumeTimer(w.epoll_health_tfd);
    closeWorkerFd(loop.epfd, &w.epoll_health_tfd);
    const now = conductor.currentTime();
    conductor.refreshIdleMemIfStale(w, now);
    if (w.shouldPing(now, conductor.cfg.ping_interval)) {
        queuePing(loop, w);
    }
}

fn handlePongReady(conductor: *Conductor, loop: *EventLoop, w: *worker.Worker) void {
    closeWorkerFd(loop.epfd, &w.epoll_ping_tfd);
    const n = posix.read(w.socket, &w.pong_buf) catch |err| {
        w.ping_pending = false;
        std.debug.print("Worker {d}: pong read error: {}\n", .{ w.id, err });
        conductor.retireWorker(w);
        return;
    };
    if (n < 5) {
        protocol.readExact(w.socket, w.pong_buf[n..]) catch {
            w.ping_pending = false;
            std.debug.print("Worker {d}: pong short read\n", .{w.id});
            conductor.retireWorker(w);
            return;
        };
    }
    // Late pong after a timeout: consume so the next ping is not desynced.
    if (!w.ping_pending) return;
    w.ping_pending = false;
    conductor.processPong(w, &w.pong_buf);
}

fn handlePongTimeout(conductor: *Conductor, loop: *EventLoop, w: *worker.Worker) void {
    if (!w.ping_pending) return;
    w.ping_pending = false;
    consumeTimer(w.epoll_ping_tfd);
    closeWorkerFd(loop.epfd, &w.epoll_ping_tfd);
    _ = linux.epoll_ctl(loop.epfd, linux.EPOLL.CTL_DEL, w.socket, null);
    if (w.active_clients > 0) {
        w.last_pinged = conductor.currentTime();
        std.debug.print("Worker {d}: ping slow while busy (ignored)\n", .{w.id});
        return;
    }
    std.debug.print("Worker {d}: ping timed out\n", .{w.id});
    conductor.retireWorker(w);
}

fn createTimerFd() !i32 {
    return fdFromRc(linux.timerfd_create(.MONOTONIC, .{ .CLOEXEC = true, .NONBLOCK = true }));
}

fn armTimer(fd: i32, delay_ms: u64, interval_ms: u64) void {
    var spec = linux.itimerspec{
        .it_interval = msToTimespec(interval_ms),
        .it_value = msToTimespec(if (delay_ms == 0) interval_ms else delay_ms),
    };
    if (delay_ms == 0 and interval_ms == 0) {
        spec.it_value = .{ .sec = 0, .nsec = 0 };
    }
    _ = linux.timerfd_settime(fd, .{}, &spec, null);
}

fn msToTimespec(ms: u64) linux.timespec {
    if (ms == 0) return .{ .sec = 0, .nsec = 0 };
    return .{
        .sec = @intCast(ms / 1000),
        .nsec = @intCast((ms % 1000) * 1_000_000),
    };
}

fn consumeTimer(fd: i32) void {
    if (fd < 0) return;
    var buf: [8]u8 = undefined;
    _ = linux.read(fd, &buf, buf.len);
}

fn closeWorkerFd(epfd: i32, fd: *posix.fd_t) void {
    if (fd.* < 0) return;
    _ = linux.epoll_ctl(epfd, linux.EPOLL.CTL_DEL, fd.*, null);
    _ = linux.close(fd.*);
    fd.* = -1;
}

fn ctlAdd(epfd: i32, fd: i32, udata: u64, events: u32) !void {
    var ev = linux.epoll_event{
        .events = events,
        .data = .{ .u64 = udata },
    };
    switch (linux.errno(linux.epoll_ctl(epfd, linux.EPOLL.CTL_ADD, fd, &ev))) {
        .SUCCESS => {},
        else => return error.EpollCtlFailed,
    }
}

/// EPOLLONESHOT disables a registration without removing it. MOD re-arms;
/// ADD is used the first time (ENOENT on MOD).
fn ctlArm(epfd: i32, fd: i32, udata: u64, events: u32) !void {
    var ev = linux.epoll_event{
        .events = events,
        .data = .{ .u64 = udata },
    };
    switch (linux.errno(linux.epoll_ctl(epfd, linux.EPOLL.CTL_MOD, fd, &ev))) {
        .SUCCESS => {},
        .NOENT => switch (linux.errno(linux.epoll_ctl(epfd, linux.EPOLL.CTL_ADD, fd, &ev))) {
            .SUCCESS => {},
            else => return error.EpollCtlFailed,
        },
        else => return error.EpollCtlFailed,
    }
}

fn fdFromRc(rc: usize) !i32 {
    return switch (linux.errno(rc)) {
        .SUCCESS => @intCast(rc),
        else => error.SyscallFailed,
    };
}
