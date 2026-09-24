// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0
//
// BSD/macOS kqueue-based event loop for the conductor. A ping's read and
// timeout are two registrations, settled by whichever clears `ping_pending`.

const std = @import("std");
const c = std.c;
const posix = std.posix;

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

// Some BSDs lack it in Zig's bindings.
const EV_ERROR: u16 = if (@hasDecl(c.EV, "ERROR")) c.EV.ERROR else 0x4000;

// Worker pointers are >= 0x1000.
const UDATA_ACCEPT: usize = 0;
const UDATA_SIGNAL: usize = 1;
const UDATA_PING_TIMER: usize = 2;
const UDATA_PRESSURE_TIMER: usize = 4;
const UDATA_LIVE_TIMER: usize = 5;
const UDATA_TICK_TIMER: usize = 6;
// Clear of any file descriptor.
const TIMER_IDENT_PING: usize = 0xFFFF_0001;
const TIMER_IDENT_PRESSURE: usize = 0xFFFF_0002;
const TIMER_IDENT_LIVE: usize = 0xFFFF_0003;
const TIMER_IDENT_TICK: usize = 0xFFFF_0004;

// EventLoop
pub const EventLoop = struct {
    kq: posix.fd_t,
    tick_armed: bool = false,

    pub fn init(_: u13) !EventLoop {
        const kq = c.kqueue();
        if (kq == -1) return error.KqueueCreateFailed;
        return .{ .kq = kq };
    }

    pub fn deinit(self: *EventLoop) void {
        _ = c.close(self.kq);
    }

    pub fn armLiveTimer(self: *EventLoop, delay_ms: u64) void {
        var ch = [1]c.Kevent{makeKevent(TIMER_IDENT_LIVE, c.EVFILT.TIMER, c.EV.ADD | c.EV.ONESHOT, 0, @intCast(delay_ms), UDATA_LIVE_TIMER)};
        _ = keventSubmit(self.kq, &ch);
    }

    pub fn scheduleHealthCheck(self: *EventLoop, w: *worker.Worker) void {
        const udata_tagged = @intFromPtr(w) | 1;
        var changes = [1]c.Kevent{makeKevent(
            udata_tagged,
            c.EVFILT.TIMER,
            c.EV.ADD | c.EV.ONESHOT,
            0,
            1000,
            udata_tagged,
        )};
        _ = keventSubmit(self.kq, &changes);
    }

    /// The pong read and its timeout race; whichever fires first settles the ping.
    pub fn awaitPong(self: *EventLoop, w: *worker.Worker, timeout_ms: u64) void {
        w.ping_pending = true;
        var changes = [2]c.Kevent{
            makeKevent(@intCast(w.socket), c.EVFILT.READ, c.EV.ADD | c.EV.ONESHOT, 0, 0, @intFromPtr(w)),
            makeKevent(@intFromPtr(w), c.EVFILT.TIMER, c.EV.ADD | c.EV.ONESHOT, 0, @intCast(timeout_ms), @intFromPtr(w)),
        };
        if (keventSubmit(self.kq, &changes) < 0) w.ping_pending = false;
    }

    pub fn watchFd(self: *EventLoop, tag: usize, fd: posix.fd_t) void {
        var ch = [1]c.Kevent{makeKevent(@intCast(fd), c.EVFILT.READ, c.EV.ADD | c.EV.ONESHOT, 0, 0, tag)};
        _ = keventSubmit(self.kq, &ch);
    }

    pub fn unwatchFd(self: *EventLoop, _: usize, fd: posix.fd_t) void {
        var ch = [1]c.Kevent{makeKevent(@intCast(fd), c.EVFILT.READ, c.EV.DELETE, 0, 0, 0)};
        _ = keventSubmit(self.kq, &ch);
    }

    pub fn armTick(self: *EventLoop) void {
        if (self.tick_armed) return;
        var tick = [1]c.Kevent{makeKevent(TIMER_IDENT_TICK, c.EVFILT.TIMER, c.EV.ADD, 0, 1000, UDATA_TICK_TIMER)};
        _ = keventSubmit(self.kq, &tick);
        self.tick_armed = true;
    }

    fn stopTick(self: *EventLoop) void {
        var ch = [1]c.Kevent{makeKevent(TIMER_IDENT_TICK, c.EVFILT.TIMER, c.EV.DELETE, 0, 0, 0)};
        _ = keventSubmit(self.kq, &ch);
        self.tick_armed = false;
    }

    /// isLiveWorker rejects any stale event.
    pub fn cancelPendingPing(self: *EventLoop, w: *worker.Worker) void {
        var hc = [1]c.Kevent{makeKevent(@intFromPtr(w) | 1, c.EVFILT.TIMER, c.EV.DELETE, 0, 0, 0)};
        _ = keventSubmit(self.kq, &hc);
        if (!w.ping_pending) return;
        var changes = [2]c.Kevent{
            makeKevent(@intCast(w.socket), c.EVFILT.READ, c.EV.DELETE, 0, 0, 0),
            makeKevent(@intFromPtr(w), c.EVFILT.TIMER, c.EV.DELETE, 0, 0, 0),
        };
        _ = keventSubmit(self.kq, &changes);
        var buf: [5]u8 = undefined;
        protocol.readExact(w.socket, &buf) catch {};
        w.ping_pending = false;
    }
};

// Main event loop
pub fn run(conductor: *Conductor, listener: *protocol.Listener) void {
    const kq = conductor.event_loop.kq;
    var server_fd: posix.fd_t = listener.fd();
    var signal_buf: [16]u8 = undefined;
    var init_changes: [3]c.Kevent = .{
        makeKevent(@intCast(server_fd), c.EVFILT.READ, c.EV.ADD, 0, 0, UDATA_ACCEPT),
        makeKevent(@intCast(signal_pipe[0]), c.EVFILT.READ, c.EV.ADD, 0, 0, UDATA_SIGNAL),
        makeKevent(
            TIMER_IDENT_PING,
            c.EVFILT.TIMER,
            c.EV.ADD,
            0,
            @intCast(conductor.cfg.ping_interval * 1000),
            UDATA_PING_TIMER,
        ),
    };
    if (keventSubmit(kq, &init_changes) < 0) {
        std.debug.print("Fatal: failed to register initial kevents\n", .{});
        return;
    }
    const pressure_active = conductor.pressure_monitor.active();
    if (pressure_active) {
        const interval_ms: isize = @intCast(conductor.pressureIntervalS() * 1000);
        var pc = [1]c.Kevent{makeKevent(TIMER_IDENT_PRESSURE, c.EVFILT.TIMER, c.EV.ADD, 0, interval_ms, UDATA_PRESSURE_TIMER)};
        _ = keventSubmit(kq, &pc);
    }
    var events: [32]c.Kevent = undefined;
    var no_changes: [0]c.Kevent = undefined;
    while (true) {
        const nevents = keventCall(kq, &no_changes, &events);
        if (nevents < 0) {
            const err: posix.E = @enumFromInt(c._errno().*);
            if (err == .INTR) continue;
            std.debug.print("Fatal: kevent wait failed: {}\n", .{err});
            return;
        }
        const event_count: usize = @intCast(nevents);
        // Whether a live `--status` view needs a repaint, once per batch.
        var pool_changed = false;
        for (events[0..event_count]) |ev| {
            if ((ev.flags & EV_ERROR) != 0) {
                std.debug.print("kevent error on ident {}: {}\n", .{ ev.ident, ev.data });
                continue;
            }
            const udata = ev.udata;
            switch (udata) {
                UDATA_ACCEPT => {
                    handleAccept(conductor, server_fd);
                    pool_changed = true;
                },
                UDATA_SIGNAL => {
                    if (handleSignal(conductor, listener, &server_fd, kq, &signal_buf)) return;
                    pool_changed = true;
                },
                UDATA_PING_TIMER => {
                    conductor.onPingTimer();
                    pool_changed = true;
                },
                UDATA_PRESSURE_TIMER => {
                    conductor.onPressureTimer();
                    pool_changed = true;
                },
                UDATA_LIVE_TIMER => conductor.onLiveTimer(),
                UDATA_TICK_TIMER => {
                    if (!conductor.tick()) conductor.event_loop.stopTick();
                    pool_changed = true;
                },
                else => {
                    // Bits 1-2 set is a pending record, else a worker (bit 0:
                    // health check).
                    if ((udata & 6) != 0) {
                        conductor.onReadable(udata);
                        pool_changed = true;
                        continue;
                    }
                    const is_health_check = (udata & 1) != 0;
                    const w: *worker.Worker = @ptrFromInt(udata & ~@as(usize, 1));
                    if (!conductor.isLiveWorker(w)) continue;
                    if (is_health_check) {
                        conductor.onHealthCheck(w);
                    } else if (ev.filter == c.EVFILT.TIMER) {
                        var read = [1]c.Kevent{makeKevent(@intCast(w.socket), c.EVFILT.READ, c.EV.DELETE, 0, 0, 0)};
                        _ = keventSubmit(kq, &read);
                        conductor.onPongTimeout(w);
                    } else {
                        var timer = [1]c.Kevent{makeKevent(@intFromPtr(w), c.EVFILT.TIMER, c.EV.DELETE, 0, 0, 0)};
                        _ = keventSubmit(kq, &timer);
                        conductor.onPong(w, null);
                    }
                    pool_changed = true;
                },
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
    const client_fd = c.accept(server_fd, &client_addr.any, &client_addr_len);
    if (client_fd < 0) {
        const err: posix.E = @enumFromInt(c._errno().*);
        std.debug.print("Accept error: {}\n", .{err});
        return;
    }
    _ = c.fcntl(client_fd, posix.F.SETFD, @as(c_int, posix.FD_CLOEXEC));
    const peer = main.PeerInfo.fromSockaddr(&client_addr);
    conductor.admitConnection(client_fd, &peer);
}

/// True when shutdown was requested.
fn handleSignal(
    conductor: *Conductor,
    listener: *protocol.Listener,
    server_fd: *posix.fd_t,
    kq: posix.fd_t,
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
                var del_changes = [1]c.Kevent{makeKevent(@intCast(server_fd.*), c.EVFILT.READ, c.EV.DELETE, 0, 0, 0)};
                _ = keventSubmit(kq, &del_changes);
                listener.close(conductor.io);
                listener.* = conductor.createServer() catch |err| {
                    std.debug.print("Failed to recreate socket: {}\n", .{err});
                    continue;
                };
                server_fd.* = listener.fd();
                var add_changes = [1]c.Kevent{makeKevent(@intCast(server_fd.*), c.EVFILT.READ, c.EV.ADD, 0, 0, UDATA_ACCEPT)};
                _ = keventSubmit(kq, &add_changes);
            },
            else => {},
        }
    }
    return false;
}

// Helpers

fn makeKevent(
    ident: usize,
    filter: i16,
    flags: u16,
    fflags: u32,
    data: isize,
    udata: usize,
) c.Kevent {
    return .{
        .ident = ident,
        .filter = filter,
        .flags = flags,
        .fflags = fflags,
        .data = data,
        .udata = udata,
    };
}
fn keventCall(kq: posix.fd_t, changelist: []const c.Kevent, eventlist: []c.Kevent) c_int {
    return c.kevent(kq, changelist.ptr, @intCast(changelist.len), eventlist.ptr, @intCast(eventlist.len), null);
}
/// -1 on error.
fn keventSubmit(kq: posix.fd_t, changelist: []const c.Kevent) c_int {
    var dummy: [0]c.Kevent = undefined;
    return keventCall(kq, changelist, &dummy);
}
