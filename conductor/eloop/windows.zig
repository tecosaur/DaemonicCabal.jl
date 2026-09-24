// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0
//
// Windows IOCP-based event loop for the conductor, structured like kqueue.zig.
// A cancelled watch stays registered until its packet arrives: the kernel
// writes into it until then.

const std = @import("std");
const win32 = std.os.windows;
const posix = std.posix;

const main = @import("../main.zig");
const Conductor = main.Conductor;
const platform = @import("../platform/main.zig");
const win = @import("../platform/windows.zig");
const protocol = @import("../protocol.zig");
const worker = @import("../worker.zig");

const EventLocation = protocol.EventLocation;
const BOOL = win32.BOOL;
const DWORD = win32.DWORD;
const ULONG = win32.ULONG;
const HANDLE = win32.HANDLE;

const WT_EXECUTEDEFAULT: ULONG = 0;
extern "kernel32" fn CreateTimerQueueTimer(phNewTimer: *HANDLE, TimerQueue: ?HANDLE, Callback: win.WAITORTIMERCALLBACK, Parameter: ?*anyopaque, DueTime: DWORD, Period: DWORD, Flags: ULONG) BOOL;
extern "kernel32" fn DeleteTimerQueueTimer(TimerQueue: ?HANDLE, Timer: HANDLE, CompletionEvent: ?HANDLE) BOOL;
extern "kernel32" fn CreateThread(lpThreadAttributes: ?*anyopaque, dwStackSize: usize, lpStartAddress: *const fn (?*anyopaque) callconv(.winapi) DWORD, lpParameter: ?*anyopaque, dwCreationFlags: DWORD, lpThreadId: ?*DWORD) ?HANDLE;
extern "kernel32" fn Sleep(dwMilliseconds: DWORD) void;
extern "kernel32" fn GetCurrentProcess() HANDLE;

// Worker keys are pointers (>= 0x1000, bit 0 set for a health check).
const tag_accept: usize = @intFromEnum(EventLocation.accept);

// --- Signals ----------------------------------------------------------------

var g_console_iocp: ?HANDLE = null;

// The watchdog covers a loop parked in an unalertable call.
fn consoleCtrlHandler(_: DWORD) callconv(.winapi) BOOL {
    if (g_console_iocp) |iocp| _ = win.PostQueuedCompletionStatus(iocp, 0, @intFromEnum(EventLocation.signal), null);
    _ = CreateThread(null, 0, &watchdogProc, null, 0, null);
    return .TRUE;
}

fn watchdogProc(_: ?*anyopaque) callconv(.winapi) DWORD {
    Sleep(5000);
    std.debug.print("\nCtrl-C: forced exit (event loop unresponsive)\n", .{});
    _ = win.TerminateProcess(GetCurrentProcess(), 130);
    return 0;
}

pub fn installSignalHandlers() !void {
    if (win.SetConsoleCtrlHandler(&consoleCtrlHandler, .TRUE) == .FALSE) return error.SetConsoleCtrlHandlerFailed;
}

pub fn cleanupSignalHandlers() void {
    _ = win.SetConsoleCtrlHandler(&consoleCtrlHandler, .FALSE);
}

// --- Timers -----------------------------------------------------------------
// An owned timer (a pong timeout) posts its context as lpOverlapped so the loop
// can tell a cancelled one; the rest free themselves in the callback.

const TimerCtx = struct { iocp: HANDLE, key: usize, timer: HANDLE, owned: bool };

fn timerFired(param: ?*anyopaque, _: BOOL) callconv(.winapi) void {
    const ctx: *TimerCtx = @ptrCast(@alignCast(param orelse return));
    if (ctx.owned) {
        _ = win.PostQueuedCompletionStatus(ctx.iocp, 0, ctx.key, @ptrCast(ctx));
        return;
    }
    _ = win.PostQueuedCompletionStatus(ctx.iocp, 0, ctx.key, null);
    _ = DeleteTimerQueueTimer(null, ctx.timer, null);
    std.heap.page_allocator.destroy(ctx);
}

fn startTimer(iocp: HANDLE, key: usize, delay_ms: u64, owned: bool) ?*TimerCtx {
    const ctx = std.heap.page_allocator.create(TimerCtx) catch return null;
    ctx.* = .{ .iocp = iocp, .key = key, .timer = undefined, .owned = owned };
    if (!CreateTimerQueueTimer(&ctx.timer, null, &timerFired, ctx, @intCast(@min(delay_ms, std.math.maxInt(u32))), 0, WT_EXECUTEDEFAULT).toBool()) {
        std.heap.page_allocator.destroy(ctx);
        return null;
    }
    return ctx;
}

fn scheduleTimer(iocp: HANDLE, key: usize, delay_ms: u64) void {
    _ = startTimer(iocp, key, delay_ms, false);
}

// --- Watches ----------------------------------------------------------------

/// `op` is first, so the packet's lpOverlapped casts back to the watch.
const Watch = extern struct {
    op: win.ReadinessOp,
    tag: usize,
    fd: HANDLE,
    cancelled: bool,
};

pub const EventLoop = struct {
    iocp: HANDLE,
    poll_device: HANDLE,
    watches: std.AutoHashMapUnmanaged(usize, *Watch) = .empty,
    ping_timers: std.AutoHashMapUnmanaged(*worker.Worker, *TimerCtx) = .empty,
    tick_armed: bool = false,

    pub fn init(_: u13) !EventLoop {
        const port = win.CreateIoCompletionPort(win32.INVALID_HANDLE_VALUE, null, 0, 0) orelse return error.IocpCreateFailed;
        errdefer win32.CloseHandle(port);
        const poll_device = try win.openPollDevice();
        errdefer platform.close(poll_device);
        try win.associate(port, poll_device);
        g_console_iocp = port;
        return .{ .iocp = port, .poll_device = poll_device };
    }

    pub fn deinit(self: *EventLoop) void {
        platform.close(self.poll_device);
        win32.CloseHandle(self.iocp);
        self.watches.deinit(std.heap.page_allocator);
        self.ping_timers.deinit(std.heap.page_allocator);
        g_console_iocp = null;
    }

    pub fn watchFd(self: *EventLoop, tag: usize, fd: posix.fd_t) void {
        const w = std.heap.page_allocator.create(Watch) catch return;
        w.* = .{ .op = undefined, .tag = tag, .fd = fd, .cancelled = false };
        self.watches.put(std.heap.page_allocator, @intFromPtr(w), w) catch {
            std.heap.page_allocator.destroy(w);
            return;
        };
        if (win.issueReadiness(self.poll_device, self.iocp, fd, &w.op))
            _ = win.PostQueuedCompletionStatus(self.iocp, 0, 0, @ptrCast(w));
    }

    pub fn unwatchFd(self: *EventLoop, tag: usize, _: posix.fd_t) void {
        var it = self.watches.valueIterator();
        while (it.next()) |w| if (w.*.tag == tag and !w.*.cancelled) {
            w.*.cancelled = true;
            win.cancelReadiness(self.poll_device, w.*.fd, &w.*.op);
        };
    }

    pub fn armTick(self: *EventLoop) void {
        if (self.tick_armed) return;
        scheduleTimer(self.iocp, @intFromEnum(EventLocation.tick_timer), 1000);
        self.tick_armed = true;
    }

    pub fn armLiveTimer(self: *EventLoop, delay_ms: u64) void {
        scheduleTimer(self.iocp, @intFromEnum(EventLocation.live_timer), delay_ms);
    }

    pub fn scheduleHealthCheck(self: *EventLoop, w: *worker.Worker) void {
        scheduleTimer(self.iocp, @intFromPtr(w) | 1, 1000);
    }

    pub fn cancelPendingPing(self: *EventLoop, w: *worker.Worker) void {
        if (!w.ping_pending) return;
        self.unwatchFd(@intFromPtr(w), w.socket);
        self.cancelPingTimer(w);
        var buf: [5]u8 = undefined;
        protocol.readExact(w.socket, &buf) catch {};
        w.ping_pending = false;
    }

    fn startPingTimer(self: *EventLoop, w: *worker.Worker, timeout_ms: u64) void {
        self.cancelPingTimer(w);
        const ctx = startTimer(self.iocp, @intFromPtr(w), timeout_ms, true) orelse return;
        self.ping_timers.put(std.heap.page_allocator, w, ctx) catch {
            _ = DeleteTimerQueueTimer(null, ctx.timer, win32.INVALID_HANDLE_VALUE);
            std.heap.page_allocator.destroy(ctx);
        };
    }

    // Waits out a mid-post callback, whose packet then fails `takePingTimer`.
    fn cancelPingTimer(self: *EventLoop, w: *worker.Worker) void {
        const kv = self.ping_timers.fetchRemove(w) orelse return;
        _ = DeleteTimerQueueTimer(null, kv.value.timer, win32.INVALID_HANDLE_VALUE);
        std.heap.page_allocator.destroy(kv.value);
    }

    fn takePingTimer(self: *EventLoop, w: *worker.Worker, ovl: *win.OVERLAPPED) bool {
        const ctx = self.ping_timers.get(w) orelse return false;
        if (@intFromPtr(ctx) != @intFromPtr(ovl)) return false;
        _ = self.ping_timers.remove(w);
        _ = DeleteTimerQueueTimer(null, ctx.timer, null);
        std.heap.page_allocator.destroy(ctx);
        return true;
    }

    fn takeWatch(self: *EventLoop, ovl: *win.OVERLAPPED) ?*Watch {
        const kv = self.watches.fetchRemove(@intFromPtr(ovl)) orelse return null;
        if (!kv.value.cancelled) return kv.value;
        std.heap.page_allocator.destroy(kv.value);
        return null;
    }
};

// --- Main loop --------------------------------------------------------------

pub fn run(conductor: *Conductor, listener: *protocol.Listener) void {
    const loop = &conductor.event_loop;
    const iocp = loop.iocp;
    const ping_timeout_ms = conductor.cfg.ping_timeout * 1000;
    const pressure_active = conductor.pressure_monitor.active();
    // A plain if: @min would narrow the result to a u3 and overflow on the scale.
    const pressure_s: u64 = if (conductor.cfg.ping_interval < 5) conductor.cfg.ping_interval else 5;
    const pressure_ms = pressure_s * 1000;
    loop.watchFd(tag_accept, listener.fd());
    scheduleTimer(iocp, @intFromEnum(EventLocation.ping_timer), conductor.cfg.ping_interval * 1000);
    if (pressure_active) scheduleTimer(iocp, @intFromEnum(EventLocation.pressure_timer), pressure_ms);
    while (true) {
        var bytes: DWORD = 0;
        var key: usize = 0;
        var ovl: ?*win.OVERLAPPED = null;
        const ok = win.GetQueuedCompletionStatus(iocp, &bytes, &key, &ovl, win.INFINITE).toBool();
        if (!ok and ovl == null) {
            std.debug.print("Fatal: GetQueuedCompletionStatus failed\n", .{});
            return;
        }
        var pool_changed = true;
        if (ovl) |o| {
            if (win.reapSyncOp(o)) continue;
            if (loop.takeWatch(o)) |w| {
                defer std.heap.page_allocator.destroy(w);
                if (w.tag == tag_accept) {
                    if (!handleAccept(conductor, listener)) {
                        std.debug.print("Fatal: the listener is gone, shutting down\n", .{});
                        conductor.gracefulShutdown();
                        return;
                    }
                    loop.watchFd(tag_accept, listener.fd());
                } else if ((w.tag & 6) != 0) {
                    conductor.onReadable(w.tag);
                } else {
                    const wk: *worker.Worker = @ptrFromInt(w.tag);
                    if (conductor.isLiveWorker(wk)) handlePongReady(conductor, wk);
                }
            } else if (key >= 0x1000 and (key & 1) == 0) {
                const wk: *worker.Worker = @ptrFromInt(key);
                if (!loop.takePingTimer(wk, o)) continue;
                if (conductor.isLiveWorker(wk)) handlePongTimeout(conductor, wk);
            } else continue;
        } else if (key >= 0x1000) {
            const wk: *worker.Worker = @ptrFromInt(key & ~@as(usize, 1));
            if (conductor.isLiveWorker(wk)) handleHealthCheck(conductor, wk);
        } else switch (@as(EventLocation, @enumFromInt(key))) {
            .signal => {
                std.debug.print("\nShutdown requested, stopping workers...\n", .{});
                conductor.gracefulShutdown();
                return;
            },
            .ping_timer => {
                if (!pressure_active) conductor.sweepPendingKills();
                conductor.enforceMaxTtl();
                queueWorkerPings(conductor, ping_timeout_ms);
                scheduleTimer(iocp, @intFromEnum(EventLocation.ping_timer), conductor.cfg.ping_interval * 1000);
            },
            .pressure_timer => {
                conductor.sweepPendingKills();
                conductor.runEvictionEpisode();
                scheduleTimer(iocp, @intFromEnum(EventLocation.pressure_timer), pressure_ms);
            },
            .live_timer => {
                conductor.onLiveTimer();
                pool_changed = false;
            },
            .tick_timer => {
                loop.tick_armed = false;
                if (conductor.tick()) loop.armTick();
            },
            .accept, .ignored, _ => pool_changed = false,
        }
        if (pool_changed) conductor.noteLiveChange();
    }
}

fn handleAccept(conductor: *Conductor, listener: *protocol.Listener) bool {
    const accepted = listener.accept(conductor.io) catch |err| {
        std.debug.print("Accept error: {}\n", .{err});
        return err != error.PipeCreateFailed;
    };
    if (conductor.cfg.transport == .tcp) protocol.setTcpNodelay(accepted.socket);
    const peer = main.PeerInfo{ .address = accepted.peer };
    conductor.admitConnection(accepted.socket, &peer);
    return true;
}

// --- Health checking --------------------------------------------------------

fn queueWorkerPings(conductor: *Conductor, timeout_ms: u64) void {
    const now = conductor.currentTime();
    var it = conductor.workers.iterator();
    while (it.next()) |entry| for (entry.value_ptr.items) |w| maybeQueuePing(conductor, w, timeout_ms, now);
    if (conductor.reserve) |r| maybeQueuePing(conductor, r, timeout_ms, now);
}

fn maybeQueuePing(conductor: *Conductor, w: *worker.Worker, timeout_ms: u64, now: i64) void {
    conductor.refreshIdleMemIfStale(w, now);
    if (!w.shouldPing(now, conductor.cfg.ping_interval)) return;
    queuePing(conductor, w, timeout_ms);
}

fn queuePing(conductor: *Conductor, w: *worker.Worker, timeout_ms: u64) void {
    w.sendPing();
    conductor.event_loop.watchFd(@intFromPtr(w), w.socket);
    conductor.event_loop.startPingTimer(w, timeout_ms);
}

fn handleHealthCheck(conductor: *Conductor, w: *worker.Worker) void {
    conductor.refreshIdleMemIfStale(w, conductor.currentTime());
    const recently_pinged = (conductor.currentTime() - w.last_pinged) < 2;
    if (w.active_clients == 0 and !w.ping_pending and !recently_pinged)
        queuePing(conductor, w, conductor.cfg.ping_timeout * 1000);
}

fn handlePongReady(conductor: *Conductor, w: *worker.Worker) void {
    if (!w.ping_pending) return;
    w.ping_pending = false;
    conductor.event_loop.cancelPingTimer(w);
    const n = platform.socketRead(w.socket, &w.pong_buf);
    if (n == 0) {
        std.debug.print("Worker {d}: connection closed\n", .{w.id});
        conductor.retireWorker(w);
        return;
    }
    if (n < w.pong_buf.len) protocol.readExact(w.socket, w.pong_buf[n..]) catch {
        std.debug.print("Worker {d}: pong short read\n", .{w.id});
        conductor.retireWorker(w);
        return;
    };
    conductor.processPong(w, &w.pong_buf);
}

fn handlePongTimeout(conductor: *Conductor, w: *worker.Worker) void {
    if (!w.ping_pending) return;
    conductor.event_loop.unwatchFd(@intFromPtr(w), w.socket);
    w.ping_pending = false;
    if (w.active_clients > 0) {
        w.last_pinged = conductor.currentTime();
        std.debug.print("Worker {d}: ping slow while busy (ignored)\n", .{w.id});
        return;
    }
    std.debug.print("Worker {d}: ping timed out\n", .{w.id});
    conductor.retireWorker(w);
}
