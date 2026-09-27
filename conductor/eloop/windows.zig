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

// Worker keys are pointers (>= 0x1000, bit 0 set for a health check).
const tag_accept: usize = @intFromEnum(EventLocation.accept);

// --- Signals ----------------------------------------------------------------

var g_console_iocp: ?HANDLE = null;

// The watchdog covers a loop parked in an unalertable call.
fn consoleCtrlHandler(_: DWORD) callconv(.winapi) BOOL {
    if (g_console_iocp) |iocp| _ = win.PostQueuedCompletionStatus(iocp, 0, @intFromEnum(EventLocation.signal), null);
    _ = win.CreateThread(null, 0, &watchdogProc, null, 0, null);
    return .TRUE;
}

fn watchdogProc(_: ?*anyopaque) callconv(.winapi) DWORD {
    win.sleepMs(5000);
    std.debug.print("\nCtrl-C: forced exit (event loop unresponsive)\n", .{});
    _ = win.TerminateProcess(win.GetCurrentProcess(), 130);
    return 0;
}

pub fn installSignalHandlers() !void {
    if (win.SetConsoleCtrlHandler(&consoleCtrlHandler, .TRUE) == .FALSE) return error.SetConsoleCtrlHandlerFailed;
}

pub fn cleanupSignalHandlers() void {
    _ = win.SetConsoleCtrlHandler(&consoleCtrlHandler, .FALSE);
}

// --- Timers -----------------------------------------------------------------
// The loop holds each timer by key until its packet is taken, arming a key
// again replacing its timer. A packet carries its timer's generation as its
// byte count, so one posted by a timer since cancelled or replaced is stale.

const TimerCtx = struct { iocp: HANDLE, key: usize, generation: DWORD, timer: HANDLE };

fn timerFired(param: ?*anyopaque, _: BOOL) callconv(.winapi) void {
    const ctx: *TimerCtx = @ptrCast(@alignCast(param orelse return));
    _ = win.PostQueuedCompletionStatus(ctx.iocp, ctx.generation, ctx.key, null);
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
    timers: std.AutoHashMapUnmanaged(usize, *TimerCtx) = .empty,
    timer_generation: DWORD = 0,
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
        var it = self.timers.valueIterator();
        while (it.next()) |ctx| {
            _ = DeleteTimerQueueTimer(null, ctx.*.timer, win32.INVALID_HANDLE_VALUE);
            std.heap.page_allocator.destroy(ctx.*);
        }
        platform.close(self.poll_device);
        win32.CloseHandle(self.iocp);
        self.watches.deinit(std.heap.page_allocator);
        self.timers.deinit(std.heap.page_allocator);
        g_console_iocp = null;
    }

    pub fn logResolution(_: *const EventLoop) void {
        std.debug.print(" - Event loop: IOCP\n", .{});
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
        self.arm(@intFromEnum(EventLocation.tick_timer), 1000);
        self.tick_armed = true;
    }

    pub fn armLiveTimer(self: *EventLoop, delay_ms: u64) void {
        self.arm(@intFromEnum(EventLocation.live_timer), delay_ms);
    }

    pub fn scheduleHealthCheck(self: *EventLoop, w: *worker.Worker) void {
        self.arm(@intFromPtr(w) | 1, 1000);
    }

    pub fn cancelPendingPing(self: *EventLoop, w: *worker.Worker) void {
        self.disarm(@intFromPtr(w) | 1);
        if (!w.ping_pending) return;
        self.unwatchFd(@intFromPtr(w), w.socket);
        self.disarm(@intFromPtr(w));
        var buf: [protocol.worker.pong_size]u8 = undefined;
        protocol.readExact(w.socket, &buf) catch {};
        w.ping_pending = false;
    }

    /// The pong watch and its timer race; whichever packet lands first settles the ping.
    pub fn awaitPong(self: *EventLoop, w: *worker.Worker, timeout_ms: u64) void {
        w.ping_pending = true;
        self.watchFd(@intFromPtr(w), w.socket);
        self.arm(@intFromPtr(w), timeout_ms);
    }

    fn arm(self: *EventLoop, key: usize, delay_ms: u64) void {
        self.disarm(key);
        self.timer_generation +%= 1;
        const ctx = std.heap.page_allocator.create(TimerCtx) catch
            return std.debug.print("IOCP: out of memory arming a timer (key {x})\n", .{key});
        ctx.* = .{ .iocp = self.iocp, .key = key, .generation = self.timer_generation, .timer = undefined };
        self.timers.put(std.heap.page_allocator, key, ctx) catch {
            std.heap.page_allocator.destroy(ctx);
            return std.debug.print("IOCP: out of memory arming a timer (key {x})\n", .{key});
        };
        if (!CreateTimerQueueTimer(&ctx.timer, null, &timerFired, ctx, @intCast(@min(delay_ms, std.math.maxInt(u32))), 0, WT_EXECUTEDEFAULT).toBool()) {
            _ = self.timers.remove(key);
            std.heap.page_allocator.destroy(ctx);
            std.debug.print("IOCP: failed to create a timer (key {x})\n", .{key});
        }
    }

    // Waits out a callback mid-post, whose packet is then stale.
    fn disarm(self: *EventLoop, key: usize) void {
        const kv = self.timers.fetchRemove(key) orelse return;
        _ = DeleteTimerQueueTimer(null, kv.value.timer, win32.INVALID_HANDLE_VALUE);
        std.heap.page_allocator.destroy(kv.value);
    }

    /// Whether the packet is its timer's, which is then released.
    fn takeTimer(self: *EventLoop, key: usize, generation: DWORD) bool {
        const ctx = self.timers.get(key) orelse return false;
        if (ctx.generation != generation) return false;
        self.disarm(key);
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
    const ping_ms = conductor.cfg.ping_interval * 1000;
    const pressure_ms = conductor.pressureIntervalS() * 1000;
    loop.watchFd(tag_accept, listener.fd());
    loop.arm(@intFromEnum(EventLocation.ping_timer), ping_ms);
    if (conductor.pressure_monitor.active()) loop.arm(@intFromEnum(EventLocation.pressure_timer), pressure_ms);
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
            const w = loop.takeWatch(o) orelse continue;
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
                if (conductor.isLiveWorker(wk)) {
                    loop.disarm(@intFromPtr(wk));
                    conductor.onPong(wk, null);
                }
            }
        } else if (key == @intFromEnum(EventLocation.signal)) {
            std.debug.print("\nShutdown requested, stopping workers...\n", .{});
            conductor.gracefulShutdown();
            return;
        } else if (!loop.takeTimer(key, bytes)) {
            continue;
        } else if (key >= 0x1000) {
            const wk: *worker.Worker = @ptrFromInt(key & ~@as(usize, 1));
            if (!conductor.isLiveWorker(wk)) continue;
            if ((key & 1) != 0) {
                conductor.onHealthCheck(wk);
            } else {
                loop.unwatchFd(@intFromPtr(wk), wk.socket);
                conductor.onPongTimeout(wk);
            }
        } else switch (@as(EventLocation, @enumFromInt(key))) {
            .ping_timer => {
                conductor.onPingTimer();
                loop.arm(key, ping_ms);
            },
            .pressure_timer => {
                conductor.onPressureTimer();
                loop.arm(key, pressure_ms);
            },
            .live_timer => {
                conductor.onLiveTimer();
                pool_changed = false;
            },
            .tick_timer => {
                loop.tick_armed = false;
                if (conductor.tick()) loop.armTick();
            },
            else => pool_changed = false,
        }
        if (pool_changed) conductor.noteLiveChange();
    }
}

fn handleAccept(conductor: *Conductor, listener: *protocol.Listener) bool {
    const accepted = listener.accept(conductor.io) catch |err| {
        std.debug.print("Accept error: {}\n", .{err});
        return err != error.PipeCreateFailed;
    };
    const peer = main.PeerInfo{ .address = accepted.peer };
    conductor.admitConnection(accepted.socket, &peer);
    return true;
}
