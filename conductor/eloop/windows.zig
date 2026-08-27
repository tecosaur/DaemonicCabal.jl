// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0
//
// Windows event loop for the conductor — IOCP-based.
//
// The POSIX loops (linux.zig / kqueue.zig) are readiness-based: register an fd,
// the kernel says "ready", then we read. Windows is completion-based: we issue
// the I/O up front (overlapped) and the kernel says "done". Per WINDOWS.md
// "I/O multiplexing", the cleanest structure converts EVERYTHING — signals,
// timers, accepts, reads — into completions posted to one IOCP, and waits on a
// single GetQueuedCompletionStatus(Ex). The console-control handler and timer
// callbacks run in their own threads; they just PostQueuedCompletionStatus —
// the self-pipe trick's Windows equivalent.
//
// posix_signals.zig is NEVER imported here (sigaction is POSIX-only). Signal
// handling is SetConsoleCtrlHandler, which runs in a separate thread with
// normal sync usable.
//
// Stubs below are implementation bookmarks: signatures pinned by the call
// sites in conductor/main.zig, bodies inert so the file compiles.

const std = @import("std");
const builtin = @import("builtin");
const win32 = std.os.windows;
const Io = std.Io;

const main = @import("../main.zig");
const Conductor = main.Conductor;
const platform = @import("../platform/main.zig");
const protocol = @import("../protocol.zig");
const worker = @import("../worker.zig");

const EventLocation = protocol.EventLocation;

// Base Win32 types from std, unqualified for readable extern signatures below.
const BOOL = win32.BOOL;
const DWORD = win32.DWORD;
const ULONG = win32.ULONG;
const HANDLE = win32.HANDLE;

// Reuse the shared Win32 types/decls (OVERLAPPED, WAITORTIMERCALLBACK,
// SetConsoleCtrlHandler, CTRL_*_EVENT...) from platform/windows.zig.
const win32ext = @import("../platform/windows.zig");

// =============================================================================
// Win32 bindings missing from std.os.windows — IOCP + timer queue only.
// Linked automatically (zig build-exe resolves kernel32 without -l flags).
// Everything else comes from std: CloseHandle (std.os.windows), cancel via
// ntdll.NtCancelIoFileEx, socket I/O via ntdll.NtDeviceIoControlFile +
// AFD IOCTLs (see AFD.md). SetConsoleCtrlHandler + OVERLAPPED +
// WAITORTIMERCALLBACK come from platform/windows.zig below.
//
// Sockets are AFD endpoint handles created by std.Io (plain overlapped
// HANDLEs); accepts are issued as NtDeviceIoControlFile(AFD.WAIT_FOR_LISTEN /
// AFD.ACCEPT) with ApcRoutine=null so completions land on our port — there is
// no AcceptEx/ws2_32 anywhere in this design.
// =============================================================================

pub const WT_EXECUTEDEFAULT: ULONG = 0;
pub const WT_EXECUTEONLYONCE: ULONG = 0x00000008;

pub extern "kernel32" fn CreateIoCompletionPort(FileHandle: HANDLE, ExistingCompletionPort: ?HANDLE, CompletionKey: usize, NumberOfConcurrentThreads: DWORD) ?HANDLE;
pub extern "kernel32" fn GetQueuedCompletionStatus(CompletionPort: HANDLE, lpNumberOfBytesTransferred: *DWORD, lpCompletionKey: *usize, lpOverlapped: ?*?*win32ext.OVERLAPPED, dwMilliseconds: DWORD) BOOL;
pub extern "kernel32" fn PostQueuedCompletionStatus(CompletionPort: HANDLE, dwNumberOfBytesTransferred: DWORD, dwCompletionKey: usize, lpOverlapped: ?*win32ext.OVERLAPPED) BOOL;
pub extern "kernel32" fn CreateTimerQueueTimer(phNewTimer: *HANDLE, TimerQueue: ?HANDLE, Callback: win32ext.WAITORTIMERCALLBACK, Parameter: ?*anyopaque, DueTime: DWORD, Period: DWORD, Flags: ULONG) BOOL;
pub extern "kernel32" fn DeleteTimerQueueTimer(TimerQueue: ?HANDLE, Timer: HANDLE, CompletionEvent: ?HANDLE) BOOL;

// =============================================================================
// Signal handling — replaces posix_signals.zig
// =============================================================================

// IOCP handle the console handler posts to. Set in EventLoop.init (where the
// port is created) — the handler is a free function with no other way to reach
// the port. One conductor per process, so a module global is fine (the POSIX
// counterpart is the same: posix_signals.signal_pipe is a global).
var g_console_iocp: ?HANDLE = null;

// → SetConsoleCtrlHandler(handler_fn, TRUE). The handler runs in a kernel-
// spawned thread, so normal sync is usable: post a completion to the IOCP
// (PostQueuedCompletionStatus) with the signal key and let run() dispatch —
// no self-pipe, no signal_pipe/signal_buf, no SIGNAL_SHUTDOWN/SIGNAL_RECREATE
// byte constants (those are internal to the POSIX loops; Windows dispatches on
// completion keys). Every console event maps to the one path this loop
// implements — shutdown. SIGUSR1's "recreate socket" has no real Win32 analog;
// dropping it (rather than remapping CTRL_BREAK_EVENT) is the lazy answer.
// Event mapping:
//   CTRL_C_EVENT / CTRL_BREAK_EVENT → shutdown  (SIGNAL_SHUTDOWN equivalent)
//   CTRL_CLOSE_EVENT / CTRL_LOGOFF_EVENT / CTRL_SHUTDOWN_EVENT → shutdown
// Return TRUE to swallow the event: FALSE would let the default handler also
// run and terminate the process immediately after our post, defeating the
// graceful shutdown. Caveat: SetConsoleCtrlHandler only sees console events —
// a daemon running without a console (service) gets none of these.
fn consoleCtrlHandler(dwCtrlType: DWORD) callconv(.winapi) BOOL {
    _ = dwCtrlType;
    if (g_console_iocp) |iocp| {
        _ = PostQueuedCompletionStatus(iocp, 0, @intFromEnum(EventLocation.signal), null);
    }
    return win32.BOOL.TRUE;
}

pub fn installSignalHandlers() !void {
    if (win32ext.SetConsoleCtrlHandler(&consoleCtrlHandler, win32.BOOL.TRUE) == .FALSE)
        return error.SetConsoleCtrlHandlerFailed;
}

// → SetConsoleCtrlHandler(handler_fn, FALSE). No pipe fds to close.
pub fn cleanupSignalHandlers() void {
    _ = win32ext.SetConsoleCtrlHandler(&consoleCtrlHandler, win32.BOOL.FALSE);
}

/// Per-timer context passed to the timer callback via `lpParameter`. Allocated on
/// the page allocator (short-lived, freed again in the callback) so the callback
/// can recover both the port to post to and the completion key to post with —
/// both of which vary per call and can't be packed into a single pointer.
const TimerCtx = struct { iocp: HANDLE, key: usize, timer: HANDLE };

/// CreateTimerQueueTimer callback (runs on a thread-pool thread): post a completion
/// to the IOCP so the single GetQueuedCompletionStatus wait wakes. The completion
/// key is the source's discriminator, exactly what `run` will switch on.
/// One-shot timers must still be deleted (Period=0 doesn't free the handle), so
/// delete here — the callback is the last thing that touches the timer.
fn iocpTimerCallback(lpParameter: ?*anyopaque, _: BOOL) callconv(.winapi) void {
    const ctx: *TimerCtx = @ptrCast(@alignCast(lpParameter orelse return));
    _ = PostQueuedCompletionStatus(ctx.iocp, 0, ctx.key, null);
    _ = DeleteTimerQueueTimer(null, ctx.timer, null);
    std.heap.page_allocator.destroy(ctx);
}

/// Fire a one-shot timer `delay_ms` out, waking the loop with `key` as the key.
fn scheduleTimer(iocp: HANDLE, key: usize, delay_ms: u64) void {
    const ctx = std.heap.page_allocator.create(TimerCtx) catch return;
    ctx.* = .{ .iocp = iocp, .key = key, .timer = undefined };
    // DueTime is absolute when >= 0, so a relative delay is encoded as a negative
    // 100ns value (two's-complement DWORD). 0 would mean "1601-01-01", never now.
    _ = CreateTimerQueueTimer(&ctx.timer, null, &iocpTimerCallback, ctx, dueTimeRelMs(delay_ms), 0, WT_EXECUTEDEFAULT);
}

// todo: overflows check.
// ponytail: @intCast(ms) to i32 panics above ~214,748 ms (~36 min); current
// callers pass seconds-scale delays. Clamp if long delays ever matter.
fn dueTimeRelMs(ms: u64) DWORD {
    return @bitCast(-@as(i32, @intCast(ms)) * 10_000);
}

// =============================================================================
// EventLoop
// =============================================================================

// IOCP core. `iocp` is the completion port every handle is associated with
// (CreateIoCompletionPort(handle, iocp, key, 0)); the key is the per-handle
// cookie (kqueue's udata / io_uring's user_data equivalent). The `entries`
// param from the router (`EventLoop.init(64)` in main.zig) is meaningless
// here — IOCP has no queue depth; ignore it.
pub const EventLoop = struct {
    iocp: win32.HANDLE,

    // → CreateIoCompletionPort(INVALID_HANDLE_VALUE, null, 0, 0) creates a
    // bare port. Return .{ .iocp = port }.
    pub fn init(_: u13) !EventLoop {
        // INVALID_HANDLE_VALUE + null port → a bare completion port (no handle
        // associated; everything is posted to it, per WINDOWS.md I/O multiplexing).
        const port = CreateIoCompletionPort(win32.INVALID_HANDLE_VALUE, null, 0, 0) orelse
            return error.IocpCreateFailed;
        // Hand the port to the console-control handler (installSignalHandlers
        // is a free function with no other way to reach it); see g_console_iocp.
        g_console_iocp = port;
        return .{ .iocp = port };
    }

    // → CloseHandle(iocp).
    pub fn deinit(self: *EventLoop) void {
        _ = win32.CloseHandle(self.iocp);
        g_console_iocp = null;
    }

    /// Fire a one-shot timer `delay_ms` out that wakes `run` with `key`.
    /// Generic wrapper over scheduleTimer — used by run() for the periodic
    /// ping/pressure arms and reusable for anything else.
    pub fn armOneShot(self: *EventLoop, key: usize, delay_ms: u64) void {
        scheduleTimer(self.iocp, key, delay_ms);
    }

    /// Arm the unified live-repaint timer `delay_ms` out (Conductor picks the delay).
    // One-shot timer → post a completion to the loop. Either CreateTimerQueueTimer
    // (callback → PostQueuedCompletionStatus; easiest) or a waitable timer
    // (CreateWaitableTimerW/SetWaitableTimer) waited on by a helper thread.
    // Completion key: the live-timer key (cf. UDATA_LIVE_TIMER in kqueue.zig).
    pub fn armLiveTimer(self: *EventLoop, delay_ms: u64) void {
        self.armOneShot(@intFromEnum(EventLocation.live_timer), delay_ms);
    }

    /// Schedule a health check for a worker after a short delay (1 second).
    /// Completion key is `@intFromPtr(w) | 1` (bit 0 set) so `run`'s worker
    /// branch can tell a health-check completion apart from a pong read — the
    /// same ptr-tagging the POSIX loops use.
    pub fn scheduleHealthCheck(self: *EventLoop, w: *worker.Worker) void {
        self.armOneShot(@intFromPtr(w) | 1, 1000);
    }

    /// Cancel in-flight ops referencing `w`. Drain any partial pong synchronously
    /// (protocol.readExact(w.socket, &buf) catch {}) so the socket isn't left with
    /// a stale pending read, then clear ping_pending so a late pong completion is
    /// ignored by `run`.
    // ponytail: we skip cancelling the one-shot health-check timer (it fires on
    // its own; `run` filters stale completions via isLiveWorker) and skip
    // NtCancelIoFileEx on the in-flight pong read — that needs the ping's
    // iosb, which lives in run, not here. Both are the documented "not
    // strictly required" paths; add them only if a leaky read ever proves real.
    pub fn cancelPendingPing(_: *EventLoop, w: *worker.Worker) void {
        var buf: [5]u8 = undefined;
        protocol.readExact(w.socket, &buf) catch {};
        w.ping_pending = false;
    }
};

// =============================================================================
// Async op plumbing — port-routed AFD issuers
// =============================================================================
//
// Synchronous setup calls use platform.syncAfdControl (issue+APC-wait inline).
// Loop-owned ops instead issue-and-return: NtDeviceIoControlFile with
// ApcRoutine=null routes the completion packet to OUR port under `apc_ctx`
// (= completion key). One GetQueuedCompletionStatus park multiplexes every
// in-flight op plus external posts (timers/console handler).
//
// Heap-backed per-op context: the kernel writes into `iosb` until completion,
// and GQCS hands us &iosb back as *OVERLAPPED (layout-compatible prefix), so
// casting it straight back recovers the whole context. Payload buffers that
// the driver also dereferences (out-storage for WAIT_FOR_LISTEN, the RECV_INFO
// input chain for RECEIVE) live INSIDE the context and thus outlive the IRP.

const ntdll = win32.ntdll;

/// Pending AFD.WAIT_FOR_LISTEN on the listener. Exactly one outstanding at a
/// time; freed by the dispatcher after the sync ACCEPT half finishes.
const AcceptWait = extern struct {
    iosb: win32.IO_STATUS_BLOCK,
    response: extern struct {
        info: win32.AFD.LISTEN_RESPONSE_INFO,
        addr_bytes: [128]u8, // peer sockaddr written by the driver
    },
};

/// Pending overlapped AFD.RECEIVE for one worker's pong (5 bytes into
/// w.pong_buf — stable storage owned by the Worker). Keyed by @intFromPtr(w);
/// freed after dispatch or ping-timeout cancel.
const PongRead = extern struct {
    iosb: win32.IO_STATUS_BLOCK,
    iovec: [1]win32.AFD.WSABUF(.@"var"),
    info: win32.AFD.RECV_INFO,
};

/// Issue one overlapped AFD IOCTL to our port and return immediately.
/// `.SUCCESS` inline and `.PENDING` both surface later as a port packet whose
/// OVERLAPPED* == `iosb` (AFD.md caveat: success-inline packets still post on
/// associated handles) — uniform handling upstream.
fn issueAfd(
    h: HANDLE,
    code: win32.CTL_CODE,
    key: usize,
    in: []const u8,
    out: []u8,
    iosb: *win32.IO_STATUS_BLOCK,
) !void {
    switch (ntdll.NtDeviceIoControlFile(
        h,
        null,
        null,
        @ptrFromInt(key),
        iosb,
        code,
        if (in.len > 0) in.ptr else null,
        @intCast(in.len),
        if (out.len > 0) out.ptr else null,
        @intCast(out.len),
    )) {
        .SUCCESS, .PENDING => {},
        else => |status| return win32.unexpectedStatus(status),
    }
}

/// Queue the async half of an accept: WAIT_FOR_LISTEN under the accept key.
/// On its completion the dispatcher runs the synchronous child-open +
/// AFD.ACCEPT half (mirrors netAcceptWindows' inline second IOCTL — cheap,
/// the TCP handshake is already done by then).
fn issueAcceptWait(listener: HANDLE) !*AcceptWait {
    const aw = try std.heap.page_allocator.create(AcceptWait);
    errdefer std.heap.page_allocator.destroy(aw);
    aw.* = .{ .iosb = undefined, .response = undefined };
    try issueAfd(
        listener,
        win32.IOCTL.AFD.WAIT_FOR_LISTEN,
        @intFromEnum(EventLocation.accept),
        &.{},
        @as([]u8, @ptrCast(&aw.response)),
        &aw.iosb,
    );
    return aw;
}

// =============================================================================
// Main loop
// =============================================================================

// → GetQueuedCompletionStatus(iocp, ...) dispatch loop, mirroring linux.zig's
// structure: wait → dispatch by completion key → rearm. Keys needed (cf.
// UDATA_* in kqueue.zig):
//   accept          overlapped accept on the listener: associate its
//                   std.Io-created AFD handle with our port, issue
//                   NtDeviceIoControlFile(AFD.WAIT_FOR_LISTEN), then open a
//                   child endpoint + AFD.ACCEPT on completion (the std.Io
//                   netAcceptWindows shape, but port-routed). PeerInfo +
//                   handleConnectionFd + platform.close, as in the POSIX
//                   loops.
//   shutdown        posted by the console handler → gracefulShutdown + return.
//   ping_timer      periodic ping sweep (sweepPendingKills, enforceMaxTtl,
//                   queueWorkerPings) → rearm.
//   pressure_timer  runEvictionEpisode → rearm (only if pressure_monitor.active()).
//   live_timer      onLiveTimer — no rearm (Conductor re-arms via armLiveTimer).
//   worker          overlapped AFD.RECEIVE into w.pong_buf, keyed by
//                   @intFromPtr(w); bit 0: 0 = pong, 1 = health-check timer —
//                   same dispatch as kqueue's `else` branch. Ping timeout is a
//                   timer completion pairing the read (see queuePing in
//                   linux.zig; no IO_LINK here — the pair is coordinated via
//                   w.ping_pending, as in kqueue.zig).
// All handles are plain overlapped HANDLEs (std.Io creates them via AFD);
// we extract .socket.handle, CreateIoCompletionPort them onto our port, and
// issue AFD IOCTLs with ApcRoutine=null so completions land here. See AFD.md.
pub fn run(conductor: *Conductor, server: *Io.net.Server) void {
    const iocp: HANDLE = conductor.event_loop.iocp;

    // Associate the std.Io-created listener AFD handle with our port under
    // the accept key — from here on its completions route to this loop.
    const listener = server.socket.handle;
    if (CreateIoCompletionPort(listener, iocp, @intFromEnum(EventLocation.accept), 0) == null) {
        std.debug.print("Fatal: failed to associate listener with IOCP\n", .{});
        return;
    }

    const pressure_active = conductor.pressure_monitor.active();

    // Initial one-shot timers; the dispatcher re-arms each on fire.
    conductor.event_loop.armOneShot(
        @intFromEnum(EventLocation.ping_timer),
        conductor.cfg.ping_interval * 1000,
    );
    if (pressure_active) {
        // min(5s, ping_interval); plain if — @min's literal-cap narrowing
        // would type the result as u3 and overflow on *1000.
        const pressure_s: u64 = if (conductor.cfg.ping_interval < 5) conductor.cfg.ping_interval else 5;
        conductor.event_loop.armOneShot(
            @intFromEnum(EventLocation.pressure_timer),
            pressure_s * 1000,
        );
    }

    // Queue the first overlapped WAIT_FOR_LISTEN. Ownership of the context
    // passes to the loop body: after its completion is dispatched (child open
    // + sync AFD.ACCEPT), it frees the ctx and re-issues a new wait.
    _ = issueAcceptWait(listener) catch |err| {
        std.debug.print("Fatal: failed to queue initial accept: {}\n", .{err});
        return;
    };

    while (true) {
        // TODO(next pass): GQCS wait + dispatch by completion key:
        //   - worker keys (>= 0x1000): pong completion (ovl != null → PongRead)
        //     vs ping timeout / health check (ovl == null timer post),
        //   - accept key: child open + sync ACCEPT + handleConnectionFd + re-issue,
        //   - signal: gracefulShutdown + return,
        //   - ping/pressure timers: sweep/enforce/ping-queue + armOneShot rearm,
        //   - live_timer: onLiveTimer (no rearm).
    }
}

// Ping cycle, IOCP edition. sendPing() already pushes the header synchronously
// via platform.write (as in POSIX); then issue the overlapped pong RECEIVE
// keyed by @intFromPtr(w), and pair it with a one-shot timeout under the SAME
// key — the dispatcher distinguishes them by the OVERLAPPED pointer being our
// PongRead iosb (data arrived) vs null (timer-posted completion). Failure to
// issue resets ping_pending and leaks nothing (mirrors linux.zig's error path).
fn queuePing(iocp: HANDLE, w: *worker.Worker, timeout_ms: u64) void {
    w.sendPing();
    const pr = std.heap.page_allocator.create(PongRead) catch {
        w.ping_pending = false;
        return;
    };
    pr.* = .{
        .iosb = undefined,
        .iovec = .{.{ .len = w.pong_buf.len, .buf = &w.pong_buf }},
        .info = .{
            .BufferArray = @ptrCast(&pr.iovec),
            .BufferCount = 1,
            .AfdFlags = .{ .NO_FAST_IO = true, .OVERLAPPED = true },
            .TdiFlags = .{ .NORMAL = true },
        },
    };
    issueAfd(w.socket, win32.IOCTL.AFD.RECEIVE, @intFromPtr(w), std.mem.asBytes(&pr.info), &.{}, &pr.iosb) catch {
        std.heap.page_allocator.destroy(pr);
        w.ping_pending = false;
        return;
    };
    scheduleTimer(iocp, @intFromPtr(w), timeout_ms);
}
