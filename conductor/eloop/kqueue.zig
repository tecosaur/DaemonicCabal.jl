// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0
//
// BSD/macOS kqueue-based event loop for the conductor.
//
// This implementation mirrors the io_uring-based Linux event loop, handling:
// - Client connection acceptance
// - Signal-to-pipe conversion for graceful shutdown
// - Periodic worker health checks (ping/pong with timeouts)
//
// Key difference from io_uring: linked operations (read + timeout) must be
// managed manually with two separate kqueue registrations, coordinated via
// the worker's `ping_pending` flag.

const std = @import("std");
const c = std.c;
const posix = std.posix;
const Io = std.Io;

const main = @import("../main.zig");
const Conductor = main.Conductor;
const platform = @import("../platform/main.zig");
const protocol = @import("../protocol.zig");
const worker = @import("../worker.zig");

// Shutdown signaling (converts Unix signals to event loop events via pipe)
pub const SIGNAL_SHUTDOWN: u8 = 'S';
pub const SIGNAL_RECREATE: u8 = 'R';

/// Signal pipe for converting async signals to event loop events
pub var signal_pipe: [2]posix.fd_t = .{ -1, -1 };

fn handleShutdown(_: posix.SIG) callconv(.c) void {
    _ = platform.write(signal_pipe[1], &[_]u8{SIGNAL_SHUTDOWN});
}

fn handleUsr1(_: posix.SIG) callconv(.c) void {
    _ = platform.write(signal_pipe[1], &[_]u8{SIGNAL_RECREATE});
}

/// Create signal pipe and install signal handlers. Call before running event loop.
pub fn installSignalHandlers() !void {
    signal_pipe = Io.Threaded.pipe2(.{ .NONBLOCK = true }) catch return error.PipeCreationFailed;
    const shutdown_sigact = posix.Sigaction{
        .handler = .{ .handler = @ptrCast(&handleShutdown) },
        .mask = std.mem.zeroes(posix.sigset_t),
        .flags = 0,
    };
    posix.sigaction(posix.SIG.TERM, &shutdown_sigact, null);
    posix.sigaction(posix.SIG.INT, &shutdown_sigact, null);
    const usr1_sigact = posix.Sigaction{
        .handler = .{ .handler = @ptrCast(&handleUsr1) },
        .mask = std.mem.zeroes(posix.sigset_t),
        .flags = 0,
    };
    posix.sigaction(posix.SIG.USR1, &usr1_sigact, null);
}

/// Close signal pipe. Call after event loop exits.
pub fn cleanupSignalHandlers() void {
    if (signal_pipe[0] != -1) posix.close(signal_pipe[0]);
    if (signal_pipe[1] != -1) posix.close(signal_pipe[1]);
    signal_pipe = .{ -1, -1 };
}

// EV flags - some BSD variants have gaps in Zig's bindings
const EV_ERROR: u16 = if (@hasDecl(c.EV, "ERROR")) c.EV.ERROR else 0x4000;

// Sentinel udata values for fixed event sources (worker pointers are >= 0x1000)
const UDATA_ACCEPT: usize = 0;
const UDATA_SIGNAL: usize = 1;
const UDATA_PING_TIMER: usize = 2;
// Unique ident for the periodic ping timer (won't collide with file descriptors)
const TIMER_IDENT_PING: usize = 0xFFFF_0001;

// EventLoop (wraps kqueue fd + configuration)
pub const EventLoop = struct {
    kq: posix.fd_t,
    ping_interval_ms: isize,
    ping_timeout_ms: isize,

    pub fn init(_: u13) !EventLoop {
        const kq = c.kqueue();
        if (kq == -1) return error.KqueueCreateFailed;
        return .{
            .kq = kq,
            .ping_interval_ms = 1000,
            .ping_timeout_ms = 5000,
        };
    }

    pub fn deinit(self: *EventLoop) void {
        _ = c.close(self.kq);
    }

    /// Schedule a health check for a worker after a short delay (1 second).
    /// Uses bit 0 of udata to distinguish from pong timeouts.
    pub fn scheduleHealthCheck(self: *EventLoop, w: *worker.Worker) void {
        const udata_tagged = @intFromPtr(w) | 1;
        var changes = [1]c.Kevent{makeKevent(
            udata_tagged, // ident: use tagged pointer for uniqueness
            c.EVFILT.TIMER,
            c.EV.ADD | c.EV.ONESHOT,
            0,
            1000, // 1 second delay
            udata_tagged,
        )};
        _ = keventSubmit(self.kq, &changes);
    }

    /// Cancel pending async ping read and drain the pong response.
    pub fn cancelPendingPing(self: *EventLoop, w: *worker.Worker) void {
        if (!w.ping_pending) return;
        // Delete the read registration (may already be gone if it fired)
        var changes = [2]c.Kevent{
            makeKevent(@intCast(w.socket), c.EVFILT.READ, c.EV.DELETE, 0, 0, 0),
            makeKevent(@intFromPtr(w), c.EVFILT.TIMER, c.EV.DELETE, 0, 0, 0),
        };
        _ = keventSubmit(self.kq, &changes);
        // Drain pong synchronously
        var buf: [7]u8 = undefined;
        protocol.readExact(w.socket, &buf) catch {};
        w.ping_pending = false;
    }
};

// Main event loop
pub fn run(conductor: *Conductor, server: *Io.net.Server) void {
    const kq = conductor.event_loop.kq;
    var server_fd: posix.fd_t = server.socket.handle;
    // Store timeout configuration
    conductor.event_loop.ping_interval_ms = @intCast(conductor.cfg.ping_interval * 1000);
    conductor.event_loop.ping_timeout_ms = @intCast(conductor.cfg.ping_timeout * 1000);
    // Buffers
    var signal_buf: [16]u8 = undefined;
    var pong_buf: [7]u8 = undefined;
    // Register initial events
    var init_changes: [3]c.Kevent = .{
        // Server accept (level-triggered read)
        makeKevent(@intCast(server_fd), c.EVFILT.READ, c.EV.ADD, 0, 0, UDATA_ACCEPT),
        // Signal pipe read
        makeKevent(@intCast(signal_pipe[0]), c.EVFILT.READ, c.EV.ADD, 0, 0, UDATA_SIGNAL),
        // Periodic ping timer
        makeKevent(
            TIMER_IDENT_PING,
            c.EVFILT.TIMER,
            c.EV.ADD,
            0,
            conductor.event_loop.ping_interval_ms,
            UDATA_PING_TIMER,
        ),
    };
    if (keventSubmit(kq, &init_changes) < 0) {
        std.debug.print("Fatal: failed to register initial kevents\n", .{});
        return;
    }
    // Event buffer
    var events: [32]c.Kevent = undefined;
    // Empty changelist for calls where we only want to wait for events
    var no_changes: [0]c.Kevent = undefined;
    // Main loop
    while (true) {
        const nevents = keventCall(kq, &no_changes, &events);
        if (nevents < 0) {
            // Check errno for EINTR (signal interrupted)
            const err: posix.E = @enumFromInt(c._errno().*);
            if (err == .INTR) continue;
            std.debug.print("Fatal: kevent wait failed: {}\n", .{err});
            return;
        }
        const event_count: usize = @intCast(nevents);
        for (events[0..event_count]) |ev| {
            // Check for errors on this event
            if ((ev.flags & EV_ERROR) != 0) {
                std.debug.print("kevent error on ident {}: {}\n", .{ ev.ident, ev.data });
                continue;
            }
            const udata = udataInt(ev);
            switch (udata) {
                UDATA_ACCEPT => {
                    handleAccept(conductor, server_fd);
                },
                UDATA_SIGNAL => {
                    if (handleSignal(conductor, server, &server_fd, kq, &signal_buf)) return;
                },
                UDATA_PING_TIMER => {
                    queueWorkerPings(conductor, kq);
                },
                else => {
                    // Worker event: udata is (worker_ptr | tag)
                    // Bit 0: 0 = pong read/timeout, 1 = health check timeout
                    const is_health_check = (udata & 1) != 0;
                    const w: *worker.Worker = @ptrFromInt(udata & ~@as(usize, 1));
                    if (ev.filter == c.EVFILT.TIMER) {
                        if (is_health_check) {
                            handleHealthCheck(conductor, kq, w);
                        } else {
                            handlePongTimeout(conductor, kq, w);
                        }
                    } else {
                        // EVFILT_READ: pong data ready
                        handlePongReady(conductor, kq, w, &pong_buf);
                    }
                },
            }
        }
    }
}

// Event handlers

fn handleAccept(conductor: *Conductor, server_fd: posix.fd_t) void {
    // Accept is level-triggered, so we don't need to re-arm
    var client_addr: c.sockaddr = undefined;
    var client_addr_len: c.socklen_t = @sizeOf(c.sockaddr);
    const client_fd = c.accept(server_fd, &client_addr, &client_addr_len);
    if (client_fd < 0) {
        const err: posix.E = @enumFromInt(c._errno().*);
        std.debug.print("Accept error: {}\n", .{err});
        return;
    }
    defer _ = c.close(client_fd);
    conductor.handleConnectionFd(client_fd) catch |err| {
        std.debug.print("Client handling failed: {}\n", .{err});
    };
}

/// Handle signal pipe read. Returns true if shutdown requested.
fn handleSignal(
    conductor: *Conductor,
    server: *Io.net.Server,
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
                // Remove old server fd from kqueue
                var del_changes = [1]c.Kevent{makeKevent(@intCast(server_fd.*), c.EVFILT.READ, c.EV.DELETE, 0, 0, 0)};
                _ = keventSubmit(kq, &del_changes);
                server.deinit(conductor.io);
                Io.Dir.deleteFileAbsolute(conductor.io, conductor.cfg.socket_path) catch {};
                server.* = conductor.createServer() catch |err| {
                    std.debug.print("Failed to recreate socket: {}\n", .{err});
                    continue;
                };
                server_fd.* = server.socket.handle;
                // Register new server fd
                var add_changes = [1]c.Kevent{makeKevent(@intCast(server_fd.*), c.EVFILT.READ, c.EV.ADD, 0, 0, UDATA_ACCEPT)};
                _ = keventSubmit(kq, &add_changes);
            },
            else => {},
        }
    }
    return false;
}

// Health checking

fn queueWorkerPings(conductor: *Conductor, kq: posix.fd_t) void {
    const now = conductor.currentTime();
    var it = conductor.workers.iterator();
    while (it.next()) |entry| {
        for (entry.value_ptr.items) |w| {
            maybeQueuePing(conductor, kq, w, now);
        }
    }
    if (conductor.reserve) |r| maybeQueuePing(conductor, kq, r, now);
}

fn maybeQueuePing(conductor: *Conductor, kq: posix.fd_t, w: *worker.Worker, now: i64) void {
    if (w.ping_pending) return;
    if (w.active_clients > 0) return;
    if (now - w.last_pinged < @as(i64, @intCast(conductor.cfg.ping_interval))) return;
    queuePing(conductor, kq, w);
}

fn queuePing(conductor: *Conductor, kq: posix.fd_t, w: *worker.Worker) void {
    w.sendPing();
    // Register both read and timeout for this ping
    var changes: [2]c.Kevent = .{
        // Read on worker socket (one-shot)
        makeKevent(
            @intCast(w.socket),
            c.EVFILT.READ,
            c.EV.ADD | c.EV.ONESHOT,
            0,
            0,
            @intFromPtr(w), // udata = worker ptr (bit 0 clear)
        ),
        // Timeout timer (one-shot)
        makeKevent(
            @intFromPtr(w), // ident = worker ptr for uniqueness
            c.EVFILT.TIMER,
            c.EV.ADD | c.EV.ONESHOT,
            0,
            conductor.event_loop.ping_timeout_ms,
            @intFromPtr(w), // udata = worker ptr (bit 0 clear)
        ),
    };
    if (keventSubmit(kq, &changes) < 0) {
        w.ping_pending = false;
    }
}

fn handleHealthCheck(conductor: *Conductor, kq: posix.fd_t, w: *worker.Worker) void {
    // Health check timer fired - send a ping if conditions are met
    const recently_pinged = (conductor.currentTime() - w.last_pinged) < 2;
    if (w.active_clients == 0 and !w.ping_pending and !recently_pinged) {
        queuePing(conductor, kq, w);
    }
}

fn handlePongReady(conductor: *Conductor, kq: posix.fd_t, w: *worker.Worker, pong_buf: *[7]u8) void {
    // Guard against race with timeout (both may fire in same kevent batch)
    if (!w.ping_pending) return;
    w.ping_pending = false; // Clear FIRST, before any fallible operations
    // Cancel timeout timer (may fail if already fired - that's fine)
    var changes = [1]c.Kevent{makeKevent(@intFromPtr(w), c.EVFILT.TIMER, c.EV.DELETE, 0, 0, 0)};
    _ = keventSubmit(kq, &changes);
    // Read pong (socket is ready, but may need multiple reads for full 7 bytes)
    const n = posix.read(w.socket, pong_buf) catch |err| {
        std.debug.print("Worker {d}: pong read error: {}\n", .{ w.id, err });
        conductor.killUnresponsiveWorker(w);
        return;
    };
    if (n < 7) {
        protocol.readExact(w.socket, pong_buf[n..]) catch {
            std.debug.print("Worker {d}: pong short read\n", .{w.id});
            conductor.killUnresponsiveWorker(w);
            return;
        };
    }
    w.last_pinged = conductor.currentTime();
    const worker_count = std.mem.readInt(u16, pong_buf[5..7], .little);
    if (worker_count != w.active_clients) {
        std.debug.print("Worker {d}: client count mismatch (worker={d}, conductor={d}), syncing\n", .{
            w.id, worker_count, w.active_clients,
        });
        conductor.syncWorkerClients(w);
    }
}

fn handlePongTimeout(conductor: *Conductor, kq: posix.fd_t, w: *worker.Worker) void {
    // Guard against race with read (both may fire in same kevent batch)
    if (!w.ping_pending) return;
    w.ping_pending = false;
    // Cancel read registration (may fail if already fired - that's fine)
    var changes = [1]c.Kevent{makeKevent(@intCast(w.socket), c.EVFILT.READ, c.EV.DELETE, 0, 0, 0)};
    _ = keventSubmit(kq, &changes);
    std.debug.print("Worker {d}: ping timed out\n", .{w.id});
    conductor.killUnresponsiveWorker(w);
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
fn udataInt(ev: c.Kevent) usize {
    return ev.udata;
}
/// Wrapper for kevent syscall using slices
fn keventCall(kq: posix.fd_t, changelist: []const c.Kevent, eventlist: []c.Kevent) c_int {
    return c.kevent(kq, changelist.ptr, @intCast(changelist.len), eventlist.ptr, @intCast(eventlist.len), null);
}
/// Submit kevent changes, ignoring the event list. Returns number of changes
/// processed, or -1 on error.
fn keventSubmit(kq: posix.fd_t, changelist: []const c.Kevent) c_int {
    var dummy: [0]c.Kevent = undefined;
    return keventCall(kq, changelist, &dummy);
}
