// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0
//
// Linux event loop for the conductor: io_uring, or epoll where the kernel
// lacks it (before 5.6, for our operations) or has it disabled.

const std = @import("std");
const posix = std.posix;

const Conductor = @import("../main.zig").Conductor;
const protocol = @import("../protocol.zig");
const worker = @import("../worker.zig");

const iouring = @import("iouring.zig");
const epoll = @import("epoll.zig");
const posix_signals = @import("posix_signals.zig");

pub const installSignalHandlers = posix_signals.installSignalHandlers;
pub const cleanupSignalHandlers = posix_signals.cleanupSignalHandlers;

pub const EventLoop = union(enum) {
    iouring: iouring.EventLoop,
    epoll: epoll.EventLoop,

    pub fn init(entries: u13) !EventLoop {
        return .{ .iouring = iouring.EventLoop.init(entries) catch |err| switch (err) {
            error.SystemOutdated, error.PermissionDenied, error.SystemResources => return .{ .epoll = try epoll.EventLoop.init(err) },
            else => return err,
        } };
    }

    pub fn deinit(self: *EventLoop) void {
        switch (self.*) {
            inline else => |*loop| loop.deinit(),
        }
    }

    pub fn logResolution(self: *const EventLoop) void {
        switch (self.*) {
            inline else => |*loop| loop.logResolution(),
        }
    }

    pub fn armLiveTimer(self: *EventLoop, delay_ms: u64) void {
        switch (self.*) {
            inline else => |*loop| loop.armLiveTimer(delay_ms),
        }
    }

    pub fn scheduleHealthCheck(self: *EventLoop, w: *worker.Worker) void {
        switch (self.*) {
            inline else => |*loop| loop.scheduleHealthCheck(w),
        }
    }

    pub fn awaitPong(self: *EventLoop, w: *worker.Worker, timeout_ms: u64) void {
        switch (self.*) {
            inline else => |*loop| loop.awaitPong(w, timeout_ms),
        }
    }

    pub fn watchFd(self: *EventLoop, tag: usize, fd: posix.fd_t) void {
        switch (self.*) {
            inline else => |*loop| loop.watchFd(tag, fd),
        }
    }

    pub fn unwatchFd(self: *EventLoop, tag: usize, fd: posix.fd_t) void {
        switch (self.*) {
            inline else => |*loop| loop.unwatchFd(tag, fd),
        }
    }

    pub fn armTick(self: *EventLoop) void {
        switch (self.*) {
            inline else => |*loop| loop.armTick(),
        }
    }

    pub fn cancelPendingPing(self: *EventLoop, w: *worker.Worker) void {
        switch (self.*) {
            inline else => |*loop| loop.cancelPendingPing(w),
        }
    }
};

pub fn run(conductor: *Conductor, listener: *protocol.Listener) void {
    switch (conductor.event_loop) {
        .iouring => |*loop| iouring.run(conductor, loop, listener),
        .epoll => |*loop| epoll.run(conductor, loop, listener),
    }
}
