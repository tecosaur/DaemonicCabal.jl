// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0
//
// Linux event loop: io_uring when the kernel supports it, epoll otherwise
// (RHEL 8 / Linux 4.18 and any host that returns ENOSYS/EPERM for io_uring).

const std = @import("std");
const Io = std.Io;

const main = @import("../main.zig");
const Conductor = main.Conductor;
const worker = @import("../worker.zig");
const posix_signals = @import("posix_signals.zig");

pub const iouring = @import("iouring.zig");
pub const epoll = @import("epoll.zig");

pub const installSignalHandlers = posix_signals.installSignalHandlers;
pub const cleanupSignalHandlers = posix_signals.cleanupSignalHandlers;

pub const EventLoop = union(enum) {
    io_uring: iouring.EventLoop,
    epoll: epoll.EventLoop,

    pub fn init(entries: u13) !EventLoop {
        if (iouring.EventLoop.init(entries)) |loop| {
            return .{ .io_uring = loop };
        } else |err| switch (err) {
            error.SystemOutdated, error.PermissionDenied => {
                std.debug.print("io_uring unavailable ({}); falling back to epoll\n", .{err});
                return .{ .epoll = try epoll.EventLoop.init(entries) };
            },
            else => return err,
        }
    }

    pub fn deinit(self: *EventLoop) void {
        switch (self.*) {
            .io_uring => |*loop| loop.deinit(),
            .epoll => |*loop| loop.deinit(),
        }
    }

    pub fn armLiveTimer(self: *EventLoop, delay_ms: u64) void {
        switch (self.*) {
            .io_uring => |*loop| loop.armLiveTimer(delay_ms),
            .epoll => |*loop| loop.armLiveTimer(delay_ms),
        }
    }

    pub fn scheduleHealthCheck(self: *EventLoop, w: *worker.Worker) void {
        switch (self.*) {
            .io_uring => |*loop| loop.scheduleHealthCheck(w),
            .epoll => |*loop| loop.scheduleHealthCheck(w),
        }
    }

    pub fn cancelPendingPing(self: *EventLoop, w: *worker.Worker) void {
        switch (self.*) {
            .io_uring => |*loop| loop.cancelPendingPing(w),
            .epoll => |*loop| loop.cancelPendingPing(w),
        }
    }
};

pub fn run(conductor: *Conductor, server: *Io.net.Server) void {
    switch (conductor.event_loop) {
        .io_uring => iouring.run(conductor, server),
        .epoll => epoll.run(conductor, server),
    }
}
