// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0

// Configuration loading from environment variables
const std = @import("std");
const platform = @import("platform/main.zig");

pub const Config = struct {
    allocator: std.mem.Allocator,
    socket_path: []const u8,
    runtime_dir: []const u8,
    worker_executable: []const u8,
    worker_args: []const u8,
    worker_project: []const u8,
    worker_maxclients: u32,
    worker_ttl: u64, // seconds
    label_ttl: u64, // seconds - how long to keep session labels after last client disconnects
    ping_interval: u64, // seconds
    ping_timeout: u64, // seconds

    pub fn load(allocator: std.mem.Allocator, env: *std.process.Environ.Map) !Config {
        const worker_project = env.get("JULIA_DAEMON_WORKER_PROJECT") orelse {
            std.debug.print("Error: JULIA_DAEMON_WORKER_PROJECT environment variable is not set.\n", .{});
            std.debug.print("This should point to the DaemonWorker project directory.\n", .{});
            std.debug.print("Run DaemonicCabal.install() to set up the daemon correctly.\n", .{});
            return error.MissingWorkerProject;
        };
        const runtime_dir = if (env.get("JULIA_DAEMON_RUNTIME")) |r|
            try allocator.dupe(u8, r)
        else
            try platform.defaultRuntimeDir(allocator, env.get("XDG_RUNTIME_DIR"), env.get("HOME"));
        errdefer allocator.free(runtime_dir);
        const socket_path = if (env.get("JULIA_DAEMON_SERVER")) |s|
            try allocator.dupe(u8, s)
        else
            try std.fmt.allocPrint(allocator, "{s}/conductor.sock", .{runtime_dir});
        return .{
            .allocator = allocator,
            .socket_path = socket_path,
            .runtime_dir = runtime_dir,
            .worker_executable = env.get("JULIA_DAEMON_WORKER_EXECUTABLE") orelse "julia",
            .worker_args = env.get("JULIA_DAEMON_WORKER_ARGS") orelse "--startup-file=no",
            .worker_project = worker_project,
            .worker_maxclients = parseUint(u32, env.get("JULIA_DAEMON_WORKER_MAXCLIENTS"), 1),
            .worker_ttl = parseUint(u64, env.get("JULIA_DAEMON_WORKER_TTL"), 7200),
            .label_ttl = parseUint(u64, env.get("JULIA_DAEMON_LABEL_TTL"), 90),
            .ping_interval = parseUint(u64, env.get("JULIA_DAEMON_PING_INTERVAL"), 30),
            .ping_timeout = parseUint(u64, env.get("JULIA_DAEMON_PING_TIMEOUT"), 5),
        };
    }

    pub fn deinit(self: *const Config) void {
        self.allocator.free(self.socket_path);
        self.allocator.free(self.runtime_dir);
    }
};

fn parseUint(comptime T: type, s: ?[]const u8, default: T) T {
    const str = s orelse return default;
    return std.fmt.parseInt(T, str, 10) catch default;
}
