// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0

// Configuration loading from environment variables
const std = @import("std");
const Io = std.Io;
const linux = std.os.linux;

pub const Config = struct {
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
        const uid = linux.getuid();
        const default_runtime = try std.fmt.allocPrint(allocator, "/run/user/{d}/julia-daemon", .{uid});
        const runtime_dir = env.get("JULIA_DAEMON_RUNTIME") orelse default_runtime;
        const default_socket = try std.fmt.allocPrint(allocator, "{s}/conductor.sock", .{runtime_dir});
        return .{
            .socket_path = env.get("JULIA_DAEMON_SERVER") orelse default_socket,
            .runtime_dir = runtime_dir,
            .worker_executable = env.get("JULIA_DAEMON_WORKER_EXECUTABLE") orelse "julia",
            .worker_args = env.get("JULIA_DAEMON_WORKER_ARGS") orelse "--startup-file=no",
            .worker_project = env.get("JULIA_DAEMON_WORKER_PROJECT") orelse "",
            .worker_maxclients = parseUint(u32, env.get("JULIA_DAEMON_WORKER_MAXCLIENTS"), 1),
            .worker_ttl = parseUint(u64, env.get("JULIA_DAEMON_WORKER_TTL"), 7200),
            .label_ttl = parseUint(u64, env.get("JULIA_DAEMON_LABEL_TTL"), 90),
            .ping_interval = parseUint(u64, env.get("JULIA_DAEMON_PING_INTERVAL"), 30),
            .ping_timeout = parseUint(u64, env.get("JULIA_DAEMON_PING_TIMEOUT"), 5),
        };
    }
};

fn parseUint(comptime T: type, s: ?[]const u8, default: T) T {
    const str = s orelse return default;
    return std.fmt.parseInt(T, str, 10) catch default;
}
