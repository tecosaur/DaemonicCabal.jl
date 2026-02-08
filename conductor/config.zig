// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0

// Configuration loading from environment variables
const std = @import("std");
const platform = @import("platform/main.zig");
const protocol = @import("protocol.zig");

pub const Config = struct {
    allocator: std.mem.Allocator,
    socket_path: []const u8,
    runtime_dir: []const u8,
    transport: protocol.TransportMode,
    bind_address: []const u8, // TCP bind address (e.g. "0.0.0.0"); empty in unix mode
    worker_executable: []const u8,
    worker_args: []const u8,
    worker_project: []const u8,
    worker_maxclients: u32,
    worker_ttl: u64, // seconds
    label_ttl: u64, // seconds - how long to keep session labels after last client disconnects
    ping_interval: u64, // seconds
    ping_timeout: u64, // seconds
    port_range: ?PortRange, // from JULIA_DAEMON_PORTS=low-high

    pub const PortRange = struct { base: u16, count: u16 };

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
        const server_env = env.get("JULIA_DAEMON_SERVER");
        const parsed = protocol.parseAddress(server_env orelse
            try std.fmt.allocPrint(allocator, "{s}/conductor.sock", .{runtime_dir})) catch {
            std.debug.print("Error: unsupported scheme in JULIA_DAEMON_SERVER={s}\nOnly tcp:// and unix paths are supported.\n", .{server_env.?});
            return error.UnsupportedScheme;
        };
        const socket_path = if (server_env != null)
            try allocator.dupe(u8, parsed.addr)
        else
            parsed.addr;
        const transport = parsed.mode;
        const bind_address: []const u8 = if (env.get("JULIA_DAEMON_BIND")) |b|
            b
        else if (transport == .tcp) blk: {
            const colon = std.mem.lastIndexOfScalar(u8, socket_path, ':') orelse break :blk "0.0.0.0";
            break :blk socket_path[0..colon];
        } else "";
        return .{
            .allocator = allocator,
            .socket_path = socket_path,
            .runtime_dir = runtime_dir,
            .transport = transport,
            .bind_address = bind_address,
            .worker_executable = env.get("JULIA_DAEMON_WORKER_EXECUTABLE") orelse "julia",
            .worker_args = env.get("JULIA_DAEMON_WORKER_ARGS") orelse "--startup-file=no",
            .worker_project = worker_project,
            .worker_maxclients = parseUint(u32, env.get("JULIA_DAEMON_WORKER_MAXCLIENTS"), 1),
            .worker_ttl = parseUint(u64, env.get("JULIA_DAEMON_WORKER_TTL"), 7200),
            .label_ttl = parseUint(u64, env.get("JULIA_DAEMON_LABEL_TTL"), 90),
            .ping_interval = parseUint(u64, env.get("JULIA_DAEMON_PING_INTERVAL"), 30),
            .ping_timeout = parseUint(u64, env.get("JULIA_DAEMON_PING_TIMEOUT"), 5),
            .port_range = if (transport == .tcp) parsePortRange(env.get("JULIA_DAEMON_PORTS")) else null,
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

fn parsePortRange(s: ?[]const u8) ?Config.PortRange {
    const str = s orelse return null;
    const dash = std.mem.indexOfScalar(u8, str, '-') orelse return null;
    const low = std.fmt.parseInt(u16, str[0..dash], 10) catch return null;
    const high = std.fmt.parseInt(u16, str[dash + 1 ..], 10) catch return null;
    if (high <= low) return null;
    const count: u16 = (high - low + 1) / 4;
    if (count == 0) return null;
    return .{ .base = low, .count = count };
}
