// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0

const std = @import("std");
const platform = @import("platform/main.zig");
const protocol = @import("protocol.zig");

pub const Config = struct {
    allocator: std.mem.Allocator,
    socket_path: []const u8,
    runtime_dir: []const u8,
    socket_dir: []const u8,
    transport: protocol.TransportMode,
    bind_address: []const u8, // empty in local mode
    worker_executable: []const u8,
    worker_args: []const u8,
    worker_project: []const u8,
    worker_maxclients: u32,
    // Durations in seconds
    min_ttl: u64,
    max_ttl: u64,
    label_ttl: u64,
    ping_interval: u64,
    ping_timeout: u64,
    spawn_timeout: u64,
    memory_pressure: bool,
    psi_threshold: f64, // PSI some-avg10 %
    memfree_low: MemThreshold,
    memfree_high: MemThreshold,
    port_range: ?PortRange,
    host_home: []const u8,
    reserve_worker: bool,
    sandbox_remote_clients: bool,
    sandbox_max_memory: ?[]const u8, // e.g. "4G"
    sandbox_max_cpu: ?u32, // percent, 200 = 2 cores
    sandbox_session_bypass: bool,

    pub const PortRange = struct { base: u16, count: u16 };

    pub const MemThreshold = union(enum) {
        fraction: f64, // 0..1
        bytes: u64,
        pub fn satisfied(self: MemThreshold, avail: u64, total: u64) bool {
            return switch (self) {
                .fraction => |f| @as(f64, @floatFromInt(avail)) < f * @as(f64, @floatFromInt(total)),
                .bytes => |b| avail < b,
            };
        }
    };

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
        const socket_dir = try platform.localSocketDir(allocator, runtime_dir);
        errdefer allocator.free(socket_dir);
        const server_env = env.get("JULIA_DAEMON_SERVER");
        const parsed = protocol.parseAddress(server_env orelse
            try platform.localSocketPath(allocator, socket_dir, "conductor.sock", .{})) catch {
            std.debug.print("Error: unsupported scheme in JULIA_DAEMON_SERVER={s}\nOnly tcp:// and local socket paths are supported.\n", .{server_env.?});
            return error.UnsupportedScheme;
        };
        const socket_path = if (server_env != null)
            try allocator.dupe(u8, parsed.addr)
        else
            parsed.addr;
        const transport = parsed.mode;
        const bind_address: []const u8 = if (env.get("JULIA_DAEMON_BIND")) |b|
            b
        else if (transport == .tcp)
            (protocol.splitHostPort(socket_path) catch {
                std.debug.print("Error: JULIA_DAEMON_SERVER={s} is not a valid host[:port]\n", .{socket_path});
                return error.InvalidAddress;
            }).host
        else
            "";
        const cfg: Config = .{
            .allocator = allocator,
            .socket_path = socket_path,
            .runtime_dir = runtime_dir,
            .socket_dir = socket_dir,
            .transport = transport,
            .bind_address = bind_address,
            .worker_executable = env.get("JULIA_DAEMON_WORKER_EXECUTABLE") orelse "julia",
            .worker_args = env.get("JULIA_DAEMON_WORKER_ARGS") orelse "--startup-file=no",
            .worker_project = worker_project,
            .worker_maxclients = parseUint(u32, env.get("JULIA_DAEMON_WORKER_MAXCLIENTS"), 1),
            .reserve_worker = !std.mem.eql(u8, env.get("JULIA_DAEMON_RESERVE_WORKER") orelse "1", "0"),
            .min_ttl = try parseUintStrict(u64, env.get("JULIA_DAEMON_MIN_TTL"), 120),
            // WORKER_TTL is the deprecated name.
            .max_ttl = try parseUintStrict(u64, env.get("JULIA_DAEMON_MAX_TTL"), parseUint(u64, env.get("JULIA_DAEMON_WORKER_TTL"), 7200)),
            .label_ttl = parseUint(u64, env.get("JULIA_DAEMON_LABEL_TTL"), 90),
            .ping_interval = parseUint(u64, env.get("JULIA_DAEMON_PING_INTERVAL"), 30),
            .ping_timeout = parseUint(u64, env.get("JULIA_DAEMON_PING_TIMEOUT"), 5),
            .spawn_timeout = try parseUintStrict(u64, env.get("JULIA_DAEMON_SPAWN_TIMEOUT"), 600),
            .memory_pressure = !std.mem.eql(u8, env.get("JULIA_DAEMON_MEMORY_PRESSURE") orelse "1", "0"),
            .psi_threshold = try parseFloatStrict(env.get("JULIA_DAEMON_PSI_THRESHOLD"), 10.0),
            .memfree_low = try parseMemThreshold(env.get("JULIA_DAEMON_MEMFREE_LOW"), .{ .fraction = 0.10 }),
            .memfree_high = try parseMemThreshold(env.get("JULIA_DAEMON_MEMFREE_HIGH"), .{ .fraction = 0.15 }),
            .port_range = if (transport == .tcp) parsePortRange(env.get("JULIA_DAEMON_PORTS")) else null,
            .host_home = env.get("HOME") orelse "",
            .sandbox_remote_clients = !std.mem.eql(u8, env.get("JULIA_DAEMON_SANDBOX_REMOTE_CLIENTS") orelse "1", "0"),
            .sandbox_max_memory = env.get("JULIA_DAEMON_SANDBOX_MAX_MEMORY"),
            .sandbox_max_cpu = parseOptionalUint(u32, env.get("JULIA_DAEMON_SANDBOX_MAX_CPU")),
            .sandbox_session_bypass = std.mem.eql(u8, env.get("JULIA_DAEMON_SANDBOX_SESSION_BYPASS") orelse "0", "1"),
        };
        if (cfg.min_ttl == 0 or cfg.min_ttl >= cfg.max_ttl) {
            std.debug.print("Error: JULIA_DAEMON_MIN_TTL ({d}) must be > 0 and < MAX_TTL ({d}).\n", .{ cfg.min_ttl, cfg.max_ttl });
            return error.InvalidConfig;
        }
        if (!memThresholdBelow(cfg.memfree_low, cfg.memfree_high)) {
            std.debug.print("Error: JULIA_DAEMON_MEMFREE_LOW must be < MEMFREE_HIGH.\n", .{});
            return error.InvalidConfig;
        }
        return cfg;
    }

    pub fn deinit(self: *const Config) void {
        self.allocator.free(self.socket_path);
        self.allocator.free(self.runtime_dir);
        self.allocator.free(self.socket_dir);
    }
};

fn parseUint(comptime T: type, s: ?[]const u8, default: T) T {
    const str = s orelse return default;
    return std.fmt.parseInt(T, str, 10) catch default;
}

// For eviction knobs, where a typo shouldn't quietly pass.
fn parseUintStrict(comptime T: type, s: ?[]const u8, default: T) !T {
    const str = s orelse return default;
    return std.fmt.parseInt(T, str, 10) catch {
        std.debug.print("Error: invalid integer config value '{s}'.\n", .{str});
        return error.InvalidConfig;
    };
}

fn parseFloatStrict(s: ?[]const u8, default: f64) !f64 {
    const str = s orelse return default;
    return std.fmt.parseFloat(f64, str) catch {
        std.debug.print("Error: invalid float config value '{s}'.\n", .{str});
        return error.InvalidConfig;
    };
}

// "<n>%" of total, or bytes with an optional K/M/G suffix.
fn parseMemThreshold(s: ?[]const u8, default: Config.MemThreshold) !Config.MemThreshold {
    const str = s orelse return default;
    if (std.mem.endsWith(u8, str, "%")) {
        const pct = std.fmt.parseFloat(f64, str[0 .. str.len - 1]) catch return error.InvalidConfig;
        return .{ .fraction = pct / 100.0 };
    }
    const mult: u64 = switch (str[str.len - 1]) {
        'G', 'g' => 1 << 30,
        'M', 'm' => 1 << 20,
        'K', 'k' => 1 << 10,
        else => 1,
    };
    const num_str = if (mult == 1) str else str[0 .. str.len - 1];
    const n = std.fmt.parseInt(u64, num_str, 10) catch {
        std.debug.print("Error: invalid memory threshold '{s}'.\n", .{str});
        return error.InvalidConfig;
    };
    return .{ .bytes = n * mult };
}

// Mixed %/bytes can't be compared without total memory, so they pass.
fn memThresholdBelow(low: Config.MemThreshold, high: Config.MemThreshold) bool {
    return switch (low) {
        .fraction => |lf| switch (high) {
            .fraction => |hf| lf < hf,
            .bytes => true,
        },
        .bytes => |lb| switch (high) {
            .bytes => |hb| lb < hb,
            .fraction => true,
        },
    };
}

fn parseOptionalUint(comptime T: type, s: ?[]const u8) ?T {
    const str = s orelse return null;
    return std.fmt.parseInt(T, str, 10) catch null;
}

fn parsePortRange(s: ?[]const u8) ?Config.PortRange {
    const str = s orelse return null;
    const dash = std.mem.indexOfScalar(u8, str, '-') orelse return null;
    const low = std.fmt.parseInt(u16, str[0..dash], 10) catch return null;
    const high = std.fmt.parseInt(u16, str[dash + 1 ..], 10) catch return null;
    if (high <= low) return null;
    const count = @min((high - low + 1) / 4, protocol.PortPool.max_port_sets);
    if (count == 0) return null;
    return .{ .base = low, .count = count };
}
