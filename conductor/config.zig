// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0

// Configuration loading from environment variables
const std = @import("std");
const builtin = @import("builtin");
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
    min_ttl: u64, // seconds - protected floor: idle workers younger than this are never culled under pressure
    max_ttl: u64, // seconds - idle deadline: workers idle longer are always culled (supersedes WORKER_TTL)
    label_ttl: u64, // seconds - how long to keep session labels after last client disconnects
    ping_interval: u64, // seconds
    ping_timeout: u64, // seconds
    memory_pressure: bool, // master switch for pressure-reactive eviction
    psi_threshold: f64, // PSI some-avg10 % for moderate pressure (when PSI is the active source)
    memfree_low: MemThreshold, // free-memory enter threshold (when level path is active)
    memfree_high: MemThreshold, // free-memory exit threshold (must exceed memfree_low)
    port_range: ?PortRange, // from JULIA_DAEMON_PORTS=low-high
    host_home: []const u8, // host user's home dir (for sandbox depot access)
    sandbox_remote_clients: bool, // sandbox remote (non-loopback) TCP clients (default: true)
    sandbox_empty_environment: bool, // mask ~/.julia/environments with empty dir in sandbox (default: true)
    sandbox_max_memory: ?[]const u8, // e.g. "4G", "512M" — per-sandbox cgroup memory limit
    sandbox_max_cpu: ?u32, // cgroup cpu.max percentage, e.g. 200 = 2 cores
    sandbox_session_bypass: bool, // allow remote --session=<name> to join local workers

    pub const PortRange = struct { base: u16, count: u16 };

    /// A free-memory threshold, either a fraction of total or an absolute byte count.
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
        const server_env = env.get("JULIA_DAEMON_SERVER");
        // Windows: default to TCP loopback on the protocol default port.
        // Julia speaks libuv named pipes for path-style sockets, not Win10
        // AF_UNIX — a unix-socket conductor is unreachable for workers.
        // (Fixed port = the existing default_tcp_port discovery semantics.)
        const default_addr = if (builtin.os.tag == .windows)
            try std.fmt.allocPrint(allocator, "tcp://127.0.0.1:{d}", .{protocol.default_tcp_port})
        else
            try std.fmt.allocPrint(allocator, "{s}/conductor.sock", .{runtime_dir});
        defer allocator.free(default_addr);
        const parsed = protocol.parseAddress(server_env orelse default_addr) catch {
            std.debug.print("Error: unsupported scheme in JULIA_DAEMON_SERVER={s}\nOnly tcp:// and unix paths are supported.\n", .{server_env orelse ""});
            return error.UnsupportedScheme;
        };
        // parsed.addr slices the input (default_addr or the env string) —
        // dupe so socket_path owns its memory regardless of which came through.
        const socket_path = try allocator.dupe(u8, parsed.addr);
        const transport = parsed.mode;
        const bind_address: []const u8 = if (env.get("JULIA_DAEMON_BIND")) |b|
            b
        else if (transport == .tcp) blk: {
            const colon = std.mem.lastIndexOfScalar(u8, socket_path, ':') orelse break :blk "0.0.0.0";
            break :blk socket_path[0..colon];
        } else "";
        const cfg: Config = .{
            .allocator = allocator,
            .socket_path = socket_path,
            .runtime_dir = runtime_dir,
            .transport = transport,
            .bind_address = bind_address,
            .worker_executable = env.get("JULIA_DAEMON_WORKER_EXECUTABLE") orelse "julia",
            .worker_args = env.get("JULIA_DAEMON_WORKER_ARGS") orelse "--startup-file=no",
            .worker_project = worker_project,
            .worker_maxclients = parseUint(u32, env.get("JULIA_DAEMON_WORKER_MAXCLIENTS"), 1),
            .min_ttl = try parseUintStrict(u64, env.get("JULIA_DAEMON_MIN_TTL"), 120),
            // max_ttl supersedes WORKER_TTL; fall back to it so existing service files keep working.
            .max_ttl = try parseUintStrict(u64, env.get("JULIA_DAEMON_MAX_TTL"), parseUint(u64, env.get("JULIA_DAEMON_WORKER_TTL"), 7200)),
            .label_ttl = parseUint(u64, env.get("JULIA_DAEMON_LABEL_TTL"), 90),
            .ping_interval = parseUint(u64, env.get("JULIA_DAEMON_PING_INTERVAL"), 30),
            .ping_timeout = parseUint(u64, env.get("JULIA_DAEMON_PING_TIMEOUT"), 5),
            // On by default; set JULIA_DAEMON_MEMORY_PRESSURE=0 to opt out.
            .memory_pressure = !std.mem.eql(u8, env.get("JULIA_DAEMON_MEMORY_PRESSURE") orelse "1", "0"),
            .psi_threshold = try parseFloatStrict(env.get("JULIA_DAEMON_PSI_THRESHOLD"), 10.0),
            .memfree_low = try parseMemThreshold(env.get("JULIA_DAEMON_MEMFREE_LOW"), .{ .fraction = 0.10 }),
            .memfree_high = try parseMemThreshold(env.get("JULIA_DAEMON_MEMFREE_HIGH"), .{ .fraction = 0.15 }),
            .port_range = if (transport == .tcp) parsePortRange(env.get("JULIA_DAEMON_PORTS")) else null,
            .host_home = env.get("HOME") orelse "",
            .sandbox_remote_clients = !std.mem.eql(u8, env.get("JULIA_DAEMON_SANDBOX_REMOTE_CLIENTS") orelse "1", "0"),
            .sandbox_empty_environment = !std.mem.eql(u8, env.get("JULIA_DAEMON_SANDBOX_EMPTY_ENVIRONMENT") orelse "1", "0"),
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
    }
};

fn parseUint(comptime T: type, s: ?[]const u8, default: T) T {
    const str = s orelse return default;
    return std.fmt.parseInt(T, str, 10) catch default;
}

// Strict variants abort on a malformed value (vs parseUint's silent default) —
// for eviction knobs where a typo shouldn't quietly pass.
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

// A memory threshold is "<n>%" (fraction of total) or a byte count with an
// optional K/M/G suffix (e.g. "2G", "512M").
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

// low < high; mixed %/bytes units can't be compared without total memory, so
// they pass (trusted to the operator).
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
