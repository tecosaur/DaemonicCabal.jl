// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0

const std = @import("std");
const platform = @import("platform/main.zig");
const protocol = @import("protocol.zig");
const settings = @import("settings.zig");

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

    pub const MemThreshold = settings.Share;

    pub fn load(allocator: std.mem.Allocator, env: *std.process.Environ.Map) !Config {
        const values = settings.fromEnv(env);
        if (values[settings.Setting.index("JULIA_DAEMON_WORKER_PROJECT")] == null) {
            std.debug.print("Error: JULIA_DAEMON_WORKER_PROJECT environment variable is not set.\n", .{});
            std.debug.print("This should point to the DaemonWorker project directory.\n", .{});
            std.debug.print("Run DaemonicCabal.install() to set up the daemon correctly.\n", .{});
            return error.MissingWorkerProject;
        }
        if (settings.conflict(&values)) |c| {
            switch (c) {
                .positive => |i| std.debug.print("Error: {s} must be above 0.\n", .{settings.all[i].key}),
                .ordered => |o| std.debug.print("Error: {s} ({s}) must be below {s} ({s}).\n", .{
                    settings.all[o.below].key, settings.resolved(&values, o.below),
                    settings.all[o.above].key, settings.resolved(&values, o.above),
                }),
            }
            return error.InvalidConfig;
        }
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
        const port_range = if (transport == .tcp) try parsePortRange(env.get("JULIA_DAEMON_PORTS")) else null;
        // Those `settings` has no field for; `read` sets the rest.
        const own = .{
            .allocator = allocator,
            .socket_path = socket_path,
            .runtime_dir = runtime_dir,
            .socket_dir = socket_dir,
            .transport = transport,
            .bind_address = bind_address,
            .port_range = port_range,
            .host_home = env.get("HOME") orelse "",
        };
        var cfg: Config = undefined;
        inline for (@typeInfo(Config).@"struct".fields) |f| {
            if (comptime @hasField(@TypeOf(own), f.name))
                @field(cfg, f.name) = @field(own, f.name)
            else if (comptime !settings.hasField(f.name))
                @compileError("nothing sets Config." ++ f.name);
        }
        try cfg.read(env, .all);
        return cfg;
    }

    /// Rereads the settings that take effect at once, or for new workers,
    /// from `env`; their text is `env`'s.
    pub fn reload(self: *Config, env: *const std.process.Environ.Map) !void {
        try self.read(env, .live);
    }

    fn read(self: *Config, env: *const std.process.Environ.Map, comptime which: enum { all, live }) !void {
        const values = settings.fromEnv(env);
        inline for (settings.all, 0..) |s, i| {
            const skip = s.field == null or (which == .live and (s.effect == .restart or s.effect == .fixed));
            if (comptime !skip) {
                const field = &@field(self, s.field.?);
                field.* = typed(@TypeOf(field.*), values[i] orelse s.default) catch {
                    // The deprecated name, when it's that the value came by.
                    const key = if (env.get(s.key) == null) s.alias orelse s.key else s.key;
                    std.debug.print("Error: {s}={s} isn't {s}.\n", .{ key, values[i].?, settings.expected(s.kind) });
                    return error.InvalidConfig;
                };
            }
        }
    }

    pub fn deinit(self: *const Config) void {
        self.allocator.free(self.socket_path);
        self.allocator.free(self.runtime_dir);
        self.allocator.free(self.socket_dir);
    }
};

// A value in its variable's form, as the field's type holds it.
fn typed(comptime T: type, text: ?[]const u8) !T {
    return switch (T) {
        []const u8 => text orelse "",
        ?[]const u8 => text,
        u32, u64 => std.fmt.parseInt(T, text.?, 10),
        ?u32 => if (text) |t| try std.fmt.parseInt(u32, t, 10) else null,
        f64 => std.fmt.parseFloat(f64, text.?),
        bool => settings.parseFlag(text.?) orelse error.Invalid,
        Config.MemThreshold => settings.parseShare(text.?),
        else => @compileError("no setting of type " ++ @typeName(T)),
    };
}

fn parsePortRange(s: ?[]const u8) !?Config.PortRange {
    const str = s orelse return null;
    const range = settings.parsePorts(str) orelse {
        std.debug.print("Error: JULIA_DAEMON_PORTS={s} isn't {s}.\n", .{ str, settings.expected(.ports) });
        return error.InvalidConfig;
    };
    const count = @min((range[1] - range[0] + 1) / 4, protocol.PortPool.max_port_sets);
    return .{ .base = range[0], .count = count };
}
