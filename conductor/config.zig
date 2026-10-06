// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0

const std = @import("std");
const builtin = @import("builtin");
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
    sandbox_reuse: bool, // per remote host

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
        errdefer allocator.free(socket_path);
        const transport = parsed.mode;
        {
            // The longest socket made there: locally a client's reply socket or a
            // worker's own, over TCP only a worker's setup socket. A sandboxed
            // worker's (Linux only) sit a subdirectory deeper.
            const sandbox_dir = if (builtin.os.tag == .linux)
                std.fmt.comptimePrint("/sandbox-{d}", .{std.math.maxInt(u32)})
            else
                "";
            // A worker names its own with its random id, then a random suffix.
            const worker_socket = if (builtin.os.tag.isDarwin()) "/w-abcdef-abcdefgh.sock" else "/worker-abcdef-abcdefgh.sock";
            const name_len = switch (transport) {
                .local => @max("/0123456789abcdef-signals.sock".len, sandbox_dir.len + worker_socket.len),
                .tcp => sandbox_dir.len + "/0123456789abcdef-wsetup.sock".len,
            };
            const most = platform.max_local_addr - 1;
            if (socket_dir.len + name_len > most) {
                std.debug.print(
                    \\Error: the runtime directory {s} is too long for the sockets made in it:
                    \\they would be up to {d} bytes, where this system allows {d}.
                    \\Set JULIA_DAEMON_RUNTIME to a directory of at most {d} bytes.
                    \\
                , .{ socket_dir, socket_dir.len + name_len, most, most - name_len });
                return error.InvalidConfig;
            }
        }
        const bind_address: []const u8 = if (transport == .tcp)
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
            .host_home = env.get("HOME") orelse env.get("USERPROFILE") orelse "",
        };
        var cfg: Config = undefined;
        inline for (@typeInfo(Config).@"struct".field_names) |name| {
            if (comptime @hasField(@TypeOf(own), name))
                @field(cfg, name) = @field(own, name)
            else if (comptime !settings.hasField(name))
                @compileError("nothing sets Config." ++ name);
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
        u32 => std.fmt.parseInt(u32, text.?, 10),
        // Every u64 setting is a duration, and every f64 a percentage.
        u64 => settings.parseDuration(text.?),
        ?u32 => if (text) |t| try std.fmt.parseInt(u32, t, 10) else null,
        f64 => settings.parsePercent(text.?),
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
    return .{ .base = range[0], .count = settings.portSets(range) };
}

fn testEnv(setting: [2][]const u8) !std.process.Environ.Map {
    var env: std.process.Environ.Map = .init(std.testing.allocator);
    errdefer env.deinit();
    try env.put("JULIA_DAEMON_WORKER_PROJECT", "/w");
    try env.put("JULIA_DAEMON_RUNTIME", "/tmp/jd");
    try env.put(setting[0], setting[1]);
    return env;
}

test "a value Config can't hold is refused as it loads, leaking nothing" {
    const cases = [_][2][]const u8{
        .{ "JULIA_DAEMON_WORKER_MAXCLIENTS", "4294967296" },
        .{ "JULIA_DAEMON_SANDBOX_MAX_CPU", "x" },
        .{ "JULIA_DAEMON_PING_TIMEOUT", "4320000" },
        .{ "JULIA_DAEMON_SPAWN_TIMEOUT", "4320000" },
        .{ "JULIA_DAEMON_PSI_THRESHOLD", "nan" },
        .{ "JULIA_DAEMON_PSI_THRESHOLD", "inf" },
        .{ "JULIA_DAEMON_PSI_THRESHOLD", "150" },
    };
    for (cases) |case| {
        var env = try testEnv(case);
        defer env.deinit();
        try std.testing.expectError(error.InvalidConfig, Config.load(std.testing.allocator, &env));
    }
}

test "what a setting takes, Config loads" {
    var env = try testEnv(.{ "JULIA_DAEMON_PSI_THRESHOLD", "12.5%" });
    defer env.deinit();
    try env.put("JULIA_DAEMON_PING_TIMEOUT", "2073600");
    try env.put("JULIA_DAEMON_WORKER_MAXCLIENTS", "4294967295");
    const cfg = try Config.load(std.testing.allocator, &env);
    defer cfg.deinit();
    try std.testing.expectEqual(12.5, cfg.psi_threshold);
    try std.testing.expectEqual(settings.max_seconds, cfg.ping_timeout);
    try std.testing.expectEqual(std.math.maxInt(u32), cfg.worker_maxclients);
}

test "a TCP server's host is where everything listens" {
    var env = try testEnv(.{ "JULIA_DAEMON_SERVER", "tcp://0.0.0.0:9591" });
    defer env.deinit();
    try env.put("JULIA_DAEMON_BIND", "10.0.0.1"); // retired, so ignored
    const cfg = try Config.load(std.testing.allocator, &env);
    defer cfg.deinit();
    try std.testing.expectEqual(.tcp, cfg.transport);
    try std.testing.expectEqualStrings("0.0.0.0", cfg.bind_address);
}

test "a runtime directory too long for its sockets is refused" {
    const name_len = "/0123456789abcdef-signals.sock".len;
    const longest = "/" ++ @as([platform.max_local_addr - 1 - name_len - 1]u8, @splat('d'));
    var fits = try testEnv(.{ "JULIA_DAEMON_RUNTIME", longest });
    defer fits.deinit();
    const cfg = try Config.load(std.testing.allocator, &fits);
    cfg.deinit();
    var too_long = try testEnv(.{ "JULIA_DAEMON_RUNTIME", longest ++ "d" });
    defer too_long.deinit();
    try std.testing.expectError(error.InvalidConfig, Config.load(std.testing.allocator, &too_long));
}
