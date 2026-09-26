// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0
//
// The daemon's settings, one row each: what `Config.load` reads, and what
// `--reconfigure` shows and changes (`RECONFIGURE.md`). A value is kept in
// its variable's form, the text the conductor and workers parse; `normalise`
// takes what a person types to it, and `display` shows it back.

const std = @import("std");
const builtin = @import("builtin");
const protocol = @import("protocol.zig");

pub const Tab = enum {
    workers,
    sessions,
    lifetime,
    memory,
    network,
    sandbox,

    pub fn title(self: Tab) []const u8 {
        return switch (self) {
            .workers => "Workers",
            .sessions => "Sessions",
            .lifetime => "Lifetime",
            .memory => "Memory",
            .network => "Network",
            .sandbox => "Sandbox",
        };
    }
};

/// The sandbox is Linux's alone.
pub const tabs: []const Tab = if (builtin.os.tag == .linux)
    std.enums.values(Tab)
else
    &.{ .workers, .sessions, .lifetime, .memory, .network };

/// When a changed value is used.
pub const Effect = enum {
    now,
    new_workers, // read by a worker as it starts
    restart, // read by the conductor as it starts
    fixed, // the installer's, not changed here
};

pub const Kind = union(enum) {
    count,
    seconds,
    bytes, // with an optional K, M or G
    share, // of memory: a percentage, or bytes
    percent,
    flag,
    choice: []const []const u8,
    threads, // as JULIA_NUM_THREADS
    ports, // "low-high"
    text,
};

pub const Setting = struct {
    key: []const u8,
    label: []const u8,
    tab: Tab,
    /// Under the row before it at `depth - 1`.
    depth: u8 = 0,
    /// A heading drawn before this row, at `depth - 1`, for it and the rows
    /// after it at its depth.
    heading: ?[]const u8 = null,
    kind: Kind,
    default: ?[]const u8,
    unset: []const u8 = "", // shown for an unset value without a default
    effect: Effect,
    about: []const u8,
    /// Whether the other settings leave it in use, and why not.
    used: ?Use = null,
    field: ?[]const u8 = null, // its `Config` field
    alias: ?[]const u8 = null, // a deprecated variable, read in its absence

    pub fn index(comptime key: []const u8) usize {
        inline for (all, 0..) |s, i| if (comptime std.mem.eql(u8, s.key, key)) return i;
        @compileError("no setting " ++ key);
    }
};

/// Whether a setting fills `Config.<name>`.
pub fn hasField(comptime name: []const u8) bool {
    inline for (all) |s| if (s.field) |f| if (comptime std.mem.eql(u8, f, name)) return true;
    return false;
}

pub const Use = struct {
    check: *const fn (values: Values) bool,
    reason: []const u8,
};

/// Each setting's value, as `all` orders them; null is unset.
pub const Values = []const ?[]const u8;

pub const all = [_]Setting{
    .{ .key = "JULIA_DAEMON_WORKER_MAXCLIENTS", .label = "Clients per worker", .tab = .workers, .kind = .count, .default = "1", .effect = .restart, .field = "worker_maxclients", .about = "How many clients a worker serves at once, 0 for no limit. Above 1, Ctrl-C can't be aimed at one client." },
    .{ .key = "JULIA_DAEMON_RESERVE_WORKER", .label = "Reserve worker", .tab = .workers, .kind = .flag, .default = "1", .effect = .now, .field = "reserve_worker", .about = "Keep a spare worker started, ready for the next new project." },
    .{ .key = "JULIA_DAEMON_WORKER_EXECUTABLE", .label = "executable", .tab = .workers, .depth = 1, .heading = "Julia", .kind = .text, .default = "julia", .effect = .new_workers, .field = "worker_executable", .about = "The Julia binary workers run, found on the daemon's PATH unless absolute." },
    .{ .key = "JULIA_DAEMON_WORKER_ARGS", .label = "arguments", .tab = .workers, .depth = 1, .kind = .text, .default = "--startup-file=no", .effect = .new_workers, .field = "worker_args", .about = "Julia's arguments for each worker, split at spaces." },
    .{ .key = "JULIA_NUM_THREADS", .label = "threads", .tab = .workers, .depth = 1, .kind = .threads, .default = null, .unset = "Julia's default", .effect = .new_workers, .about = "Workers' threads, as JULIA_NUM_THREADS: a count, auto, or with interactive threads, 4,1. A client's --threads wins." },
    .{ .key = "JULIA_DAEMON_WORKER_PROJECT", .label = "DaemonWorker", .tab = .workers, .kind = .text, .default = null, .effect = .fixed, .field = "worker_project", .about = "Where the worker's package is installed; DaemonicCabal.install() sets it." },
    .{ .key = "JULIA_DAEMON_RECORD", .label = "Record", .tab = .sessions, .kind = .{ .choice = &.{ "sync", "interactive", "session" } }, .default = "session", .effect = .new_workers, .about = "Which sessions are recorded from their start: --sync ones, those at a terminal REPL too, or all. Any is recorded from its first --watch." },
    .{ .key = "JULIA_DAEMON_HISTORY_BYTES", .label = "Transcript size", .tab = .sessions, .kind = .bytes, .default = "1M", .effect = .new_workers, .about = "The size of each session's transcript ring." },
    .{ .key = "JULIA_DAEMON_REVISE", .label = "Revise", .tab = .sessions, .kind = .{ .choice = &.{ "yes", "no" } }, .default = "no", .effect = .new_workers, .about = "Load Revise.jl for each session, unless its client says otherwise with --revise." },
    .{ .key = "JULIA_DAEMON_LABEL_TTL", .label = "Labels kept for", .tab = .sessions, .kind = .seconds, .default = "90", .effect = .now, .field = "label_ttl", .about = "How long a session's label outlives its last client." },
    .{ .key = "JULIA_DAEMON_MIN_TTL", .label = "protected for", .tab = .lifetime, .depth = 1, .heading = "Idle workers", .kind = .seconds, .default = "120", .effect = .now, .field = "min_ttl", .about = "An idle worker younger than this is never culled for memory." },
    .{ .key = "JULIA_DAEMON_MAX_TTL", .label = "culled after", .tab = .lifetime, .depth = 1, .kind = .seconds, .default = "7200", .effect = .now, .field = "max_ttl", .alias = "JULIA_DAEMON_WORKER_TTL", .about = "An idle worker older than this is always culled." },
    .{ .key = "JULIA_DAEMON_PING_INTERVAL", .label = "ping every", .tab = .lifetime, .depth = 1, .heading = "Health checks", .kind = .seconds, .default = "30", .effect = .restart, .field = "ping_interval", .about = "How often idle workers are pinged." },
    .{ .key = "JULIA_DAEMON_PING_TIMEOUT", .label = "answer within", .tab = .lifetime, .depth = 1, .kind = .seconds, .default = "5", .effect = .now, .field = "ping_timeout", .about = "How long a ping may go unanswered before the worker is interrupted, then killed." },
    .{ .key = "JULIA_DAEMON_SPAWN_TIMEOUT", .label = "Spawn timeout", .tab = .lifetime, .kind = .seconds, .default = "600", .effect = .now, .field = "spawn_timeout", .about = "How long a new worker may take to connect; in a fresh depot it precompiles first." },
    .{ .key = "JULIA_DAEMON_MEMORY_PRESSURE", .label = "Memory pressure", .tab = .memory, .kind = .flag, .default = "1", .effect = .restart, .field = "memory_pressure", .about = "Cull idle workers when memory is scarce, the least valuable first. Off leaves only their TTLs." },
    .{ .key = "JULIA_DAEMON_PSI_THRESHOLD", .label = "PSI threshold", .tab = .memory, .depth = 1, .kind = .percent, .default = "10.0", .effect = .now, .field = "psi_threshold", .used = pressure_on, .about = "The PSI \"some avg10\" level taken as memory pressure, on Linux where it's available." },
    .{ .key = "JULIA_DAEMON_MEMFREE_LOW", .label = "pressure below", .tab = .memory, .depth = 2, .heading = "Free memory", .kind = .share, .default = "10%", .effect = .now, .field = "memfree_low", .used = pressure_on, .about = "Below this much free memory (bytes, or a percentage of it all), memory is under pressure." },
    .{ .key = "JULIA_DAEMON_MEMFREE_HIGH", .label = "eased above", .tab = .memory, .depth = 2, .kind = .share, .default = "15%", .effect = .now, .field = "memfree_high", .used = pressure_on, .about = "Above this much free memory, the pressure has eased." },
    .{ .key = "JULIA_DAEMON_SERVER", .label = "Server", .tab = .network, .kind = .text, .default = null, .unset = "a local socket", .effect = .restart, .about = "Where clients reach the conductor: a local socket's path, or tcp://host:port." },
    .{ .key = "JULIA_DAEMON_BIND", .label = "bind address", .tab = .network, .depth = 1, .kind = .text, .default = null, .unset = "the server's host", .effect = .restart, .used = tcp, .about = "The address the conductor and its workers listen on, such as 0.0.0.0." },
    .{ .key = "JULIA_DAEMON_PORTS", .label = "worker ports", .tab = .network, .depth = 1, .kind = .ports, .default = null, .unset = "any free", .effect = .restart, .used = tcp, .about = "The ports workers listen on for their clients, such as 10000-10100." },
    .{ .key = "JULIA_DAEMON_RUNTIME", .label = "Runtime directory", .tab = .network, .kind = .text, .default = null, .unset = "the platform's", .effect = .restart, .about = "Where the conductor keeps its sockets and pid file." },
    .{ .key = "JULIA_DAEMON_SANDBOX_REMOTE_CLIENTS", .label = "Sandbox remote clients", .tab = .sandbox, .kind = .flag, .default = "1", .effect = .now, .field = "sandbox_remote_clients", .about = "Run the clients of other hosts in a sandbox of their own." },
    .{ .key = "JULIA_DAEMON_SANDBOX_MAX_MEMORY", .label = "memory limit", .tab = .sandbox, .depth = 1, .kind = .bytes, .default = null, .unset = "none", .effect = .restart, .field = "sandbox_max_memory", .used = sandboxing, .about = "Each sandbox's memory limit. Limits need a delegated cgroup, as the installed service has." },
    .{ .key = "JULIA_DAEMON_SANDBOX_MAX_CPU", .label = "CPU limit", .tab = .sandbox, .depth = 1, .kind = .count, .default = null, .unset = "none", .effect = .restart, .field = "sandbox_max_cpu", .used = sandboxing, .about = "Each sandbox's CPU limit, as a percentage: 200 is two cores." },
    .{ .key = "JULIA_DAEMON_SANDBOX_SESSION_BYPASS", .label = "session bypass", .tab = .sandbox, .depth = 1, .kind = .flag, .default = "0", .effect = .now, .field = "sandbox_session_bypass", .used = sandboxing, .about = "Let a remote client's --session=<label> join a local, unsandboxed worker." },
};

const pressure_on: Use = .{ .check = struct {
    fn check(values: Values) bool {
        return isOn(resolved(values, Setting.index("JULIA_DAEMON_MEMORY_PRESSURE")));
    }
}.check, .reason = "unused while memory pressure is off" };

const tcp: Use = .{ .check = struct {
    fn check(values: Values) bool {
        const server = values[Setting.index("JULIA_DAEMON_SERVER")] orelse return false;
        const address = protocol.parseAddress(server) catch return false;
        return address.mode == .tcp;
    }
}.check, .reason = "unused but by a TCP server" };

const sandboxing: Use = .{ .check = struct {
    fn check(values: Values) bool {
        return isOn(resolved(values, Setting.index("JULIA_DAEMON_SANDBOX_REMOTE_CLIENTS")));
    }
}.check, .reason = "unused while remote clients aren't sandboxed" };

/// A setting's value, else its default, else empty.
pub fn resolved(values: Values, i: usize) []const u8 {
    return values[i] orelse all[i].default orelse "";
}

pub fn isOn(flag: []const u8) bool {
    return parseFlag(flag) orelse false;
}

pub const Invalid = error{Invalid};

/// What a person typed, in the variable's form, in `buf`; empty is unset.
pub fn normalise(s: *const Setting, input: []const u8, buf: []u8) Invalid!?[]const u8 {
    const text = std.mem.trim(u8, input, " \t");
    if (text.len == 0) return null;
    return try formOf(s.kind, text, buf);
}

fn formOf(kind: Kind, text: []const u8, buf: []u8) Invalid![]const u8 {
    return switch (kind) {
        .count => printed(buf, "{d}", .{std.fmt.parseInt(u64, text, 10) catch return error.Invalid}),
        .seconds => printed(buf, "{d}", .{try parseDuration(text)}),
        .bytes => blk: {
            const b = try parseBytes(text);
            break :blk printed(buf, "{d}{s}", .{ b.count, b.suffix });
        },
        .share => if (std.mem.endsWith(u8, text, "%"))
            printed(buf, "{s}%", .{try percentText(text[0 .. text.len - 1])})
        else blk: {
            const b = try parseBytes(text);
            break :blk printed(buf, "{d}{s}", .{ b.count, b.suffix });
        },
        .percent => printed(buf, "{s}", .{try percentText(std.mem.trimEnd(u8, text, "%"))}),
        .flag => if (parseFlag(text)) |on| (if (on) "1" else "0") else error.Invalid,
        .choice => |options| for (options) |option| {
            if (std.ascii.eqlIgnoreCase(option, text)) break option;
        } else error.Invalid,
        .threads => if (isThreads(text)) printed(buf, "{s}", .{text}) else error.Invalid,
        .ports => blk: {
            const range = parsePorts(text) orelse return error.Invalid;
            break :blk printed(buf, "{d}-{d}", .{ range[0], range[1] });
        },
        .text => printed(buf, "{s}", .{text}),
    };
}

/// What `normalise` takes, for a reason it gives none of.
pub fn expected(kind: Kind) []const u8 {
    return switch (kind) {
        .count => "a whole number",
        .seconds => "a duration, such as 90, 90s, 2m, 1h30m or 1d",
        .bytes => "a size, such as 512K, 1M or 4G",
        .share => "a percentage, such as 10%, or a size, such as 2G",
        .percent => "a percentage, such as 10 or 12.5%",
        .flag => "on or off",
        .choice => "one of its choices",
        .threads => "a count, auto, or two such as 4,1",
        .ports => "a range of at least four ports, such as 10000-10100, within 1024-65535",
        .text => "some text",
    };
}

/// A value as shown: a duration in its largest whole unit, a flag as on or
/// off. Unset, it is its default's, or `unset`.
pub fn display(s: *const Setting, value: ?[]const u8, buf: []u8) []const u8 {
    const text = value orelse s.default orelse return s.unset;
    return switch (s.kind) {
        .seconds => durationText(std.fmt.parseInt(u64, text, 10) catch return text, buf),
        .flag => if (parseFlag(text)) |on| (if (on) "on" else "off") else text,
        .percent => printed(buf, "{s}%", .{text}) catch text,
        else => text,
    };
}

/// A rule `values` break: a setting that must be positive, or two that must
/// be ordered.
pub const Conflict = union(enum) {
    positive: usize,
    ordered: struct { below: usize, above: usize },

    /// The settings it involves.
    pub fn involves(self: Conflict, i: usize) bool {
        return switch (self) {
            .positive => |p| p == i,
            .ordered => |o| o.below == i or o.above == i,
        };
    }
};

pub fn conflict(values: Values) ?Conflict {
    const min = Setting.index("JULIA_DAEMON_MIN_TTL");
    const max = Setting.index("JULIA_DAEMON_MAX_TTL");
    const ttl_min = std.fmt.parseInt(u64, resolved(values, min), 10) catch 0;
    const ttl_max = std.fmt.parseInt(u64, resolved(values, max), 10) catch 0;
    if (ttl_min == 0) return .{ .positive = min };
    if (ttl_min >= ttl_max) return .{ .ordered = .{ .below = min, .above = max } };
    const low = Setting.index("JULIA_DAEMON_MEMFREE_LOW");
    const high = Setting.index("JULIA_DAEMON_MEMFREE_HIGH");
    const free_low = parseShare(resolved(values, low)) catch return null;
    const free_high = parseShare(resolved(values, high)) catch return null;
    if (!free_low.below(free_high)) return .{ .ordered = .{ .below = low, .above = high } };
    return null;
}

/// Each setting's value in `env`, a deprecated alias standing in for it.
pub fn fromEnv(env: *const std.process.Environ.Map) [all.len]?[]const u8 {
    var values: [all.len]?[]const u8 = undefined;
    for (&all, &values) |s, *value| {
        value.* = env.get(s.key) orelse if (s.alias) |alias| env.get(alias) else null;
    }
    return values;
}

/// Free memory as a fraction of it all, or bytes.
pub const Share = union(enum) {
    fraction: f64,
    bytes: u64,

    pub fn satisfied(self: Share, avail: u64, total: u64) bool {
        return switch (self) {
            .fraction => |f| @as(f64, @floatFromInt(avail)) < f * @as(f64, @floatFromInt(total)),
            .bytes => |b| avail < b,
        };
    }

    /// A fraction and bytes can't be compared without the total, so pass.
    pub fn below(self: Share, other: Share) bool {
        return switch (self) {
            .fraction => |f| switch (other) {
                .fraction => |g| f < g,
                .bytes => true,
            },
            .bytes => |b| switch (other) {
                .bytes => |c| b < c,
                .fraction => true,
            },
        };
    }
};

// --- Parsing a variable's form ---

pub fn parseShare(text: []const u8) Invalid!Share {
    if (std.mem.endsWith(u8, text, "%")) {
        const pct = std.fmt.parseFloat(f64, text[0 .. text.len - 1]) catch return error.Invalid;
        if (!(pct >= 0 and pct <= 100)) return error.Invalid;
        return .{ .fraction = pct / 100.0 };
    }
    const b = try parseBytes(text);
    return .{ .bytes = b.count * b.scale };
}

pub fn parseFlag(text: []const u8) ?bool {
    for ([_][]const u8{ "1", "yes", "true", "on" }) |word| if (std.ascii.eqlIgnoreCase(text, word)) return true;
    for ([_][]const u8{ "0", "no", "false", "off" }) |word| if (std.ascii.eqlIgnoreCase(text, word)) return false;
    return null;
}

/// At least four ports, a worker's set, within the unprivileged ones.
pub fn parsePorts(text: []const u8) ?[2]u16 {
    const dash = std.mem.indexOfScalar(u8, text, '-') orelse return null;
    const low = std.fmt.parseInt(u16, text[0..dash], 10) catch return null;
    const high = std.fmt.parseInt(u16, text[dash + 1 ..], 10) catch return null;
    if (low < 1024 or high < low +| 3) return null;
    return .{ low, high };
}

const Bytes = struct { count: u64, suffix: []const u8, scale: u64 };

fn parseBytes(text: []const u8) Invalid!Bytes {
    if (text.len == 0) return error.Invalid;
    const units = [_]struct { []const u8, u64 }{ .{ "K", 1 << 10 }, .{ "M", 1 << 20 }, .{ "G", 1 << 30 } };
    const last = std.ascii.toUpper(text[text.len - 1]);
    for (units) |unit| if (last == unit[0][0]) return .{
        .count = std.fmt.parseInt(u64, text[0 .. text.len - 1], 10) catch return error.Invalid,
        .suffix = unit[0],
        .scale = unit[1],
    };
    return .{ .count = std.fmt.parseInt(u64, text, 10) catch return error.Invalid, .suffix = "", .scale = 1 };
}

// "90", "90s", "2m", "1h30m", "1d".
fn parseDuration(text: []const u8) Invalid!u64 {
    var total: u64 = 0;
    var i: usize = 0;
    while (i < text.len) {
        const start = i;
        while (i < text.len and std.ascii.isDigit(text[i])) i += 1;
        if (i == start) return error.Invalid;
        const n = std.fmt.parseInt(u64, text[start..i], 10) catch return error.Invalid;
        const scale: u64 = if (i == text.len) 1 else switch (text[i]) {
            's' => 1,
            'm' => 60,
            'h' => 3600,
            'd' => 86400,
            else => return error.Invalid,
        };
        if (i < text.len) i += 1;
        total = std.math.add(u64, total, std.math.mul(u64, n, scale) catch return error.Invalid) catch return error.Invalid;
    }
    return total;
}

fn durationText(seconds: u64, buf: []u8) []const u8 {
    const units = [_]struct { u64, u8 }{ .{ 86400, 'd' }, .{ 3600, 'h' }, .{ 60, 'm' } };
    for (units) |unit| if (seconds > 0 and seconds % unit[0] == 0)
        return printed(buf, "{d}{c}", .{ seconds / unit[0], unit[1] }) catch "";
    return printed(buf, "{d}s", .{seconds}) catch "";
}

// A number, as typed, once it parses.
fn percentText(text: []const u8) Invalid![]const u8 {
    const pct = std.fmt.parseFloat(f64, text) catch return error.Invalid;
    if (!(pct >= 0 and pct <= 100)) return error.Invalid;
    return text;
}

fn isThreads(text: []const u8) bool {
    var parts = std.mem.splitScalar(u8, text, ',');
    var n: usize = 0;
    while (parts.next()) |part| : (n += 1) {
        const ok = std.mem.eql(u8, part, "auto") or (part.len > 0 and
            (std.fmt.parseInt(u16, part, 10) catch 0) > 0);
        if (!ok or n == 2) return false;
    }
    return true;
}

fn printed(buf: []u8, comptime fmt: []const u8, fmt_args: anytype) Invalid![]const u8 {
    return std.fmt.bufPrint(buf, fmt, fmt_args) catch error.Invalid;
}

test "typed values normalise to their variable's form" {
    var buf: [64]u8 = undefined;
    const cases = [_]struct { []const u8, []const u8, ?[]const u8 }{
        .{ "JULIA_DAEMON_MAX_TTL", "2h", "7200" },
        .{ "JULIA_DAEMON_MAX_TTL", "1h30m", "5400" },
        .{ "JULIA_DAEMON_MAX_TTL", " 90 ", "90" },
        .{ "JULIA_DAEMON_HISTORY_BYTES", "4m", "4M" },
        .{ "JULIA_DAEMON_MEMFREE_LOW", "8%", "8%" },
        .{ "JULIA_DAEMON_MEMFREE_LOW", "2g", "2G" },
        .{ "JULIA_DAEMON_PSI_THRESHOLD", "12.5%", "12.5" },
        .{ "JULIA_DAEMON_RESERVE_WORKER", "off", "0" },
        .{ "JULIA_DAEMON_RECORD", "Interactive", "interactive" },
        .{ "JULIA_NUM_THREADS", "4,1", "4,1" },
        .{ "JULIA_DAEMON_PORTS", "10000-10100", "10000-10100" },
        .{ "JULIA_DAEMON_SERVER", "", null },
    };
    inline for (cases) |case| {
        const got = try normalise(&all[Setting.index(case[0])], case[1], &buf);
        if (case[2]) |want| try std.testing.expectEqualStrings(want, got.?) else try std.testing.expect(got == null);
    }
}

test "what doesn't parse is invalid" {
    var buf: [64]u8 = undefined;
    const cases = [_]struct { []const u8, []const u8 }{
        .{ "JULIA_DAEMON_MAX_TTL", "2x" },
        .{ "JULIA_DAEMON_MAX_TTL", "h" },
        .{ "JULIA_DAEMON_MAX_TTL", "99999999999999999999d" },
        .{ "JULIA_DAEMON_WORKER_MAXCLIENTS", "-1" },
        .{ "JULIA_DAEMON_HISTORY_BYTES", "1T" },
        .{ "JULIA_DAEMON_MEMFREE_LOW", "120%" },
        .{ "JULIA_DAEMON_RESERVE_WORKER", "maybe" },
        .{ "JULIA_DAEMON_RECORD", "all" },
        .{ "JULIA_NUM_THREADS", "4,1,1" },
        .{ "JULIA_NUM_THREADS", "0" },
        .{ "JULIA_DAEMON_PORTS", "80-100" },
        .{ "JULIA_DAEMON_PORTS", "10000-10002" },
    };
    inline for (cases) |case|
        try std.testing.expectError(error.Invalid, normalise(&all[Setting.index(case[0])], case[1], &buf));
}

test "every default is valid, and displays as it normalises" {
    var buf: [64]u8 = undefined;
    var shown: [64]u8 = undefined;
    for (&all) |*s| {
        const default = s.default orelse continue;
        try std.testing.expectEqualStrings(default, (try normalise(s, default, &buf)).?);
        const text = display(s, default, &shown);
        try std.testing.expectEqualStrings(default, (try normalise(s, text, &buf)).?);
    }
}

test "display picks a duration's largest whole unit" {
    var buf: [16]u8 = undefined;
    const ttl = &all[Setting.index("JULIA_DAEMON_MAX_TTL")];
    try std.testing.expectEqualStrings("2h", display(ttl, "7200", &buf));
    try std.testing.expectEqualStrings("90s", display(ttl, "90", &buf));
    try std.testing.expectEqualStrings("1d", display(ttl, "86400", &buf));
    try std.testing.expectEqualStrings("0s", display(ttl, "0", &buf));
    const threads = &all[Setting.index("JULIA_NUM_THREADS")];
    try std.testing.expectEqualStrings("Julia's default", display(threads, null, &buf));
}

test "the TTLs and free-memory levels must stay ordered" {
    var values = [_]?[]const u8{null} ** all.len;
    try std.testing.expect(conflict(&values) == null);
    values[Setting.index("JULIA_DAEMON_MIN_TTL")] = "0";
    try std.testing.expectEqual(Setting.index("JULIA_DAEMON_MIN_TTL"), conflict(&values).?.positive);
    values[Setting.index("JULIA_DAEMON_MIN_TTL")] = "7200";
    const ttl = conflict(&values).?;
    try std.testing.expectEqual(Setting.index("JULIA_DAEMON_MIN_TTL"), ttl.ordered.below);
    values[Setting.index("JULIA_DAEMON_MAX_TTL")] = "7201";
    try std.testing.expect(conflict(&values) == null);
    values[Setting.index("JULIA_DAEMON_MEMFREE_HIGH")] = "5%";
    try std.testing.expectEqual(Setting.index("JULIA_DAEMON_MEMFREE_HIGH"), conflict(&values).?.ordered.above);
    values[Setting.index("JULIA_DAEMON_MEMFREE_HIGH")] = "4G"; // mixed: can't tell
    try std.testing.expect(conflict(&values) == null);
}

test "rows are used as the settings they hang on allow" {
    var values = [_]?[]const u8{null} ** all.len;
    const psi = all[Setting.index("JULIA_DAEMON_PSI_THRESHOLD")].used.?;
    const ports = all[Setting.index("JULIA_DAEMON_PORTS")].used.?;
    try std.testing.expect(psi.check(&values));
    try std.testing.expect(!ports.check(&values));
    values[Setting.index("JULIA_DAEMON_MEMORY_PRESSURE")] = "0";
    values[Setting.index("JULIA_DAEMON_SERVER")] = "tcp://localhost:9345";
    try std.testing.expect(!psi.check(&values));
    try std.testing.expect(ports.check(&values));
}
