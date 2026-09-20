// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0

const std = @import("std");
const Allocator = std.mem.Allocator;
const SwitchList = std.array_list.AlignedManaged(Switch, null);

const short_to_long = std.StaticStringMap([]const u8).initComptime(.{
    .{ "-e", "--eval" },
    .{ "-E", "--print" },
    .{ "-L", "--load" },
    .{ "-P", "--project" },
    .{ "-t", "--threads" },
});

const no_value_switches = std.StaticStringMap(void).initComptime(.{
    .{ "-i", {} },
    .{ "-v", {} },
    .{ "--version", {} },
    .{ "-h", {} },
    .{ "--help", {} },
    .{ "--restart", {} },
    .{ "--sync", {} },
    .{ "--sandbox", {} },
    .{ "-q", {} },
    .{ "--quiet", {} },
});

// Switches whose value may only be given as --switch=value; a following
// argument is the program file, as in `julia --project script.jl`.
const optional_value_switches = std.StaticStringMap(void).initComptime(.{
    .{ "--session", {} },
    .{ "--status", {} },
    .{ "--revise", {} },
    .{ "--project", {} },
    .{ "--code-coverage", {} },
    .{ "--track-allocation", {} },
    .{ "--debug-info", {} },
});

pub const Switch = struct {
    name: []const u8,
    value: []const u8,
};

pub const ParsedArgs = struct {
    julia_channel: ?[]const u8, // JuliaUp channel selector (e.g., "+1.10", "+release")
    switches: SwitchList,
    program_file: ?[]const u8,
    program_args: []const []const u8,

    pub fn deinit(self: *ParsedArgs) void {
        self.switches.deinit();
    }

    pub fn getSwitch(self: *const ParsedArgs, name: []const u8) ?[]const u8 {
        var result: ?[]const u8 = null;
        for (self.switches.items) |sw| {
            if (std.mem.eql(u8, sw.name, name)) result = sw.value;
        }
        return result;
    }

    pub fn hasSwitch(self: *const ParsedArgs, name: []const u8) bool {
        for (self.switches.items) |sw| {
            if (std.mem.eql(u8, sw.name, name)) return true;
        }
        return false;
    }

    /// The effective `--threads`/`-t` spec, or `threads_unset` if absent/empty.
    pub fn threadSwitch(self: *const ParsedArgs) Threads {
        return parseThreads(self.getSwitch("--threads") orelse "");
    }
};

/// A Julia `--threads` spec as (default pool, interactive pool) counts.
///
/// Julia fixes thread counts at process startup, so this becomes part of a
/// worker's identity: a client can only reuse a worker spawned with the same
/// spec. Sentinels per field: `0` = unset (Julia default), `0xffff` = `auto`.
/// A `[2]u16` compares directly and is cheap to use as a map key.
pub const Threads = [2]u16;
pub const threads_unset: u16 = 0;
pub const threads_auto: u16 = 0xffff;
pub const threads_none = Threads{ threads_unset, threads_unset };

/// A single comparable value identifying a spec, for embedding in pool keys.
pub fn packThreads(spec: Threads) u32 {
    return (@as(u32, spec[0]) << 16) | spec[1];
}

/// Parse a `--threads` value (`N`, `auto`, `N,M`, `auto,M`). Unrecognised
/// fields fall back to `auto`, leaving the final verdict to Julia at startup.
pub fn parseThreads(value: []const u8) Threads {
    if (value.len == 0) return threads_none;
    const comma = std.mem.indexOfScalar(u8, value, ',');
    const default = if (comma) |c| value[0..c] else value;
    const interactive = if (comma) |c| value[c + 1 ..] else "";
    return .{ parseThreadField(default), parseThreadField(interactive) };
}

fn parseThreadField(field: []const u8) u16 {
    if (field.len == 0) return threads_unset;
    if (std.mem.eql(u8, field, "auto")) return threads_auto;
    return std.fmt.parseInt(u16, field, 10) catch threads_auto;
}

/// Render a spec as a `--threads` value (`3`, `auto`, `4,1`), or null when
/// unset. Caller owns the result.
pub fn renderThreads(allocator: Allocator, spec: Threads) !?[]const u8 {
    if (spec[0] == threads_unset and spec[1] == threads_unset) return null;
    // A u16 is at most 5 digits; "65535,65535" fits comfortably.
    var buf: [16]u8 = undefined;
    var d_buf: [8]u8 = undefined;
    const default = threadField(&d_buf, spec[0]);
    const rendered = if (spec[1] == threads_unset)
        default
    else blk: {
        var i_buf: [8]u8 = undefined;
        break :blk try std.fmt.bufPrint(&buf, "{s},{s}", .{ default, threadField(&i_buf, spec[1]) });
    };
    return try allocator.dupe(u8, rendered);
}

/// Format one field into `buf` as `auto` or a decimal count.
fn threadField(buf: []u8, val: u16) []const u8 {
    if (val == threads_auto or val == threads_unset) return "auto";
    return std.fmt.bufPrint(buf, "{d}", .{val}) catch unreachable;
}

pub fn parse(allocator: Allocator, input_args: []const []const u8) !ParsedArgs {
    var switches = SwitchList.init(allocator);
    errdefer switches.deinit();
    var seen_double_dash = false;
    var program_file: ?[]const u8 = null;
    var i: usize = 1;
    // Check for JuliaUp channel selector as first argument (e.g., "+1.10")
    var julia_channel: ?[]const u8 = null;
    if (i < input_args.len and input_args[i].len > 0 and input_args[i][0] == '+') {
        julia_channel = input_args[i];
        i += 1;
    }
    const args = input_args;
    while (i < args.len and program_file == null) {
        const arg = args[i];
        i += 1;
        if (std.mem.eql(u8, arg, "--")) {
            seen_double_dash = true;
        } else if (seen_double_dash) {
            program_file = arg;
        } else if (std.mem.startsWith(u8, arg, "--")) {
            if (std.mem.indexOf(u8, arg, "=")) |eq_pos| {
                try switches.append(.{ .name = arg[0..eq_pos], .value = arg[eq_pos + 1 ..] });
            } else if (no_value_switches.has(arg)) {
                try switches.append(.{ .name = arg, .value = "" });
            } else if (optional_value_switches.has(arg)) {
                // Optional value switches: --switch or --switch=value (no space-separated value)
                try switches.append(.{ .name = arg, .value = "" });
            } else {
                const value = if (i < args.len) blk: {
                    const v = args[i];
                    i += 1;
                    break :blk v;
                } else "";
                try switches.append(.{ .name = arg, .value = value });
            }
        } else if (arg.len > 1 and arg[0] == '-') {
            const short = arg[0..2];
            const name = short_to_long.get(short) orelse short;
            if (no_value_switches.has(name)) {
                try switches.append(.{ .name = name, .value = "" });
            } else {
                const value = if (arg.len > 2)
                    arg[2..]
                else if (i < args.len) blk: {
                    const v = args[i];
                    i += 1;
                    break :blk v;
                } else "";
                try switches.append(.{ .name = name, .value = value });
            }
        } else {
            program_file = arg;
        }
    }
    return .{
        .julia_channel = julia_channel,
        .switches = switches,
        .program_file = program_file,
        .program_args = args[i..],
    };
}
