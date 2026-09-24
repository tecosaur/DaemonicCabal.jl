// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0

const std = @import("std");
const Allocator = std.mem.Allocator;
const SwitchList = std.array_list.AlignedManaged(Switch, null);

const short_to_long = std.StaticStringMap([]const u8).initComptime(.{
    .{ "-a", "--address" },
    .{ "-e", "--eval" },
    .{ "-E", "--print" },
    .{ "-g", "--debug-info" },
    .{ "-L", "--load" },
    .{ "-O", "--optimize" },
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

// Only --switch=value (or -Xvalue): in `julia --project script.jl` the next
// word is the program.
const optional_value_switches = std.StaticStringMap(void).initComptime(.{
    .{ "--session", {} },
    .{ "--status", {} },
    .{ "--revise", {} },
    .{ "--project", {} },
    .{ "--code-coverage", {} },
    .{ "--track-allocation", {} },
    .{ "--debug-info", {} },
    .{ "--optimize", {} },
});

// Every other switch only applies as Julia starts, which a reused worker
// has done already. A value given here is the only one honoured.
const honoured_switches = std.StaticStringMap(?[]const u8).initComptime(.{
    .{ "--address", null },     .{ "--help", null },     .{ "-h", null },
    .{ "--version", null },     .{ "-v", null },         .{ "--status", null },
    .{ "--restart", null },     .{ "--sandbox", null },  .{ "--session", null },
    .{ "--sync", null },        .{ "--project", null },  .{ "--threads", null },
    .{ "--revise", null },      .{ "--eval", null },     .{ "--print", null },
    .{ "--load", null },        .{ "-i", null },         .{ "-q", null },
    .{ "--quiet", null },       .{ "--banner", null },   .{ "--color", null },
    .{ "--history-file", null }, .{ "--startup-file", "no" },
});

pub const Switch = struct {
    name: []const u8,
    value: []const u8,
    /// The argv words it occupies: `words` of them from `index`.
    index: usize,
    words: usize,

    pub fn isHonoured(self: Switch) bool {
        const only = honoured_switches.get(self.name) orelse return false;
        return only == null or std.mem.eql(u8, only.?, self.value);
    }
};

pub const ParsedArgs = struct {
    julia_channel: ?[]const u8, // JuliaUp's "+1.10"
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

    pub fn threadSwitch(self: *const ParsedArgs) Threads {
        return parseThreads(self.getSwitch("--threads") orelse "");
    }
};

/// (default pool, interactive pool) counts. Julia fixes these at startup, so
/// they are part of a worker's identity.
pub const Threads = [2]u16;
pub const threads_unset: u16 = 0;
pub const threads_auto: u16 = 0xffff;
pub const threads_none = Threads{ threads_unset, threads_unset };

pub fn packThreads(spec: Threads) u32 {
    return (@as(u32, spec[0]) << 16) | spec[1];
}

/// Unrecognised fields fall back to `auto`, leaving the verdict to Julia.
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

/// Null when unset.
pub fn renderThreads(allocator: Allocator, spec: Threads) !?[]const u8 {
    if (spec[0] == threads_unset and spec[1] == threads_unset) return null;
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
    var julia_channel: ?[]const u8 = null;
    if (i < input_args.len and input_args[i].len > 0 and input_args[i][0] == '+') {
        julia_channel = input_args[i];
        i += 1;
    }
    const args = input_args;
    while (i < args.len and program_file == null) {
        const index = i;
        const arg = args[i];
        i += 1;
        if (std.mem.eql(u8, arg, "--")) {
            seen_double_dash = true;
            continue;
        }
        if (seen_double_dash or arg.len < 2 or arg[0] != '-') {
            // After -e or -E, as in Julia, every positional is an ARG.
            const evaluates = for (switches.items) |sw| {
                if (std.mem.eql(u8, sw.name, "--eval") or std.mem.eql(u8, sw.name, "--print")) break true;
            } else false;
            if (evaluates) {
                i = index;
                break;
            }
            program_file = arg;
            continue;
        }
        const Named = struct { name: []const u8, value: []const u8 };
        const named: Named = if (std.mem.startsWith(u8, arg, "--")) blk: {
            if (std.mem.indexOf(u8, arg, "=")) |eq_pos|
                break :blk .{ .name = arg[0..eq_pos], .value = arg[eq_pos + 1 ..] };
            if (no_value_switches.has(arg) or optional_value_switches.has(arg))
                break :blk .{ .name = arg, .value = "" };
            break :blk .{ .name = arg, .value = takeValue(args, &i) };
        } else blk: {
            const short = arg[0..2];
            const name = short_to_long.get(short) orelse short;
            if (no_value_switches.has(name) or (arg.len == 2 and optional_value_switches.has(name)))
                break :blk .{ .name = name, .value = "" };
            break :blk .{ .name = name, .value = if (arg.len > 2) arg[2..] else takeValue(args, &i) };
        };
        try switches.append(.{ .name = named.name, .value = named.value, .index = index, .words = i - index });
    }
    return .{
        .julia_channel = julia_channel,
        .switches = switches,
        .program_file = program_file,
        .program_args = args[i..],
    };
}

/// The next word as a switch's value, or "" at the end of argv.
fn takeValue(args: []const []const u8, i: *usize) []const u8 {
    if (i.* == args.len) return "";
    defer i.* += 1;
    return args[i.*];
}
