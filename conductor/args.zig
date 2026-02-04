const std = @import("std");
const Allocator = std.mem.Allocator;
const SwitchList = std.array_list.AlignedManaged(Switch, null);

const short_to_long = std.StaticStringMap([]const u8).initComptime(.{
    .{ "-e", "--eval" },
    .{ "-E", "--print" },
    .{ "-L", "--load" },
});

const no_value_switches = std.StaticStringMap(void).initComptime(.{
    .{ "-i", {} },
    .{ "-v", {} },
    .{ "--version", {} },
    .{ "-h", {} },
    .{ "--help", {} },
    .{ "--restart", {} },
    .{ "-q", {} },
    .{ "--quiet", {} },
});

// Switches that take an optional value (only via --switch=value syntax)
const optional_value_switches = std.StaticStringMap(void).initComptime(.{
    .{ "--session", {} },
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
};

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
