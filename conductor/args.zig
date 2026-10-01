// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0

//! Julia's command line, parsed as its `jl_parse_opts` does with
//! `getopt_long` (shortopts "+vhqH:e:E:L:J:C:it:p:O:g:m:P:"): options stop at
//! the first positional or `--`, short options bundle, long ones may be
//! abbreviated to any unique prefix, and a required value may be the next word.

const std = @import("std");
const Allocator = std.mem.Allocator;
const SwitchList = std.array_list.AlignedManaged(Switch, null);

const Arity = enum { none, required, optional };

/// Whether a reused worker, its Julia started already, can act on a switch.
const Honour = enum { never, always, only_as_no };

const Option = struct {
    long: []const u8,
    short: ?u8 = null,
    /// Of the long form: a short one takes a value as `required` does, save
    /// that one missing at the end of the line leaves an `optional` one bare.
    arity: Arity,
    honoured: Honour = .never,
    /// `|`-separated values checked as Julia would.
    choices: ?[]const u8 = null,
    /// Parsing ends here: `-m` takes the rest as ARGS, and Julia exits at once
    /// after `-h` or `-v`.
    stops: bool = false,
    needs_own_julia: bool = false,
    /// The client's, not Julia's: an abbreviation is of Julia's first.
    own: bool = false,
    /// An optional value left bare, as Julia takes it.
    bare: []const u8 = "",

    pub fn format(self: *const Option, w: *std.Io.Writer) std.Io.Writer.Error!void {
        if (self.short) |c| try w.print("-{c}/", .{c});
        try w.writeAll(self.long);
    }
};

// Julia's (the union of 1.10's onwards, which only ever gained options), then
// the client's own.
const options = [_]Option{
    .{ .long = "--version", .short = 'v', .arity = .none, .honoured = .always, .stops = true },
    .{ .long = "--help", .short = 'h', .arity = .none, .honoured = .always, .stops = true },
    .{ .long = "--help-hidden", .arity = .none, .honoured = .always, .stops = true },
    .{ .long = "--interactive", .short = 'i', .arity = .none, .honoured = .always },
    .{ .long = "--quiet", .short = 'q', .arity = .none, .honoured = .always },
    .{ .long = "--banner", .arity = .required, .honoured = .always, .choices = "yes|no|auto|short" },
    .{ .long = "--home", .short = 'H', .arity = .required },
    .{ .long = "--eval", .short = 'e', .arity = .required, .honoured = .always },
    .{ .long = "--module", .short = 'm', .arity = .required, .honoured = .always, .stops = true },
    .{ .long = "--print", .short = 'E', .arity = .required, .honoured = .always },
    .{ .long = "--load", .short = 'L', .arity = .required, .honoured = .always },
    .{ .long = "--bug-report", .arity = .required, .needs_own_julia = true },
    .{ .long = "--sysimage", .short = 'J', .arity = .required },
    .{ .long = "--sysimage-native-code", .arity = .required },
    .{ .long = "--compiled-modules", .arity = .required },
    .{ .long = "--pkgimages", .arity = .required },
    .{ .long = "--cpu-target", .short = 'C', .arity = .required },
    .{ .long = "--procs", .short = 'p', .arity = .required },
    .{ .long = "--threads", .short = 't', .arity = .required, .honoured = .always },
    .{ .long = "--gcthreads", .arity = .required },
    .{ .long = "--machine-file", .arity = .required },
    .{ .long = "--project", .short = 'P', .arity = .optional, .honoured = .always, .bare = "@." },
    .{ .long = "--color", .arity = .required, .honoured = .always, .choices = "yes|no|auto" },
    .{ .long = "--history-file", .arity = .required, .honoured = .always, .choices = "yes|no" },
    .{ .long = "--startup-file", .arity = .required, .honoured = .only_as_no, .choices = "yes|no" },
    .{ .long = "--compile", .arity = .required },
    .{ .long = "--code-coverage", .arity = .optional },
    .{ .long = "--code-coverage-mode", .arity = .required },
    .{ .long = "--track-allocation", .arity = .optional },
    .{ .long = "--optimize", .short = 'O', .arity = .optional, .choices = "0|1|2|3" },
    .{ .long = "--min-optlevel", .arity = .optional },
    .{ .long = "--debug-info", .short = 'g', .arity = .optional, .choices = "0|1|2" },
    .{ .long = "--check-bounds", .arity = .required },
    .{ .long = "--output-bc", .arity = .required },
    .{ .long = "--output-unopt-bc", .arity = .required },
    .{ .long = "--output-o", .arity = .required },
    .{ .long = "--output-asm", .arity = .required },
    .{ .long = "--output-ji", .arity = .required },
    .{ .long = "--output-incremental", .arity = .required },
    .{ .long = "--depwarn", .arity = .required },
    .{ .long = "--warn-overwrite", .arity = .required },
    .{ .long = "--warn-scope", .arity = .required },
    .{ .long = "--inline", .arity = .required },
    .{ .long = "--polly", .arity = .required },
    .{ .long = "--timeout-for-safepoint-straggler", .arity = .required },
    .{ .long = "--trace-compile", .arity = .required },
    .{ .long = "--trace-compile-timing", .arity = .none },
    .{ .long = "--trace-dispatch", .arity = .required },
    .{ .long = "--task-metrics", .arity = .required },
    .{ .long = "--math-mode", .arity = .required },
    .{ .long = "--handle-signals", .arity = .required },
    .{ .long = "--experimental", .arity = .none },
    .{ .long = "--worker", .arity = .optional },
    .{ .long = "--bind-to", .arity = .required },
    .{ .long = "--lisp", .arity = .none, .needs_own_julia = true },
    .{ .long = "--image-codegen", .arity = .none },
    .{ .long = "--rr-detach", .arity = .none },
    .{ .long = "--strip-metadata", .arity = .none },
    .{ .long = "--strip-ir", .arity = .none },
    .{ .long = "--permalloc-pkgimg", .arity = .required },
    .{ .long = "--heap-size-hint", .arity = .required },
    .{ .long = "--hard-heap-limit", .arity = .required },
    .{ .long = "--heap-target-increment", .arity = .required },
    .{ .long = "--gc-sweep-always-full", .arity = .none },
    .{ .long = "--trim", .arity = .optional },
    .{ .long = "--compress-sysimage", .arity = .required },
    .{ .long = "--trace-eval", .arity = .optional },
    .{ .long = "--target-sanitize", .arity = .required },
    .{ .long = "--address", .short = 'a', .arity = .required, .honoured = .always, .own = true },
    .{ .long = "--session", .arity = .optional, .honoured = .always, .own = true },
    .{ .long = "--sync", .arity = .optional, .honoured = .always, .own = true },
    .{ .long = "--status", .arity = .optional, .honoured = .always, .own = true },
    .{ .long = "--watch", .arity = .optional, .honoured = .always, .own = true },
    .{ .long = "--revise", .arity = .optional, .honoured = .always, .own = true },
    .{ .long = "--restart", .arity = .none, .honoured = .always, .own = true },
    .{ .long = "--reconfigure", .arity = .none, .honoured = .always, .own = true },
    .{ .long = "--sandbox", .arity = .none, .honoured = .always, .own = true },
};

pub const Switch = struct {
    /// Its long form (`--eval` for `-e`).
    name: []const u8,
    value: []const u8,
    /// The argv words it occupies: `words` of them from `index`, which a
    /// bundle's switches (`-qe code`) share.
    index: usize,
    words: usize,

    pub fn isHonoured(self: Switch) bool {
        const option = for (&options) |*option| {
            if (std.mem.eql(u8, option.long, self.name)) break option;
        } else return false;
        return switch (option.honoured) {
            .never => false,
            .always => true,
            .only_as_no => std.mem.eql(u8, self.value, "no"),
        };
    }
};

/// Why Julia would refuse the command line, in its words (printed after
/// `ERROR: `, exiting 1).
pub const Problem = union(enum) {
    unknown: []const u8,
    unknown_short: u8,
    missing_value: *const Option,
    unexpected_value: *const Option,
    invalid_value: struct { option: *const Option, value: []const u8 },
    needs_own_julia: *const Option,

    pub fn format(self: Problem, w: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (self) {
            .unknown => |word| try w.print("unknown option `{s}`", .{word}),
            .unknown_short => |c| try w.print("unknown option `-{c}`", .{c}),
            .missing_value => |option| try w.print("option `{f}` is missing an argument", .{option}),
            .unexpected_value => |option| try w.print("option `{f}` does not accept an argument", .{option}),
            .invalid_value => |invalid| if (invalid.option.short) |c|
                try w.print("julia: invalid argument to -{c} ({s})", .{ c, invalid.value })
            else
                try w.print("julia: invalid argument to {s}={{{s}}} ({s})", .{ invalid.option.long, invalid.option.choices.?, invalid.value }),
            .needs_own_julia => |option| try w.print("option `{s}` needs a Julia process of its own: run it with `julia`", .{option.long}),
        }
    }
};

pub const ParsedArgs = struct {
    julia_channel: ?[]const u8, // JuliaUp's "+1.10"
    /// In argv order, repeats included.
    switches: SwitchList,
    program_file: ?[]const u8,
    program_args: []const []const u8,

    pub fn deinit(self: *ParsedArgs) void {
        self.switches.deinit();
    }

    /// The last occurrence's value, as Julia takes.
    pub fn getSwitch(self: *const ParsedArgs, name: []const u8) ?[]const u8 {
        var result: ?[]const u8 = null;
        for (self.switches.items) |sw| {
            if (std.mem.eql(u8, sw.name, name)) result = sw.value;
        }
        return result;
    }

    pub fn hasSwitch(self: *const ParsedArgs, name: []const u8) bool {
        return self.getSwitch(name) != null;
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
    const default, const interactive = std.mem.cutScalar(u8, value, ',') orelse .{ value, "" };
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
    var d_buf: [8]u8 = undefined;
    var i_buf: [8]u8 = undefined;
    const default = threadField(&d_buf, spec[0]);
    if (spec[1] == threads_unset) return try allocator.dupe(u8, default);
    return try std.fmt.allocPrint(allocator, "{s},{s}", .{ default, threadField(&i_buf, spec[1]) });
}

fn threadField(buf: []u8, val: u16) []const u8 {
    if (val == threads_auto or val == threads_unset) return "auto";
    return std.fmt.bufPrint(buf, "{d}", .{val}) catch unreachable;
}

pub const Error = Allocator.Error || error{InvalidArguments};

/// As `parseReporting`, where why a command line is refused isn't wanted.
pub fn parse(allocator: Allocator, argv: []const []const u8) Error!ParsedArgs {
    var problem: Problem = undefined;
    return parseReporting(allocator, argv, &problem);
}

/// Split `argv` (the executable first) into switches, program file and ARGS.
/// On `error.InvalidArguments`, `problem` holds why.
pub fn parseReporting(allocator: Allocator, argv: []const []const u8, problem: *Problem) Error!ParsedArgs {
    const julia_channel: ?[]const u8 = if (argv.len > 1 and argv[1].len > 0 and argv[1][0] == '+') argv[1] else null;
    var switches = SwitchList.init(allocator);
    errdefer switches.deinit();
    const scan = try scanSwitches(&switches, argv, if (julia_channel == null) 1 else 2);
    const rest = switch (scan) {
        .invalid => |why| {
            problem.* = why;
            return error.InvalidArguments;
        },
        .positionals, .stopped => |at| at,
    };
    var parsed: ParsedArgs = .{
        .julia_channel = julia_channel,
        .switches = switches,
        .program_file = null,
        .program_args = argv[rest..],
    };
    // After -e or -E, as in Julia, every positional is an ARG.
    if (scan == .positionals and rest < argv.len and !parsed.hasSwitch("--eval") and !parsed.hasSwitch("--print")) {
        parsed.program_file = argv[rest];
        parsed.program_args = argv[rest + 1 ..];
    }
    return parsed;
}

const Scan = union(enum) {
    /// Where the positionals begin: the program file, unless -e or -E.
    positionals: usize,
    /// Where ARGS begin, a switch having ended the command line.
    stopped: usize,
    invalid: Problem,
};

fn scanSwitches(switches: *SwitchList, argv: []const []const u8, first: usize) Allocator.Error!Scan {
    var i = first;
    while (i < argv.len) {
        const arg = argv[i];
        if (std.mem.eql(u8, arg, "--")) return .{ .positionals = i + 1 };
        if (arg.len < 2 or arg[0] != '-') return .{ .positionals = i };
        const index = i;
        i += 1;
        if (arg[1] == '-') {
            const eq = std.mem.indexOfScalar(u8, arg, '=');
            const option = findLong(arg[0 .. eq orelse arg.len]) orelse return .{ .invalid = .{ .unknown = arg } };
            const value = if (eq) |e| blk: {
                if (option.arity == .none) return .{ .invalid = .{ .unexpected_value = option } };
                break :blk arg[e + 1 ..];
            } else if (option.arity != .required)
                option.bare
            else
                nextWord(argv, &i) orelse return .{ .invalid = .{ .missing_value = option } };
            if (try accept(switches, option, value, index, i)) |end| return end;
            continue;
        }
        for (arg[1..], 2..) |c, after| {
            const option = for (&options) |*option| {
                if (option.short == c) break option;
            } else return .{ .invalid = .{ .unknown_short = c } };
            const value = if (option.arity == .none)
                ""
            else if (after < arg.len)
                arg[after..]
            else
                nextWord(argv, &i) orelse if (option.arity == .optional) option.bare else return .{ .invalid = .{ .missing_value = option } };
            if (try accept(switches, option, value, index, i)) |end| return end;
            if (option.arity != .none) break;
        }
    }
    return .{ .positionals = i };
}

/// An exact match, else the only one of Julia's options `name` abbreviates,
/// else, abbreviating none of them, the only one of the client's.
fn findLong(name: []const u8) ?*const Option {
    for (&options) |*option| {
        if (std.mem.eql(u8, option.long, name)) return option;
    }
    for ([_]bool{ false, true }) |own| {
        var found: ?*const Option = null;
        for (&options) |*option| {
            if (option.own != own or !std.mem.startsWith(u8, option.long, name)) continue;
            if (found != null) return null;
            found = option;
        }
        if (found) |option| return option;
    }
    return null;
}

fn nextWord(argv: []const []const u8, i: *usize) ?[]const u8 {
    if (i.* == argv.len) return null;
    defer i.* += 1;
    return argv[i.*];
}

/// Records the switch, spanning `argv[index..end]`; the scan's end if Julia
/// would refuse it or stop there.
fn accept(switches: *SwitchList, option: *const Option, value: []const u8, index: usize, end: usize) Allocator.Error!?Scan {
    if (option.needs_own_julia) return .{ .invalid = .{ .needs_own_julia = option } };
    if (option.choices) |choices| if (value.len > 0 or option.arity != .optional) {
        var allowed = std.mem.splitScalar(u8, choices, '|');
        while (allowed.next()) |choice| {
            if (std.mem.eql(u8, choice, value)) break;
        } else return .{ .invalid = .{ .invalid_value = .{ .option = option, .value = value } } };
    };
    try switches.append(.{ .name = option.long, .value = value, .index = index, .words = end - index });
    return if (option.stops) .{ .stopped = end } else null;
}
