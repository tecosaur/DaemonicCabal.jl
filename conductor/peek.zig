// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0
//
// A worker's stack snapshot, as Julia's runtime writes it to stderr on
// SIGUSR1 (SIGINFO on BSD and macOS): a banner, each thread's stack, then,
// once its profile is sampled, a closing banner. The profile's report comes
// separately, from the worker (`peek_report`).

const std = @import("std");

pub const max_stack_bytes = 64 << 10;
const max_line_bytes = 4 << 10;

/// Picks the stacks out of a stream of stderr, passing everything through.
pub const Scanner = struct {
    line: std.ArrayList(u8) = .empty,
    stacks: std.ArrayList(u8) = .empty,
    capturing: bool = false,
    ready: bool = false, // `stacks` holds a whole snapshot, for `take`

    pub fn deinit(self: *Scanner, gpa: std.mem.Allocator) void {
        self.line.deinit(gpa);
        self.stacks.deinit(gpa);
    }

    pub fn feed(self: *Scanner, gpa: std.mem.Allocator, bytes: []const u8) void {
        var rest = bytes;
        while (std.mem.indexOfScalar(u8, rest, '\n')) |nl| {
            self.appendLine(gpa, rest[0..nl]);
            self.endLine(gpa);
            rest = rest[nl + 1 ..];
        }
        self.appendLine(gpa, rest);
    }

    /// The snapshot's stacks, once `ready`; the caller owns them.
    pub fn take(self: *Scanner, gpa: std.mem.Allocator) ?[]u8 {
        if (!self.ready) return null;
        self.ready = false;
        return self.stacks.toOwnedSlice(gpa) catch null;
    }

    fn appendLine(self: *Scanner, gpa: std.mem.Allocator, bytes: []const u8) void {
        const room = max_line_bytes -| self.line.items.len;
        self.line.appendSlice(gpa, bytes[0..@min(room, bytes.len)]) catch {};
    }

    fn endLine(self: *Scanner, gpa: std.mem.Allocator) void {
        defer self.line.clearRetainingCapacity();
        const line = std.mem.trimEnd(u8, self.line.items, "\r");
        if (std.mem.startsWith(u8, line, "Information request received")) {
            self.stacks.clearRetainingCapacity();
            self.capturing = true;
            self.ready = false;
            return;
        }
        if (!self.capturing) return;
        if (std.mem.startsWith(u8, line, "Profile collected")) {
            self.capturing = false;
            while (self.stacks.items.len > 0 and endsInFiller(self.stacks.items))
                self.stacks.shrinkRetainingCapacity(lastLineStart(self.stacks.items));
            self.ready = true;
            return;
        }
        const filler = line.len == 0 and self.stacks.items.len == 0 or
            std.mem.startsWith(u8, line, "====") or std.mem.startsWith(u8, line, "--trace-compile") or
            std.mem.startsWith(u8, line, "precompile(");
        if (filler or self.stacks.items.len + line.len + 1 > max_stack_bytes) return;
        self.stacks.appendSlice(gpa, line) catch return;
        self.stacks.append(gpa, '\n') catch {};
    }
};

// The banner's rule and the blank lines around it.
fn endsInFiller(text: []const u8) bool {
    const last = text[lastLineStart(text)..];
    const line = std.mem.trimEnd(u8, last, "\n");
    return line.len == 0 or std.mem.startsWith(u8, line, "====");
}

fn lastLineStart(text: []const u8) usize {
    const body = if (text.len > 0 and text[text.len - 1] == '\n') text[0 .. text.len - 1] else text;
    return if (std.mem.lastIndexOfScalar(u8, body, '\n')) |i| i + 1 else 0;
}

/// A readable digest of `stacks`: each busy thread's Julia frames, up to
/// `max_frames`, down to where the worker's own code runs the client's, then
/// a count of the threads waiting for work. Lines are slices of `stacks`, or
/// static text, appended to `out`.
pub fn digest(gpa: std.mem.Allocator, stacks: []const u8, max_frames: usize, out: *std.ArrayList([]const u8)) !void {
    var idle: usize = 0;
    var busy: usize = 0;
    var blocks = std.mem.splitSequence(u8, stacks, "unknown function (ip: (nil))");
    while (blocks.next()) |block| {
        if (isIdle(block)) {
            idle += 1;
            continue;
        }
        if (std.mem.indexOf(u8, block, ".jl:") == null) continue; // no thread's stack
        if (busy > 0) try out.append(gpa, "");
        busy += 1;
        try out.append(gpa, "A running thread:");
        var lines = std.mem.splitScalar(u8, block, '\n');
        var frames: usize = 0;
        while (lines.next()) |line| {
            if (!isJuliaFrame(line)) continue;
            if (std.mem.indexOf(u8, line, worker_source) != null or frames == max_frames) break;
            try out.append(gpa, line);
            frames += 1;
        }
    }
    if (busy == 0) try out.append(gpa, "No thread is running Julia code.");
    if (idle > 0) {
        try out.append(gpa, "");
        try out.append(gpa, if (idle == 1) "1 other thread is waiting for work." else "Other threads are waiting for work.");
    }
}

// Where DaemonWorker's source lies, below which a stack is its own.
const worker_source = "/worker/src/";

// Waiting in the scheduler, collecting garbage, or the profile's listener.
fn isIdle(block: []const u8) bool {
    for ([_][]const u8{ "jl_task_get_next", "jl_parallel_gc_threadfun", "jl_concurrent_gc_threadfun", "profile_printing_listener", "jl_gc_mark_threadfun" }) |mark| {
        if (std.mem.indexOf(u8, block, mark) != null) return true;
    }
    return false;
}

// "sin at ./math.jl:1332 [inlined]", not a C frame of the runtime.
fn isJuliaFrame(line: []const u8) bool {
    const at = std.mem.indexOf(u8, line, " at ") orelse return false;
    const where = line[at + 4 ..];
    return std.mem.indexOf(u8, where, ".jl:") != null;
}

test "the scanner keeps the stacks between the banners" {
    const gpa = std.testing.allocator;
    var scanner = Scanner{};
    defer scanner.deinit(gpa);
    const stderr_text =
        \\a log line
        \\======================================================================================
        \\Information request received. A stacktrace will print followed by a 1.0 second profile.
        \\--trace-compile is enabled during profile collection.
        \\======================================================================================
        \\
        \\cmd: julia 305572 running 1 of 1
        \\
        \\signal (10): User defined signal 1
        \\spin at /tmp/spin.jl:15
        \\precompile(Tuple{typeof(sin), Float64})
        \\unknown function (ip: (nil)) at (unknown file)
        \\
        \\
        \\==============================================================
        \\Profile collected. A report will print at the next yield point.
        \\
    ;
    // In awkward pieces, as a pipe may deliver it.
    var i: usize = 0;
    while (i < stderr_text.len) : (i += 7) scanner.feed(gpa, stderr_text[i..@min(i + 7, stderr_text.len)]);
    const stacks = scanner.take(gpa).?;
    defer gpa.free(stacks);
    try std.testing.expectEqualStrings(
        \\cmd: julia 305572 running 1 of 1
        \\
        \\signal (10): User defined signal 1
        \\spin at /tmp/spin.jl:15
        \\unknown function (ip: (nil)) at (unknown file)
        \\
    , stacks);
    try std.testing.expect(scanner.take(gpa) == null);
}

test "a digest leads with the running threads' Julia frames" {
    const gpa = std.testing.allocator;
    const stacks =
        \\signal (10): User defined signal 1
        \\pthread_cond_wait at /lib64/libc.so.6 (unknown line)
        \\ijl_task_get_next at /src/scheduler.c:599
        \\wait at ./task.jl:1296
        \\unknown function (ip: (nil)) at (unknown file)
        \\sin at ./math.jl:1332 [inlined]
        \\spin at /tmp/spin.jl:15
        \\jl_apply at /src/julia.h:2318 [inlined]
        \\eval at ./boot.jl:489
        \\runclient at /dev/DaemonicCabal/worker/src/run.jl:345 [inlined]
        \\unknown function (ip: (nil)) at (unknown file)
        \\
    ;
    var lines: std.ArrayList([]const u8) = .empty;
    defer lines.deinit(gpa);
    try digest(gpa, stacks, 8, &lines);
    const expected = [_][]const u8{
        "A running thread:",
        "sin at ./math.jl:1332 [inlined]",
        "spin at /tmp/spin.jl:15",
        "eval at ./boot.jl:489",
        "",
        "1 other thread is waiting for work.",
    };
    try std.testing.expectEqual(expected.len, lines.items.len);
    for (expected, lines.items) |want, got| try std.testing.expectEqualStrings(want, got);
}
