// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0
//
// JULIACLIENT_DEBUG=1, in a debug build: each event the client handles, on
// stderr, timed. A release build has none of it.

const std = @import("std");
const builtin = @import("builtin");
const platform = @import("platform/main.zig");

pub const available = builtin.mode == .debug;

const preview_bytes = 48; // of a chunk, before it's cut short

var enabled = false;
var newline: []const u8 = "\n";
var start_ns: u64 = 0;
var last_ns: u64 = 0;

/// Logs from now on, if `env` sets JULIACLIENT_DEBUG to other than empty or 0.
pub fn init(env: []const [*:0]const u8) void {
    if (!available) return;
    for (env) |kv_z| {
        const value = std.mem.cutPrefix(u8, std.mem.span(kv_z), "JULIACLIENT_DEBUG=") orelse continue;
        enabled = value.len > 0 and !std.mem.eql(u8, value, "0");
    }
    if (!enabled) return;
    // A raw terminal moves down a line without returning.
    if (platform.isatty(platform.getStderrHandle())) newline = "\r\n";
    start_ns = platform.monotonicNs();
    last_ns = start_ns;
}

/// A line: milliseconds since `init`, and since the line before, then what.
pub fn event(comptime fmt: []const u8, args: anytype) void {
    if (!available or !enabled) return;
    const now = platform.monotonicNs();
    const ms = struct {
        fn of(ns: u64) f64 {
            return @as(f64, @floatFromInt(ns)) / std.time.ns_per_ms;
        }
    }.of;
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    w.print("[{d:>10.3} +{d:>8.3}] " ++ fmt, .{ ms(now - start_ns), ms(now - last_ns) } ++ args) catch {};
    w.writeAll(newline) catch {};
    last_ns = now;
    platform.writeFile(platform.getStderrHandle(), w.buffered());
}

/// `bytes`, quoted, its controls escaped, cut short past `preview_bytes`.
pub fn preview(bytes: []const u8) Preview {
    return .{ .bytes = bytes };
}

pub const Preview = struct {
    bytes: []const u8,

    pub fn format(self: Preview, w: *std.Io.Writer) std.Io.Writer.Error!void {
        const shown = self.bytes[0..@min(self.bytes.len, preview_bytes)];
        try w.writeByte('"');
        for (shown) |byte| switch (byte) {
            0x1b => try w.writeAll("\\e"),
            '\r' => try w.writeAll("\\r"),
            '\n' => try w.writeAll("\\n"),
            '\t' => try w.writeAll("\\t"),
            '"', '\\' => try w.print("\\{c}", .{byte}),
            0...0x08, 0x0b, 0x0c, 0x0e...0x1a, 0x1c...0x1f, 0x7f => try w.print("\\x{x:0>2}", .{byte}),
            else => try w.writeByte(byte),
        };
        try w.writeByte('"');
        if (shown.len < self.bytes.len) try w.writeAll("…");
    }
};

test "a preview escapes controls and cuts a long chunk short" {
    var buf: [128]u8 = undefined;
    const shown = try std.fmt.bufPrint(&buf, "{f}", .{preview("a\x1b[0K\r\n\x7f\"é")});
    try std.testing.expectEqualStrings("\"a\\e[0K\\r\\n\\x7f\\\"é\"", shown);
    const long = try std.fmt.bufPrint(&buf, "{f}", .{preview(&@as([60]u8, @splat('x')))});
    try std.testing.expectEqualStrings("\"" ++ @as([preview_bytes]u8, @splat('x')) ++ "\"…", long);
}
