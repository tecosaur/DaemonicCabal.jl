// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0
//
// Terminal palette probe and OKLab gradients for `--status`, probed over the
// client's proxied stdio. A trailing CSI 5n bounds the read: every VT terminal
// answers it, in stream order.

const std = @import("std");

pub const Rgb = struct {
    r: u8,
    g: u8,
    b: u8,
    pub fn init(r: u8, g: u8, b: u8) Rgb {
        return .{ .r = r, .g = g, .b = b };
    }
};

pub const Palette = struct {
    foreground: ?Rgb = null, // OSC 10
    background: ?Rgb = null, // OSC 11
    ansi: [16]?Rgb = [_]?Rgb{null} ** 16, // OSC 4

    pub fn isPopulated(self: Palette) bool {
        if (self.foreground != null or self.background != null) return true;
        for (self.ansi) |c| if (c != null) return true;
        return false;
    }
};

// --- queries -----------------------------------------------------------------

pub const probed_slots = [_]u8{ 1, 2, 3, 4, 5, 6 };

/// The CSI 5n reply.
pub const sentinel = "\x1b[0n";

/// BEL-terminated: wider support than ST.
pub fn writeQueries(buf: *[query_buf_len]u8) []const u8 {
    var pos: usize = 0;
    for ([_][]const u8{ "\x1b]10;?\x07", "\x1b]11;?\x07" }) |q| {
        pos += (std.fmt.bufPrint(buf[pos..], "{s}", .{q}) catch unreachable).len;
    }
    for (probed_slots) |n| {
        pos += (std.fmt.bufPrint(buf[pos..], "\x1b]4;{d};?\x07", .{n}) catch unreachable).len;
    }
    pos += (std.fmt.bufPrint(buf[pos..], "\x1b[5n", .{}) catch unreachable).len;
    return buf[0..pos];
}

/// OSC 10/11 (7 each) + 6 × OSC 4 (≤10 each) + CSI 5n (4), rounded up.
pub const query_buf_len = 96;

// --- reply parsing -----------------------------------------------------------

/// Idempotent over re-scans of a growing buffer.
pub fn parse(bytes: []const u8, palette: *Palette) void {
    var i: usize = 0;
    while (i + 1 < bytes.len) {
        if (bytes[i] != 0x1b or bytes[i + 1] != ']') {
            i += 1;
            continue;
        }
        const body = bytes[i + 2 ..];
        var end = body.len;
        var skip: usize = 0;
        for (body, 0..) |b, j| {
            if (b == 0x07) {
                end, skip = .{ j, 1 };
            } else if (b == 0x1b and j + 1 < body.len and body[j + 1] == '\\') {
                end, skip = .{ j, 2 };
            } else continue;
            break;
        }
        consumeReply(body[0..end], palette);
        i += 2 + end + skip;
    }
}

fn consumeReply(body: []const u8, palette: *Palette) void {
    var parts = std.mem.splitScalar(u8, body, ';');
    const kind = parts.next() orelse return;
    if (std.mem.eql(u8, kind, "10")) {
        if (nextColor(&parts)) |rgb| palette.foreground = rgb;
    } else if (std.mem.eql(u8, kind, "11")) {
        if (nextColor(&parts)) |rgb| palette.background = rgb;
    } else if (std.mem.eql(u8, kind, "4")) {
        const idx = std.fmt.parseInt(usize, parts.next() orelse return, 10) catch return;
        if (idx < palette.ansi.len) {
            if (nextColor(&parts)) |rgb| palette.ansi[idx] = rgb;
        }
    }
}

fn nextColor(parts: *std.mem.SplitIterator(u8, .scalar)) ?Rgb {
    return parseXtermRgb(std.mem.trim(u8, parts.next() orelse return null, " "));
}

/// `rgb:R/G/B` or `rgba:R/G/B/A`, each channel 1–4 hex digits scaled by its
/// high nibble.
pub fn parseXtermRgb(s: []const u8) ?Rgb {
    const channels: usize, const body = if (std.mem.startsWith(u8, s, "rgb:"))
        .{ 3, s[4..] }
    else if (std.mem.startsWith(u8, s, "rgba:"))
        .{ 4, s[5..] }
    else
        return null;
    var it = std.mem.splitScalar(u8, body, '/');
    var rgb: [3]u8 = undefined;
    for (0..channels) |n| {
        const chan = it.next() orelse return null;
        const v = channelToU8(chan) orelse return null;
        if (n < 3) rgb[n] = v;
    }
    if (it.next() != null) return null;
    return Rgb.init(rgb[0], rgb[1], rgb[2]);
}

fn channelToU8(h: []const u8) ?u8 {
    if (h.len == 0 or h.len > 4) return null;
    const raw = std.fmt.parseInt(u16, h, 16) catch return null;
    const shift: i32 = (@as(i32, @intCast(h.len)) - 2) * 4;
    return if (shift >= 0)
        @truncate(raw >> @intCast(shift))
    else
        @truncate(raw << @intCast(-shift));
}

// --- OKLab -------------------------------------------------------------------

const Oklab = struct { l: f64, a: f64, b: f64 };

// StyledStrings' ^2.2 gamma approximation, so blends match Julia's.
fn srgbToOklab(c: Rgb) Oklab {
    const r = std.math.pow(f64, @as(f64, @floatFromInt(c.r)) / 255.0, 2.2);
    const g = std.math.pow(f64, @as(f64, @floatFromInt(c.g)) / 255.0, 2.2);
    const b = std.math.pow(f64, @as(f64, @floatFromInt(c.b)) / 255.0, 2.2);
    const l = std.math.cbrt(0.4122214708 * r + 0.5363325363 * g + 0.0514459929 * b);
    const m = std.math.cbrt(0.2119034982 * r + 0.6806995451 * g + 0.1073969566 * b);
    const s = std.math.cbrt(0.0883024619 * r + 0.2817188376 * g + 0.6299787005 * b);
    return .{
        .l = 0.2104542553 * l + 0.7936177850 * m - 0.0040720468 * s,
        .a = 1.9779984951 * l - 2.4285922050 * m + 0.4505937099 * s,
        .b = 0.0259040371 * l + 0.7827717662 * m - 0.8086757660 * s,
    };
}

fn oklabToSrgb(c: Oklab) Rgb {
    const l_ = c.l + 0.3963377774 * c.a + 0.2158037573 * c.b;
    const m_ = c.l - 0.1055613458 * c.a - 0.0638541728 * c.b;
    const s_ = c.l - 0.0894841775 * c.a - 1.2914855480 * c.b;
    const l = l_ * l_ * l_;
    const m = m_ * m_ * m_;
    const s = s_ * s_ * s_;
    return Rgb.init(
        toHex(4.0767416621 * l - 3.3077115913 * m + 0.2309699292 * s),
        toHex(-1.2684380046 * l + 2.6097574011 * m - 0.3413193965 * s),
        toHex(-0.0041960863 * l - 0.7034186147 * m + 1.7076147010 * s),
    );
}

fn toHex(v: f64) u8 {
    const clamped = @max(0.0, v);
    const out = std.math.pow(f64, clamped, 1.0 / 2.2);
    return @intFromFloat(@min(255.0, @round(255.0 * out)));
}

/// Matches StyledStrings.blend(lo=>1-t, hi=>t).
pub fn blend(lo: Rgb, hi: Rgb, t: f64) Rgb {
    const f = std.math.clamp(t, 0.0, 1.0);
    const a = srgbToOklab(lo);
    const b = srgbToOklab(hi);
    return oklabToSrgb(.{
        .l = a.l * (1 - f) + b.l * f,
        .a = a.a * (1 - f) + b.a * f,
        .b = a.b * (1 - f) + b.b * f,
    });
}

// --- gradient ----------------------------------------------------------------

pub const sgr_fg_len = 19;

pub fn sgrFg(c: Rgb, buf: *[sgr_fg_len]u8) []const u8 {
    return std.fmt.bufPrint(buf, "\x1b[38;2;{d};{d};{d}m", .{ c.r, c.g, c.b }) catch unreachable;
}

pub fn slot(palette: *const Palette, idx: usize, default: Rgb) Rgb {
    if (idx >= palette.ansi.len) return default;
    return palette.ansi[idx] orelse default;
}
