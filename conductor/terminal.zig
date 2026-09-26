// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0
//
// A client's terminal, held open for a view the conductor draws in it
// (`--status=live`, `--reconfigure`): its keys and replies are read as the
// event loop finds them, and output never blocks the conductor. What the
// terminal doesn't take is queued, and one too far behind is let go.

const std = @import("std");
const posix = std.posix;
const main = @import("main.zig");
const platform = @import("platform/main.zig");
const protocol = @import("protocol.zig");
const pal = @import("palette.zig");

const Conductor = main.Conductor;
const ClientStreams = Conductor.ClientStreams;

const max_queued_bytes = 1 << 20;

/// The low bits of an event-loop tag for a `Watch`, whose address it carries.
pub const tag: usize = 5;

/// A descriptor the event loop watches for a view. Aligned so the tag's low
/// bits are free. A view matches its own by address: one gone may still be
/// reported, and mustn't be read.
pub const Watch = struct {
    kind: enum { input, signals, watch_output, watch_signals } align(8),
    fd: posix.socket_t,
};

pub fn watch(c: *Conductor, w: *Watch) void {
    c.event_loop.watchFd(@intFromPtr(w) | tag, w.fd);
}

pub fn unwatch(c: *Conductor, w: *Watch) void {
    c.event_loop.unwatchFd(@intFromPtr(w) | tag, w.fd);
}

pub const Size = struct { rows: u16 = 24, cols: u16 = 80 };

pub const Terminal = struct {
    streams: ClientStreams, // held open across repaints
    palette: ?pal.Palette, // probed once, as the view began
    id: u32, // the client's, matched on its exit or interrupt
    input: Watch = undefined,
    signals: Watch = undefined,
    frames: SignalFrames = .{},
    size: Size = .{},
    lines_last_printed: usize = 0, // for the cursor-up redraw
    drawn: u64 = 0, // the last frame's hash: an identical one isn't sent
    queued: std.ArrayList(u8) = .empty, // output the terminal hasn't taken yet
    gone: bool = false,

    /// Keys as they're pressed, and the terminal's size, from here on.
    pub fn open(self: *Terminal, c: *Conductor) void {
        const signals = self.streams.fd(.signals);
        platform.write(signals, &[_]u8{ protocol.signals.raw_mode, 0x01, 0x01 });
        self.querySize();
        self.input = .{ .kind = .input, .fd = self.streams.fd(.stdin) };
        self.signals = .{ .kind = .signals, .fd = signals };
        watch(c, &self.input);
        watch(c, &self.signals);
    }

    /// Stops reading it, sends `leaving`, and lets the client exit.
    pub fn close(self: *Terminal, c: *Conductor, leaving: ?[]const u8) void {
        if (leaving) |bytes| {
            unwatch(c, &self.input);
            unwatch(c, &self.signals);
            _ = platform.sendNonBlocking(self.stdout(), bytes);
        }
        self.streams.closeForExit(0);
        self.streams.deinit();
        self.queued.deinit(c.allocator);
    }

    pub fn stdout(self: *const Terminal) posix.socket_t {
        return self.streams.fd(.stdout);
    }

    pub fn querySize(self: *const Terminal) void {
        platform.write(self.streams.fd(.signals), &[_]u8{ protocol.signals.query_size, 0x00 });
    }

    pub fn send(self: *Terminal, gpa: std.mem.Allocator, bytes: []const u8) void {
        var rest = bytes;
        if (self.queued.items.len == 0) {
            const n = platform.sendNonBlocking(self.stdout(), rest) orelse {
                self.gone = true;
                return;
            };
            rest = rest[n..];
        }
        if (rest.len == 0) return;
        self.queued.appendSlice(gpa, rest) catch {
            self.gone = true;
            return;
        };
        if (self.queued.items.len > max_queued_bytes) self.gone = true;
    }

    /// Whether it has caught up.
    pub fn flushQueued(self: *Terminal) bool {
        const n = platform.sendNonBlocking(self.stdout(), self.queued.items) orelse {
            self.gone = true;
            return false;
        };
        self.queued.replaceRangeAssumeCapacity(0, n, &.{});
        return self.queued.items.len == 0;
    }

    /// Repainting what is already shown would still clear a selection in it.
    pub fn sendFrame(self: *Terminal, gpa: std.mem.Allocator, frame: []const u8) void {
        const hash = std.hash.Wyhash.hash(0, frame);
        if (hash == self.drawn) return;
        self.drawn = hash;
        self.send(gpa, frame);
    }

    /// The client's replies: a raw-mode ack, or the terminal's size.
    pub fn onSignals(self: *Terminal, bytes: []const u8) void {
        for (bytes) |byte| {
            const msg = self.frames.feed(byte) orelse continue;
            if (msg[0] == protocol.signals.query_size and msg[1] == 4) self.size = .{
                .rows = std.mem.readInt(u16, msg[2..4], .little),
                .cols = std.mem.readInt(u16, msg[4..6], .little),
            };
        }
    }
};

/// Messages framed `id len data`, as a signals socket carries them.
pub const SignalFrames = struct {
    bytes: [16]u8 = undefined,
    len: usize = 0,

    /// The message `byte` completes, if any.
    pub fn feed(self: *SignalFrames, byte: u8) ?[]const u8 {
        if (self.len == self.bytes.len) self.len = 0; // nothing sent is this long
        self.bytes[self.len] = byte;
        self.len += 1;
        const msg = self.bytes[0..self.len];
        if (msg.len < 2 or msg.len < 2 + msg[1]) return null;
        self.len = 0;
        return msg;
    }
};

/// A footer's keys, bold, each with its action dim; keys without actions
/// in a row share one, as in "y/n".
pub fn hints(comptime pairs: []const [2][]const u8) []const u8 {
    comptime var text: []const u8 = "";
    inline for (pairs, 0..) |pair, i| {
        if (i > 0) text = text ++ if (pair[1].len == 0 and pairs[i - 1][1].len == 0) "/" else " · ";
        text = text ++ "\x1b[0;1m" ++ pair[0] ++ "\x1b[0;2m" ++ (if (pair[1].len > 0) " " ++ pair[1] else "");
    }
    return text;
}
