// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0
//
// Cooked-mode line editing for --sync clients, done locally.

const std = @import("std");
const posix = std.posix;
const platform = @import("platform/main.zig");
const debuglog = @import("debuglog.zig");
const typeahead = @import("typeahead.zig");

/// Local stdin on its way to the worker: line-edited here while a `--sync`
/// worker wants cooked input, passed straight through otherwise. What it
/// forwards waits for `flush`, so a worker not reading its stdin holds up
/// only the next read of ours, never its output.
pub const StdinForwarder = struct {
    dst: posix.socket_t,
    sync_mode: bool,
    /// The signal parser's; on Windows another thread writes it.
    wants_raw: *const bool,
    cooked: CookedState = .{},
    /// What one `forward` or `end` made of its input, a line held back included.
    unsent: [@sizeOf(@FieldType(CookedState, "line_buf")) + 2 * max_read]u8 = undefined,
    unsent_start: usize = 0,
    unsent_end: usize = 0,
    /// Local input is over: the worker's stdin ends once `unsent` has gone.
    ended: bool = false,
    eof_sent: bool = false,

    /// The most `forward` is given at once, and only once all before has gone.
    pub const max_read = 1024;

    /// A Ctrl-C typed in raw mode comes as a byte, as in Julia's: unless the
    /// REPL takes it as a key, it interrupts, as the terminal's signal would.
    pub fn forward(self: *StdinForwarder, bytes: []const u8) void {
        debuglog.event("stdin: {d} B {f}", .{ bytes.len, debuglog.preview(bytes) });
        typeahead.typed(bytes);
        var rest = bytes;
        if (platform.ctrlCIsInput() and !platform.ctrlCIsKey()) {
            while (std.mem.findScalar(u8, rest, 0x03)) |i| {
                self.pass(rest[0..i]);
                if (self.isCooked()) self.cooked.discard();
                platform.interrupt();
                rest = rest[i + 1 ..];
            }
        }
        self.pass(rest);
    }

    /// At the end of local input, returns whether it goes on: a terminal's,
    /// in cooked mode, is a Ctrl-D, which the worker takes as a TTY does, as
    /// the end of input so far.
    pub fn end(self: *StdinForwarder) bool {
        if (platform.isatty(platform.getStdinHandle()) and !platform.inRawMode()) {
            self.put("\x04");
            return true;
        }
        self.ended = true;
        return false;
    }

    /// Sends what is unsent without waiting, and then any end of input;
    /// whether all has gone. Until it has, local stdin is left unread.
    pub fn flush(self: *StdinForwarder) bool {
        while (self.unsent_start < self.unsent_end) {
            const sent = platform.sendNonBlocking(self.dst, self.unsent[self.unsent_start..self.unsent_end]) orelse {
                // The worker's stdin has closed, so nothing will read it.
                self.unsent_start = self.unsent_end;
                break;
            };
            if (sent == 0) return false;
            self.unsent_start += sent;
        }
        self.unsent_start = 0;
        self.unsent_end = 0;
        if (self.ended and !self.eof_sent) {
            platform.sendEof(self.dst);
            self.eof_sent = true;
        }
        return true;
    }

    fn put(self: *StdinForwarder, bytes: []const u8) void {
        if (bytes.len > self.unsent.len - self.unsent_end) {
            // Never while `forward` keeps within `max_read`; written out, rather than lost.
            platform.write(self.dst, self.unsent[self.unsent_start..self.unsent_end]);
            self.unsent_start = 0;
            self.unsent_end = 0;
            return platform.write(self.dst, bytes);
        }
        @memcpy(self.unsent[self.unsent_end..][0..bytes.len], bytes);
        self.unsent_end += bytes.len;
    }

    fn pass(self: *StdinForwarder, bytes: []const u8) void {
        if (self.isCooked()) {
            for (bytes) |byte| self.cooked.process(byte, self);
        } else self.put(bytes);
    }

    fn isCooked(self: *const StdinForwarder) bool {
        return self.sync_mode and !@atomicLoad(bool, self.wants_raw, .acquire);
    }
};

/// A terminal's canonical mode: a line goes once Enter or end-of-input ends
/// it, edited meanwhile with the terminal's own keys. Control characters are
/// kept, echoed as `^X`.
pub const CookedState = struct {
    line_buf: [4096]u8 = undefined,
    line_len: usize = 0,
    keys: ?platform.LineEditingKeys = null,

    /// Echo goes to local stdout.
    pub fn process(self: *CookedState, byte: u8, out: *StdinForwarder) void {
        const keys = self.keys orelse keys: {
            self.keys = platform.lineEditingKeys();
            break :keys self.keys.?;
        };
        if (byte == '\r' or byte == '\n') {
            writeLocal("\r\n");
            self.send(out);
            out.put("\n");
        } else if (byte == keys.eof) {
            // Ends input on an empty line, as the worker takes a lone 0x04
            // while cooked, else sends the line so far.
            if (self.line_len == 0) out.put("\x04") else self.send(out);
        } else if (byte == keys.erase) {
            if (self.line_len > 0) self.eraseChar();
        } else if (byte == keys.kill) {
            while (self.line_len > 0) self.eraseChar();
        } else if (byte == keys.werase) {
            while (self.line_len > 0 and self.line_buf[self.line_len - 1] == ' ') self.eraseChar();
            while (self.line_len > 0 and self.line_buf[self.line_len - 1] != ' ') self.eraseChar();
        } else if (self.line_len < self.line_buf.len) {
            const start = column(self.line_buf[0..self.line_len]);
            self.line_buf[self.line_len] = byte;
            self.line_len += 1;
            if (byte == '\t') {
                const width = column(self.line_buf[0..self.line_len]) - start;
                writeLocal("        "[0..width]);
            } else if (isControl(byte)) {
                writeLocal(&.{ '^', byte ^ 0x40 });
            } else writeLocal(&.{byte});
        }
    }

    /// An interrupt flushes the line, as the terminal's signal would.
    pub fn discard(self: *CookedState) void {
        self.line_len = 0;
        writeLocal("^C");
    }

    fn send(self: *CookedState, out: *StdinForwarder) void {
        if (self.line_len > 0) out.put(self.line_buf[0..self.line_len]);
        self.line_len = 0;
    }

    // A whole UTF-8 character, and the cells its echo took.
    fn eraseChar(self: *CookedState) void {
        var start = self.line_len - 1;
        while (start > 0 and self.line_buf[start] & 0xC0 == 0x80) start -= 1;
        const cells = column(self.line_buf[0..self.line_len]) - column(self.line_buf[0..start]);
        self.line_len = start;
        for (0..cells) |_| writeLocal("\x08 \x08");
    }

    // The column after echoing `line` from the line's start, tabs every eight.
    fn column(line: []const u8) usize {
        var col: usize = 0;
        for (line) |byte| {
            if (byte == '\t') {
                col = (col / 8 + 1) * 8;
            } else if (isControl(byte)) {
                col += 2;
            } else if (byte & 0xC0 != 0x80) col += 1;
        }
        return col;
    }

    fn isControl(byte: u8) bool {
        return byte < 0x20 or byte == 0x7F;
    }

    fn writeLocal(data: []const u8) void {
        platform.writeFile(platform.getStdoutHandle(), data);
    }
};
