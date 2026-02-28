// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0
//
// Cooked mode emulation for --sync clients.
// When the worker requests cooked mode (e.g. readline()), the client
// emulates line editing locally: buffering, echo, backspace, and
// sending complete lines on enter.

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const platform = @import("platform/main.zig");

pub const CookedState = struct {
    line_buf: [4096]u8 = undefined,
    line_len: usize = 0,

    /// Process a single input byte in cooked mode.
    /// stdin_fd is the worker's stdin socket; local echo goes to local stdout.
    pub fn process(self: *@This(), byte: u8, stdin_fd: posix.socket_t) void {
        switch (byte) {
            0x7F => {
                if (self.line_len > 0) {
                    self.line_len -= 1;
                    writeLocal("\x08 \x08");
                }
            },
            '\r', '\n' => {
                writeLocal("\r\n");
                if (self.line_len > 0) {
                    platform.socketWrite(stdin_fd, self.line_buf[0..self.line_len]);
                }
                platform.socketWrite(stdin_fd, "\n");
                self.line_len = 0;
            },
            0x03 => {
                platform.socketWrite(stdin_fd, "\x03");
                self.line_len = 0;
            },
            0x04 => {
                if (self.line_len == 0) closeSocket(stdin_fd);
            },
            else => {
                if (byte >= 0x20 and self.line_len < self.line_buf.len) {
                    self.line_buf[self.line_len] = byte;
                    self.line_len += 1;
                    writeLocal(&[_]u8{byte});
                }
            },
        }
    }

    fn writeLocal(data: []const u8) void {
        platform.write(platform.getStdoutHandle(), data);
    }

    fn closeSocket(fd: posix.socket_t) void {
        if (builtin.os.tag == .windows) {
            _ = std.os.windows.ws2_32.closesocket(fd);
        } else {
            posix.close(fd);
        }
    }
};
