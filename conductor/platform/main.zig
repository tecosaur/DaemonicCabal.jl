// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0
//
// Platform abstraction layer for OS-specific functionality.

const std = @import("std");
const Io = std.Io;
const builtin = @import("builtin");
const os = builtin.os.tag;

const impl = if (os == .linux)
    @import("linux.zig")
else
    @compileError("unsupported OS");

// Re-export platform implementation
pub const fd_t = impl.fd_t;
pub const pid_t = impl.pid_t;
pub const uid_t = impl.uid_t;
pub const SIG = impl.SIG;
pub const getuid = impl.getuid;
pub const getpid = impl.getpid;
pub const getppid = impl.getppid;
pub const write = impl.write;
pub const kill = impl.kill;
pub const WaitPidResult = impl.WaitPidResult;
pub const waitpidNonBlocking = impl.waitpidNonBlocking;
pub const setRecvTimeout = impl.setRecvTimeout;
pub const getTerminalSize = impl.getTerminalSize;
pub const isatty = impl.isatty;
pub const defaultRuntimeDir = impl.defaultRuntimeDir;

// Time (common implementation)
pub fn timeSeconds(io: Io) i64 {
    return (Io.Clock.now(.awake, io) catch Io.Timestamp{ .nanoseconds = 0 }).toSeconds();
}
