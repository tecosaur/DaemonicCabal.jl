// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0
//
// Platform abstraction layer for OS-specific functionality.
// On POSIX: platform-specific primitives from linux.zig/bsd.zig,
//           shared implementations from posix.zig.
// On Windows: everything from windows.zig.

const std = @import("std");
const Io = std.Io;
const builtin = @import("builtin");
const os = builtin.os.tag;

const impl = if (os == .linux)
    @import("linux.zig")
else if (os == .windows)
    @compileError("Unsupported OS")
else
    @import("bsd.zig");

// Platform-specific (different implementation per OS)
pub const SIG = impl.SIG;
pub const getpid = impl.getpid;
pub const getppid = impl.getppid;
pub const write = impl.write;
pub const kill = impl.kill;
pub const defaultRuntimeDir = impl.defaultRuntimeDir;
// Standard handles — POSIX constants vs Win32 GetStdHandle
pub fn getStdinHandle() std.posix.fd_t {
    if (os == .windows) return impl.getStdinHandle();
    return impl.STDIN_HANDLE;
}
pub fn getStdoutHandle() std.posix.fd_t {
    if (os == .windows) return impl.getStdoutHandle();
    return impl.STDOUT_HANDLE;
}

// Shared POSIX / Windows-specific
const shared = if (os != .windows) @import("posix.zig") else impl;
pub const socketWrite = shared.socketWrite;
pub const socketRead = shared.socketRead;
pub const getChildPid = shared.getChildPid;
pub const WaitPidResult = shared.WaitPidResult;
pub const waitpidNonBlocking = shared.waitpidNonBlocking;
pub const setRecvTimeout = shared.setRecvTimeout;
pub const getTerminalSize = shared.getTerminalSize;
pub const isatty = shared.isatty;
pub const SignalHandler = shared.SignalHandler;
pub const registerSignalHandlers = shared.registerSignalHandlers;
pub const setRawMode = if (os != .windows) shared.setRawModeStdin else impl.setRawMode;

// Time (common implementation)
pub fn timeSeconds(io: Io) i64 {
    return (Io.Clock.now(.awake, io) catch Io.Timestamp{ .nanoseconds = 0 }).toSeconds();
}
