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
    @import("windows.zig")
else
    @import("bsd.zig");

// Platform-specific (different implementation per OS)
pub const SIG = impl.SIG;
pub const getpid = impl.getpid;
pub const getppid = impl.getppid;
pub const write = impl.write;
// Console/pipe/file-handle writes (client stdout/stderr): WriteFile on
// Windows, same as write on POSIX where fds are unified.
pub const writeFile = if (os != .windows) impl.write else impl.writeFile;
pub const kill = impl.kill;
pub const rawSocket = impl.rawSocket;
pub const rawConnect = impl.rawConnect;
pub const rawClose = impl.rawClose;
pub const defaultRuntimeDir = impl.defaultRuntimeDir;
pub const isLoopback = if (os != .windows) impl.isLoopback else struct {
    fn f(_: anytype, _: anytype) bool {
        return true;
    } // Windows: treat all as local for now
}.f;
// Standard handles — POSIX constants vs Win32 GetStdHandle
pub fn getStdinHandle() std.posix.fd_t {
    if (os == .windows) return impl.getStdinHandle();
    return impl.STDIN_HANDLE;
}
pub fn getStdoutHandle() std.posix.fd_t {
    if (os == .windows) return impl.getStdoutHandle();
    return impl.STDOUT_HANDLE;
}
pub fn getStderrHandle() std.posix.fd_t {
    if (os == .windows) return impl.getStderrHandle();
    return impl.STDERR_HANDLE;
}

// Shared POSIX / Windows-specific
const shared = if (os != .windows) @import("posix.zig") else impl;
pub const socketWrite = shared.socketWrite;
pub const socketRead = shared.socketRead;
pub const close = shared.close;
pub const getChildPid = shared.getChildPid;
pub const WaitPidResult = shared.WaitPidResult;
pub const waitpidNonBlocking = shared.waitpidNonBlocking;
pub const ProcessStats = shared.ProcessStats;
pub const getProcessStats = shared.getProcessStats;
pub const mem_is_reclaimable = shared.mem_is_reclaimable;
pub const processReclaimable = shared.processReclaimable;
pub const MemInfo = shared.MemInfo;
pub const readPsiSomeAvg10 = shared.readPsiSomeAvg10;
pub const readMemInfo = shared.readMemInfo;
pub const getParentName = shared.getParentName;

/// Shared code tracks pids as plain integers; the platform carrier differs
/// (POSIX: i32, Windows: pointer-typed). Bridge integer pids into the
/// platform's carrier type here instead of @intCast-ing at call sites.
pub fn pidFromInt(pid: u32) std.posix.pid_t {
    return if (os == .windows)
        @ptrFromInt(@as(usize, pid))
    else
        @intCast(pid);
}
/// The POSIX waitpid "no news (WNOHANG) → 0" sentinel, carrier-agnostic.
pub fn pidIsNull(p: std.posix.pid_t) bool {
    return if (os == .windows) @intFromPtr(p) == 0 else p == 0;
}
pub fn getParentNamePid(pid: u32, buf: []u8) ?[]const u8 {
    return getParentName(pidFromInt(pid), buf);
}
pub const setRecvTimeout = shared.setRecvTimeout;
pub const setTcpNodelay = shared.setTcpNodelay;
pub const getTerminalSize = shared.getTerminalSize;
pub const isatty = shared.isatty;
pub const SignalHandler = shared.SignalHandler;
pub const registerSignalHandlers = shared.registerSignalHandlers;
pub const setRawMode = if (os != .windows) shared.setRawModeStdin else struct {
    // One-arg client shape (POSIX setRawModeStdin parity): the fd is always
    // the local console stdin handle.
    fn f(raw: bool) void {
        impl.setRawMode(impl.getStdinHandle(), raw);
    }
}.f;
pub const setWorkerRawMode = if (os != .windows) shared.setWorkerRawMode else struct {
    fn f(_: bool) void {}
}.f;
pub const setWorkerExecuting = if (os != .windows) shared.setWorkerExecuting else struct {
    fn f(_: bool) void {}
}.f;
// Client console configuration (VT processing + UTF-8 codepages). POSIX
// consoles need none of it — terminals decode UTF-8 and ANSI natively.
pub const setupConsoleIo = if (os == .windows) impl.setupConsoleIo else struct {
    fn f(_: std.posix.fd_t, _: std.posix.fd_t) ?*anyopaque {
        return null;
    }
}.f;
pub const restoreConsoleIo = if (os == .windows) impl.restoreConsoleIo else struct {
    fn f(_: ?*anyopaque) void {}
}.f;
// Named-pipe transport (windows only).
pub const pipeAsServer = if (os == .windows) impl.pipeAsServer else undefined;
pub const pipeAsStream = if (os == .windows) impl.pipeAsStream else undefined;
pub const acceptPipeSync = if (os == .windows) impl.acceptPipeSync else undefined;
pub const listenPipe = if (os == .windows) impl.listenPipe else undefined;
pub const connectPipe = if (os == .windows) impl.connectPipe else undefined;

// Time (common implementation)
pub fn timeSeconds(io: Io) i64 {
    return Io.Clock.now(.awake, io).toSeconds();
}
