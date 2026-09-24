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
pub const rawSocket = impl.rawSocket;
pub const rawConnect = impl.rawConnect;
pub const rawClose = impl.rawClose;
pub const defaultRuntimeDir = impl.defaultRuntimeDir;
pub const isLoopback = if (os != .windows) impl.isLoopback else struct {
    fn f(_: anytype, _: anytype) bool { return true; } // Windows: treat all as local for now
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
pub const shutdownWrite = shared.shutdownWrite;
// Local (path-addressed) transport: AF_UNIX on POSIX, named pipes on Windows.
// Every local address is formed by `localSocketPath` inside the directory
// `localSocketDir` derives from the runtime dir.
pub const Listener = shared.Listener;
pub const localSocketDir = shared.localSocketDir;
pub const localSocketPath = shared.localSocketPath;
pub const listenLocal = shared.listenLocal;
pub const connectLocal = shared.connectLocal;
pub const connectLocalOnce = shared.connectLocalOnce;
pub const rawConnectLocal = shared.rawConnectLocal;
pub const probeLocal = shared.probeLocal;
pub const probeTcp = shared.probeTcp;
pub const local_transport_name = shared.local_transport_name;
pub const spawnWorker = shared.spawnWorker;
pub const getChildPid = shared.getChildPid;
pub const WaitPidResult = shared.WaitPidResult;
pub const waitpidNonBlocking = shared.waitpidNonBlocking;
pub const peerPid = shared.peerPid;
pub const peerForeignMountNs = shared.peerForeignMountNs;
pub const peerMountNs = shared.peerMountNs;
pub const parentPid = shared.parentPid;
pub const spawnDetached = shared.spawnDetached;
pub const pidfdOpen = shared.pidfdOpen;
pub const pidfdSignal = shared.pidfdSignal;
pub const pidfdExited = shared.pidfdExited;
pub const ProcessStats = shared.ProcessStats;
pub const getProcessStats = shared.getProcessStats;
pub const mem_is_reclaimable = shared.mem_is_reclaimable;
pub const processReclaimable = shared.processReclaimable;
pub const MemInfo = shared.MemInfo;
pub const readPsiSomeAvg10 = shared.readPsiSomeAvg10;
pub const readMemInfo = shared.readMemInfo;
pub const getParentName = shared.getParentName;
pub const setRecvTimeout = shared.setRecvTimeout;
pub const setTcpNodelay = shared.setTcpNodelay;
pub const getTerminalSize = shared.getTerminalSize;
pub const isatty = shared.isatty;
pub const SignalHandler = shared.SignalHandler;
pub const registerSignalHandlers = shared.registerSignalHandlers;
pub const setRawMode = if (os != .windows) shared.setRawModeStdin else impl.setRawMode;
pub const setWorkerRawMode = if (os != .windows) shared.setWorkerRawMode else struct {
    fn f(_: bool) void {}
}.f;
pub const setWorkerExecuting = if (os != .windows) shared.setWorkerExecuting else struct {
    fn f(_: bool) void {}
}.f;

// Time (common implementation)
pub fn timeSeconds(io: Io) i64 {
    return Io.Clock.now(.awake, io).toSeconds();
}
