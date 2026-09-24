// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0
//
// Platform abstraction layer, selected at comptime: linux.zig/bsd.zig plus
// the shared posix.zig, or windows.zig alone.

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

pub const SIG = impl.SIG;
pub const getpid = impl.getpid;
pub const getppid = impl.getppid;
pub const write = impl.write;
/// For console, pipe and file handles.
pub const writeFile = if (os != .windows) impl.write else impl.writeFile;
pub const kill = impl.kill;
pub const rawSocket = impl.rawSocket;
pub const rawConnect = impl.rawConnect;
pub const rawClose = impl.rawClose;
pub const defaultRuntimeDir = impl.defaultRuntimeDir;
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

const shared = if (os != .windows) @import("posix.zig") else impl;
pub const socketWrite = shared.socketWrite;
pub const socketRead = shared.socketRead;
pub const close = shared.close;
pub const shutdownWrite = shared.shutdownWrite;
// Local transport: AF_UNIX on POSIX, named pipes on Windows.
pub const Listener = shared.Listener;
pub const localSocketDir = shared.localSocketDir;
pub const localSocketPath = shared.localSocketPath;
pub const listenLocal = shared.listenLocal;
pub const connectLocal = shared.connectLocal;
pub const connectLocalOnce = shared.connectLocalOnce;
pub const rawConnectLocal = shared.rawConnectLocal;
pub const connectTcp = shared.connectTcp;
pub const local_transport_name = shared.local_transport_name;
pub const spawnWorker = shared.spawnWorker;
pub const no_child = shared.no_child;
pub const no_socket = shared.no_socket;
pub const pidNumber = shared.pidNumber;
pub const dumpChildStderr = shared.dumpChildStderr;
pub const collectEnviron = shared.collectEnviron;
pub const requestSocketRecreate = shared.requestSocketRecreate;
pub const getChildPid = shared.getChildPid;
pub const WaitPidResult = shared.WaitPidResult;
pub const waitpidNonBlocking = shared.waitpidNonBlocking;
// Linux-only; elsewhere "unavailable", so no peer is ever refused.
const linux_only = if (os == .linux) impl else struct {
    pub fn peerPid(_: std.posix.socket_t) ?std.posix.pid_t { return null; }
    pub fn peerForeignMountNs(_: std.posix.socket_t) ?u64 { return null; }
    pub fn peerMountNs(_: std.posix.socket_t) ?u64 { return null; }
    pub fn parentPid(_: std.posix.pid_t) ?std.posix.pid_t { return null; }
    pub fn pidfdOpen(_: std.posix.pid_t) ?std.posix.fd_t { return null; }
    pub fn pidfdSignal(_: std.posix.fd_t, _: SIG) usize { return 1; }
    pub fn pidfdExited(_: std.posix.fd_t) bool { return true; }
    pub fn spawnDetached(_: [*:null]const ?[*:0]const u8, _: [*:null]const ?[*:0]const u8) !void { return error.SpawnUnsupported; }
};
/// As this process's pid namespace sees it.
pub const peerPid = linux_only.peerPid;
/// Null when the same as ours, or unknown.
pub const peerForeignMountNs = linux_only.peerForeignMountNs;
pub const peerMountNs = linux_only.peerMountNs;
pub const parentPid = linux_only.parentPid;
/// Immune to pid reuse.
pub const pidfdOpen = linux_only.pidfdOpen;
/// 0 on success, like `kill`.
pub const pidfdSignal = linux_only.pidfdSignal;
pub const pidfdExited = linux_only.pidfdExited;
/// Own session, stdio on /dev/null, no inherited fds; fails before forking.
pub const spawnDetached = linux_only.spawnDetached;
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
pub const setRawMode = shared.setRawModeStdin;
pub const setWorkerRawMode = shared.setWorkerRawMode;
pub const setWorkerExecuting = shared.setWorkerExecuting;
pub const setupConsoleIo = if (os == .windows) impl.setupConsoleIo else struct {
    fn f(_: std.posix.fd_t, _: std.posix.fd_t) ?*anyopaque { return null; }
}.f;
pub const restoreConsoleIo = if (os == .windows) impl.restoreConsoleIo else struct {
    fn f(_: ?*anyopaque) void {}
}.f;

pub fn timeSeconds(io: Io) i64 {
    return Io.Clock.now(.awake, io).toSeconds();
}
