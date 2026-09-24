// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0
//
// Platform abstraction layer for OS-specific functionality.
// On POSIX: platform-specific primitives from linux.zig/bsd.zig,
//           shared implementations from posix.zig.
// On Windows: everything from windows.zig.
//
// Everything here is selected at comptime; shared code pays nothing for the
// choice and holds no OS conditionals of its own.

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
/// Write to a console, pipe or file handle: WriteFile on Windows, `write` on
/// POSIX where every descriptor is alike.
pub const writeFile = if (os != .windows) impl.write else impl.writeFile;
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
pub const connectTcp = shared.connectTcp;
pub const probeLocal = shared.probeLocal;
pub const probeTcp = shared.probeTcp;
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
// Peer credentials, mount namespaces, pidfds and the detached spawn exist only
// on Linux. Elsewhere they report "unavailable", so no client-spawned worker
// arises and no peer is ever refused.
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
/// Pid of a unix-socket peer as this process sees it; null when unavailable.
pub const peerPid = linux_only.peerPid;
/// Inode of the peer's mount namespace when it differs from ours; null when same or unknown.
pub const peerForeignMountNs = linux_only.peerForeignMountNs;
/// Inode of the peer's mount namespace; null when unavailable.
pub const peerMountNs = linux_only.peerMountNs;
/// Parent pid of a process; null when unreadable.
pub const parentPid = linux_only.parentPid;
/// Handle on a process that is not our child, immune to pid reuse; null when unsupported.
pub const pidfdOpen = linux_only.pidfdOpen;
/// Signal a process through its pidfd; 0 on success, like `kill`.
pub const pidfdSignal = linux_only.pidfdSignal;
/// A pidfd turns readable once its process has exited.
pub const pidfdExited = linux_only.pidfdExited;
/// Exec an absolute command as a daemon: own session, stdio on /dev/null, no
/// inherited fds. Fails before forking when the path is not executable here or
/// /dev/null cannot be opened.
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
// Console configuration (VT processing, UTF-8 code pages) that POSIX
// terminals need none of.
pub const setupConsoleIo = if (os == .windows) impl.setupConsoleIo else struct {
    fn f(_: std.posix.fd_t, _: std.posix.fd_t) ?*anyopaque { return null; }
}.f;
pub const restoreConsoleIo = if (os == .windows) impl.restoreConsoleIo else struct {
    fn f(_: ?*anyopaque) void {}
}.f;

// Time (common implementation)
pub fn timeSeconds(io: Io) i64 {
    return Io.Clock.now(.awake, io).toSeconds();
}
