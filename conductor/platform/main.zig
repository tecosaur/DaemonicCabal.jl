// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0
//
// Platform abstraction layer, selected at comptime: linux.zig/bsd.zig plus
// the shared posix.zig, or windows.zig alone.

const std = @import("std");
const Io = std.Io;
const builtin = @import("builtin");
const os = builtin.target.os.tag;

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
/// Output relayed to our own stdout or stderr, false once its reader has
/// gone: left unread, the worker's writes then fail as they would to it.
pub const writeOutput = if (os != .windows) impl.writeAll else impl.writeFileAll;
pub const kill = impl.kill;
pub const defaultRuntimeDir = impl.defaultRuntimeDir;
pub const rotateLog = impl.rotateLog;
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
pub const sendNonBlocking = shared.sendNonBlocking;
pub const recvNonBlocking = shared.recvNonBlocking;
pub const waitReadable = shared.waitReadable;
pub const readAvailable = shared.readAvailable;
pub const peek_signal = impl.peek_signal;
pub const close = shared.close;
pub const eprint = shared.eprint;
/// The peer reads EOF; the handle stays valid wherever the transport can half-close.
pub const sendEof = if (os == .windows) impl.sendEof else shared.shutdownWrite;
// Local transport: AF_UNIX on POSIX, named pipes on Windows.
pub const Listener = shared.Listener;
pub const runtime_dir_permissions = shared.runtime_dir_permissions;
pub const secureRuntimeDir = shared.secureRuntimeDir;
pub const private_file_permissions = shared.private_file_permissions;
pub const readSmallFile = shared.readSmallFile;
pub const localSocketDir = shared.localSocketDir;
pub const localSocketPath = shared.localSocketPath;
pub const max_local_addr = shared.max_local_addr;
pub const listenLocal = shared.listenLocal;
pub const connectLocal = shared.connectLocal;
pub const connectLocalOnce = shared.connectLocalOnce;
pub const connectTcp = shared.connectTcp;
pub const connectTcpEach = shared.connectTcpEach;
pub const local_transport_name = shared.local_transport_name;
pub const spawnWorker = shared.spawnWorker;
pub const no_child = shared.no_child;
pub const no_socket = shared.no_socket;
pub const pidNumber = shared.pidNumber;
pub const dumpChildStderr = shared.dumpChildStderr;
pub const processInputs = shared.processInputs;
pub const requestSocketRecreate = shared.requestSocketRecreate;
pub const sleepMs = shared.sleepMs;
/// Taken in turns by a client's threads: Windows reads local input on one
/// of its own, apart from the output it writes.
pub const Lock = shared.Lock;
/// Nanoseconds on a clock that never steps back, for timing alone.
pub const monotonicNs = shared.monotonicNs;
pub const currentDir = shared.currentDir;
pub const lookupHost = shared.lookupHost;
pub const getChildPid = shared.getChildPid;
pub const reapIfExited = shared.reapIfExited;
pub const pollExit = shared.pollExit;
pub const waitForExit = shared.waitForExit;
/// Frees what holds a child process of ours, its pid aside.
pub const releaseChild = if (os == .windows) impl.releaseChild else struct {
    fn f(_: *std.process.Child) void {}
}.f;
// Linux-only; elsewhere "unavailable", so no peer is ever refused.
const linux_only = if (os == .linux) impl else struct {
    pub fn peerPid(_: std.posix.socket_t) ?std.posix.pid_t { return null; }
    pub fn peerForeignMountNs(_: std.posix.socket_t) ?u64 { return null; }
    pub fn peerMountNs(_: std.posix.socket_t) ?u64 { return null; }
    pub fn childMountNs(_: std.process.Child) ?u64 { return null; }
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
pub const childMountNs = linux_only.childMountNs;
pub const parentPid = linux_only.parentPid;
/// Immune to pid reuse.
pub const pidfdOpen = linux_only.pidfdOpen;
/// 0 on success, like `kill`.
pub const pidfdSignal = linux_only.pidfdSignal;
pub const pidfdExited = linux_only.pidfdExited;
/// Own session, stdio on /dev/null, no inherited fds; fails before forking.
pub const spawnDetached = linux_only.spawnDetached;
pub const getProcessStats = shared.getProcessStats;
pub const mem_is_reclaimable = shared.mem_is_reclaimable;
pub const processReclaimable = shared.processReclaimable;
pub const readPsiSomeAvg10 = shared.readPsiSomeAvg10;
pub const readMemInfo = shared.readMemInfo;
/// The ports the system picks a listener's from, given port 0.
pub const ephemeralPorts = impl.ephemeralPorts;
pub const getParentName = shared.getParentName;
pub const setTcpNodelay = shared.setTcpNodelay;
pub const setTcpKeepalive = shared.setTcpKeepalive;
pub const getTerminalSize = shared.getTerminalSize;
pub const isatty = shared.isatty;
pub const registerSignalHandlers = shared.registerSignalHandlers;
pub const setRawMode = shared.setRawMode;
pub const setWorkerRawMode = shared.setWorkerRawMode;
pub const setWorkerExecuting = shared.setWorkerExecuting;
pub const inRawMode = shared.inRawMode;
pub const suspendSelf = shared.suspendSelf;
pub const ctrlCIsInput = shared.ctrlCIsInput;
pub const ctrlCIsKey = shared.ctrlCIsKey;
pub const interrupt = shared.interrupt;
pub const lineEditingKeys = shared.lineEditingKeys;
pub const LineEditingKeys = shared.LineEditingKeys;
pub const openClosedStdio = if (os != .windows) shared.openClosedStdio else struct {
    fn f() void {}
}.f;
pub const setupConsoleIo = if (os == .windows) impl.setupConsoleIo else struct {
    fn f(_: std.posix.fd_t, _: std.posix.fd_t) ?*anyopaque { return null; }
}.f;
pub const restoreConsoleIo = if (os == .windows) impl.restoreConsoleIo else struct {
    fn f(_: ?*anyopaque) void {}
}.f;

pub fn timeSeconds(io: Io) i64 {
    return Io.Clock.now(.awake, io).toSeconds();
}
