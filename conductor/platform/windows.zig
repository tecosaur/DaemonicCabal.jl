// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0
//
// Windows platform module.
//
// On POSIX the router (main.zig) splits work between a raw-primitives impl
// (linux.zig / bsd.zig) and a shared-logic layer (posix.zig). Windows has no
// POSIX to share, so posix.zig is *never imported* (see main.zig:
// `const shared = if (os != .windows) @import("posix.zig") else impl;`) and
// windows.zig must export BOTH buckets itself.
//
// HANDLE note: POSIX unifies everything behind a small-int fd; Windows has no
// unified namespace, BUT under our design every socket is an AFD endpoint
// handle created by std.Io — a plain overlapped-capable HANDLE. So `close`
// is always `CloseHandle` here, and socket read/write are
// NtDeviceIoControlFile(AFD.RECEIVE/SEND) IOCTLs, not recv/send (there is no
// ws2_32 layer at all — see AFD.md for the full map).
//
// Stubs below are implementation bookmarks: signatures kept where the router
// or callers pin them down, bodies inert so the file compiles.

const std = @import("std");
const builtin = @import("builtin");
const win32 = std.os.windows;
const posix = std.posix;

// Base Win32 types from std, unqualified for readable extern signatures below.
const BOOL = win32.BOOL;
const DWORD = win32.DWORD;
const ULONG = win32.ULONG;
const WORD = win32.WORD;
const HANDLE = win32.HANDLE;
const FILETIME = win32.FILETIME;

// =============================================================================
// Win32 bindings missing from std.os.windows (0.16 binds only a handful of
// helpers — GetCurrentProcessId, GetCurrentProcess, GetLastError, CloseHandle,
// GetProcessHeap, peb/teb...; kernel32.zig has only CreateProcessW; ntdll.zig
// has the full NT surface incl. NtCreateFile/NtDeviceIoControlFile and all
// AFD structs live in std.os.windows.AFD). std.os.windows supplies the base
// types (HANDLE, DWORD, BOOL, ULONG, FILETIME, COORD...). All declarations
// below are pub so the eloop (eloop/windows.zig) can reuse them.
// NOTE: linked automatically — zig build-exe resolves kernel32/psapi without
// -l flags (verified).
// =============================================================================

pub const STD_INPUT_HANDLE: DWORD = @bitCast(@as(i32, -10));
pub const STD_OUTPUT_HANDLE: DWORD = @bitCast(@as(i32, -11));
pub const STD_ERROR_HANDLE: DWORD = @bitCast(@as(i32, -12));

pub const CTRL_C_EVENT: DWORD = 0;
pub const CTRL_BREAK_EVENT: DWORD = 1;
pub const CTRL_CLOSE_EVENT: DWORD = 2;
pub const CTRL_LOGOFF_EVENT: DWORD = 5;
pub const CTRL_SHUTDOWN_EVENT: DWORD = 6;

pub const FILE_TYPE_CHAR: DWORD = 0x0002;
pub const STILL_ACTIVE: DWORD = 259;
pub const PROCESS_QUERY_LIMITED_INFORMATION: DWORD = 0x1000;
pub const PROCESS_TERMINATE: DWORD = 0x0001;
pub const PROCESS_SYNCHRONIZE: DWORD = 0x00100000;
const WAIT_OBJECT_0: DWORD = 0x00000000;
const WAIT_TIMEOUT: DWORD = 0x00000102;

// POSIX-style pids ride around as fd_t (*anyopaque) in this codebase; real
// Windows PIDs are DWORD — all our pids originate from CreateProcess, so
// ptr-int roundtrip never loses bits.
fn openProcessFor(pid: posix.pid_t, access: DWORD) ?HANDLE {
    return OpenProcess(access, win32.BOOL.FALSE, @as(u32, @truncate(@intFromPtr(pid))));
}

pub const HANDLER_ROUTINE = fn (dwCtrlType: DWORD) callconv(.winapi) BOOL;
pub const PHANDLER_ROUTINE = *const HANDLER_ROUTINE;
pub const WAITORTIMERCALLBACK = *const fn (lpParameter: ?*anyopaque, timer_or_wait_fired: BOOL) callconv(.winapi) void;

pub const OVERLAPPED = extern struct {
    Internal: usize,
    InternalHigh: usize,
    Union: extern struct {
        Offset: u32,
        OffsetHigh: u32,
    },
    hEvent: HANDLE,
};
// NOTE: IO_STATUS_BLOCK (std.os.windows) and OVERLAPPED share the first two
// fields (Internal/InternalHigh ≡ u.Status/Information), so an iosb pointer
// from NtDeviceIoControlFile can be cast to *OVERLAPPED for IOCP retrieval.

pub const MEMORYSTATUSEX = extern struct {
    dwLength: DWORD,
    dwMemoryLoad: DWORD,
    ullTotalPhys: u64,
    ullAvailPhys: u64,
    ullTotalPageFile: u64,
    ullAvailPageFile: u64,
    ullTotalVirtual: u64,
    ullAvailVirtual: u64,
    ullAvailExtendedVirtual: u64,
};

pub const PROCESS_MEMORY_COUNTERS_EX = extern struct {
    cb: DWORD,
    PageFaultCount: DWORD,
    PeakWorkingSetSize: usize,
    WorkingSetSize: usize,
    QuotaPeakPagedPoolUsage: usize,
    QuotaPagedPoolUsage: usize,
    QuotaPeakNonPagedPoolUsage: usize,
    QuotaNonPagedPoolUsage: usize,
    PagefileUsage: usize,
    PeakPagefileUsage: usize,
    PrivateUsage: usize,
};

pub const SMALL_RECT = extern struct {
    Left: i16,
    Top: i16,
    Right: i16,
    Bottom: i16,
};

pub const CONSOLE_SCREEN_BUFFER_INFO = extern struct {
    dwSize: win32.COORD,
    dwCursorPosition: win32.COORD,
    wAttributes: WORD,
    srWindow: SMALL_RECT,
    dwMaximumWindowSize: win32.COORD,
};

// --- kernel32 ---
pub extern "kernel32" fn GetStdHandle(nStdHandle: DWORD) HANDLE;
pub extern "kernel32" fn GetConsoleMode(hConsoleHandle: HANDLE, lpMode: *DWORD) BOOL;
pub extern "kernel32" fn SetConsoleMode(hConsoleHandle: HANDLE, dwMode: DWORD) BOOL;
pub extern "kernel32" fn GetConsoleScreenBufferInfo(hConsoleOutput: HANDLE, lpConsoleScreenBufferInfo: *CONSOLE_SCREEN_BUFFER_INFO) BOOL;
pub extern "kernel32" fn GlobalMemoryStatusEx(lpBuffer: *MEMORYSTATUSEX) BOOL;
pub extern "kernel32" fn OpenProcess(dwDesiredAccess: DWORD, bInheritHandle: BOOL, dwProcessId: DWORD) ?HANDLE;
pub extern "kernel32" fn TerminateProcess(hProcess: HANDLE, uExitCode: u32) BOOL;
pub extern "kernel32" fn GetExitCodeProcess(hProcess: HANDLE, lpExitCode: *DWORD) BOOL;
pub extern "kernel32" fn WaitForSingleObject(hHandle: HANDLE, dwMilliseconds: DWORD) DWORD;
pub extern "kernel32" fn WriteFile(hFile: HANDLE, lpBuffer: *const anyopaque, nNumberOfBytesToWrite: DWORD, lpNumberOfBytesWritten: ?*DWORD, lpOverlapped: ?*OVERLAPPED) BOOL;
pub extern "kernel32" fn ReadFile(hFile: HANDLE, lpBuffer: [*]u8, nNumberOfBytesToRead: DWORD, lpNumberOfBytesRead: ?*DWORD, lpOverlapped: ?*OVERLAPPED) BOOL;
pub extern "kernel32" fn GetFileType(hFile: HANDLE) DWORD;
pub extern "kernel32" fn SetConsoleCtrlHandler(handler_routine: ?PHANDLER_ROUTINE, add: BOOL) BOOL;
pub extern "kernel32" fn GetProcessTimes(hProcess: HANDLE, lpCreationTime: *FILETIME, lpExitTime: *FILETIME, lpKernelTime: *FILETIME, lpUserTime: *FILETIME) BOOL;
pub extern "kernel32" fn GenerateConsoleCtrlEvent(dwCtrlEvent: DWORD, dwProcessGroupId: DWORD) BOOL;
pub extern "kernel32" fn GetProcessId(hProcess: HANDLE) DWORD;

// --- psapi ---
pub extern "psapi" fn GetProcessMemoryInfo(hProcess: HANDLE, ppsmemCounters: *PROCESS_MEMORY_COUNTERS_EX, cb: DWORD) BOOL;

// NOTE: no ws2_32 bindings at all — sockets are AFD endpoint handles from
// std.Io, driven via std.os.windows.ntdll.NtDeviceIoControlFile + the AFD
// IOCTLs/structs in std.os.windows (AFD.RECEIVE/SEND/WAIT_FOR_LISTEN/ACCEPT/
// BIND/START_LISTEN/SOCKOPT...). See AFD.md for the POSIX→AFD translation.

// =============================================================================
// AFD plumbing — every Windows socket is an AFD endpoint handle (the object
// std.Io creates under Io.net); these helpers issue the IOCTLs synchronously.
// Reference shapes: std.Io.Threaded openSocketAfd (Threaded.zig:12348),
// socketOptionAfd (:12052), bindSocketIpAfd/bindSocketUnixAfd (:12402/:12421),
// netConnectIpWindows/netConnectUnixWindows (:12090/:12145).
// =============================================================================

const ntdll = win32.ntdll;
const wthreaded = std.Io.Threaded;

/// APC callback that flips a done flag — mirror of Threaded.flagApc (:9729).
fn afdDoneApc(userdata: ?*anyopaque, _: *win32.IO_STATUS_BLOCK, _: win32.ULONG) align(2) callconv(.winapi) void {
    const done: *bool = @ptrCast(userdata.?);
    done.* = true;
}

/// Alertable sleep until the next APC fires (Threaded.waitForApcOrAlert :1554).
fn waitForApcOrAlert() void {
    const forever: win32.LARGE_INTEGER = std.math.minInt(win32.LARGE_INTEGER);
    _ = ntdll.NtDelayExecution(.TRUE, &forever);
}

/// Run one AFD IOCTL to completion on this thread: pended IRP + APC +
/// alertable wait. Threaded.deviceIoControl's (:18504) nonblocking branch
/// minus the cancellation machinery — no cancel context outside Io threads.
/// Returns the transfer count (IO_STATUS_BLOCK.Information; byte count for
/// data IOCTLS, opaque for others).
pub fn syncAfdControl(h: HANDLE, code: win32.CTL_CODE, in: []const u8, out: []u8) !usize {
    var iosb: win32.IO_STATUS_BLOCK = undefined;
    var done = false;
    switch (ntdll.NtDeviceIoControlFile(
        h,
        null,
        &afdDoneApc,
        &done,
        &iosb,
        code,
        if (in.len > 0) in.ptr else null,
        @intCast(in.len),
        if (out.len > 0) out.ptr else null,
        @intCast(out.len),
    )) {
        .PENDING, .SUCCESS => while (!done) waitForApcOrAlert(),
        else => |status| return win32.unexpectedStatus(status),
    }
    switch (iosb.u.Status) {
        .SUCCESS => return iosb.Information,
        else => |status| return win32.unexpectedStatus(status),
    }
}

/// Create a stream-mode AFD endpoint — the real object behind every socket.
/// Mirror of Threaded.openSocketAfd (:12348), stream mode only. Doubles as the
/// accept-path child-handle factory for the event loop.
pub fn openAfdEndpoint(family: posix.sa_family_t) !posix.fd_t {
    const mode_protocol = try wthreaded.posixSocketModeProtocol(family, .stream, null);
    var handle: HANDLE = undefined;
    var iosb: win32.IO_STATUS_BLOCK = undefined;
    switch (ntdll.NtCreateFile(
        &handle,
        .{
            .STANDARD = .{ .RIGHTS = .{ .WRITE_DAC = true }, .SYNCHRONIZE = true },
            .GENERIC = .{ .WRITE = true, .READ = true },
        },
        &.{
            .ObjectName = @constCast(&win32.UNICODE_STRING.init(
                win32.AFD.DEVICE_NAME ++ .{ '\\', 'E', 'n', 'd', 'p', 'o', 'i', 'n', 't' },
            )),
        },
        &iosb,
        null,
        .{},
        .{ .READ = true, .WRITE = true },
        .OPEN_IF,
        .{ .IO = .ASYNCHRONOUS },
        &win32.AFD.OPEN_PACKET.FULL_EA_INFORMATION{
            .Value = .{
                .EndpointType = .{}, // stream: no CONNECTIONLESS / MESSAGEMODE / RAW bits
                .GroupID = 0,
                .AddressFamily = family,
                .SocketType = @bitCast(mode_protocol[0]),
                .Protocol = @bitCast(mode_protocol[1]),
                .TransportDeviceNameLength = 0,
                .TransportDeviceName = undefined,
            },
        },
        @sizeOf(win32.AFD.OPEN_PACKET.FULL_EA_INFORMATION),
    )) {
        .SUCCESS => return handle,
        .PROTOCOL_NOT_SUPPORTED => return error.AddressFamilyUnsupported,
        .NO_SUCH_FILE => return error.ProtocolUnsupportedByAddressFamily,
        else => |status| return win32.unexpectedStatus(status),
    }
}

/// AFD.SOCKOPT wrapper (mirror of Threaded.socketOptionAfd :12052).
pub fn afdSockopt(
    h: HANDLE,
    mode: win32.AFD.SOCKOPT_INFO.Mode,
    level: i32,
    optname: u32,
    opt_val: []const u8,
) !void {
    _ = try syncAfdControl(h, win32.IOCTL.AFD.SOCKOPT, @as([]const u8, @ptrCast(&win32.AFD.SOCKOPT_INFO{
        .mode = mode,
        .level = level,
        .optname = optname,
        .optval = opt_val.ptr,
        .optlen = opt_val.len,
    })), &.{});
}

/// AFD.BIND wrapper (bindSocketIpAfd / bindSocketUnixAfd shape :12402/:12421):
/// `addr_bytes` is a raw sockaddr (family + payload), truncated to its length.
pub fn afdBind(h: HANDLE, mode: win32.AFD.BIND_INFO.MODE, addr_bytes: []const u8) !void {
    const Storage = extern struct { info: win32.AFD.BIND_INFO, addr: [128]u8 };
    var storage: Storage = .{ .info = .{ .Mode = mode }, .addr = undefined };
    @memcpy(storage.addr[0..addr_bytes.len], addr_bytes);
    _ = try syncAfdControl(
        h,
        win32.IOCTL.AFD.BIND,
        @as([]const u8, @ptrCast(&storage))[0 .. @offsetOf(Storage, "addr") + addr_bytes.len],
        @as([]u8, @ptrCast(&storage.addr)),
    );
}

/// One overlapped AFD.SEND, synchronous wait (syncAfdControl shape). Returns
/// bytes sent; short sends are possible — callers loop.
fn afdSend(h: HANDLE, bytes: []const u8) !usize {
    var iovecs = [_]win32.AFD.WSABUF(.@"const"){.{ .len = @intCast(bytes.len), .buf = bytes.ptr }};
    var info: win32.AFD.SEND_INFO = .{
        .BufferArray = &iovecs,
        .BufferCount = 1,
        .AfdFlags = .{ .NO_FAST_IO = true, .OVERLAPPED = true },
        .TdiFlags = .{},
    };
    return dataTransferAfd(h, win32.IOCTL.AFD.SEND, std.mem.asBytes(&info), null, 0);
}

/// One overlapped AFD.RECEIVE, synchronous wait. Disconnect/reset statuses
/// report 0 (EOF-ish); genuinely unexpected statuses error.
fn afdRecv(h: HANDLE, buf: []u8) !usize {
    var iovecs = [_]win32.AFD.WSABUF(.@"var"){.{ .len = @intCast(buf.len), .buf = buf.ptr }};
    var info: win32.AFD.RECV_INFO = .{
        .BufferArray = &iovecs,
        .BufferCount = 1,
        .AfdFlags = .{ .NO_FAST_IO = true, .OVERLAPPED = true },
        .TdiFlags = .{ .NORMAL = true },
    };
    const out_ptr: ?[*]u8 = if (buf.len > 0) buf.ptr else null;
    return dataTransferAfd(
        h,
        win32.IOCTL.AFD.RECEIVE,
        std.mem.asBytes(&info),
        out_ptr,
        buf.len,
    );
}

/// Issue one data IOCTL, wait for APC completion, map status → byte count.
fn dataTransferAfd(h: HANDLE, code: win32.CTL_CODE, in: []const u8, out: ?[*]u8, out_len: usize) !usize {
    var iosb: win32.IO_STATUS_BLOCK = undefined;
    var done = false;
    switch (ntdll.NtDeviceIoControlFile(
        h,
        null,
        &afdDoneApc,
        &done,
        &iosb,
        code,
        in.ptr,
        @intCast(in.len),
        out,
        @intCast(out_len),
    )) {
        .PENDING, .SUCCESS => while (!done) waitForApcOrAlert(),
        else => |status| return win32.unexpectedStatus(status),
    }
    switch (iosb.u.Status) {
        .SUCCESS => return iosb.Information,
        // Peer closed / hard reset read as EOF-0, matching posix.zig's
        // silent ConnectionResetByPeer handling and protocol.readExact's
        // n==0 → EndOfStream contract.
        .GRACEFUL_DISCONNECT, .REMOTE_DISCONNECT, .CONNECTION_RESET => return 0,
        else => |status| return win32.unexpectedStatus(status),
    }
}

/// Format into either an allocator (returns owned slice) or a `[]u8` buffer (returns sub-slice).
pub fn print(out: anytype, comptime fmt: []const u8, args: anytype) ![]const u8 {
    if (@TypeOf(out) == std.mem.Allocator)
        return std.fmt.allocPrint(out, fmt, args)
    else
        return std.fmt.bufPrint(out, fmt, args) catch error.NameTooLong;
}

// =============================================================================
// Bucket 1 — raw primitives (router: `pub const X = impl.X`)
// =============================================================================

// Signal set passed to `kill`. No real signals on Windows [Signals]. Callers
// use exactly four values (grep `platform.SIG.`): INT, TERM, KILL, USR1. USR1
// is client-only (live-status repaint); TERM/KILL both mean "kill it" via
// TerminateProcess. IGN/PIPE are posix.zig-internal, never cross on Windows.
pub const SIG = enum { INT, TERM, KILL, USR1 };

pub fn getpid() DWORD {
    return win32.GetCurrentProcessId();
}

// No direct analog — Windows doesn't track PPID. Callers must tolerate 0 /
// null (getParentName also returns null). Hack if ever needed:
// NtQueryInformationProcess with ProcessBasicInformation (ntdll, unstable).
pub fn getppid() DWORD {
    return 0;
}

// Low-level write. On POSIX this backs posix_signals.zig; on Windows every
// current caller passes an AFD socket (worker.zig / main.zig streams), so it
// routes through the SEND loop like platform.write does there.
pub fn write(fd: posix.fd_t, buf: []const u8) void {
    socketWrite(fd, buf);
}

// No general kill(pid, sig) on Windows: every signal is TerminateProcess
// (the always-"SIGKILL" primitive). INT deliberately ≡ TERM (option A):
// GenerateConsoleCtrlEvent only reaches console-sharing process groups, and
// spawned workers aren't one. USR1 has no callers on Windows (verified) —
// no-op success. Returns 0 success / 1 failure (bsd.zig shape).
pub fn kill(pid: posix.pid_t, sig: SIG) usize {
    switch (sig) {
        .KILL, .TERM, .INT => {},
        .USR1 => return 0,
    }
    const h = openProcessFor(pid, PROCESS_TERMINATE) orelse return 1;
    defer win32.CloseHandle(h);
    return if (TerminateProcess(h, 1).toBool()) 0 else 1;
}

// → NtCreateFile(\Device\Afd\Endpoint): create the AFD stream endpoint that
// underlies every Windows socket (mirror of Threaded.openSocketAfd,
// Threaded.zig:12348). No WSAStartup — AFD sits below WinSock2 entirely.
pub fn rawSocket(family: u32, sock_type: u32) ?posix.fd_t {
    if (sock_type != posix.SOCK.STREAM) {
        std.debug.print("rawSocket: only SOCK.STREAM supported (got {d})\n", .{sock_type});
        return null;
    }
    return openAfdEndpoint(@intCast(family)) catch |err| {
        std.debug.print("rawSocket: AFD endpoint creation failed: {}\n", .{err});
        return null;
    };
}

fn connectAfd(h: HANDLE, addr: *const posix.sockaddr, len: posix.socklen_t) !void {
    switch (addr.family) {
        posix.AF.INET, posix.AF.INET6 => {
            var one: bool = true;
            try afdSockopt(h, .set, win32.ws2_32.SOL.SOCKET, win32.ws2_32.SO.REUSE_UNICASTPORT, @as([]u8, @ptrCast(&one))[0..1]);
            // Bind unspecified(:0), same family as the target
            // (netConnectIpWindows :12103-12109 shape).
            var bind_addr: [28]u8 = [_]u8{0} ** 28;
            const blen: usize = switch (addr.family) {
                posix.AF.INET => blk: {
                    std.mem.writeInt(u16, bind_addr[0..2], posix.AF.INET, .little);
                    break :blk @sizeOf(posix.sockaddr.in);
                },
                else => blk: {
                    std.mem.writeInt(u16, bind_addr[0..2], posix.AF.INET6, .little);
                    break :blk @sizeOf(posix.sockaddr.in6);
                },
            };
            try afdBind(h, .Active, bind_addr[0..blen]);
        },
        posix.AF.UNIX => {
            if (!std.Io.net.has_unix_sockets) return error.AddressFamilyUnsupported;
            const un: *const posix.sockaddr.un = @ptrCast(@alignCast(addr));
            const path_len = std.mem.indexOfScalar(u8, &un.path, 0) orelse un.path.len;
            if (path_len == 0) return error.AbstractNamespaceUnsupported;
            // Filesystem paths publish their name via the SO.UNIX_PATH
            // special-option (netConnectUnixWindows :12154-12169 shape).
            const wps = try wthreaded.sliceToPrefixedFileW(null, un.path[0..path_len], .{ .allow_relative = false });
            var unix_path: win32.AFD.SOCKOPT_INFO.UNIX_PATH = .{ .Path = undefined };
            @memcpy(unix_path.Path[0..wps.len], wps.data[0..wps.len]);
            unix_path.Path[wps.len] = 0;
            try afdSockopt(
                h,
                .special,
                0,
                win32.ws2_32.SO.UNIX_PATH,
                @as([]u8, @ptrCast(&unix_path))[0 .. @offsetOf(win32.AFD.SOCKOPT_INFO.UNIX_PATH, "Path") + @sizeOf(win32.WCHAR) * wps.len],
            );
            // Empty-name bind: full-length zeroed sockaddr_un with just the
            // family set (addressUnixToPosix("") shape — Windows AFD wants
            // the whole struct).
            var empty_un: posix.sockaddr.un = std.mem.zeroes(posix.sockaddr.un);
            empty_un.family = posix.AF.UNIX;
            try afdBind(h, .Unix, @as([*]const u8, @ptrCast(&empty_un))[0..@sizeOf(posix.sockaddr.un)]);
        },
        else => return error.AddressFamilyUnsupported,
    }
    // CONNECT input = { Reserved0: [3]usize = 0 } followed by the sockaddr
    // bytes (netConnect*Windows :12110-12116 / :12176-12182 shape).
    const ConnectStorage = extern struct { reserved: [3]usize, addr: [128]u8 };
    var storage: ConnectStorage = .{ .reserved = @splat(0), .addr = undefined };
    @memcpy(storage.addr[0..len], @as([*]const u8, @ptrCast(addr))[0..len]);
    _ = try syncAfdControl(
        h,
        win32.IOCTL.AFD.CONNECT,
        @as([]const u8, @ptrCast(&storage))[0 .. @offsetOf(ConnectStorage, "addr") + len],
        &.{},
    );
}

// → AFD.CONNECT IOCTL (see connectAfd). Takes the same POSIX-ish args as the
// linux impl; errors are logged and reported as `false` (matches sibling
// primitives' bool contract).
pub fn rawConnect(fd: posix.fd_t, addr: *const posix.sockaddr, len: posix.socklen_t) bool {
    connectAfd(fd, addr, len) catch |err| {
        std.debug.print("rawConnect failed: {}\n", .{err});
        return false;
    };
    return true;
}

// → CloseHandle — our sockets are plain HANDLEs (AFD endpoints), so there is
// no closesocket distinction at all.
pub fn rawClose(fd: posix.fd_t) void {
    win32.CloseHandle(fd);
}

// No /run/user/$UID on Windows → %LOCALAPPDATA%\julia-daemon. The env var is
// set for every interactive login; read it std-only with NO libc (build.jl
// links none): `std.process.Environ{ .block = .global }` reads the live
// process env from the PEB via ntdll (Environ.zig:488) — the same mechanism
// `std.process.Init.environ_map` is built from, so nothing needs plumbing
// through this signature. getAlloc returns owned WTF-8 []u8; errors
// OutOfMemory | EnvironmentVariableMissing | InvalidWtf8. Persisted per-user,
// NOT auto-cleaned like /run/user — the cleanupRuntimeDir wart still has work
// to do (named pipes are kernel objects, auto-cleaned on handle close, so no
// stale-inode problem). Keep the POSIX arg shape for router symmetry, ignore
// xdg_runtime_dir and home.
pub fn defaultRuntimeDir(out: anytype, _: ?[]const u8, _: ?[]const u8) ![]const u8 {
    const env: std.process.Environ = .{ .block = .global };
    const appdata = try env.getAlloc(std.heap.page_allocator, "LOCALAPPDATA");
    defer std.heap.page_allocator.free(appdata);
    return print(out, "{s}/julia-daemon", .{appdata});
}

// → GetStdHandle(STD_INPUT_HANDLE / STDOUT / STDERR). Returns a HANDLE, not a
// small int. The router calls these as fns on Windows (vs consts on POSIX), so
// they must stay fns. GetStdHandle is cheap and per-process-stable — no caching.
pub fn getStdinHandle() posix.fd_t {
    return GetStdHandle(STD_INPUT_HANDLE);
}
pub fn getStdoutHandle() posix.fd_t {
    return GetStdHandle(STD_OUTPUT_HANDLE);
}
pub fn getStderrHandle() posix.fd_t {
    return GetStdHandle(STD_ERROR_HANDLE);
}

// Raw terminal mode → GetConsoleMode/SetConsoleMode on a console handle.
// raw = clear ENABLE_LINE_INPUT + ENABLE_ECHO_INPUT. Restore = re-set the saved
// mode (keep a saved-mode var like posix.zig's `saved_termios`). NOTE: the
// router binds `setRawMode = impl.setRawMode` on Windows (NOT the shared
// no-fd `setRawModeStdin` wrapper), so this takes the fd, not nothing.
const ENABLE_LINE_INPUT: DWORD = 0x0002;
const ENABLE_ECHO_INPUT: DWORD = 0x0004;
var saved_mode: ?DWORD = null;
pub fn setRawMode(stdin: posix.fd_t, raw: bool) void {
    if (raw) {
        var mode: DWORD = undefined;
        if (!GetConsoleMode(stdin, &mode).toBool()) {
            return;
        }
        if (saved_mode == null) saved_mode = mode;
        _ = SetConsoleMode(stdin, mode & ~(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT));
    } else if (saved_mode) |mode| {
        _ = SetConsoleMode(stdin, mode);
        saved_mode = null;
    }
}

// =============================================================================
// Bucket 2 — shared logic (router: `pub const X = shared.X`, where on Windows
// shared === impl). Must be re-implemented, not copied: they call POSIX-only
// API on POSIX. Reference shapes: posix.zig.
// =============================================================================

// → AFD.SEND. Loop for short writes (match POSIX impl).
pub fn socketWrite(fd: posix.fd_t, buf: []const u8) void {
    var sent: usize = 0;
    while (sent < buf.len) {
        const n = afdSend(fd, buf[sent..]) catch {
            // posix.zig keeps socket writes silent on failure.
            return;
        };
        if (n == 0) return;
        sent += n;
    }
}

// → AFD.RECEIVE. Return 0 on error (matches posix.zig behavior —
// ConnectionResetByPeer silent, others logged).
pub fn socketRead(fd: posix.fd_t, buf: []u8) usize {
    return afdRecv(fd, buf) catch |err| {
        std.debug.print("socketRead error: {}\n", .{err});
        return 0;
    };
}

// Every handle we manage is a plain HANDLE (AFD endpoints included), so this
// is just CloseHandle — no socket-vs-file dispatch needed. Kept as its own fn
// for router symmetry with POSIX.
pub fn close(fd: posix.fd_t) void {
    win32.CloseHandle(fd);
}

// → numeric Windows PID for display/logging. Child.id on Windows is the
// process HANDLE (std.process.Child.Id = HANDLE, "On Windows this is the
// hProcess"), not a pid — GetProcessId recovers the number callers print.
pub fn getChildPid(child: anytype) DWORD {
    return if (child.id) |process| GetProcessId(process) else 0;
}

pub const WaitPidResult = struct { pid: posix.pid_t, exited: bool };

// POSIX waitpid(WNOHANG) equivalent: poll the process handle with a zero
// timeout. The POSIX impl takes a bare pid; we OpenProcess per call — same
// order as Linux's /proc reaping cost and no pid→handle bookkeeping.
// Process gone (open fails) reads as "exited", matching ECHILD treatment.
pub fn waitpidNonBlocking(pid: posix.pid_t) WaitPidResult {
    const h = openProcessFor(pid, PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION) orelse
        return .{ .pid = pid, .exited = true };
    defer win32.CloseHandle(h);
    const state = WaitForSingleObject(h, 0);
    return .{ .pid = pid, .exited = state != WAIT_TIMEOUT };
}

pub const ProcessStats = struct { mem_bytes: u64, cpu_seconds: f64 };

// FILETIME is two DWORDs of 100ns units since 1601 — durations only need the
// raw count, not the epoch offset.
fn filetimeToU64(ft: FILETIME) u64 {
    return @as(u64, ft.dwHighDateTime) << 32 | @as(u64, ft.dwLowDateTime);
}

// → GetProcessMemoryInfo (psapi) → PROCESS_MEMORY_COUNTERS_EX.WorkingSetSize
// (RSS-equivalent) + GetProcessTimes → kernel+user seconds.
pub fn getProcessStats(pid: posix.pid_t) ?ProcessStats {
    const h = openProcessFor(pid, PROCESS_QUERY_LIMITED_INFORMATION) orelse return null;
    defer win32.CloseHandle(h);

    var pmc = std.mem.zeroes(PROCESS_MEMORY_COUNTERS_EX);
    pmc.cb = @sizeOf(PROCESS_MEMORY_COUNTERS_EX);
    if (!GetProcessMemoryInfo(h, &pmc, pmc.cb).toBool()) return null;

    var creation: FILETIME = undefined;
    var exit_t: FILETIME = undefined;
    var kernel: FILETIME = undefined;
    var user: FILETIME = undefined;
    if (!GetProcessTimes(h, &creation, &exit_t, &kernel, &user).toBool()) return null;

    const cpu_100ns: f64 = @floatFromInt(filetimeToU64(kernel) + filetimeToU64(user));
    return .{
        .mem_bytes = pmc.WorkingSetSize,
        .cpu_seconds = cpu_100ns / 10_000_000.0,
    };
}

// false: WorkingSetSize is RSS, not USS. A true USS-equivalent needs a
// VirtualQueryEx walk. Match Linux's `false` so the eviction pass calls
// processReclaimable as a fallback.
pub const mem_is_reclaimable = false;

// null unless we implement the VirtualQueryEx walk. Returning null makes the
// caller fall back to RSS (mem_bytes) — the documented escape hatch in posix.zig.
pub fn processReclaimable(pid: posix.pid_t) ?u64 {
    _ = pid;
    return null;
}

pub const MemInfo = struct { available: u64, total: u64 };

// No PSI on Windows → null. pressure.zig's PSI branch goes inert and falls
// back to the level path (readMemInfo). TTL-only if readMemInfo also returns null.
pub fn readPsiSomeAvg10() ?f64 {
    return null;
}

// → GlobalMemoryStatusEx → MEMORYSTATUSEX.ullAvailPhys / .ullTotalPhys.
// Set .dwLength = @sizeOf(MEMORYSTATUSEX) before the call — load-bearing,
// the API returns ERROR_INVALID_PARAMETER if dwLength is wrong.
pub fn readMemInfo() ?MemInfo {
    var ms = std.mem.zeroes(MEMORYSTATUSEX);
    ms.dwLength = @sizeOf(MEMORYSTATUSEX);
    if (!GlobalMemoryStatusEx(&ms).toBool()) return null;
    return .{ .available = ms.ullAvailPhys, .total = ms.ullTotalPhys };
}

// No PPID tracking → null. bsd.zig already returns null; the caller (orphan-
// worker detection) must tolerate null. Grep to verify it's only used there.
pub fn getParentName(pid: posix.pid_t, buf: []u8) ?[]const u8 {
    _ = pid;
    _ = buf;
    return null;
}

// → AFD.SOCKOPT with SOL_SOCKET/SO_RCVTIMEO, value = DWORD milliseconds
// (NOT a timeval) — multiply seconds by 1000. Silently ignore errors
// (matches posix.zig `catch {}`).
pub fn setRecvTimeout(socket: posix.fd_t, seconds: u32) void {
    const timeout_ms: DWORD = seconds * 1000;
    afdSockopt(socket, .set, win32.ws2_32.SOL.SOCKET, win32.ws2_32.SO.RCVTIMEO, std.mem.asBytes(&timeout_ms)) catch {};
}

// → AFD.SOCKOPT with IPPROTO_TCP/TCP_NODELAY, &c_int{1}. Same numeric
// constants as POSIX (6, 1).
pub fn setTcpNodelay(socket: posix.fd_t) void {
    const one: c_int = 1;
    afdSockopt(socket, .set, win32.ws2_32.IPPROTO.TCP, win32.ws2_32.TCP.NODELAY, std.mem.asBytes(&one)) catch {};
}

// → GetConsoleScreenBufferInfo(handle) → CONSOLE_SCREEN_BUFFER_INFO;
// rows = srWindow.Bottom - Top + 1, cols = srWindow.Right - Left + 1. null if
// not a console handle.
pub fn getTerminalSize(fd: posix.fd_t) ?struct { rows: u16, cols: u16 } {
    var csbi = std.mem.zeroes(CONSOLE_SCREEN_BUFFER_INFO);
    if (!GetConsoleScreenBufferInfo(fd, &csbi).toBool()) return null;
    return .{
        .rows = @intCast(csbi.srWindow.Bottom - csbi.srWindow.Top + 1),
        .cols = @intCast(csbi.srWindow.Right - csbi.srWindow.Left + 1),
    };
}

// → GetFileType(handle) == FILE_TYPE_CHAR.
pub fn isatty(fd: posix.fd_t) bool {
    return GetFileType(fd) == FILE_TYPE_CHAR;
}

// Client-side handler routing SIGINT between raw/cooked modes. This struct is
// type-safe as-is (no POSIX API in it) — copy verbatim from posix.zig.
pub const SignalHandler = struct {
    sockets_ptr: *anyopaque,
    write_fn: *const fn (*anyopaque, []const u8) void,
    notify_exit_fn: *const fn () void,
    notify_interrupt_fn: *const fn () void,
    pub fn writeStdio(self: SignalHandler, data: []const u8) void {
        self.write_fn(self.sockets_ptr, data);
    }
    pub fn notifyExit(self: SignalHandler) void {
        self.notify_exit_fn();
    }
    pub fn notifyInterrupt(self: SignalHandler) void {
        self.notify_interrupt_fn();
    }
};

// → SetConsoleCtrlHandler(handler_fn, TRUE). Runs in its own kernel-spawned
// thread — no self-pipe, no async-signal-safety, normal sync usable. Map:
//   CTRL_C_EVENT / CTRL_BREAK_EVENT → raw: writeStdio("\x03"), cooked: notifyInterrupt()
//   CTRL_CLOSE_EVENT / CTRL_LOGOFF_EVENT / CTRL_SHUTDOWN_EVENT → notifyExit()
// No SIGPIPE equivalent needed (no SIGPIPE on Windows; broken-socket writes
// fail via the AFD.SEND status).
pub fn registerSignalHandlers(handler: SignalHandler) void {
    _ = handler;
}

// =============================================================================
// Excluded — the router binds these inline on Windows, NOT through impl. Do
// NOT define here; doing so would be dead code the router never reaches.
//   - isLoopback       → main.zig inline no-op (returns true) on Windows
//   - setWorkerRawMode → main.zig inline no-op (fn f(_: bool) void {}) on Windows
// =============================================================================
