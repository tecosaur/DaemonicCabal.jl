// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0
//
// Windows platform module: the whole `platform` surface, since nothing in
// posix.zig applies. Every socket is an AFD endpoint handle and every local
// socket a named-pipe instance, both plain overlapped HANDLEs driven through
// ntdll, dispatched on a per-handle kind. There is no ws2_32 layer.
//
// A handle the loop has associated with its port rejects APC-routed I/O, so a
// synchronous operation on one is issued with an Event and a heap token that
// the loop reaps when the matching completion packet surfaces (`reapSyncOp`).

const std = @import("std");
const builtin = @import("builtin");
const win32 = std.os.windows;
const ntdll = win32.ntdll;
const posix = std.posix;
const Io = std.Io;
const Allocator = std.mem.Allocator;
const protocol = @import("../protocol.zig");

const BOOL = win32.BOOL;
const DWORD = win32.DWORD;
const ULONG = win32.ULONG;
const WORD = win32.WORD;
const HANDLE = win32.HANDLE;
const FILETIME = win32.FILETIME;

// =============================================================================
// Win32 bindings absent from std.os.windows. kernel32/psapi/advapi32 link
// without -l flags. Everything the event loops need is pub.
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
pub const INFINITE: DWORD = 0xFFFFFFFF;
const WAIT_OBJECT_0: DWORD = 0x00000000;
const WAIT_TIMEOUT: DWORD = 0x00000102;
const WAIT_FAILED: DWORD = 0xFFFFFFFF;

pub const HANDLER_ROUTINE = fn (dwCtrlType: DWORD) callconv(.winapi) BOOL;
pub const PHANDLER_ROUTINE = *const HANDLER_ROUTINE;
pub const WAITORTIMERCALLBACK = *const fn (lpParameter: ?*anyopaque, timer_or_wait_fired: BOOL) callconv(.winapi) void;

// IO_STATUS_BLOCK and OVERLAPPED share their first two fields, so the iosb
// handed to an Nt* call comes back from the completion port as *OVERLAPPED.
pub const OVERLAPPED = extern struct {
    Internal: usize,
    InternalHigh: usize,
    Union: extern struct { Offset: u32, OffsetHigh: u32 },
    hEvent: HANDLE,
};

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

pub const SMALL_RECT = extern struct { Left: i16, Top: i16, Right: i16, Bottom: i16 };

pub const CONSOLE_SCREEN_BUFFER_INFO = extern struct {
    dwSize: win32.COORD,
    dwCursorPosition: win32.COORD,
    wAttributes: WORD,
    srWindow: SMALL_RECT,
    dwMaximumWindowSize: win32.COORD,
};

pub extern "kernel32" fn GetStdHandle(nStdHandle: DWORD) HANDLE;
pub extern "kernel32" fn GetConsoleMode(hConsoleHandle: HANDLE, lpMode: *DWORD) BOOL;
pub extern "kernel32" fn SetConsoleMode(hConsoleHandle: HANDLE, dwMode: DWORD) BOOL;
pub extern "kernel32" fn GetConsoleScreenBufferInfo(hConsoleOutput: HANDLE, lpConsoleScreenBufferInfo: *CONSOLE_SCREEN_BUFFER_INFO) BOOL;
pub extern "kernel32" fn GlobalMemoryStatusEx(lpBuffer: *MEMORYSTATUSEX) BOOL;
pub extern "kernel32" fn TerminateProcess(hProcess: HANDLE, uExitCode: u32) BOOL;
pub extern "kernel32" fn WaitForSingleObject(hHandle: HANDLE, dwMilliseconds: DWORD) DWORD;
pub extern "kernel32" fn OpenProcess(dwDesiredAccess: DWORD, bInheritHandle: BOOL, dwProcessId: DWORD) ?HANDLE;
pub extern "kernel32" fn QueryFullProcessImageNameW(hProcess: HANDLE, dwFlags: DWORD, lpExeName: [*]u16, lpdwSize: *DWORD) BOOL;
pub extern "kernel32" fn CancelIoEx(hFile: HANDLE, lpOverlapped: ?*OVERLAPPED) BOOL;
pub extern "kernel32" fn WriteFile(hFile: HANDLE, lpBuffer: *const anyopaque, nNumberOfBytesToWrite: DWORD, lpNumberOfBytesWritten: ?*DWORD, lpOverlapped: ?*OVERLAPPED) BOOL;
pub extern "kernel32" fn ReadFile(hFile: HANDLE, lpBuffer: [*]u8, nNumberOfBytesToRead: DWORD, lpNumberOfBytesRead: ?*DWORD, lpOverlapped: ?*OVERLAPPED) BOOL;
pub extern "kernel32" fn GetFileType(hFile: HANDLE) DWORD;
pub extern "kernel32" fn SetConsoleCtrlHandler(handler_routine: ?PHANDLER_ROUTINE, add: BOOL) BOOL;
pub extern "kernel32" fn GetProcessTimes(hProcess: HANDLE, lpCreationTime: *FILETIME, lpExitTime: *FILETIME, lpKernelTime: *FILETIME, lpUserTime: *FILETIME) BOOL;
pub extern "kernel32" fn GetProcessId(hProcess: HANDLE) DWORD;
pub extern "kernel32" fn SetConsoleOutputCP(wCodePageID: DWORD) BOOL;
pub extern "kernel32" fn GetConsoleOutputCP() DWORD;
pub extern "kernel32" fn SetConsoleCP(wCodePageID: DWORD) BOOL;
pub extern "kernel32" fn GetConsoleCP() DWORD;
pub extern "kernel32" fn CreateEventW(lpEventAttributes: ?*anyopaque, bManualReset: DWORD, bInitialState: DWORD, lpName: ?[*:0]const u16) ?HANDLE;
pub extern "kernel32" fn CreateIoCompletionPort(FileHandle: HANDLE, ExistingCompletionPort: ?HANDLE, CompletionKey: usize, NumberOfConcurrentThreads: DWORD) ?HANDLE;
pub extern "kernel32" fn GetQueuedCompletionStatus(CompletionPort: HANDLE, lpNumberOfBytesTransferred: *DWORD, lpCompletionKey: *usize, lpOverlapped: ?*?*OVERLAPPED, dwMilliseconds: DWORD) BOOL;
pub extern "kernel32" fn PostQueuedCompletionStatus(CompletionPort: HANDLE, dwNumberOfBytesTransferred: DWORD, dwCompletionKey: usize, lpOverlapped: ?*OVERLAPPED) BOOL;
pub extern "kernel32" fn CreateNamedPipeW(lpName: [*:0]const u16, dwOpenMode: DWORD, dwPipeMode: DWORD, nMaxInstances: DWORD, nOutBufferSize: DWORD, nInBufferSize: DWORD, nDefaultTimeOut: DWORD, lpSecurityAttributes: ?*win32.SECURITY_ATTRIBUTES) ?HANDLE;
pub extern "kernel32" fn AcquireSRWLockExclusive(SRWLock: *win32.SRWLOCK) void;
pub extern "kernel32" fn ReleaseSRWLockExclusive(SRWLock: *win32.SRWLOCK) void;
extern "kernel32" fn Sleep(dwMilliseconds: DWORD) void;
extern "kernel32" fn GetCurrentProcess() HANDLE;
extern "kernel32" fn DuplicateHandle(hSourceProcessHandle: HANDLE, hSourceHandle: HANDLE, hTargetProcessHandle: HANDLE, lpTargetHandle: *HANDLE, dwDesiredAccess: DWORD, bInheritHandle: BOOL, dwOptions: DWORD) BOOL;
extern "psapi" fn GetProcessMemoryInfo(hProcess: HANDLE, ppsmemCounters: *PROCESS_MEMORY_COUNTERS_EX, cb: DWORD) BOOL;
extern "advapi32" fn GetUserNameW(lpBuffer: [*]u16, pcbBuffer: *DWORD) BOOL;
extern "advapi32" fn ConvertStringSecurityDescriptorToSecurityDescriptorW(StringSecurityDescriptor: [*:0]const u16, StringSDRevision: DWORD, SecurityDescriptor: *?*anyopaque, SecurityDescriptorSize: ?*ULONG) BOOL;

// =============================================================================
// Handle registry. A handle is opaque, so its recorded kind decides which
// syscalls move its bytes, and its port association decides how a synchronous
// operation on it must be issued. Locked: touched from several threads.
// =============================================================================

/// A pipe_listener turning readable means a client connected to it.
pub const HandleKind = enum { afd, pipe, pipe_listener };

const IoStatusToken = struct { iosb: win32.IO_STATUS_BLOCK };

var handle_kinds: std.AutoHashMapUnmanaged(usize, HandleKind) = .empty;
var associated: std.AutoHashMapUnmanaged(usize, void) = .empty;
var read_timeouts_ms: std.AutoHashMapUnmanaged(usize, u32) = .empty;
var sync_tokens: std.AutoHashMapUnmanaged(usize, *IoStatusToken) = .empty;
var registry_lock: win32.SRWLOCK = win32.SRWLOCK_INIT;

fn lockRegistry() void {
    AcquireSRWLockExclusive(&registry_lock);
}
fn unlockRegistry() void {
    ReleaseSRWLockExclusive(&registry_lock);
}

pub fn handleKind(fd: HANDLE) HandleKind {
    lockRegistry();
    defer unlockRegistry();
    return handle_kinds.get(@intFromPtr(fd)) orelse .afd;
}

fn setKind(fd: HANDLE, kind: HandleKind) void {
    lockRegistry();
    defer unlockRegistry();
    handle_kinds.put(std.heap.page_allocator, @intFromPtr(fd), kind) catch {};
}

pub fn isAssociated(fd: HANDLE) bool {
    lockRegistry();
    defer unlockRegistry();
    return associated.contains(@intFromPtr(fd));
}

/// Idempotent: a handle joins a port once for its lifetime.
pub fn associate(port: HANDLE, fd: HANDLE) !void {
    if (isAssociated(fd)) return;
    if (CreateIoCompletionPort(fd, port, 0, 0) == null) return error.IocpAssociateFailed;
    lockRegistry();
    defer unlockRegistry();
    associated.put(std.heap.page_allocator, @intFromPtr(fd), {}) catch {};
}

/// Record a handle the caller associated itself.
pub fn markAssociated(fd: HANDLE) void {
    lockRegistry();
    defer unlockRegistry();
    associated.put(std.heap.page_allocator, @intFromPtr(fd), {}) catch {};
}

fn forgetHandle(fd: HANDLE) void {
    lockRegistry();
    defer unlockRegistry();
    _ = associated.remove(@intFromPtr(fd));
    _ = handle_kinds.remove(@intFromPtr(fd));
    _ = read_timeouts_ms.remove(@intFromPtr(fd));
}

/// Remove one completed sync-op token. True when `ovl` belonged to a
/// synchronous operation, whose result was already consumed via its Event.
pub fn reapSyncOp(ovl: *OVERLAPPED) bool {
    lockRegistry();
    const kv = sync_tokens.fetchRemove(@intFromPtr(ovl));
    unlockRegistry();
    const entry = kv orelse return false;
    std.heap.page_allocator.destroy(entry.value);
    return true;
}

// One auto-reset event per synchronous operation: the binaries are built
// -fsingle-threaded, so a threadlocal event would be shared with the helper
// threads and let them wake each other.
fn ensureEvent() !HANDLE {
    return CreateEventW(null, 0, 0, null) orelse error.EventCreateFailed;
}

// =============================================================================
// Synchronous I/O
// =============================================================================

fn afdDoneApc(userdata: ?*anyopaque, _: *win32.IO_STATUS_BLOCK, _: ULONG) align(2) callconv(.winapi) void {
    const done: *bool = @ptrCast(userdata.?);
    done.* = true;
}

fn waitForApcOrAlert() void {
    const forever: win32.LARGE_INTEGER = std.math.minInt(win32.LARGE_INTEGER);
    _ = ntdll.NtDelayExecution(.TRUE, &forever);
}

/// Map an AFD connect status to an error callers can branch on.
pub fn mapAfdStatus(status: win32.NTSTATUS) anyerror {
    return switch (status) {
        .IO_TIMEOUT, .TIMEOUT => error.ConnectionTimedOut,
        .CONNECTION_REFUSED => error.ConnectionRefused,
        .NETWORK_UNREACHABLE => error.NetworkUnreachable,
        .HOST_UNREACHABLE => error.HostUnreachable,
        else => win32.unexpectedStatus(status),
    };
}

pub fn syncAfdControl(h: HANDLE, code: win32.CTL_CODE, in: []const u8, out: []u8) !usize {
    if (isAssociated(h)) return syncViaPort(h, code, in, if (out.len > 0) out.ptr else null, out.len);
    var iosb: win32.IO_STATUS_BLOCK = undefined;
    var done = false;
    switch (ntdll.NtDeviceIoControlFile(h, null, &afdDoneApc, &done, &iosb, code, if (in.len > 0) in.ptr else null, @intCast(in.len), if (out.len > 0) out.ptr else null, @intCast(out.len))) {
        .PENDING, .SUCCESS => while (!done) waitForApcOrAlert(),
        else => |status| return mapAfdStatus(status),
    }
    return switch (iosb.u.Status) {
        .SUCCESS => iosb.Information,
        else => |status| mapAfdStatus(status),
    };
}

/// Synchronous completion on a port-associated handle: issue with an Event,
/// wait on it, and leave the token for the loop to reap with the packet.
fn syncViaPort(h: HANDLE, code: win32.CTL_CODE, in: []const u8, out: ?[*]u8, out_len: usize) !usize {
    const tok = try std.heap.page_allocator.create(IoStatusToken);
    tok.* = .{ .iosb = undefined };
    const ev = ensureEvent() catch |err| {
        std.heap.page_allocator.destroy(tok);
        return err;
    };
    defer win32.CloseHandle(ev);
    lockRegistry();
    sync_tokens.put(std.heap.page_allocator, @intFromPtr(&tok.iosb), tok) catch {
        unlockRegistry();
        std.heap.page_allocator.destroy(tok);
        return error.OutOfMemory;
    };
    unlockRegistry();
    const issued = ntdll.NtDeviceIoControlFile(h, ev, null, @ptrCast(&tok.iosb), &tok.iosb, code, if (in.len > 0) in.ptr else null, @intCast(in.len), if (out_len > 0) out else null, @intCast(out_len));
    switch (issued) {
        .SUCCESS, .PENDING => {},
        else => |status| {
            // No IRP in flight, so no packet will come: the token is ours again.
            lockRegistry();
            _ = sync_tokens.remove(@intFromPtr(&tok.iosb));
            unlockRegistry();
            std.heap.page_allocator.destroy(tok);
            return win32.unexpectedStatus(status);
        },
    }
    if (WaitForSingleObject(ev, INFINITE) == WAIT_FAILED) return error.EventWaitFailed;
    return switch (tok.iosb.u.Status) {
        .SUCCESS => tok.iosb.Information,
        .GRACEFUL_DISCONNECT, .REMOTE_DISCONNECT, .CONNECTION_RESET => 0,
        else => |status| win32.unexpectedStatus(status),
    };
}

fn dataTransferAfd(h: HANDLE, code: win32.CTL_CODE, in: []const u8, out: ?[*]u8, out_len: usize) !usize {
    if (isAssociated(h)) return syncViaPort(h, code, in, out, out_len);
    var iosb: win32.IO_STATUS_BLOCK = undefined;
    var done = false;
    switch (ntdll.NtDeviceIoControlFile(h, null, &afdDoneApc, &done, &iosb, code, in.ptr, @intCast(in.len), out, @intCast(out_len))) {
        .PENDING, .SUCCESS => while (!done) waitForApcOrAlert(),
        else => |status| return win32.unexpectedStatus(status),
    }
    return switch (iosb.u.Status) {
        .SUCCESS => iosb.Information,
        // A closed or reset peer reads as EOF, as on POSIX.
        .GRACEFUL_DISCONNECT, .REMOTE_DISCONNECT, .CONNECTION_RESET => 0,
        else => |status| win32.unexpectedStatus(status),
    };
}

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

fn afdRecv(h: HANDLE, buf: []u8) !usize {
    var iovecs = [_]win32.AFD.WSABUF(.@"var"){.{ .len = @intCast(buf.len), .buf = buf.ptr }};
    var info: win32.AFD.RECV_INFO = .{
        .BufferArray = &iovecs,
        .BufferCount = 1,
        .AfdFlags = .{ .NO_FAST_IO = true, .OVERLAPPED = true },
        .TdiFlags = .{ .NORMAL = true },
    };
    return dataTransferAfd(h, win32.IOCTL.AFD.RECEIVE, std.mem.asBytes(&info), if (buf.len > 0) buf.ptr else null, buf.len);
}

// A pipe read or write: Event + token when the handle is on the loop's port
// (the loop reaps the token), a private token otherwise.
fn pipeSyncOp(h: HANDLE, read: bool, buf: []const u8) !usize {
    const tok = try std.heap.page_allocator.create(IoStatusToken);
    tok.* = .{ .iosb = undefined };
    const ev = ensureEvent() catch |err| {
        std.heap.page_allocator.destroy(tok);
        return err;
    };
    defer win32.CloseHandle(ev);
    lockRegistry();
    const is_assoc = associated.contains(@intFromPtr(h));
    if (is_assoc) sync_tokens.put(std.heap.page_allocator, @intFromPtr(&tok.iosb), tok) catch {
        unlockRegistry();
        std.heap.page_allocator.destroy(tok);
        return error.OutOfMemory;
    };
    unlockRegistry();
    const disown = struct {
        fn f(t: *IoStatusToken) void {
            lockRegistry();
            _ = sync_tokens.remove(@intFromPtr(&t.iosb));
            unlockRegistry();
            std.heap.page_allocator.destroy(t);
        }
    }.f;
    const stat = if (read)
        ntdll.NtReadFile(h, ev, null, @ptrCast(&tok.iosb), &tok.iosb, @ptrCast(@constCast(buf.ptr)), @intCast(buf.len), null, null)
    else
        ntdll.NtWriteFile(h, ev, null, @ptrCast(&tok.iosb), &tok.iosb, @ptrCast(buf.ptr), @intCast(buf.len), null, null);
    switch (stat) {
        .SUCCESS, .PENDING => {},
        // Synchronous disconnect: no IRP, no packet, EOF.
        .PIPE_BROKEN, .PIPE_DISCONNECTED, .PIPE_CLOSING, .END_OF_FILE, .GRACEFUL_DISCONNECT, .REMOTE_DISCONNECT, .CONNECTION_RESET => {
            disown(tok);
            return 0;
        },
        else => {
            disown(tok);
            return win32.unexpectedStatus(stat);
        },
    }
    if (WaitForSingleObject(ev, INFINITE) == WAIT_FAILED) {
        disown(tok);
        return error.EventWaitFailed;
    }
    const result: usize = switch (tok.iosb.u.Status) {
        .SUCCESS => tok.iosb.Information,
        .PIPE_BROKEN, .PIPE_DISCONNECTED, .PIPE_CLOSING, .END_OF_FILE, .GRACEFUL_DISCONNECT, .REMOTE_DISCONNECT, .CONNECTION_RESET => 0,
        else => {
            disown(tok);
            return win32.unexpectedStatus(tok.iosb.u.Status);
        },
    };
    // An associated token stays registered for the loop; a private one is done.
    if (!is_assoc) std.heap.page_allocator.destroy(tok);
    return result;
}

pub fn socketWrite(fd: HANDLE, buf: []const u8) void {
    var sent: usize = 0;
    while (sent < buf.len) {
        const n = switch (handleKind(fd)) {
            .pipe, .pipe_listener => pipeSyncOp(fd, false, buf[sent..]) catch return,
            .afd => afdSend(fd, buf[sent..]) catch return,
        };
        if (n == 0) return;
        sent += n;
    }
}

/// Read once, honouring any `setRecvTimeout` deadline on the handle; 0 on
/// timeout, EOF or error, as on POSIX.
pub fn socketRead(fd: HANDLE, buf: []u8) usize {
    lockRegistry();
    const timeout_ms = read_timeouts_ms.get(@intFromPtr(fd));
    unlockRegistry();
    if (timeout_ms) |ms| return socketReadTimeout(fd, buf, ms);
    return switch (handleKind(fd)) {
        .pipe, .pipe_listener => pipeSyncOp(fd, true, buf) catch |err| {
            std.debug.print("socketRead error: {}\n", .{err});
            return 0;
        },
        .afd => afdRecv(fd, buf) catch |err| {
            std.debug.print("socketRead error: {}\n", .{err});
            return 0;
        },
    };
}

fn issueReadEvent(fd: HANDLE, buf: []u8, ev: HANDLE, iosb: *win32.IO_STATUS_BLOCK) !void {
    switch (handleKind(fd)) {
        .pipe, .pipe_listener => switch (ntdll.NtReadFile(fd, ev, null, null, iosb, buf.ptr, @intCast(buf.len), null, null)) {
            .SUCCESS, .PENDING => {},
            else => |status| return win32.unexpectedStatus(status),
        },
        .afd => {
            var iovecs = [_]win32.AFD.WSABUF(.@"var"){.{ .len = @intCast(buf.len), .buf = buf.ptr }};
            var info: win32.AFD.RECV_INFO = .{
                .BufferArray = &iovecs,
                .BufferCount = 1,
                .AfdFlags = .{ .NO_FAST_IO = true, .OVERLAPPED = true },
                .TdiFlags = .{ .NORMAL = true },
            };
            switch (ntdll.NtDeviceIoControlFile(fd, ev, null, null, iosb, win32.IOCTL.AFD.RECEIVE, std.mem.asBytes(&info), @intCast(@sizeOf(win32.AFD.RECV_INFO)), null, 0)) {
                .SUCCESS, .PENDING => {},
                else => |status| return win32.unexpectedStatus(status),
            }
        },
    }
}

/// A read bounded by `timeout_ms`: issued against a private Event, cancelled
/// and waited out on expiry (the IRP writes into this frame's iosb and `buf`).
/// Neither pipes nor raw AFD handles accept a per-handle receive timeout.
pub fn socketReadTimeout(fd: HANDLE, buf: []u8, timeout_ms: u32) usize {
    var iosb: win32.IO_STATUS_BLOCK = undefined;
    const ev = ensureEvent() catch return 0;
    defer win32.CloseHandle(ev);
    issueReadEvent(fd, buf, ev, &iosb) catch return 0;
    switch (WaitForSingleObject(ev, timeout_ms)) {
        WAIT_OBJECT_0 => {},
        WAIT_TIMEOUT => {
            var scratch: win32.IO_STATUS_BLOCK = undefined;
            _ = ntdll.NtCancelIoFileEx(fd, &iosb, &scratch);
            _ = WaitForSingleObject(ev, INFINITE);
            return 0;
        },
        else => return 0,
    }
    return switch (iosb.u.Status) {
        .SUCCESS => iosb.Information,
        .CANCELLED, .GRACEFUL_DISCONNECT, .REMOTE_DISCONNECT, .CONNECTION_RESET, .PIPE_BROKEN, .PIPE_DISCONNECTED, .END_OF_FILE => 0,
        else => |status| blk: {
            std.debug.print("socketReadTimeout: {any}\n", .{status});
            break :blk 0;
        },
    };
}

/// Bound every following `socketRead` on `fd` (0 lifts the bound).
pub fn setRecvTimeout(fd: HANDLE, seconds: u32) void {
    lockRegistry();
    defer unlockRegistry();
    if (seconds == 0) {
        _ = read_timeouts_ms.remove(@intFromPtr(fd));
    } else {
        read_timeouts_ms.put(std.heap.page_allocator, @intFromPtr(fd), seconds * 1000) catch {};
    }
}

/// Half-close the sending side. A pipe cannot; its peer reads EOF at close.
pub fn shutdownWrite(fd: HANDLE) void {
    if (handleKind(fd) != .afd) return;
    const info = win32.AFD.PARTIAL_DISCONNECT_INFO{ .DisconnectMode = .{ .SEND = true, .RECEIVE = false }, .Timeout = -1 };
    _ = syncAfdControl(fd, win32.IOCTL.AFD.PARTIAL_DISCONNECT, std.mem.asBytes(&info), &.{}) catch {};
}

/// CloseHandle, forgetting whatever the registry knew about the value.
pub fn close(fd: HANDLE) void {
    forgetHandle(fd);
    win32.CloseHandle(fd);
}
pub const rawClose = close;

pub fn write(fd: HANDLE, buf: []const u8) void {
    socketWrite(fd, buf);
}

/// WriteFile, for console, pipe and file handles that are not sockets.
pub fn writeFile(fd: HANDLE, buf: []const u8) void {
    var off: usize = 0;
    while (off < buf.len) {
        var written: DWORD = 0;
        if (!WriteFile(fd, @ptrCast(buf[off..].ptr), @intCast(buf.len - off), &written, null).toBool()) return;
        if (written == 0) return;
        off += written;
    }
}

// =============================================================================
// AFD sockets
// =============================================================================

/// Create a stream-mode AFD endpoint (the object behind every socket).
pub fn openAfdEndpoint(family: posix.sa_family_t) !HANDLE {
    const mode_protocol = try Io.Threaded.posixSocketModeProtocol(family, .stream, null);
    var handle: HANDLE = undefined;
    var iosb: win32.IO_STATUS_BLOCK = undefined;
    switch (ntdll.NtCreateFile(
        &handle,
        .{ .STANDARD = .{ .RIGHTS = .{ .WRITE_DAC = true }, .SYNCHRONIZE = true }, .GENERIC = .{ .WRITE = true, .READ = true } },
        &.{ .ObjectName = @constCast(&win32.UNICODE_STRING.init(win32.AFD.DEVICE_NAME ++ .{ '\\', 'E', 'n', 'd', 'p', 'o', 'i', 'n', 't' })) },
        &iosb,
        null,
        .{},
        .{ .READ = true, .WRITE = true },
        .OPEN_IF,
        .{ .IO = .ASYNCHRONOUS },
        &win32.AFD.OPEN_PACKET.FULL_EA_INFORMATION{
            .Value = .{
                .EndpointType = .{},
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

fn afdSockopt(h: HANDLE, mode: win32.AFD.SOCKOPT_INFO.Mode, level: i32, optname: u32, opt_val: []const u8) !void {
    _ = try syncAfdControl(h, win32.IOCTL.AFD.SOCKOPT, @as([]const u8, @ptrCast(&win32.AFD.SOCKOPT_INFO{
        .mode = mode,
        .level = level,
        .optname = optname,
        .optval = opt_val.ptr,
        .optlen = opt_val.len,
    })), &.{});
}

fn afdBind(h: HANDLE, mode: win32.AFD.BIND_INFO.MODE, addr_bytes: []const u8) !void {
    const Storage = extern struct { info: win32.AFD.BIND_INFO, addr: [128]u8 };
    var storage: Storage = .{ .info = .{ .Mode = mode }, .addr = undefined };
    @memcpy(storage.addr[0..addr_bytes.len], addr_bytes);
    _ = try syncAfdControl(h, win32.IOCTL.AFD.BIND, @as([]const u8, @ptrCast(&storage))[0 .. @offsetOf(Storage, "addr") + addr_bytes.len], @as([]u8, @ptrCast(&storage.addr)));
}

/// Connect an AFD endpoint to an IP address, reporting the failure reason.
/// Connect, abandoning the attempt after `timeout_ms` when one is given.
fn connectAfd(fd: HANDLE, addr: *const posix.sockaddr, len: posix.socklen_t, timeout_ms: ?u32) !void {
    switch (addr.family) {
        posix.AF.INET, posix.AF.INET6 => {},
        else => return error.AddressFamilyUnsupported,
    }
    var one: bool = true;
    try afdSockopt(fd, .set, win32.ws2_32.SOL.SOCKET, win32.ws2_32.SO.REUSE_UNICASTPORT, @as([]u8, @ptrCast(&one))[0..1]);
    // AFD wants an explicit bind of the unspecified address before a connect.
    var bind_addr: [28]u8 = [_]u8{0} ** 28;
    std.mem.writeInt(u16, bind_addr[0..2], addr.family, .little);
    const blen: usize = if (addr.family == posix.AF.INET) @sizeOf(posix.sockaddr.in) else @sizeOf(posix.sockaddr.in6);
    try afdBind(fd, .Active, bind_addr[0..blen]);
    const ConnectStorage = extern struct { reserved: [3]usize, addr: [128]u8 };
    var storage: ConnectStorage = .{ .reserved = @splat(0), .addr = undefined };
    @memcpy(storage.addr[0..len], @as([*]const u8, @ptrCast(addr))[0..len]);
    const request = @as([]const u8, @ptrCast(&storage))[0 .. @offsetOf(ConnectStorage, "addr") + len];
    if (timeout_ms) |ms| return boundedAfdControl(fd, win32.IOCTL.AFD.CONNECT, request, ms);
    _ = try syncAfdControl(fd, win32.IOCTL.AFD.CONNECT, request, &.{});
}

/// An AFD IOCTL on an unassociated handle, cancelled and waited out if it has
/// not completed within `timeout_ms` (the IRP writes into this frame's iosb).
fn boundedAfdControl(h: HANDLE, code: win32.CTL_CODE, in: []const u8, timeout_ms: u32) !void {
    var iosb: win32.IO_STATUS_BLOCK = undefined;
    const ev = try ensureEvent();
    defer win32.CloseHandle(ev);
    switch (ntdll.NtDeviceIoControlFile(h, ev, null, null, &iosb, code, in.ptr, @intCast(in.len), null, 0)) {
        .SUCCESS, .PENDING => {},
        else => |status| return mapAfdStatus(status),
    }
    switch (WaitForSingleObject(ev, timeout_ms)) {
        WAIT_OBJECT_0 => {},
        WAIT_TIMEOUT => {
            var scratch: win32.IO_STATUS_BLOCK = undefined;
            _ = ntdll.NtCancelIoFileEx(h, &iosb, &scratch);
            _ = WaitForSingleObject(ev, INFINITE);
            return error.ConnectionTimedOut;
        },
        else => return error.EventWaitFailed,
    }
    if (iosb.u.Status != .SUCCESS) return mapAfdStatus(iosb.u.Status);
}

pub fn rawSocket(family: u32, sock_type: u32) ?HANDLE {
    if (sock_type != posix.SOCK.STREAM) return null;
    return openAfdEndpoint(@intCast(family)) catch |err| {
        std.debug.print("rawSocket: AFD endpoint creation failed: {}\n", .{err});
        return null;
    };
}

pub fn rawConnect(fd: HANDLE, addr: *const posix.sockaddr, len: posix.socklen_t) bool {
    connectAfd(fd, addr, len, null) catch |err| {
        std.debug.print("rawConnect failed: {}\n", .{err});
        return false;
    };
    return true;
}

/// Connect to an IP address. The platform primitives report why a connect
/// failed, where std's collapse the reasons into error.Unexpected.
pub fn connectTcp(io: Io, ip: Io.net.IpAddress) !HANDLE {
    _ = io;
    return dialIp(ip, null);
}

/// Whether something accepts TCP connections at `ip` within `timeout_ms`.
pub fn probeTcp(ip: Io.net.IpAddress, timeout_ms: u32) bool {
    close(dialIp(ip, timeout_ms) catch return false);
    return true;
}

fn dialIp(ip: Io.net.IpAddress, timeout_ms: ?u32) !HANDLE {
    const fd = switch (ip) {
        .ip4 => rawSocket(posix.AF.INET, posix.SOCK.STREAM),
        .ip6 => rawSocket(posix.AF.INET6, posix.SOCK.STREAM),
    } orelse return error.SocketCreateFailed;
    errdefer close(fd);
    switch (ip) {
        .ip4 => |a| {
            var sa: posix.sockaddr.in = std.mem.zeroes(posix.sockaddr.in);
            sa.family = posix.AF.INET;
            sa.port = std.mem.nativeToBig(u16, a.port);
            sa.addr = @bitCast(a.bytes);
            try connectAfd(fd, @ptrCast(&sa), @sizeOf(posix.sockaddr.in), timeout_ms);
        },
        .ip6 => |a| {
            var sa: posix.sockaddr.in6 = std.mem.zeroes(posix.sockaddr.in6);
            sa.family = posix.AF.INET6;
            sa.port = std.mem.nativeToBig(u16, a.port);
            sa.addr = a.bytes;
            try connectAfd(fd, @ptrCast(&sa), @sizeOf(posix.sockaddr.in6), timeout_ms);
        },
    }
    return fd;
}

pub fn setTcpNodelay(fd: HANDLE) void {
    const one: c_int = 1;
    afdSockopt(fd, .set, win32.ws2_32.IPPROTO.TCP, win32.ws2_32.TCP.NODELAY, std.mem.asBytes(&one)) catch {};
}

// =============================================================================
// Named pipes: the local transport. Each instance carries a DACL admitting
// only its owner, and the first instance claims the name with
// FIRST_PIPE_INSTANCE, so no other local user can squat or join it.
// =============================================================================

pub const max_local_addr = 256;
const pipe_namespace = "\\\\.\\pipe\\julia-daemon";
const PIPE_ACCESS_DUPLEX: DWORD = 0x00000003;
const FILE_FLAG_OVERLAPPED: DWORD = 0x40000000;
const FILE_FLAG_FIRST_PIPE_INSTANCE: DWORD = 0x00080000;
const PIPE_UNLIMITED_INSTANCES: DWORD = 255;
const DUPLICATE_SAME_ACCESS: DWORD = 2;
const SDDL_REVISION_1: DWORD = 1;

fn comptimeWide(comptime name: []const u8) [name.len:0]u16 {
    var out: [name.len:0]u16 = undefined;
    for (name, 0..) |c, i| out[i] = c;
    out[name.len] = 0;
    return out;
}

/// The per-user pipe namespace, standing in for the runtime directory.
pub fn localSocketDir(out: anytype, _: []const u8) ![]const u8 {
    var wide: [257]u16 = undefined;
    var len: DWORD = wide.len;
    if (!GetUserNameW(&wide, &len).toBool()) return error.UserNameUnavailable;
    var user_buf: [512]u8 = undefined;
    const n = try std.unicode.utf16LeToUtf8(&user_buf, wide[0 .. len - 1]);
    return print(out, pipe_namespace ++ "\\{s}", .{user_buf[0..n]});
}

pub fn localSocketPath(out: anytype, dir: []const u8, comptime name_fmt: []const u8, name_args: anytype) ![]const u8 {
    return print(out, "{s}\\" ++ name_fmt, .{dir} ++ name_args);
}

/// The Win32 pipe path for `name`, tolerating `/` and the `\\?\pipe\` spelling.
fn pipeWin32Name(buf: *[max_local_addr + 1]u16, name: []const u8) ![:0]const u16 {
    const prefixes = [_][]const u8{ "\\\\.\\pipe\\", "\\\\?\\pipe\\", "\\??\\pipe\\", "//./pipe/", "//?/pipe/" };
    var rel = name;
    for (prefixes) |p| if (std.mem.startsWith(u8, name, p)) {
        rel = name[p.len..];
        break;
    };
    const prefix = comptimeWide("\\\\.\\pipe\\");
    if (rel.len == 0 or prefix.len + rel.len > buf.len - 1) return error.NameTooLong;
    @memcpy(buf[0..prefix.len], &prefix);
    for (rel, buf[prefix.len..][0..rel.len]) |c, *w| w.* = if (c == '/') '\\' else c;
    buf[prefix.len + rel.len] = 0;
    return buf[0 .. prefix.len + rel.len :0];
}

var pipe_security: ?win32.SECURITY_ATTRIBUTES = null;

// A DACL granting everything to the object's owner and nothing to anyone else.
fn pipeSecurityAttributes() !*win32.SECURITY_ATTRIBUTES {
    if (pipe_security == null) {
        const sddl = comptimeWide("D:P(A;;GA;;;OW)");
        var descriptor: ?*anyopaque = null;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(&sddl, SDDL_REVISION_1, &descriptor, null).toBool())
            return error.PipeSecurityFailed;
        pipe_security = .{ .nLength = @sizeOf(win32.SECURITY_ATTRIBUTES), .lpSecurityDescriptor = descriptor, .bInheritHandle = .FALSE };
    }
    return &pipe_security.?;
}

/// A byte-stream, duplex, overlapped instance of `name`: what libuv (and so
/// Julia's Sockets) speaks. `first` claims the name.
fn createPipeInstance(name: []const u8, first: bool) !HANDLE {
    var wide: [max_local_addr + 1]u16 = undefined;
    const path = try pipeWin32Name(&wide, name);
    const first_flag: DWORD = if (first) FILE_FLAG_FIRST_PIPE_INSTANCE else 0;
    const handle = CreateNamedPipeW(path.ptr, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | first_flag, 0, PIPE_UNLIMITED_INSTANCES, 4096, 4096, 0, try pipeSecurityAttributes()) orelse
        return if (first) error.AddressInUse else error.PipeCreateFailed;
    setKind(handle, .pipe_listener);
    return handle;
}

/// Pend the accept (FSCTL PIPE LISTEN) on an instance. The status left in
/// `iosb` tells whether it is pending or the instance is already connected.
pub fn issuePipeListen(h: HANDLE, iosb: *win32.IO_STATUS_BLOCK) !void {
    switch (ntdll.NtFsControlFile(h, null, null, @ptrCast(iosb), iosb, win32.CTL_CODE.PIPE.LISTEN, null, 0, null, 0)) {
        .SUCCESS, .PENDING, .PIPE_CONNECTED => |status| iosb.u.Status = status,
        // A peer that connected and left before we listened is readiness, not
        // an error: the readable dispatch reads it and sees EOF.
        .PIPE_CLOSING, .PIPE_BROKEN, .PIPE_DISCONNECTED, .END_OF_FILE => |status| iosb.u.Status = status,
        else => |status| return win32.unexpectedStatus(status),
    }
}

fn pipeConnected(h: HANDLE) bool {
    const LocalInfo = extern struct {
        NamedPipeType: ULONG,
        NamedPipeConfiguration: ULONG,
        MaximumInstances: ULONG,
        CurrentInstances: ULONG,
        InboundQuota: ULONG,
        ReadDataAvailable: ULONG,
        OutboundQuota: ULONG,
        WriteQuotaAvailable: ULONG,
        NamedPipeState: ULONG,
        NamedPipeEnd: ULONG,
    };
    var info: LocalInfo = undefined;
    var iosb: win32.IO_STATUS_BLOCK = undefined;
    if (ntdll.NtQueryInformationFile(h, &iosb, &info, @sizeOf(LocalInfo), .PipeLocal) != .SUCCESS) return false;
    return info.NamedPipeState == 3; // FILE_PIPE_CONNECTED_STATE
}

/// Wait up to `timeout_ms` for a client on an unwatched instance.
fn awaitPipeClient(h: HANDLE, timeout_ms: u32) !bool {
    var iosb: win32.IO_STATUS_BLOCK = undefined;
    const ev = try ensureEvent();
    defer win32.CloseHandle(ev);
    switch (ntdll.NtFsControlFile(h, ev, null, null, &iosb, win32.CTL_CODE.PIPE.LISTEN, null, 0, null, 0)) {
        .SUCCESS, .PIPE_CONNECTED, .PIPE_CLOSING => return true,
        .PENDING => {},
        else => |status| return win32.unexpectedStatus(status),
    }
    switch (WaitForSingleObject(ev, timeout_ms)) {
        WAIT_OBJECT_0 => {},
        WAIT_TIMEOUT => {
            _ = CancelIoEx(h, null);
            _ = WaitForSingleObject(ev, INFINITE);
            return false;
        },
        else => return error.EventWaitFailed,
    }
    return switch (iosb.u.Status) {
        .SUCCESS, .PIPE_CONNECTED, .PIPE_CLOSING, .PIPE_BROKEN => true,
        .CANCELLED => false,
        else => |status| win32.unexpectedStatus(status),
    };
}

/// Open the client end of a pipe, retrying for up to `wait_ms` while the server
/// is between instances (it re-creates one after each accept). A missing name
/// is waited for too when `name_may_appear`: a worker's socket may not exist yet.
fn connectPipe(name: []const u8, wait_ms: u32, name_may_appear: bool) !HANDLE {
    var wide: [max_local_addr + 1]u16 = undefined;
    const path = try pipeWin32Name(&wide, name);
    // NtCreateFile wants the NT spelling of the same name.
    const nt_prefix = comptimeWide("\\??\\pipe\\");
    var nt_buf: [max_local_addr + 1]u16 = undefined;
    const rel = path[comptimeWide("\\\\.\\pipe\\").len..];
    @memcpy(nt_buf[0..nt_prefix.len], &nt_prefix);
    @memcpy(nt_buf[nt_prefix.len..][0..rel.len], rel);
    const obj_name = nt_buf[0 .. nt_prefix.len + rel.len];
    var attempts: usize = 0;
    while (attempts < wait_ms / 50) : (attempts += 1) {
        var handle: HANDLE = undefined;
        var iosb: win32.IO_STATUS_BLOCK = undefined;
        var ua = win32.UNICODE_STRING.init(obj_name);
        switch (ntdll.NtCreateFile(
            &handle,
            .{ .GENERIC = .{ .READ = true, .WRITE = true }, .STANDARD = .{ .SYNCHRONIZE = true } },
            &.{ .ObjectName = @constCast(&ua) },
            &iosb,
            null,
            .{},
            .{ .READ = true, .WRITE = true },
            .OPEN,
            .{ .IO = .ASYNCHRONOUS },
            null,
            0,
        )) {
            .SUCCESS => {
                setKind(handle, .pipe);
                return handle;
            },
            .OBJECT_NAME_NOT_FOUND => if (!name_may_appear) return error.FileNotFound,
            .PIPE_BUSY, .INSTANCE_NOT_AVAILABLE, .PIPE_NOT_AVAILABLE, .PIPE_CLOSING => {},
            else => |status| return win32.unexpectedStatus(status),
        }
        Sleep(50);
    }
    return error.ConnectionTimedOut;
}

fn dupHandle(h: HANDLE) !HANDLE {
    var out: HANDLE = undefined;
    if (!DuplicateHandle(GetCurrentProcess(), h, GetCurrentProcess(), &out, 0, .FALSE, DUPLICATE_SAME_ACCESS).toBool())
        return error.DuplicateHandleFailed;
    lockRegistry();
    defer unlockRegistry();
    if (handle_kinds.get(@intFromPtr(h))) |kind| handle_kinds.put(std.heap.page_allocator, @intFromPtr(out), kind) catch {};
    if (associated.contains(@intFromPtr(h))) associated.put(std.heap.page_allocator, @intFromPtr(out), {}) catch {};
    return out;
}

pub fn listenLocal(io: Io, path: []const u8) !Listener {
    _ = io;
    return Listener.init(.{ .pipe = try createPipeInstance(path, true) }, path);
}

pub const local_transport_name = "named pipe";

pub fn connectLocal(io: Io, path: []const u8) !HANDLE {
    _ = io;
    return connectPipe(path, 10_000, true);
}

/// A missing name means no server; a busy one is retried within `timeout_ms`.
pub fn probeLocal(path: []const u8, timeout_ms: u32) bool {
    close(connectPipe(path, timeout_ms, false) catch return false);
    return true;
}

/// A pipe name vanishes with its last instance, so there is nothing to retire.
pub const connectLocalOnce = connectLocal;

/// Usable off the main thread (the console-control handler); null on failure.
pub fn rawConnectLocal(path: []const u8) ?HANDLE {
    return connectPipe(path, 10_000, true) catch null;
}

const closeHandle = close; // unambiguous inside Listener, which has its own `close`

/// A listening pipe instance or AFD socket with its address.
pub const Listener = struct {
    backing: union(enum) { pipe: HANDLE, socket: Io.net.Server },
    addr_buf: [max_local_addr]u8,
    addr_len: usize,

    fn init(backing: @FieldType(Listener, "backing"), address: []const u8) !Listener {
        var l = Listener{ .backing = backing, .addr_buf = undefined, .addr_len = address.len };
        if (address.len > l.addr_buf.len) return error.PathTooLong;
        @memcpy(l.addr_buf[0..address.len], address);
        return l;
    }
    pub fn fromServer(server: Io.net.Server, mode: protocol.TransportMode, address: []const u8) !Listener {
        std.debug.assert(mode == .tcp); // local listeners come from listenLocal
        return init(.{ .socket = server }, address);
    }
    pub fn addr(self: *const Listener) []const u8 {
        return self.addr_buf[0..self.addr_len];
    }
    pub fn fd(self: *const Listener) HANDLE {
        return switch (self.backing) {
            .pipe => |h| h,
            .socket => |s| s.socket.handle,
        };
    }
    /// Accept the connection an event loop reported waiting.
    pub fn accept(self: *Listener, io: Io) !protocol.Accepted {
        return switch (self.backing) {
            .pipe => .{ .socket = try self.takePipeConnection(), .peer = null },
            .socket => |*s| blk: {
                const stream = try s.accept(io);
                break :blk .{ .socket = stream.socket.handle, .peer = stream.socket.address };
            },
        };
    }
    /// Accept a connection arriving within `timeout_ms` (0: one already waiting); null when none does.
    pub fn acceptTimeout(self: *Listener, io: Io, timeout_ms: i32) !?HANDLE {
        switch (self.backing) {
            .pipe => |instance| {
                if (!pipeConnected(instance)) {
                    if (timeout_ms == 0) return null;
                    if (!try awaitPipeClient(instance, @intCast(timeout_ms))) return null;
                }
                return try self.takePipeConnection();
            },
            .socket => |*s| {
                if (!try pollReadable(s.socket.handle, timeout_ms)) return null;
                return (try s.accept(io)).socket.handle;
            },
        }
    }
    pub fn close(self: *Listener, io: Io) void {
        switch (self.backing) {
            .pipe => |h| closeHandle(h),
            .socket => |*s| s.deinit(io),
        }
    }
    // The connected instance becomes the connection; a fresh instance takes over
    // listening. The old handle must be closed before the name is re-created,
    // or the create fails with ACCESS_DENIED, so the connection lives on a dup.
    fn takePipeConnection(self: *Listener) !HANDLE {
        const instance = self.backing.pipe;
        const conn = try dupHandle(instance);
        errdefer closeHandle(conn);
        setKind(conn, .pipe);
        closeHandle(instance);
        self.backing.pipe = try createPipeInstance(self.addr(), false);
        return conn;
    }
};

// =============================================================================
// Readiness, for the conductor's event loop. The AFD poll is issued on a
// dedicated handle so sockets themselves never join the port, keeping the
// cheap APC path for their synchronous reads.
// =============================================================================

const PollHandleInfo = extern struct { Handle: HANDLE, Events: ULONG, Status: win32.NTSTATUS };
const PollInfo = extern struct { Timeout: i64, NumberOfHandles: ULONG, Exclusive: ULONG, Handles: [1]PollHandleInfo };
// RECEIVE | DISCONNECT | ABORT | LOCAL_CLOSE | ACCEPT | CONNECT_FAIL
const poll_readable: ULONG = 0x0001 | 0x0008 | 0x0010 | 0x0020 | 0x0080 | 0x0100;

fn pollInfo(fd: HANDLE, timeout_ms: i32) PollInfo {
    return .{
        .Timeout = if (timeout_ms < 0) std.math.maxInt(i64) else -@as(i64, timeout_ms) * 10_000,
        .NumberOfHandles = 1,
        .Exclusive = 0,
        .Handles = .{.{ .Handle = fd, .Events = poll_readable, .Status = .SUCCESS }},
    };
}

/// Whether a socket turns readable within `timeout_ms` (negative: forever).
fn pollReadable(fd: HANDLE, timeout_ms: i32) !bool {
    var info = pollInfo(fd, timeout_ms);
    _ = syncAfdControl(fd, win32.IOCTL.AFD.POLL, std.mem.asBytes(&info), std.mem.asBytes(&info)) catch |err| switch (err) {
        error.ConnectionTimedOut => return false,
        else => return err,
    };
    return info.NumberOfHandles > 0;
}

/// The AFD handle the loop issues socket polls on; associate it with the port.
pub fn openPollDevice() !HANDLE {
    return openAfdEndpoint(posix.AF.INET);
}

/// Storage for one pending readiness notification; `iosb` is the packet's
/// lpOverlapped, so the owner is recovered by casting it back.
pub const ReadinessOp = extern struct { iosb: win32.IO_STATUS_BLOCK, poll: PollInfo };
var zero_read_buf: [1]u8 = undefined; // a zero-length read still wants a buffer address

/// Arm a one-shot readiness notification for `fd` into `op`, routed to `port`.
/// Returns true when the condition already holds and no completion packet will
/// follow, in which case the caller posts one itself.
pub fn issueReadiness(poll_device: HANDLE, port: HANDLE, fd: HANDLE, op: *ReadinessOp) bool {
    switch (handleKind(fd)) {
        .afd => {
            op.poll = pollInfo(fd, -1);
            const status = ntdll.NtDeviceIoControlFile(poll_device, null, null, @ptrCast(&op.iosb), &op.iosb, win32.IOCTL.AFD.POLL, std.mem.asBytes(&op.poll), @sizeOf(PollInfo), std.mem.asBytes(&op.poll), @sizeOf(PollInfo));
            return status != .SUCCESS and status != .PENDING;
        },
        .pipe_listener => {
            associate(port, fd) catch return true;
            issuePipeListen(fd, &op.iosb) catch return true;
            // An instance a client reached first (and may have left already,
            // its bytes still buffered) completes inline without a packet.
            return op.iosb.u.Status != .PENDING;
        },
        .pipe => {
            associate(port, fd) catch return true;
            const status = ntdll.NtReadFile(fd, null, null, @ptrCast(&op.iosb), &op.iosb, &zero_read_buf, 0, null, null);
            return status != .SUCCESS and status != .PENDING;
        },
    }
}

/// Abandon a pending readiness notification; its packet still arrives, cancelled.
pub fn cancelReadiness(poll_device: HANDLE, fd: HANDLE, op: *ReadinessOp) void {
    var scratch: win32.IO_STATUS_BLOCK = undefined;
    const issued_on = if (handleKind(fd) == .afd) poll_device else fd;
    _ = ntdll.NtCancelIoFileEx(issued_on, &op.iosb, &scratch);
}

/// One in-flight overlapped read into a caller's buffer (the client loop's
/// stream reads); `iosb` is the packet's lpOverlapped. Null when the stream is
/// already dead, which callers treat as EOF.
pub const RecvCtx = extern struct {
    iosb: win32.IO_STATUS_BLOCK,
    iovec: [1]win32.AFD.WSABUF(.@"var"),
    info: win32.AFD.RECV_INFO,
};

pub fn issueRecv(h: HANDLE, buf: []u8) ?*RecvCtx {
    const ctx = std.heap.page_allocator.create(RecvCtx) catch return null;
    ctx.* = .{
        .iosb = undefined,
        .iovec = .{.{ .len = @intCast(buf.len), .buf = buf.ptr }},
        .info = .{
            .BufferArray = @ptrCast(&ctx.iovec),
            .BufferCount = 1,
            .AfdFlags = .{ .NO_FAST_IO = true, .OVERLAPPED = true },
            .TdiFlags = .{ .NORMAL = true },
        },
    };
    const status = switch (handleKind(h)) {
        .pipe, .pipe_listener => ntdll.NtReadFile(h, null, null, @ptrCast(&ctx.iosb), &ctx.iosb, buf.ptr, @intCast(buf.len), null, null),
        .afd => ntdll.NtDeviceIoControlFile(h, null, null, @ptrCast(&ctx.iosb), &ctx.iosb, win32.IOCTL.AFD.RECEIVE, std.mem.asBytes(&ctx.info), @intCast(@sizeOf(win32.AFD.RECV_INFO)), null, 0),
    };
    switch (status) {
        .SUCCESS, .PENDING => return ctx,
        else => {
            std.heap.page_allocator.destroy(ctx);
            return null;
        },
    }
}

// =============================================================================
// Processes. A child's `pid` is its process handle (std's Child.Id), used
// directly for waits, termination and statistics.
// =============================================================================

/// The signals shared code sends. TERM and KILL both terminate; INT would
/// need a shared console, which spawned workers have none of; USR1 is a
/// POSIX-only nudge.
pub const SIG = enum { INT, TERM, KILL, USR1 };

pub fn getpid() DWORD {
    return win32.GetCurrentProcessId();
}

/// Windows keeps no parent link; callers tolerate 0.
pub fn getppid() DWORD {
    return 0;
}

pub fn kill(pid: posix.pid_t, sig: SIG) usize {
    if (sig == .USR1) return 0;
    return if (TerminateProcess(pid, 1).toBool()) 0 else 1;
}

/// Start a worker on pipes: a headless conductor's inherited stdio is
/// file-backed, which libuv rejects at worker start. Its stdin is at EOF and
/// its stdout closed, so a stray raw write fails rather than filling a pipe
/// nobody drains; stderr is kept for `dumpChildStderr`.
pub fn spawnWorker(io: Io, argv: []const []const u8) !std.process.Child {
    var child = try std.process.spawn(io, .{ .argv = argv, .stdin = .pipe, .stdout = .pipe, .stderr = .pipe });
    if (child.stdin) |f| f.close(io);
    child.stdin = null;
    if (child.stdout) |f| f.close(io);
    child.stdout = null;
    return child;
}

/// Print what a dead worker wrote to its stderr pipe, then close it. The
/// process must have exited: the read runs to EOF.
pub fn dumpChildStderr(io: Io, allocator: Allocator, child: *std.process.Child, id: u32) void {
    var f = child.stderr orelse return;
    child.stderr = null;
    defer f.close(io);
    var buf: [8192]u8 = undefined;
    var fr = f.reader(io, &buf);
    const data = fr.interface.allocRemaining(allocator, .limited(1 << 20)) catch return;
    defer allocator.free(data);
    if (data.len > 0) std.debug.print("Worker {d} stderr:\n{s}\n", .{ id, data });
}

/// The number a pid prints and travels the wire as (a pid here is a process handle).
pub fn pidNumber(pid: posix.pid_t) u32 {
    return GetProcessId(pid);
}
/// A socket slot with no connection in it yet.
pub const no_socket: posix.socket_t = win32.INVALID_HANDLE_VALUE;
/// A worker some other process started for us: no handle to wait on or kill.
pub const no_child = std.process.Child{ .id = null, .thread_handle = undefined, .stdin = null, .stdout = null, .stderr = null, .request_resource_usage_statistics = false };

pub fn getChildPid(child: anytype) DWORD {
    return if (child.id) |process| GetProcessId(process) else 0;
}

pub const WaitPidResult = struct { pid: posix.pid_t, exited: bool };

pub fn waitpidNonBlocking(pid: posix.pid_t) WaitPidResult {
    return .{ .pid = pid, .exited = WaitForSingleObject(pid, 0) != WAIT_TIMEOUT };
}

pub const ProcessStats = struct { mem_bytes: u64, cpu_seconds: f64 };

fn filetimeToU64(ft: FILETIME) u64 {
    return @as(u64, ft.dwHighDateTime) << 32 | @as(u64, ft.dwLowDateTime);
}

pub fn getProcessStats(pid: posix.pid_t) ?ProcessStats {
    var pmc = std.mem.zeroes(PROCESS_MEMORY_COUNTERS_EX);
    pmc.cb = @sizeOf(PROCESS_MEMORY_COUNTERS_EX);
    if (!GetProcessMemoryInfo(pid, &pmc, pmc.cb).toBool()) return null;
    var creation: FILETIME = undefined;
    var exit_t: FILETIME = undefined;
    var kernel: FILETIME = undefined;
    var user: FILETIME = undefined;
    if (!GetProcessTimes(pid, &creation, &exit_t, &kernel, &user).toBool()) return null;
    const cpu_100ns: f64 = @floatFromInt(filetimeToU64(kernel) + filetimeToU64(user));
    return .{ .mem_bytes = pmc.WorkingSetSize, .cpu_seconds = cpu_100ns / 10_000_000.0 };
}

// WorkingSetSize is resident, not private, and no cheap private-page figure
// exists here, so eviction sizes workers by their resident set.
pub const mem_is_reclaimable = false;
pub fn processReclaimable(_: posix.pid_t) ?u64 {
    return null;
}

pub const MemInfo = struct { available: u64, total: u64 };

pub fn readPsiSomeAvg10() ?f64 {
    return null;
}

pub fn readMemInfo() ?MemInfo {
    var ms = std.mem.zeroes(MEMORYSTATUSEX);
    ms.dwLength = @sizeOf(MEMORYSTATUSEX);
    if (!GlobalMemoryStatusEx(&ms).toBool()) return null;
    return .{ .available = ms.ullAvailPhys, .total = ms.ullTotalPhys };
}

/// Image base name of a process given its numeric pid, for the status report.
pub fn getParentName(pid: u32, buf: []u8) ?[]const u8 {
    const PROCESS_QUERY_LIMITED_INFORMATION: DWORD = 0x1000;
    const handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, .FALSE, pid) orelse return null;
    defer win32.CloseHandle(handle);
    var wide: [1024]u16 = undefined;
    var size: DWORD = wide.len;
    if (!QueryFullProcessImageNameW(handle, 0, &wide, &size).toBool()) return null;
    var full_buf: [2048]u8 = undefined;
    const full_len = std.unicode.utf16LeToUtf8(&full_buf, wide[0..size]) catch return null;
    const base = std.fs.path.basename(full_buf[0..full_len]);
    const n = @min(base.len, buf.len);
    @memcpy(buf[0..n], base[0..n]);
    return buf[0..n];
}

/// The POSIX SIGUSR1 socket-recreate nudge has no counterpart here.
pub fn requestSocketRecreate(_: u32) void {}

/// %LOCALAPPDATA%\julia-daemon: persistent, so startup cleanup still matters.
pub fn defaultRuntimeDir(out: anytype, _: ?[]const u8, _: ?[]const u8) ![]const u8 {
    const env: std.process.Environ = .{ .block = .global };
    const appdata = try env.getAlloc(std.heap.page_allocator, "LOCALAPPDATA");
    defer std.heap.page_allocator.free(appdata);
    return print(out, "{s}\\julia-daemon", .{appdata});
}

/// Every `KEY=VALUE` of the process environment, as UTF-8. The block lives in
/// the PEB as one double-NUL-terminated wide string, walked under its lock.
pub fn collectEnviron(allocator: Allocator, environ: std.process.Environ) ![]const []const u8 {
    _ = environ;
    const peb = win32.peb();
    _ = ntdll.RtlEnterCriticalSection(peb.FastPebLock);
    defer _ = ntdll.RtlLeaveCriticalSection(peb.FastPebLock);
    var kvs: std.ArrayList([]const u8) = .empty;
    const block: [*:0]u16 = peb.ProcessParameters.Environment;
    var i: usize = 0;
    while (block[i] != 0) {
        const start = i;
        while (block[i] != 0) : (i += 1) {}
        try kvs.append(allocator, try std.unicode.wtf16LeToWtf8Alloc(allocator, block[start..i]));
        i += 1;
    }
    return kvs.items;
}

/// Format into either an allocator (owned slice) or a `[]u8` buffer (sub-slice).
pub fn print(out: anytype, comptime fmt: []const u8, args: anytype) ![]const u8 {
    if (@TypeOf(out) == std.mem.Allocator)
        return std.fmt.allocPrint(out, fmt, args)
    else
        return std.fmt.bufPrint(out, fmt, args) catch error.NameTooLong;
}

// =============================================================================
// Console
// =============================================================================

pub fn getStdinHandle() HANDLE {
    return GetStdHandle(STD_INPUT_HANDLE);
}
pub fn getStdoutHandle() HANDLE {
    return GetStdHandle(STD_OUTPUT_HANDLE);
}
pub fn getStderrHandle() HANDLE {
    return GetStdHandle(STD_ERROR_HANDLE);
}

const ENABLE_LINE_INPUT: DWORD = 0x0002;
const ENABLE_ECHO_INPUT: DWORD = 0x0004;
const ENABLE_VIRTUAL_TERMINAL_INPUT: DWORD = 0x0200;
var saved_mode: ?DWORD = null;

// Raw: no line buffering or echo, and VT input so arrow and home/end keys
// arrive as the sequences LineEdit parses. Processed input stays on so Ctrl-C
// still reaches the console-control handler.
pub fn setRawMode(stdin: HANDLE, raw: bool) void {
    if (raw) {
        var mode: DWORD = undefined;
        if (!GetConsoleMode(stdin, &mode).toBool()) return;
        if (saved_mode == null) saved_mode = mode;
        _ = SetConsoleMode(stdin, (mode & ~(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT)) | ENABLE_VIRTUAL_TERMINAL_INPUT);
    } else if (saved_mode) |mode| {
        _ = SetConsoleMode(stdin, mode);
        saved_mode = null;
    }
}
pub fn setRawModeStdin(raw: bool) void {
    setRawMode(getStdinHandle(), raw);
}

const ConsoleSaved = struct { stdout: HANDLE, stderr: HANDLE, out_mode: DWORD, err_mode: DWORD, out_cp: DWORD, in_cp: DWORD };

/// Switch the console to VT processing and UTF-8 code pages, so the worker's
/// escapes and text render; null when stdout is not a console. Restore with
/// `restoreConsoleIo`.
pub fn setupConsoleIo(stdout: HANDLE, stderr: HANDLE) ?*anyopaque {
    var out_mode: DWORD = undefined;
    if (!GetConsoleMode(stdout, &out_mode).toBool()) return null;
    const saved = std.heap.page_allocator.create(ConsoleSaved) catch return null;
    saved.* = .{ .stdout = stdout, .stderr = stderr, .out_mode = out_mode, .err_mode = 0, .out_cp = GetConsoleOutputCP(), .in_cp = GetConsoleCP() };
    _ = SetConsoleMode(stdout, out_mode | win32.ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    if (GetConsoleMode(stderr, &saved.err_mode).toBool())
        _ = SetConsoleMode(stderr, saved.err_mode | win32.ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    _ = SetConsoleOutputCP(65001);
    _ = SetConsoleCP(65001);
    return saved;
}

pub fn restoreConsoleIo(saved: ?*anyopaque) void {
    const state: *ConsoleSaved = @ptrCast(@alignCast(saved orelse return));
    _ = SetConsoleMode(state.stdout, state.out_mode);
    if (GetConsoleMode(state.stderr, &state.err_mode).toBool()) _ = SetConsoleMode(state.stderr, state.err_mode);
    _ = SetConsoleOutputCP(state.out_cp);
    _ = SetConsoleCP(state.in_cp);
    std.heap.page_allocator.destroy(state);
}

pub fn getTerminalSize(fd: HANDLE) ?struct { rows: u16, cols: u16 } {
    var csbi = std.mem.zeroes(CONSOLE_SCREEN_BUFFER_INFO);
    if (!GetConsoleScreenBufferInfo(fd, &csbi).toBool()) return null;
    return .{
        .rows = @intCast(csbi.srWindow.Bottom - csbi.srWindow.Top + 1),
        .cols = @intCast(csbi.srWindow.Right - csbi.srWindow.Left + 1),
    };
}

pub fn isatty(fd: HANDLE) bool {
    return GetFileType(fd) == FILE_TYPE_CHAR;
}

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

var worker_raw: bool = false;
pub fn setWorkerRawMode(raw: bool) void {
    worker_raw = raw;
}
var worker_executing: bool = false;
pub fn setWorkerExecuting(executing: bool) void {
    worker_executing = executing;
}
var g_signal_handler: ?SignalHandler = null;

// Runs on a console-spawned thread. Ctrl-C at a raw prompt is a \x03 for
// LineEdit, otherwise an interrupt notification; the console going away is an
// exit. TRUE keeps the default handler from terminating the process first.
fn clientCtrlHandler(dwCtrlType: DWORD) callconv(.winapi) BOOL {
    const handler = g_signal_handler orelse return .FALSE;
    switch (dwCtrlType) {
        CTRL_C_EVENT, CTRL_BREAK_EVENT => {
            if (worker_raw and !worker_executing) handler.writeStdio("\x03") else handler.notifyInterrupt();
        },
        CTRL_CLOSE_EVENT, CTRL_LOGOFF_EVENT, CTRL_SHUTDOWN_EVENT => {
            handler.notifyExit();
            std.process.exit(130);
        },
        else => return .FALSE,
    }
    return .TRUE;
}

pub fn registerSignalHandlers(handler: SignalHandler) void {
    g_signal_handler = handler;
    _ = SetConsoleCtrlHandler(&clientCtrlHandler, .TRUE);
}
