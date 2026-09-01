// Named-pipe dialect smoke test — Zig ↔ Julia/libuv, both directions.
//
//   zig build-exe -fsingle-threaded conductor/pipe_smoke.zig
//
// Phase A: Zig creates a pipe instance + pends FSCTL.PIPE.LISTEN; spawns
//          Julia, which connects (Sockets.connect) and round-trips a line.
// Phase B: Julia listens (Sockets.listen); Zig connects (NtCreateFile
//          OPEN_EXISTING, retrying while the instance isn't up yet) and
//          round-trips a line.
// Also discovers the EOF status Julia's disconnect produces (needed for the
// transport's EOF-0 mapping). Scaffolding — delete once the platform's pipe
// transport covers the same path.

const std = @import("std");
const win32 = std.os.windows;
const posix = std.posix;
const ntdll = win32.ntdll;

const DWORD = win32.DWORD;

const PIPE_NAME = "julia-daemon-pipe-smoke-0.sock";
// libuv does NOT auto-prefix pipe names: Julia needs the full \\.\pipe\ spec.
const JULIA_NAME = "\\\\.\\pipe\\" ++ PIPE_NAME;

pub fn main(init: std.process.Init) !void {
    g_event = CreateEventW(null, 0, 0, null) orelse return error.EventCreateFailed;

    try phaseA(init.io);
    try phaseB(init.io);
    std.debug.print("PIPE SMOKE TEST PASSED\n", .{});
}

fn stage(name: []const u8) void {
    std.debug.print("PASS: {s}\n", .{name});
}

var g_event: win32.HANDLE = undefined;
var last_read_status: win32.NTSTATUS = .SUCCESS;

extern "kernel32" fn CreateEventW(lpEventAttributes: ?*anyopaque, bManualReset: DWORD, bInitialState: DWORD, lpName: ?[*:0]const u16) ?win32.HANDLE;
extern "kernel32" fn WaitForSingleObject(hHandle: win32.HANDLE, dwMilliseconds: DWORD) DWORD;
extern "kernel32" fn Sleep(dwMilliseconds: DWORD) void;

/// Wide literal from a byte string (names are ASCII here).
fn comptimeWide(comptime name: []const u8) [name.len:0]u16 {
    var out: [name.len:0]u16 = undefined;
    for (name, 0..) |c, i| out[i] = c;
    out[name.len] = 0;
    return out;
}

/// Open the NamedPipe device root (\Device\NamedPipe\) — std.Io's
/// getNamedPipeDevice pattern; NtCreateNamedPipeFile then takes pipe names
/// RELATIVE to this root (an absolute \??\pipe\<name> ObjectName fails with
/// STATUS_INVALID_PARAMETER).
fn openPipeDevice() !posix.fd_t {
    var handle: win32.HANDLE = undefined;
    var iosb: win32.IO_STATUS_BLOCK = undefined;
    switch (ntdll.NtOpenFile(
        &handle,
        .{ .STANDARD = .{ .SYNCHRONIZE = true } },
        &.{
            .ObjectName = @constCast(&win32.UNICODE_STRING.init(&comptimeWide("\\Device\\NamedPipe\\"))),
        },
        &iosb,
        .VALID_FLAGS,
        .{ .IO = .SYNCHRONOUS_NONALERT },
    )) {
        .SUCCESS => return handle,
        else => |status| {
            std.debug.print("openPipeDevice: {any}\n", .{status});
            return win32.unexpectedStatus(status);
        },
    }
}

/// Create one pipe server instance. Start byte-identical to std's working
/// windowsCreatePipe, then bisect toward the named/duplex shape we need.
fn createPipeInstance(device: posix.fd_t, comptime name: []const u8) !posix.fd_t {
    const named = use_named;
    var handle: win32.HANDLE = undefined;
    var iosb: win32.IO_STATUS_BLOCK = undefined;
    var timeout: win32.LARGE_INTEGER = -120 * std.time.ns_per_s / 100;
    const obj_attr = if (named)
        win32.OBJECT.ATTRIBUTES{
            .RootDirectory = device,
            .ObjectName = @constCast(&win32.UNICODE_STRING.init(&comptimeWide(name))),
            .Attributes = .{ .INHERIT = false },
        }
    else
        win32.OBJECT.ATTRIBUTES{
            .RootDirectory = device,
            .Attributes = .{ .INHERIT = false },
        };
    switch (ntdll.NtCreateNamedPipeFile(
        &handle,
        .{
            .SPECIFIC = .{ .FILE_PIPE = .{
                .READ_DATA = true,
                .WRITE_DATA = use_duplex,
                .WRITE_ATTRIBUTES = true,
            } },
            .STANDARD = .{ .SYNCHRONIZE = true },
        },
        &obj_attr,
        &iosb,
        .{ .READ = true, .WRITE = true },
        .CREATE,
        .{ .IO = .ASYNCHRONOUS },
        .{ .TYPE = .BYTE_STREAM },
        .{ .MODE = .BYTE_STREAM },
        .{ .OPERATION = .QUEUE },
        if (named) 0xFF else 1,
        if (named) 4096 else 65536,
        if (named) 4096 else 65536,
        &timeout,
    )) {
        .SUCCESS => {},
        else => |status| {
            std.debug.print("createPipeInstance (named={}): {any}\n", .{ named, status });
            return win32.unexpectedStatus(status);
        },
    }
    return handle;
}

const use_named = true;
const use_duplex = true;

/// Pend FSCTL.PIPE.LISTEN (the accept equivalent) on a fresh instance.
/// Completion is observed via waitPipeListen on the same iosb.
fn issuePipeListen(h: win32.HANDLE, iosb: *win32.IO_STATUS_BLOCK) !void {
    switch (ntdll.NtFsControlFile(h, g_event, null, null, iosb, win32.CTL_CODE.PIPE.LISTEN, null, 0, null, 0)) {
        .SUCCESS => {},
        .PENDING => {},
        else => |status| {
            std.debug.print("issuePipeListen: {any}\n", .{status});
            return win32.unexpectedStatus(status);
        },
    }
}

const WAIT_OBJECT_0: DWORD = 0x00000000;
const WAIT_TIMEOUT: DWORD = 0x00000102;

fn waitPipeListen(iosb: *win32.IO_STATUS_BLOCK) !void {
    if (WaitForSingleObject(g_event, 30_000) != WAIT_OBJECT_0)
        return error.ListenTimeout;
    if (iosb.u.Status != .SUCCESS) return win32.unexpectedStatus(iosb.u.Status);
}

/// One read via the event; waits when pended. Disconnect statuses surface
/// via last_read_status (mapped to EOF-0 by the future transport).
fn pipeRead(h: win32.HANDLE, buf: []u8) !usize {
    var iosb: win32.IO_STATUS_BLOCK = undefined;
    switch (ntdll.NtReadFile(h, g_event, null, null, &iosb, buf.ptr, @intCast(buf.len), null, null)) {
        .SUCCESS => {},
        .PENDING => {
            _ = WaitForSingleObject(g_event, 30_000);
        },
        else => |status| {
            last_read_status = status;
            return win32.unexpectedStatus(status);
        },
    }
    if (iosb.u.Status != .SUCCESS) {
        last_read_status = iosb.u.Status;
        return win32.unexpectedStatus(iosb.u.Status);
    }
    return iosb.Information;
}

fn pipeWrite(h: win32.HANDLE, bytes: []const u8) !usize {
    var iosb: win32.IO_STATUS_BLOCK = undefined;
    switch (ntdll.NtWriteFile(h, g_event, null, null, &iosb, @ptrCast(bytes.ptr), @intCast(bytes.len), null, null)) {
        .SUCCESS => {},
        .PENDING => {
            _ = WaitForSingleObject(g_event, 30_000);
        },
        else => |status| {
            std.debug.print("pipeWrite: {any}\n", .{status});
            return win32.unexpectedStatus(status);
        },
    }
    if (iosb.u.Status != .SUCCESS) return win32.unexpectedStatus(iosb.u.Status);
    return iosb.Information;
}

const ReadResult = union(enum) { line: []const u8, eof_status: win32.NTSTATUS };

/// Read until '\n' (or an EOF-ish status).
fn readLine(h: win32.HANDLE, buf: []u8) !ReadResult {
    var i: usize = 0;
    while (i < buf.len) {
        const n = pipeRead(h, buf[i .. i + 1]) catch {
            return .{ .eof_status = last_read_status };
        };
        if (n == 0) return .{ .eof_status = .SUCCESS };
        if (buf[i] == '\n') return .{ .line = buf[0..i] };
        i += 1;
    }
    return .{ .line = buf };
}

fn phaseA(io: std.Io) !void {
    // Zig listens; Julia connects.
    const device = try openPipeDevice();
    defer _ = win32.CloseHandle(device);
    const server = try createPipeInstance(device, PIPE_NAME);
    defer _ = win32.CloseHandle(server);
    var listen_iosb: win32.IO_STATUS_BLOCK = undefined;
    try issuePipeListen(server, &listen_iosb);
    stage("A: pipe instance created, LISTEN pended");

    const script =
        \\using Sockets
        \\s = connect(ARGS[1])
        \\write(s, "hello-from-julia\n")
        \\flush(s)
        \\msg = readline(s)
        \\println("SMOKE-JULIA-GOT: ", msg)
        \\@assert msg == "hello-from-zig"
        \\close(s)
    ;
    _ = try std.process.spawn(io, .{
        .argv = &.{ "julia", "--startup-file=no", "-e", script, JULIA_NAME },
    });

    try waitPipeListen(&listen_iosb);
    stage("A: LISTEN completed — julia connected");

    _ = try pipeWrite(server, "hello-from-zig\n");
    var buf: [64]u8 = undefined;
    switch (try readLine(server, &buf)) {
        .line => |line| {
            if (!std.mem.eql(u8, line, "hello-from-julia")) {
                std.debug.print("MISMATCH: got '{s}'\n", .{line});
                return error.DataMismatch;
            }
        },
        .eof_status => |status| {
            std.debug.print("unexpected EOF during read: {any}\n", .{status});
            return error.UnexpectedEof;
        },
    }
    stage("A: round-trip ok (zig listened, julia connected)");
}

fn phaseB(io: std.Io) !void {
    // Julia listens; Zig connects (with retry while the instance comes up).
    const script =
        \\using Sockets
        \\s = listen(ARGS[1])
        \\c = accept(s) # pipe accept returns a bare PipeEndpoint
        \\msg = readline(c)
        \\println("SMOKE-JULIA-GOT: ", msg)
        \\@assert msg == "hello-from-zig"
        \\write(c, "hello-from-julia\n")
        \\flush(c)
        \\close(c)
    ;
    _ = try std.process.spawn(io, .{
        .argv = &.{ "julia", "--startup-file=no", "-e", script, JULIA_NAME },
    });

    const client = try connectPipeRetry(PIPE_NAME, 200);
    defer _ = win32.CloseHandle(client);
    stage("B: connected to julia-listened pipe");

    _ = try pipeWrite(client, "hello-from-zig\n");
    var buf: [64]u8 = undefined;
    switch (try readLine(client, &buf)) {
        .line => |line| {
            if (!std.mem.eql(u8, line, "hello-from-julia")) {
                std.debug.print("MISMATCH: got '{s}'\n", .{line});
                return error.DataMismatch;
            }
        },
        .eof_status => |status| {
            std.debug.print("unexpected EOF during read: {any}\n", .{status});
            return error.UnexpectedEof;
        },
    }
    stage("B: round-trip ok (julia listened, zig connected)");

    // EOF discovery: julia closed the pipe — one more read surfaces the
    // disconnect status the transport must map to EOF-0 (found: PIPE_BROKEN).
    var scratch: [8]u8 = undefined;
    if (readLine(client, &scratch)) |res| {
        switch (res) {
            .eof_status => |status| std.debug.print("EOF status after julia close: {any}\n", .{status}),
            .line => |line| std.debug.print("unexpected data after close: '{s}'\n", .{line}),
        }
    } else |err| {
        std.debug.print("EOF after julia close: {} (status={any})\n", .{ err, last_read_status });
    }
}

/// NtCreateFile(\\??\pipe\<name>, OPEN_EXISTING) with retry — the client
/// half of the dialect (what Julia's uv_pipe_connect does via CreateFileW).
fn connectPipeRetry(comptime name: []const u8, max_attempts: usize) !posix.fd_t {
    const wname = comptimeWide("\\??\\pipe\\" ++ name);
    var attempts: usize = 0;
    while (attempts < max_attempts) : (attempts += 1) {
        var handle: win32.HANDLE = undefined;
        var iosb: win32.IO_STATUS_BLOCK = undefined;
        switch (ntdll.NtCreateFile(
            &handle,
            .{ .GENERIC = .{ .READ = true, .WRITE = true }, .STANDARD = .{ .SYNCHRONIZE = true } },
            &.{
                .ObjectName = @constCast(&win32.UNICODE_STRING.init(&wname)),
            },
            &iosb,
            null,
            .{},
            .{ .READ = true, .WRITE = true },
            .OPEN,
            .{ .IO = .ASYNCHRONOUS },
            null,
            0,
        )) {
            .SUCCESS => return handle,
            .PIPE_BUSY, .OBJECT_NAME_NOT_FOUND => {}, // instance not up yet — retry
            else => |status| {
                std.debug.print("connectPipeRetry: {any}\n", .{status});
                return win32.unexpectedStatus(status);
            },
        }
        Sleep(50); // ~10s total budget
    }
    return error.PipeConnectTimeout;
}
