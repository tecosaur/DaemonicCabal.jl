// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0
//
// Windows IOCP event loop for the client.
// Multiplexes worker stdout, worker stderr, and the signals socket on the
// port; local console stdin is NOT overlapped-capable, so a helper thread
// owns it entirely: blocking ReadFile → (cooked) → worker stdin socket.
// The worker stdin socket is never port-associated (the client only writes
// it), so every packet on this port is one of ours — no stray-packet guards.

const std = @import("std");
const win32 = std.os.windows;
const posix = std.posix;

const platform = @import("../platform/windows.zig");
const protocol = @import("../protocol.zig");
const cooked = @import("../cooked.zig");

const Location = enum(u64) {
    worker_stdout,
    worker_stderr,
    signals,
};

const buf_size = 1024;

// Receive contexts come from the shared platform plumbing:
// platform.AfdRecvCtx + platform.issueAfdRecv (same ctx the conductor uses
// for pong reads).

// --- stdin helper thread -------------------------------------------------
// Console/pipe stdin can't join the IOCP, so this thread blocks in ReadFile
// and forwards to the worker stdin socket directly. Created via raw
// CreateThread: the binaries build -fsingle-threaded, so std.Thread is out.
extern "kernel32" fn CreateThread(lpThreadAttributes: ?*anyopaque, dwStackSize: usize, lpStartAddress: *const fn (?*anyopaque) callconv(.winapi) win32.DWORD, lpParameter: ?*anyopaque, dwCreationFlags: win32.DWORD, lpThreadId: ?*win32.DWORD) ?win32.HANDLE;

const StdinArgs = struct {
    src: posix.fd_t, // local console/pipe handle
    dst: posix.fd_t, // worker stdin socket
    sync_mode: bool,
    wants_raw: *bool, // shared with the loop thread — read atomically
};

fn stdinProc(param: ?*anyopaque) callconv(.winapi) win32.DWORD {
    const args: *StdinArgs = @ptrCast(@alignCast(param orelse return 1));
    var cooked_state = cooked.CookedState{};
    var buf: [buf_size]u8 = undefined;
    while (true) {
        var got: win32.DWORD = 0;
        if (!platform.ReadFile(args.src, &buf, buf.len, &got, null).toBool() or got == 0) break;
        // In sync mode with the worker asking for cooked input, emulate line
        // editing locally (linux.zig parity). wants_raw is mutated by the
        // loop thread — atomic load, plain bool field.
        if (args.sync_mode and !@atomicLoad(bool, args.wants_raw, .acquire)) {
            for (buf[0..got]) |byte| {
                cooked_state.process(byte, args.dst);
            }
        } else {
            platform.write(args.dst, buf[0..got]);
        }
    }
    // stdin EOF: close the worker stdin socket so the worker sees EOF too.
    platform.close(args.dst);
    return 0;
}

/// Run the client I/O loop on the IOCP.
/// Returns exit code when complete.
pub fn run(
    stdin_fd: posix.fd_t,
    stdout_fd: posix.fd_t,
    stderr_fd: posix.fd_t,
    signals_fd: posix.fd_t,
    signal_parser: anytype,
    sync_mode: bool,
) !u8 {
    const port = platform.CreateIoCompletionPort(win32.INVALID_HANDLE_VALUE, null, 0, 0) orelse
        return error.IocpCreateFailed;
    defer win32.CloseHandle(port);

    // Start the stdin helper before anything can block the loop.
    const args = try std.heap.page_allocator.create(StdinArgs);
    args.* = .{
        .src = platform.getStdinHandle(),
        .dst = stdin_fd,
        .sync_mode = sync_mode,
        .wants_raw = &signal_parser.worker_wants_raw,
    };
    _ = CreateThread(null, 0, &stdinProc, args, 0, null) orelse
        return error.StdinThreadFailed;

    // Associate the three read streams and queue their first receives.
    const stream_fds = [3]posix.fd_t{ stdout_fd, stderr_fd, signals_fd };
    var bufs: [3][buf_size]u8 = undefined;
    var ctxs: [3]?*platform.AfdRecvCtx = .{ null, null, null };
    for (stream_fds, 0..) |fd, i| {
        const loc: Location = @enumFromInt(i);
        if (platform.CreateIoCompletionPort(fd, port, @intFromEnum(loc), 0) == null)
            return error.IocpAssociateFailed;
        platform.markAssociated(fd);
        ctxs[i] = try platform.issueAfdRecv(fd, &bufs[i]);
    }

    // Wait for: stdout+stderr EOF (guarantees output flushed) and exit code
    // (from the signals socket). Signals EOF without an exit code means the
    // worker crashed — exit 1 (linux.zig parity).
    var exit_code: ?u8 = null;
    var eof = [3]bool{ false, false, false };
    while (true) {
        var bytes: win32.DWORD = 0;
        var key: usize = 0;
        var ovl: ?*platform.OVERLAPPED = null;
        if (!platform.GetQueuedCompletionStatus(port, &bytes, &key, &ovl, platform.INFINITE).toBool() and ovl == null) {
            std.debug.print("Fatal: GetQueuedCompletionStatus failed\n", .{});
            return error.IocpWaitFailed;
        }
        // A non-enum key can only be a stray packet from a synchronous op on
        // an associated socket (signal_parser writes); ignore whole — never
        // touch its ovl, which belongs to the issuer's frame. With the
        // Event+token reaping above this should be unreachable; warn if not.
        if (key >= 3) {
            std.debug.print("event loop: stray completion (key={d}) — ignoring\n", .{key});
            continue;
        }
        // Sync-op tokens (event-based ops on associated handles) are reaped
        // before dispatch — their packets carry the same association keys.
        if (ovl) |op| {
            if (platform.reapSyncOp(op)) continue;
        }
        const loc: Location = @enumFromInt(key);
        const idx: usize = @intFromEnum(loc);

        const ctx = ctxs[idx] orelse continue;
        ctxs[idx] = null;
        const status = ctx.iosb.u.Status;
        std.heap.page_allocator.destroy(ctx);

        switch (loc) {
            .worker_stdout, .worker_stderr => {
                if (status == .SUCCESS and bytes > 0) {
                    const dst = if (loc == .worker_stdout)
                        platform.getStdoutHandle()
                    else
                        platform.getStderrHandle();
                    platform.writeFile(dst, bufs[idx][0..@intCast(bytes)]);
                    ctxs[idx] = try platform.issueAfdRecv(stream_fds[idx], &bufs[idx]);
                } else {
                    // EOF (graceful close, 0 bytes, or stream error).
                    eof[idx] = true;
                }
            },
            .signals => {
                if (status == .SUCCESS and bytes > 0) {
                    switch (signal_parser.feed(bufs[idx][0..@intCast(bytes)], signals_fd)) {
                        .exit => |code| {
                            exit_code = code;
                        },
                        .none => ctxs[idx] = try platform.issueAfdRecv(signals_fd, &bufs[idx]),
                    }
                } else if (exit_code == null) {
                    exit_code = 1;
                }
            },
        }
        // Exit only once we have the exit code AND both output streams drained.
        if (exit_code != null and eof[0] and eof[1]) {
            return exit_code.?;
        }
    }
}
