// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0
//
// Windows IOCP event loop for the client. Console stdin cannot join a port,
// so a helper thread forwards it to the worker.

const std = @import("std");
const win32 = std.os.windows;
const posix = std.posix;

const platform = @import("../platform/windows.zig");
const cooked = @import("../cooked.zig");
const debuglog = @import("../debuglog.zig");
const typeahead = @import("../typeahead.zig");

const Location = enum(u64) {
    worker_stdout,
    worker_stderr,
    signals,
};

const buf_size = 1024;

const StdinArgs = struct { src: posix.fd_t, fwd: cooked.StdinForwarder };
// The stdin thread's, for the process's life.
var stdin_args: StdinArgs = undefined;
// The kernel's while a read is pending, which may outlast `run`.
var bufs: [3][buf_size]u8 = undefined;
var ctxs: [3]platform.RecvCtx = undefined;

fn stdinProc(param: ?*anyopaque) callconv(.winapi) win32.DWORD {
    const args: *StdinArgs = @ptrCast(@alignCast(param orelse return 1));
    var buf: [cooked.StdinForwarder.max_read]u8 = undefined;
    while (true) {
        var got: win32.DWORD = 0;
        platform.awaitConsoleKey(args.src);
        if (!platform.ReadFile(args.src, &buf, buf.len, &got, null).toBool()) break;
        // Its own thread, so sends here may wait.
        if (got == 0) {
            const goes_on = args.fwd.end();
            _ = args.fwd.flush();
            if (goes_on) continue;
            return 0;
        }
        args.fwd.forward(buf[0..got]);
        _ = args.fwd.flush();
    }
    platform.sendEof(args.fwd.dst);
    return 0;
}

/// Returns the worker's exit code.
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

    stdin_args = .{
        .src = platform.getStdinHandle(),
        .fwd = .{ .dst = stdin_fd, .sync_mode = sync_mode, .wants_raw = &signal_parser.worker_wants_raw },
    };
    _ = platform.CreateThread(null, 0, &stdinProc, &stdin_args, 0, null) orelse
        return error.StdinThreadFailed;

    const stream_fds = [3]posix.fd_t{ stdout_fd, stderr_fd, signals_fd };
    var pending = [3]bool{ false, false, false };
    for (stream_fds, 0..) |fd, i| {
        const loc: Location = @enumFromInt(i);
        if (platform.CreateIoCompletionPort(fd, port, @intFromEnum(loc), 0) == null)
            return error.IocpAssociateFailed;
        platform.markAssociated(fd);
        pending[i] = platform.issueRecv(fd, &bufs[i], &ctxs[i]);
        if (!pending[i]) return error.StreamDead;
    }

    // Signals EOF without an exit code means the worker crashed.
    var exit_code: ?u8 = null;
    var eof = [3]bool{ false, false, false };
    while (true) {
        var bytes: win32.DWORD = 0;
        var key: usize = 0;
        var ovl: ?*platform.OVERLAPPED = null;
        if (!platform.GetQueuedCompletionStatus(port, &bytes, &key, &ovl, platform.INFINITE).toBool() and ovl == null) {
            platform.eprint("Fatal: GetQueuedCompletionStatus failed\n", .{});
            return error.IocpWaitFailed;
        }
        if (key >= 3) {
            platform.eprint("event loop: stray completion (key={d}) — ignoring\n", .{key});
            continue;
        }
        if (ovl) |op| {
            if (platform.reapSyncOp(op)) continue;
        }
        const loc: Location = @enumFromInt(key);
        const idx: usize = @intFromEnum(loc);

        if (!pending[idx]) continue;
        pending[idx] = false;
        const status = ctxs[idx].iosb.u.Status;

        switch (loc) {
            .worker_stdout, .worker_stderr => {
                if (status == .SUCCESS and bytes > 0) {
                    const dst = if (loc == .worker_stdout)
                        platform.getStdoutHandle()
                    else
                        platform.getStderrHandle();
                    const data = bufs[idx][0..@intCast(bytes)];
                    debuglog.event("{s}: {d} B {f}", .{ if (loc == .worker_stdout) "stdout" else "stderr", data.len, debuglog.preview(data) });
                    if (!typeahead.relay(dst, data)) {
                        platform.close(stream_fds[idx]);
                        eof[idx] = true;
                        continue;
                    }
                    pending[idx] = platform.issueRecv(stream_fds[idx], &bufs[idx], &ctxs[idx]);
                    if (!pending[idx]) eof[idx] = true;
                } else {
                    eof[idx] = true;
                }
            },
            .signals => {
                if (status == .SUCCESS and bytes > 0) {
                    switch (signal_parser.feed(bufs[idx][0..@intCast(bytes)], signals_fd)) {
                        .exit => |code| {
                            exit_code = code;
                        },
                        .none => {
                            pending[idx] = platform.issueRecv(signals_fd, &bufs[idx], &ctxs[idx]);
                            if (!pending[idx] and exit_code == null) exit_code = 1;
                        },
                    }
                } else if (exit_code == null) {
                    exit_code = 1;
                }
            },
        }
        if (exit_code != null and eof[0] and eof[1]) {
            return exit_code.?;
        }
    }
}
