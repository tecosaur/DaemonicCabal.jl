// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0

const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;
const Io = std.Io;
const Allocator = std.mem.Allocator;
const protocol = @import("protocol.zig");
const config = @import("config.zig");
const args = @import("args.zig");

const BufWriter = protocol.BufWriter;
const readExact = protocol.readExact;
const randomSocketPath = protocol.randomSocketPath;

const max_recent_ppids = 32;

pub const Worker = struct {
    allocator: Allocator,
    id: u32,
    process: std.process.Child,
    socket: posix.socket_t,
    project: ?[]const u8,
    julia_channel: ?[]const u8,
    session_label: ?[]const u8,
    created_at: i64,
    last_active: i96,
    last_pinged: i64,
    ping_pending: bool = false,
    active_clients: u32,
    recent_ppids: [max_recent_ppids]u32 = .{0} ** max_recent_ppids,
    recent_ppids_next: usize = 0,

    pub fn spawn(
        allocator: Allocator,
        io: Io,
        cfg: *const config.Config,
        id: u32,
        runtime_dir: []const u8,
        julia_channel: ?[]const u8,
    ) !Worker {
        var path_buf: [std.fs.max_path_bytes]u8 = undefined;
        const setup_path = try randomSocketPath(io, runtime_dir, "wsetup.sock", &path_buf);
        const setup_addr = try Io.net.UnixAddress.init(setup_path);
        var setup_server = try setup_addr.listen(io, .{});
        defer setup_server.deinit(io);
        defer Io.Dir.deleteFileAbsolute(io, setup_path) catch {};
        const eval_expr = try std.fmt.allocPrint(
            allocator,
            "using DaemonWorker; DaemonWorker.runworker(\"{s}\", {d})",
            .{ setup_path, id },
        );
        defer allocator.free(eval_expr);
        var argv = std.array_list.AlignedManaged([]const u8, null).init(allocator);
        defer argv.deinit();
        try argv.append(cfg.worker_executable);
        // JuliaUp channel selector must come immediately after executable
        if (julia_channel) |ch| try argv.append(ch);
        if (cfg.worker_project.len > 0) {
            const project_arg = try std.fmt.allocPrint(allocator, "--project={s}", .{cfg.worker_project});
            try argv.append(project_arg);
        }
        var it = std.mem.splitScalar(u8, cfg.worker_args, ' ');
        while (it.next()) |arg| {
            if (arg.len > 0) try argv.append(arg);
        }
        try argv.append("--eval");
        try argv.append(eval_expr);
        // Spawn in separate process group so terminal SIGINT only goes to conductor
        const child = try std.process.spawn(io, .{
            .argv = argv.items,
            .pgid = 0,
        });
        const worker_stream = try setup_server.accept(io);
        const socket = worker_stream.socket.handle;
        // Set read timeout to avoid blocking conductor if worker becomes unresponsive
        const timeout = linux.timeval{ .sec = @intCast(cfg.ping_timeout), .usec = 0 };
        const timeout_bytes = std.mem.asBytes(&timeout);
        _ = linux.setsockopt(socket, posix.SOL.SOCKET, posix.SO.RCVTIMEO, timeout_bytes.ptr, timeout_bytes.len);
        var magic_buf: [4]u8 = undefined;
        std.mem.writeInt(u32, &magic_buf, protocol.worker.magic, .little);
        _ = linux.write(socket, &magic_buf, 4);
        var ts: linux.timespec = undefined;
        _ = linux.clock_gettime(.MONOTONIC, &ts);
        return .{
            .allocator = allocator,
            .id = id,
            .process = child,
            .socket = socket,
            .project = null,
            .julia_channel = julia_channel,
            .session_label = null,
            .created_at = ts.sec,
            .last_active = ts.sec,
            .last_pinged = ts.sec,
            .active_clients = 0,
        };
    }

    /// Record a PPID for session affinity tracking (circular buffer, 0 = empty)
    pub fn recordPpid(self: *Worker, ppid: u32, max_history: u32) void {
        const cap = @min(max_history, max_recent_ppids);
        if (cap == 0) return;
        self.recent_ppids[self.recent_ppids_next] = ppid;
        self.recent_ppids_next = (self.recent_ppids_next + 1) % cap;
    }

    pub fn deinit(self: *Worker) void {
        if (self.project) |p| self.allocator.free(p);
        if (self.session_label) |l| self.allocator.free(l);
        posix.close(self.socket);
    }

    fn writeHeader(self: *Worker, msg_type: protocol.worker.MessageType, payload_len: u32) void {
        var buf: [5]u8 = undefined;
        buf[0] = @intFromEnum(msg_type);
        std.mem.writeInt(u32, buf[1..5], payload_len, .little);
        _ = linux.write(self.socket, &buf, 5);
    }

    const Header = struct {
        msg_type: protocol.worker.MessageType,
        payload_len: u32,
        raw: [5]u8,
    };

    fn readHeader(self: *Worker) !Header {
        var buf: [5]u8 = undefined;
        try readExact(self.socket, &buf);
        return .{
            .msg_type = @enumFromInt(buf[0]),
            .payload_len = std.mem.readInt(u32, buf[1..5], .little),
            .raw = buf,
        };
    }

    pub fn ping(self: *Worker) !void {
        self.writeHeader(.ping, 0);
        const header = try self.readHeader();
        if (header.msg_type != .pong) {
            std.debug.print("Worker {d}: ping expected pong, got {s} ({s})\n", .{
                self.id, @tagName(header.msg_type), &std.fmt.bytesToHex(header.raw, .lower),
            });
            return error.UnexpectedResponse;
        }
        // Drain the 2-byte client count payload
        var payload: [2]u8 = undefined;
        try readExact(self.socket, &payload);
    }

    /// Send ping without waiting for response (for async ping via io_uring)
    pub fn sendPing(self: *Worker) void {
        self.writeHeader(.ping, 0);
        self.ping_pending = true;
    }

    /// Cancel pending async ping read and drain the pong response.
    /// Must be called before any synchronous worker communication if ping_pending is true.
    /// The cancelled read completion will be ignored in the main event loop (checks for ECANCELED).
    pub fn cancelPendingPing(self: *Worker, ring: *linux.IoUring) void {
        if (!self.ping_pending) return;
        // Cancel the pending io_uring read using worker pointer as user_data
        _ = ring.cancel(@intFromEnum(EventLocation.ignored), @intFromPtr(self), 0) catch {};
        // Submit cancel request (completions handled later in main loop)
        _ = ring.submit() catch {};
        // Drain the pong from the socket (7 bytes: 5 header + 2 client count)
        var buf: [7]u8 = undefined;
        readExact(self.socket, &buf) catch {};
        self.ping_pending = false;
    }

    const EventLocation = protocol.EventLocation;

    /// Takes ownership of project slice (caller must not free on success)
    pub fn setProject(self: *Worker, project: []const u8) !void {
        self.writeHeader(.set_project, @intCast(2 + project.len));
        var len_buf: [2]u8 = undefined;
        std.mem.writeInt(u16, &len_buf, @intCast(project.len), .little);
        _ = linux.write(self.socket, &len_buf, 2);
        _ = linux.write(self.socket, project.ptr, project.len);
        const header = try self.readHeader();
        if (header.msg_type == .err) {
            std.debug.print("Worker {d}: setProject got {s} ({s})\n", .{
                self.id, @tagName(header.msg_type), &std.fmt.bytesToHex(header.raw, .lower),
            });
            return error.ProjectError;
        }
        if (header.msg_type != .project_ok) {
            std.debug.print("Worker {d}: setProject expected project_ok, got {s} ({s})\n", .{
                self.id, @tagName(header.msg_type), &std.fmt.bytesToHex(header.raw, .lower),
            });
            return error.UnexpectedResponse;
        }
        self.project = project;
    }

    pub fn softExit(self: *Worker) void {
        self.writeHeader(.soft_exit, 0);
    }

    /// Send list of active PIDs to worker; worker kills any clients not in list.
    /// Returns the worker's reported remaining client count.
    pub fn syncClients(self: *Worker, pids: []const u32) !u16 {
        const payload_len: u32 = 2 + @as(u32, @intCast(pids.len)) * 4;
        self.writeHeader(.sync_clients, payload_len);
        var len_buf: [2]u8 = undefined;
        std.mem.writeInt(u16, &len_buf, @intCast(pids.len), .little);
        _ = linux.write(self.socket, &len_buf, 2);
        for (pids) |pid| {
            var pid_buf: [4]u8 = undefined;
            std.mem.writeInt(u32, &pid_buf, pid, .little);
            _ = linux.write(self.socket, &pid_buf, 4);
        }
        // Wait for ack with remaining client count
        const header = try self.readHeader();
        if (header.msg_type != .ack) {
            std.debug.print("Worker {d}: syncClients expected ack, got {s} ({s})\n", .{
                self.id, @tagName(header.msg_type), &std.fmt.bytesToHex(header.raw, .lower),
            });
            return error.UnexpectedResponse;
        }
        // Read 2-byte payload: remaining client count
        var count_buf: [2]u8 = undefined;
        try readExact(self.socket, &count_buf);
        return std.mem.readInt(u16, &count_buf, .little);
    }

    pub const SocketPaths = struct {
        stdio: []const u8,
        signals: []const u8,
    };

    pub fn runClient(
        self: *Worker,
        allocator: Allocator,
        client_info: *const ClientInfo,
    ) !SocketPaths {
        // Calculate payload size
        const pf_len: usize = if (client_info.programfile) |pf| pf.len + 2 else 0;
        var payload_size: usize = 1 + 4 + 2 + client_info.cwd.len + 2 + 2 + 1 + pf_len + 2;
        for (client_info.env) |e| payload_size += 4 + e.key.len + e.value.len;
        for (client_info.switches) |sw| payload_size += 4 + sw.name.len + sw.value.len;
        for (client_info.args) |arg| payload_size += 2 + arg.len;
        // Build message
        const send_buf = try allocator.alloc(u8, payload_size);
        defer allocator.free(send_buf);
        var w = BufWriter{ .buf = send_buf };
        w.writeInt(u8, @bitCast(protocol.worker.Flags{ .tty = client_info.tty, .force = client_info.force }));
        w.writeInt(u32, client_info.pid);
        w.writeLenPrefixed(u16, client_info.cwd);
        w.writeInt(u16, @intCast(client_info.env.len));
        for (client_info.env) |e| {
            w.writeLenPrefixed(u16, e.key);
            w.writeLenPrefixed(u16, e.value);
        }
        w.writeInt(u16, @intCast(client_info.switches.len));
        for (client_info.switches) |sw| {
            w.writeLenPrefixed(u16, sw.name);
            w.writeLenPrefixed(u16, sw.value);
        }
        if (client_info.programfile) |pf| {
            w.writeInt(u8, 1);
            w.writeLenPrefixed(u16, pf);
        } else {
            w.writeInt(u8, 0);
        }
        w.writeInt(u16, @intCast(client_info.args.len));
        for (client_info.args) |arg| {
            w.writeLenPrefixed(u16, arg);
        }
        // Send header + payload
        self.writeHeader(.client_run, @intCast(payload_size));
        _ = linux.write(self.socket, send_buf.ptr, payload_size);
        // Read response
        const header = try self.readHeader();
        if (header.msg_type == .err) {
            std.debug.print("Worker {d}: runClient got {s} ({s})\n", .{
                self.id, @tagName(header.msg_type), &std.fmt.bytesToHex(header.raw, .lower),
            });
            // Try to read and print error details if payload is reasonable size
            if (header.payload_len > 0 and header.payload_len < 4096) {
                const err_payload = allocator.alloc(u8, header.payload_len) catch {
                    return error.WorkerError;
                };
                defer allocator.free(err_payload);
                readExact(self.socket, err_payload) catch {
                    return error.WorkerError;
                };
                if (header.payload_len >= 4) {
                    const err_code = std.mem.readInt(u16, err_payload[0..2], .little);
                    const msg_len = std.mem.readInt(u16, err_payload[2..4], .little);
                    if (4 + msg_len <= header.payload_len) {
                        const err_msg = err_payload[4..][0..msg_len];
                        std.debug.print("Worker {d}: error (code {d}): {s}\n", .{ self.id, err_code, err_msg });
                    }
                }
            }
            return error.WorkerError;
        }
        if (header.msg_type != .sockets) {
            std.debug.print("Worker {d}: runClient expected sockets, got {s} ({s})\n", .{
                self.id, @tagName(header.msg_type), &std.fmt.bytesToHex(header.raw, .lower),
            });
            return error.UnexpectedResponse;
        }
        // Read payload
        const payload = try allocator.alloc(u8, header.payload_len);
        defer allocator.free(payload);
        try readExact(self.socket, payload);
        // Parse: active_clients (u32) + stdio path + signals path
        var rpos: usize = 0;
        self.active_clients = std.mem.readInt(u32, payload[rpos..][0..4], .little);
        rpos += 4;
        const stdio_len = std.mem.readInt(u16, payload[rpos..][0..2], .little);
        rpos += 2;
        // Empty stdio path means worker rejected (at capacity)
        if (stdio_len == 0) return error.WorkerBusy;
        const stdio = try allocator.dupe(u8, payload[rpos..][0..stdio_len]);
        rpos += stdio_len;
        const signals_len = std.mem.readInt(u16, payload[rpos..][0..2], .little);
        rpos += 2;
        const signals = try allocator.dupe(u8, payload[rpos..][0..signals_len]);
        return .{ .stdio = stdio, .signals = signals };
    }
};

pub const ClientInfo = struct {
    tty: bool,
    force: bool, // Bypass worker capacity check
    pid: u32,
    ppid: u32,
    cwd: []const u8,
    env: []const EnvVar,
    switches: []const args.Switch,
    programfile: ?[]const u8,
    args: []const []const u8,
};

pub const EnvVar = struct {
    key: []const u8,
    value: []const u8,
};
