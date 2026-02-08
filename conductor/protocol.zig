// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0

const std = @import("std");
const Io = std.Io;
const platform = @import("platform/main.zig");

// Client ↔ Conductor Protocol
//   1. Client sends: magic + flags + pid + ppid + cwd + env_fingerprint + args
//   2. Conductor replies with either:
//      a. env_request ('?') if fingerprint not cached, then client sends full env
//      b. Socket paths directly (length-prefixed) if fingerprint cached
//   3. Client connects to worker sockets for stdio and signals
pub const client = struct {
    pub const magic: u32 = 0x4A444301; // "JDC\x01" little-endian
    pub const env_request: u8 = 0x3F; // '?' - conductor requests full environment

    pub const Flags = packed struct(u8) {
        tty: bool,
        _reserved: u7 = 0,
    };
};

// Conductor ↔ Worker Protocol
pub const worker = struct {
    pub const magic: u32 = 0x4A445701; // "JDW\x01" little-endian

    pub const MessageType = enum(u8) {
        ping = 0x01,
        pong = 0x02,
        set_project = 0x10,
        project_ok = 0x11,
        client_run = 0x20,
        sockets = 0x21,
        query_state = 0x30,
        state = 0x31,
        soft_exit = 0x40,
        ack = 0x41,
        sync_clients = 0x50, // Conductor sends list of active PIDs; worker kills any not in list
        err = 0xFF,
    };

    pub const ErrorCode = enum(u16) {
        unknown = 0,
        invalid_message = 1,
        project_not_found = 2,
        worker_busy = 3,
        internal_error = 4,
        _,
    };

    pub const Flags = packed struct(u8) {
        tty: bool,
        force: bool = false, // Bypass capacity check (for labeled sessions)
        _reserved: u6 = 0,
    };
};

// Notification Protocol (Worker/Client → Conductor via main socket)
// Flow: connect to conductor socket, send magic + type + payload, close
pub const notification = struct {
    pub const magic: u32 = 0x4A444E01; // "JDN\x01" little-endian

    pub const Type = enum(u8) {
        client_done = 0x01, // Worker: client disconnected. Payload: pid (u32)
        worker_unresponsive = 0x02, // Client: worker not responding. Payload: pid (u32)
        worker_exit = 0x03, // Worker: exiting (TTL expired). Payload: worker_id (u32)
        client_exit = 0x04, // Client: exiting. Payload: pid (u32)
    };
};

// Signal Protocol (Worker → Client via signals socket)
// Format: id:u8 + len:u8 + data
pub const signals = struct {
    pub const exit: u8 = 0x01;
    pub const raw_mode: u8 = 0x02;   // data: 0x00 = cooked, 0x01 = raw
    pub const query_size: u8 = 0x03; // response: height(u16) + width(u16)
};

// Event user_data encoding for io_uring:
// - Low values (0-3): fixed events (accept, signal, ping_timer, ignored)
// - High values (>= 0x1000): worker pointer | tag (bit 0: 0=pong, 1=health check timeout)
pub const EventLocation = enum(u64) {
    accept = 0,
    signal = 1,
    ping_timer = 2,
    ignored = 3, // For link_timeout completions we don't need to handle
    _,
};

/// Read exactly buf.len bytes from socket, returning error on EOF.
pub fn readExact(fd: std.posix.socket_t, buf: []u8) !void {
    var total: usize = 0;
    while (total < buf.len) {
        const n = platform.socketRead(fd, buf[total..]);
        if (n == 0) return error.EndOfStream;
        total += n;
    }
}

/// Helper for building binary protocol messages into a fixed buffer
pub const BufWriter = struct {
    buf: []u8,
    pos: usize = 0,

    pub fn writeInt(self: *@This(), comptime T: type, val: T) void {
        std.mem.writeInt(T, self.buf[self.pos..][0..@sizeOf(T)], val, .little);
        self.pos += @sizeOf(T);
    }

    pub fn writeSlice(self: *@This(), data: []const u8) void {
        @memcpy(self.buf[self.pos..][0..data.len], data);
        self.pos += data.len;
    }

    pub fn writeLenPrefixed(self: *@This(), comptime T: type, data: []const u8) void {
        self.writeInt(T, @intCast(data.len));
        self.writeSlice(data);
    }

    pub fn written(self: *const @This()) []const u8 {
        return self.buf[0..self.pos];
    }
};

/// Helper for reading binary protocol messages from a socket
pub const BufReader = struct {
    fd: std.posix.socket_t,

    pub fn readInt(self: BufReader, comptime T: type) !T {
        var buf: [@sizeOf(T)]u8 = undefined;
        try readExact(self.fd, &buf);
        return std.mem.readInt(T, &buf, .little);
    }

    pub fn readSlice(self: BufReader, buf: []u8) !void {
        try readExact(self.fd, buf);
    }

    /// Read a length-prefixed byte slice, allocating with the given allocator.
    pub fn readLenPrefixed(self: BufReader, comptime T: type, allocator: std.mem.Allocator) ![]u8 {
        const len = try self.readInt(T);
        const buf = try allocator.alloc(u8, len);
        errdefer allocator.free(buf);
        try readExact(self.fd, buf);
        return buf;
    }

    pub fn skip(self: BufReader, n: usize) !void {
        var discard: [8]u8 = undefined;
        var remaining = n;
        while (remaining > 0) {
            const to_read = @min(remaining, discard.len);
            try readExact(self.fd, discard[0..to_read]);
            remaining -= to_read;
        }
    }
};

/// Generate a random socket path in the given runtime directory
pub fn randomSocketPath(io: Io, runtime_dir: []const u8, suffix: []const u8, buf: []u8) ![]const u8 {
    var rand_buf: [8]u8 = undefined;
    io.random(&rand_buf);
    const hex = std.fmt.bytesToHex(rand_buf, .lower);
    return std.fmt.bufPrint(buf, "{s}/{s}-{s}", .{ runtime_dir, &hex, suffix }) catch error.PathTooLong;
}

// --- Port pool for managed TCP port ranges ---

/// Manages a pool of port sets (4 consecutive ports each) for TCP mode.
/// Port set `i` maps to ports `base + i*4` through `base + i*4 + 3`
/// (stdin, stdout, stderr, signals).
pub const PortPool = struct {
    base: u16,
    count: u16,
    free: std.StaticBitSet(max_port_sets),

    pub const max_port_sets = 2048;
    pub const none: u16 = 0xFFFF; // sentinel: no managed port set

    pub fn init(base: u16, count: u16) PortPool {
        std.debug.assert(count <= max_port_sets);
        var free = std.StaticBitSet(max_port_sets).initEmpty();
        for (0..count) |i| free.set(i);
        return .{ .base = base, .count = count, .free = free };
    }

    pub fn allocate(self: *PortPool) ?u16 {
        const bit = self.free.findFirstSet() orelse return null;
        self.free.unset(bit);
        return @intCast(bit);
    }

    pub fn release(self: *PortPool, index: u16) void {
        std.debug.assert(index < self.count);
        self.free.set(index);
    }

    pub fn portsForIndex(self: *const PortPool, index: u16) [4]u16 {
        const start = self.base + index * 4;
        return .{ start, start + 1, start + 2, start + 3 };
    }
};

// --- Dual transport (Unix sockets / TCP) ---

pub const TransportMode = enum { unix, tcp };

pub const Address = struct {
    mode: TransportMode,
    addr: []const u8,
};

/// Detect transport mode from address string, stripping any `tcp://` scheme prefix.
/// `tcp://host[:port]` or bare `host[:port]` → tcp; paths (containing `/` or starting with `.`) → unix.
pub fn parseAddress(raw: []const u8) error{UnsupportedScheme}!Address {
    if (std.mem.indexOf(u8, raw, "://")) |sep| {
        if (std.mem.eql(u8, raw[0..sep], "tcp"))
            return .{ .mode = .tcp, .addr = raw[sep + 3 ..] };
        return error.UnsupportedScheme;
    }
    if (raw.len > 0 and raw[0] != '/' and raw[0] != '.' and
        std.mem.indexOfScalar(u8, raw, '/') == null)
        return .{ .mode = .tcp, .addr = raw };
    return .{ .mode = .unix, .addr = raw };
}

pub const default_tcp_port: u16 = 9345;

fn parseHostPort(addr: []const u8) !Io.net.IpAddress {
    const colon = std.mem.lastIndexOfScalar(u8, addr, ':');
    const host = if (colon) |c| addr[0..c] else addr;
    const port: u16 = if (colon) |c|
        std.fmt.parseInt(u16, addr[c + 1 ..], 10) catch return error.InvalidAddress
    else
        default_tcp_port;
    return Io.net.IpAddress.parse(host, port) catch return error.InvalidAddress;
}

pub fn connectAddress(io_ctx: Io, mode: TransportMode, addr: []const u8) !Io.net.Stream {
    return switch (mode) {
        .unix => (try Io.net.UnixAddress.init(addr)).connect(io_ctx),
        .tcp => Io.net.IpAddress.connect(try parseHostPort(addr), io_ctx, .{ .mode = .stream }),
    };
}

pub fn listenAddress(io_ctx: Io, mode: TransportMode, addr: []const u8) !Io.net.Server {
    return switch (mode) {
        .unix => (try Io.net.UnixAddress.init(addr)).listen(io_ctx, .{ .kernel_backlog = 128 }),
        .tcp => Io.net.IpAddress.listen(try parseHostPort(addr), io_ctx, .{ .kernel_backlog = 128, .reuse_address = true }),
    };
}

pub const Listener = struct { server: Io.net.Server, addr: []const u8 };

pub fn createListener(
    io_ctx: Io,
    mode: TransportMode,
    runtime_dir: []const u8,
    suffix: []const u8,
    bind_addr: []const u8,
    buf: []u8,
) !Listener {
    switch (mode) {
        .unix => {
            const path = try randomSocketPath(io_ctx, runtime_dir, suffix, buf);
            const unix_addr = try Io.net.UnixAddress.init(path);
            return .{ .server = try unix_addr.listen(io_ctx, .{}), .addr = path };
        },
        .tcp => return listenTcp(io_ctx, bind_addr, 0, buf),
    }
}

/// Port 0 = ephemeral (OS-assigned).
pub fn listenTcp(io_ctx: Io, bind_addr: []const u8, port: u16, buf: []u8) !Listener {
    const ip = Io.net.IpAddress.parse(bind_addr, port) catch return error.InvalidAddress;
    var server = try Io.net.IpAddress.listen(ip, io_ctx, .{ .reuse_address = true });
    const actual_port = switch (server.socket.address) {
        .ip4 => |a| a.port,
        .ip6 => |a| a.port,
    };
    const addr_str = std.fmt.bufPrint(buf, "{s}:{d}", .{ bind_addr, actual_port }) catch {
        server.deinit(io_ctx);
        return error.NameTooLong;
    };
    return .{ .server = server, .addr = addr_str };
}
