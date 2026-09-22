// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0

const std = @import("std");
const Io = std.Io;
const platform = @import("platform/main.zig");

// Client ↔ Conductor Protocol
//   1. Client sends: magic + flags + pid + ppid + cwd + env_fingerprint + args
//   2. Conductor replies with a sequence of frames, each introduced by a kind byte:
//      env_request if the fingerprint is not cached (the client then sends its
//      full env), spawn_request if the client must start its own worker, and
//      finally socket_paths
//   3. Client connects to worker sockets for stdio and signals
pub const client = struct {
    pub const magic_prefix: u32 = 0x4A4443; // "JDC"; the low byte is the protocol version
    pub const version: u8 = 2; // v2: framed replies carrying the client id
    pub const magic: u32 = magic_prefix << 8 | version; // "JDC\x02" little-endian
    // Reply frame kinds:
    pub const env_request: u8 = 0x3F; // '?' - send the full environment (fingerprint cache miss)
    // Spawn your own worker (you are in a mount namespace the conductor cannot see):
    // u16 argc, argc × (u16 len + bytes), then u16 n, n × (u16 len + "KEY=VALUE") of
    // daemon settings to place ahead of the client's environment.
    pub const spawn_request: u8 = 0x00;
    // u32 client id (the client names itself by it in notifications), then four
    // len-prefixed paths: stdin, stdout, stderr, signals.
    pub const socket_paths: u8 = 0x01;

    pub const Flags = packed struct(u8) {
        tty: bool,
        _reserved: u7 = 0,
    };
};

// Conductor ↔ Worker Protocol
pub const worker = struct {
    pub const magic: u32 = 0x4A445702; // "JDW\x02" little-endian — v2: client_run carries the client id

    pub const MessageType = enum(u8) {
        ping = 0x01,
        pong = 0x02,
        set_project = 0x10,
        project_ok = 0x11,
        client_run = 0x20,
        sockets = 0x21,
        query_state = 0x30,
        state = 0x31,
        query_clients = 0x32,
        clients = 0x33,
        soft_exit = 0x40,
        ack = 0x41,
        sync_clients = 0x50, // Conductor sends list of active PIDs; worker kills any not in list
        drop_session = 0x51, // Conductor: session label expired; tear down its REPL. Payload: label (u16-len + bytes)
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
        client_done = 0x01, // Worker: client disconnected. Payload: client id (u32)
        worker_unresponsive = 0x02, // Client: worker not responding. Payload: pid (u32)
        worker_exit = 0x03, // Worker: exiting (TTL expired). Payload: worker_id (u32)
        client_exit = 0x04, // Client: exiting. Payload: client id (u32)
        client_interrupt = 0x05, // Client: interrupt my task. Payload: client id (u32)
    };
};

// Signal Protocol (Worker → Client via signals socket)
// Format: id:u8 + len:u8 + data
pub const signals = struct {
    pub const exit: u8 = 0x01;
    pub const raw_mode: u8 = 0x02;   // data: 0x00 = cooked, 0x01 = raw
    pub const query_size: u8 = 0x03; // response: height(u16) + width(u16)
    pub const nodelay: u8 = 0x04;    // disable Nagle on stdin+signals (low-latency connection)
    pub const executing: u8 = 0x05;  // data: 0x00 = at prompt, 0x01 = evaluating
};

// Event user_data encoding for io_uring:
// - Low values (0-6): fixed events (accept, signal, ping_timer, ignored, pressure_timer, live_timer, tick_timer)
// - High values (>= 0x1000): a pointer with tag bits. Bit 2 set: pending connection
//   (readable). Else bit 1 set: pending spawn (bit 0: 0=setup listener readable,
//   1=waiting client's socket readable). Else worker (bit 0: 0=pong, 1=health check timeout)
pub const EventLocation = enum(u64) {
    accept = 0,
    signal = 1,
    ping_timer = 2,
    ignored = 3, // For link_timeout completions we don't need to handle
    pressure_timer = 4,
    live_timer = 5, // --status=live repaint (debounce + heartbeat unified)
    tick_timer = 6, // 1s tick while anything is pending: spawn deadlines, early exits, silent connections
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

/// Generate a random local socket address in `socket_dir`, ending in `suffix`.
pub fn randomSocketPath(io: Io, socket_dir: []const u8, suffix: []const u8, buf: []u8) ![]const u8 {
    var rand_buf: [8]u8 = undefined;
    io.random(&rand_buf);
    const hex = std.fmt.bytesToHex(rand_buf, .lower);
    return platform.localSocketPath(buf, socket_dir, "{s}-{s}", .{ &hex, suffix });
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
        const start: u16 = @intCast(@as(u32, self.base) + @as(u32, index) * 4);
        return .{ start, start + 1, start + 2, start + 3 };
    }
};

// --- Dual transport ---
// `local` is path-addressed and same-host: AF_UNIX on POSIX, named pipes on
// Windows. `tcp` is host:port. The platform owns the local implementation.

pub const TransportMode = enum { local, tcp };
pub const Listener = platform.Listener;

pub const Address = struct {
    mode: TransportMode,
    addr: []const u8,
};

/// Disable Nagle's algorithm on a TCP socket.
pub fn setTcpNodelay(fd: std.posix.socket_t) void {
    platform.setTcpNodelay(fd); // IPPROTO_TCP=6, TCP_NODELAY=1
}

/// Detect transport mode from address string, stripping any `tcp://` scheme prefix.
/// `tcp://host[:port]` or bare `host[:port]` → tcp; paths (containing a
/// separator or starting with `.`) → local.
pub fn parseAddress(raw: []const u8) error{UnsupportedScheme}!Address {
    if (std.mem.indexOf(u8, raw, "://")) |sep| {
        if (std.mem.eql(u8, raw[0..sep], "tcp"))
            return .{ .mode = .tcp, .addr = raw[sep + 3 ..] };
        return error.UnsupportedScheme;
    }
    if (raw.len > 0 and raw[0] != '/' and raw[0] != '\\' and raw[0] != '.' and
        std.mem.indexOfAny(u8, raw, "/\\") == null)
        return .{ .mode = .tcp, .addr = raw };
    return .{ .mode = .local, .addr = raw };
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

pub fn connectAddress(io_ctx: Io, mode: TransportMode, addr: []const u8) !std.posix.socket_t {
    switch (mode) {
        .local => return platform.connectLocal(io_ctx, addr),
        .tcp => {
            const ip = try parseHostPort(addr);
            return (try ip.connect(io_ctx, .{ .mode = .stream })).socket.handle;
        },
    }
}

pub fn listenAddress(io_ctx: Io, mode: TransportMode, addr: []const u8) !Listener {
    switch (mode) {
        .local => return platform.listenLocal(io_ctx, addr),
        .tcp => {
            const ip = try parseHostPort(addr);
            var server = try ip.listen(io_ctx, .{ .kernel_backlog = 128, .reuse_address = true });
            errdefer server.deinit(io_ctx);
            return Listener.fromServer(server, .tcp, addr);
        },
    }
}

/// Listen on a fresh random local address in `socket_dir`, or an ephemeral TCP port.
pub fn createListener(io_ctx: Io, mode: TransportMode, socket_dir: []const u8, suffix: []const u8, bind_addr: []const u8) !Listener {
    switch (mode) {
        .local => {
            var buf: [std.fs.max_path_bytes]u8 = undefined;
            return platform.listenLocal(io_ctx, try randomSocketPath(io_ctx, socket_dir, suffix, &buf));
        },
        .tcp => return listenTcp(io_ctx, bind_addr, 0),
    }
}

/// Port 0 = ephemeral (OS-assigned).
pub fn listenTcp(io_ctx: Io, bind_addr: []const u8, port: u16) !Listener {
    const ip = Io.net.IpAddress.parse(bind_addr, port) catch return error.InvalidAddress;
    var server = try ip.listen(io_ctx, .{ .reuse_address = true });
    errdefer server.deinit(io_ctx);
    const actual_port = switch (server.socket.address) {
        .ip4 => |a| a.port,
        .ip6 => |a| a.port,
    };
    var buf: [64]u8 = undefined;
    const addr_str = std.fmt.bufPrint(&buf, "{s}:{d}", .{ bind_addr, actual_port }) catch return error.NameTooLong;
    return Listener.fromServer(server, .tcp, addr_str);
}
