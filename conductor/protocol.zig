const std = @import("std");
const posix = std.posix;
const Io = std.Io;

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

/// Read exactly buf.len bytes from socket, returning error on EOF
pub fn readExact(fd: posix.socket_t, buf: []u8) !void {
    var total: usize = 0;
    while (total < buf.len) {
        const n = try posix.read(fd, buf[total..]);
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

/// Generate a random socket path in the given runtime directory
pub fn randomSocketPath(io: Io, runtime_dir: []const u8, suffix: []const u8, buf: []u8) ![]const u8 {
    var rand_buf: [8]u8 = undefined;
    io.random(&rand_buf);
    const hex = std.fmt.bytesToHex(rand_buf, .lower);
    return std.fmt.bufPrint(buf, "{s}/{s}-{s}", .{ runtime_dir, &hex, suffix }) catch error.PathTooLong;
}
