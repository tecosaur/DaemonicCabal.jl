// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const platform = @import("platform/main.zig");

// Help and version text
pub const VERSION = blk: {
    const project_toml = @embedFile("Project.toml");
    const marker = "\nversion = \"";
    const start = if (std.mem.indexOf(u8, project_toml, marker)) |i| i + marker.len else unreachable;
    const end = if (std.mem.indexOfPos(u8, project_toml, start, "\"")) |i| i else unreachable;
    break :blk project_toml[start..end];
};

pub const DAEMON_MANAGEMENT_HELP = switch (builtin.os.tag) {
    .linux =>
        \\Daemon management (systemd):
        \\
        \\ systemctl --user {start | stop | restart | status} julia-daemon
        \\
    ,
    .macos =>
        \\Daemon management (launchd):
        \\
        \\ launchctl {start | stop} org.julialang.julia-daemon
        \\ tail -f ~/Library/Logs/julia-daemon.log
        \\
    ,
    .windows =>
        \\Daemon management (Task Scheduler):
        \\
        \\ schtasks /{run | query} /tn "Julia\JuliaDaemon"
        \\ taskkill /F /IM julia-conductor.exe   (stop: the task does not track it)
        \\ Get-Process julia-conductor         (status, PowerShell)
        \\ log: %LOCALAPPDATA%\Programs\julia-daemon\conductor.log
        \\
    ,
    else =>
        \\Daemon management:
        \\
        \\ pgrep -f julia-conductor   (status)
        \\ pkill -f julia-conductor   (stop)
        \\
    ,
};

pub const CLIENT_HELP =
    \\
    \\    juliaclient [switches] -- [programfile] [args...]
    \\
    \\Switches (a '*' marks the default value, if applicable):
    \\
    \\ -v, --version              Display version information
    \\ -h, --help                 Print this message
    \\ -P, --project[=<dir>|@.]    Set <dir> as the home project/environment
    \\ -e, --eval <expr>          Evaluate <expr>
    \\ -E, --print <expr>         Evaluate <expr> and display the result
    \\ -L, --load <file>          Load <file> immediately on all processors
    \\ -i                         Interactive mode; REPL runs and `isinteractive()` is true
    \\ -t, --threads <N|auto>[,<M|auto>]  Launch N threads (and M interactive threads)
    \\ -q, --quiet                Quiet startup: no banner, suppress REPL warnings
    \\ --banner={yes|no|auto*}    Enable or disable startup banner
    \\ --color={yes|no|auto*}     Enable or disable color text
    \\ --history-file={yes*|no}   Load or save history
    \\
    \\Client-specific switches:
    \\
    \\ -a, --address <addr>       Connect to conductor at <addr> instead of default
    \\ --session[=<label>]        Reuse worker state in Main module. With a label,
    \\                            multiple clients can share the same session.
    \\ --sync                     Attach to shared REPL (requires --session=<label>)
    \\ --revise[=yes|no*]         Enable or disable Revise.jl integration
    \\ --restart                  Kill workers for the project and exit
    \\ --sandbox                  Run in an isolated sandbox (Linux only)
    \\ --status[=live|json]       Show the state of the workers, optionally in json
    \\ --watch[=json][,once]      Follow the session's transcript (this project's,
    \\                            or --session=<label>'s), as JSON lines, or once
    \\
    \\
++ DAEMON_MANAGEMENT_HELP;


// Client ↔ Conductor: magic + flags + pid + ppid + cwd + env_fingerprint + args,
// answered by kind-byte frames ending in socket_paths.
pub const client = struct {
    pub const magic_prefix: u32 = 0x4A4443; // "JDC", then the version byte
    pub const version: u8 = 2;
    pub const magic: u32 = magic_prefix << 8 | version;
    pub const env_request: u8 = 0x3F; // fingerprint cache miss: send the full env
    // The client spawns its own worker: u16 argc, argc × (u16 len + bytes), then
    // u16 n, n × (u16 len + "KEY=VALUE") placed ahead of the client's env.
    pub const spawn_request: u8 = 0x00;
    // u32 client id, then len-prefixed stdin, stdout, stderr, signals paths.
    pub const socket_paths: u8 = 0x01;

    pub const Flags = packed struct(u8) {
        tty: bool,
        color: bool = false,
        _reserved: u6 = 0,
    };
};

// Conductor ↔ Worker Protocol
pub const worker = struct {
    pub const magic: u32 = 0x4A445703; // "JDW\x03"
    /// Header, then the ping's sequence byte echoed and the worker's client count (u16).
    pub const pong_size = 3 + 1 + 2;

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
        sync_clients = 0x50, // the worker kills any client not listed
        drop_session = 0x51, // payload: label (u16-len + bytes)
        err = 0xFF,
    };

    pub const ErrorCode = enum(u16) {
        unknown = 0,
        invalid_message = 1,
        project_not_found = 2,
        worker_busy = 3,
        internal_error = 4,
        stale_code = 5,
        _,
    };

    pub const Flags = packed struct(u8) {
        tty: bool,
        color: bool = false,
        force: bool = false, // bypass the capacity check, for labelled sessions
        _reserved: u5 = 0,
    };
};

// Notifications → Conductor: connect, send magic + type + payload, close.
// Payloads are a u32: the client id, except as noted.
pub const notification = struct {
    pub const magic: u32 = 0x4A444E01; // "JDN\x01"

    pub const Type = enum(u8) {
        client_done = 0x01,
        worker_unresponsive = 0x02, // pid
        worker_exit = 0x03, // worker id
        client_exit = 0x04,
        client_interrupt = 0x05,
    };
};

// Signals (Worker → Client): id:u8 + len:u8 + data
pub const signals = struct {
    pub const exit: u8 = 0x01;
    pub const raw_mode: u8 = 0x02;   // data: 0x00 = cooked, 0x01 = raw
    pub const query_size: u8 = 0x03; // response: height(u16) + width(u16)
    pub const nodelay: u8 = 0x04;
    pub const executing: u8 = 0x05;  // data: 0x00 = at prompt, 0x01 = evaluating
};

// Event keys >= 0x1000 are pointers with tag bits. Bit 2: pending connection.
// Else bit 1: pending spawn (bit 0: waiting client, not setup listener). Else a
// worker (bit 0: health check, not pong).
pub const EventLocation = enum(u64) {
    accept = 0,
    signal = 1,
    ping_timer = 2,
    ignored = 3, // link_timeout completions
    pressure_timer = 4,
    live_timer = 5, // --status=live repaint
    tick_timer = 6, // 1s, while anything is pending
    _,
};

pub fn readExact(fd: std.posix.socket_t, buf: []u8) !void {
    var total: usize = 0;
    while (total < buf.len) {
        const n = platform.socketRead(fd, buf[total..]);
        if (n == 0) return error.EndOfStream;
        total += n;
    }
}

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

    pub fn readLenPrefixed(self: BufReader, comptime T: type, allocator: std.mem.Allocator) ![]u8 {
        const len = try self.readInt(T);
        const buf = try allocator.alloc(u8, len);
        errdefer allocator.free(buf);
        try readExact(self.fd, buf);
        return buf;
    }
};

pub fn randomSocketPath(io: Io, socket_dir: []const u8, suffix: []const u8, buf: []u8) ![]const u8 {
    var rand_buf: [8]u8 = undefined;
    io.random(&rand_buf);
    const hex = std.fmt.bytesToHex(rand_buf, .lower);
    return platform.localSocketPath(buf, socket_dir, "{s}-{s}", .{ &hex, suffix });
}

// --- Port pool for managed TCP port ranges ---

/// Sets of 4 consecutive ports: stdin, stdout, stderr, signals.
pub const PortPool = struct {
    base: u16,
    count: u16,
    free: std.StaticBitSet(max_port_sets),

    pub const max_port_sets = 2048;
    pub const none: u16 = 0xFFFF;

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

pub const TransportMode = enum { local, tcp };
pub const Listener = platform.Listener;
/// `peer` is set over TCP only.
pub const Connection = struct { socket: std.posix.socket_t, peer: ?Io.net.IpAddress };

pub const Address = struct {
    mode: TransportMode,
    addr: []const u8,
};


/// Paths (containing a separator or starting with `.`) are local; the rest,
/// with any `tcp://` stripped, are TCP.
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

/// Per address tried.
pub const connect_timeout_ms: u32 = 5000;
/// As the worker's `TCP_KEEPALIVE_IDLE_S`.
pub const tcp_keepalive_idle_s: u32 = 60;

/// Split `host[:port]`, where an IPv6 host with a port must be bracketed.
pub fn splitHostPort(addr: []const u8) !struct { host: []const u8, port: u16 } {
    var host = addr;
    var port_text: ?[]const u8 = null;
    if (addr.len > 0 and addr[0] == '[') {
        const end = std.mem.indexOfScalar(u8, addr, ']') orelse return error.InvalidAddress;
        host = addr[1..end];
        const rest = addr[end + 1 ..];
        if (rest.len > 0) {
            if (rest[0] != ':') return error.InvalidAddress;
            port_text = rest[1..];
        }
    } else if (std.mem.lastIndexOfScalar(u8, addr, ':')) |colon| {
        host = addr[0..colon];
        port_text = addr[colon + 1 ..];
    }
    const port = if (port_text) |text| std.fmt.parseInt(u16, text, 10) catch return error.InvalidAddress else default_tcp_port;
    return .{ .host = host, .port = port };
}

/// For connecting, in resolver order. Through the platform, not std, whose
/// resolver would cost the client ~100 KB.
pub fn resolveHost(host: []const u8, port: u16, buf: []Io.net.IpAddress) ![]Io.net.IpAddress {
    if (Io.net.IpAddress.parse(host, port)) |ip| {
        buf[0] = ip;
        return buf[0..1];
    } else |_| {}
    Io.net.HostName.validate(host) catch return error.InvalidAddress;
    return platform.lookupHost(host, port, buf);
}

/// Tries each address a TCP host resolves to in turn.
pub fn connectAddress(mode: TransportMode, addr: []const u8, timeout_ms: u32) !Connection {
    switch (mode) {
        .local => return .{ .socket = try platform.connectLocal(addr, timeout_ms), .peer = null },
        .tcp => {
            const target = try splitHostPort(addr);
            var buf: [8]Io.net.IpAddress = undefined;
            var last_err: anyerror = error.UnknownHostName;
            for (try resolveHost(target.host, target.port, &buf)) |ip| {
                const socket = platform.connectTcp(ip, timeout_ms) catch |err| {
                    last_err = err;
                    continue;
                };
                return .{ .socket = socket, .peer = ip };
            }
            return last_err;
        },
    }
}

pub fn probeAddress(mode: TransportMode, addr: []const u8, timeout_ms: u32) bool {
    const connection = connectAddress(mode, addr, timeout_ms) catch return false;
    platform.close(connection.socket);
    return true;
}

/// For listening, which only the conductor does, so through std. Prefers IPv4,
/// as a name like `localhost` is most commonly reached that way.
fn resolveListen(io_ctx: Io, host: []const u8, port: u16) !Io.net.IpAddress {
    if (Io.net.IpAddress.parse(host, port)) |ip| return ip else |_| {}
    const name = Io.net.HostName.init(host) catch return error.InvalidAddress;
    // Lookup never blocks on a queue of at least 16, so it can run inline.
    var results: [16]Io.net.HostName.LookupResult = undefined;
    var queue: Io.Queue(Io.net.HostName.LookupResult) = .init(&results);
    try name.lookup(io_ctx, &queue, .{ .port = port });
    var first: ?Io.net.IpAddress = null;
    while (queue.getOne(io_ctx)) |result| switch (result) {
        .address => |ip| {
            if (ip == .ip4) return ip;
            if (first == null) first = ip;
        },
        .canonical_name => {},
    } else |_| {}
    return first orelse error.UnknownHostName;
}

pub fn listenAddress(io_ctx: Io, mode: TransportMode, addr: []const u8) !Listener {
    switch (mode) {
        .local => return platform.listenLocal(io_ctx, addr),
        .tcp => {
            const target = try splitHostPort(addr);
            const ip = try resolveListen(io_ctx, target.host, target.port);
            var server = try ip.listen(io_ctx, .{ .kernel_backlog = 128, .reuse_address = true });
            errdefer server.deinit(io_ctx);
            return Listener.fromServer(server, .tcp, addr);
        },
    }
}

pub fn createListener(io_ctx: Io, mode: TransportMode, socket_dir: []const u8, suffix: []const u8, bind_addr: []const u8) !Listener {
    switch (mode) {
        .local => {
            var buf: [std.fs.max_path_bytes]u8 = undefined;
            return platform.listenLocal(io_ctx, try randomSocketPath(io_ctx, socket_dir, suffix, &buf));
        },
        .tcp => return listenTcp(io_ctx, bind_addr, 0),
    }
}

/// Port 0 is ephemeral. Labelled `:port`, since a wildcard bind is no host to dial.
pub fn listenTcp(io_ctx: Io, bind_addr: []const u8, port: u16) !Listener {
    const ip = try resolveListen(io_ctx, bind_addr, port);
    var server = try ip.listen(io_ctx, .{ .reuse_address = true });
    errdefer server.deinit(io_ctx);
    const actual_port = switch (server.socket.address) {
        .ip4 => |a| a.port,
        .ip6 => |a| a.port,
    };
    var buf: [8]u8 = undefined;
    return Listener.fromServer(server, .tcp, try std.fmt.bufPrint(&buf, ":{d}", .{actual_port}));
}
