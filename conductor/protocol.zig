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
    const start = if (std.mem.find(u8, project_toml, marker)) |i| i + marker.len else unreachable;
    const end = if (std.mem.findPos(u8, project_toml, start, "\"")) |i| i else unreachable;
    break :blk project_toml[start..end];
};

pub const DAEMON_MANAGEMENT_HELP = switch (builtin.target.os.tag) {
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

const help_usage =
    \\
    \\    juliaclient [switches] -- [programfile] [args...]
    \\
    \\
;

pub const CLIENT_HELP = help_usage ++
    \\Switches (a '*' marks the default value, if applicable):
    \\
    \\ -v, --version              Display version information
    \\ -h, --help                 Print command-line options (this message)
    \\ --help-hidden              Print uncommon options not shown by `-h`
    \\ -P, --project[={<dir>|@.}] Set <dir> as the active project/environment
    \\ -e, --eval <expr>          Evaluate <expr>
    \\ -E, --print <expr>         Evaluate <expr> and display the result
    \\ -m, --module <Package> [args]
    \\                            Run entry point of `Package` (`@main` function) with `args`
    \\ -L, --load <file>          Load <file> immediately on all processors
    \\ -t, --threads {auto|N[,auto|M]}
    \\                            Enable N[+M] threads, M in the `interactive` threadpool
    \\ -i, --interactive          Interactive mode; REPL runs and `isinteractive()` is true
    \\ -q, --quiet                Quiet startup: no banner, suppress REPL warnings
    \\ --banner={yes|no|short|auto*}
    \\                            Enable or disable startup banner
    \\ --color={yes|no|auto*}     Enable or disable color text
    \\ --history-file={yes*|no}   Load or save history
    \\
    \\Julia's other switches only apply as a worker starts: set them for every
    \\worker in JULIA_DAEMON_WORKER_ARGS.
    \\
    \\
++ client_switches_help;

/// Points to stock julia's `--help-hidden`, none of whose switches a running
/// worker takes.
pub const CLIENT_HELP_HIDDEN = help_usage ++
    \\Julia's uncommon switches (see `julia --help-hidden`) only apply as a
    \\worker starts: set them for every worker in JULIA_DAEMON_WORKER_ARGS.
    \\
    \\
++ client_switches_help;

const client_switches_help =
    \\Client-specific switches:
    \\
    \\ -a, --address <addr>       Connect to conductor at <addr> instead of default
    \\ --session[=<label>]        Reuse worker state in Main module. With a label,
    \\                            multiple clients can share the same session.
    \\ --sync[=<pages>]           Attach to shared REPL (requires --session=<label>),
    \\                            replaying up to <pages> of it (0 for all)
    \\ --revise[=yes|no*]         Enable or disable Revise.jl integration
    \\ --restart                  Kill workers for the project (or just the
    \\                            --session=<label>'s) and exit
    \\ --sandbox                  Run in an isolated sandbox (Linux only)
    \\ --status[=live|json]       Show the state of the workers, as JSON, or live:
    \\                            ↓ focuses a session, to preview, follow,
    \\                            show its stacktrace, interrupt or terminate it
    \\ --watch[=json][,once]      Follow the session's transcript (this project's,
    \\                            or --session=<label>'s), as JSON lines, or once
    \\ --reconfigure              Show the daemon's settings, to change them live
    \\                            and save them to its service
    \\
    \\
++ DAEMON_MANAGEMENT_HELP;


// Client ↔ Conductor: magic + flags + pid + ppid + host key + cwd +
// env_fingerprint + args, answered by kind-byte frames ending in socket_paths.
// Over TCP, the host key (`host_key_file` in the runtime dir) shows a
// loopback client to be the host's, not a sandbox's; zeros elsewhere.
//
// A client's key, sent with its paths, it gives first on each of its stdio
// connections, and with each notification it sends; a worker's, sent as it
// connects, it gives with its notifications. Both are MACs of their ids
// under a secret of the conductor's, so none can be forged from an id.
pub const client = struct {
    pub const magic_prefix: u32 = 0x4A4443; // "JDC", then the version byte
    pub const version: u8 = 3;
    pub const magic: u32 = magic_prefix << 8 | version;
    pub const env_request: u8 = 0x3F; // fingerprint cache miss: send the full env
    pub const host_key_file = "conductor.key";
    pub const HostKey = [16]u8;
    // The client spawns its own worker: u16 argc, argc × (u16 len + bytes), then
    // u16 n, n × (u16 len + "KEY=VALUE") placed ahead of the client's env.
    pub const spawn_request: u8 = 0x00;
    // u32 client id, then u16-len-prefixed stdin, stdout, stderr, signals
    // paths, then the client's key (u64). A client of another version reads
    // as far as the paths, so a mismatch can be reported to it.
    pub const socket_paths: u8 = 0x01;

    pub const Flags = packed struct(u8) {
        tty: bool,
        color: bool = false,
        _reserved: u6 = 0,
    };
};

// Conductor ↔ Worker Protocol
pub const worker = struct {
    pub const magic: u32 = 0x4A445704; // "JDW\x04"
    /// type(u8) + payload length(u32).
    pub const header_size = 5;
    /// Header, then the ping's sequence byte echoed and the worker's client count (u16).
    pub const pong_size = header_size + 1 + 2;

    pub const MessageType = enum(u8) {
        ping = 0x01,
        pong = 0x02,
        set_project = 0x10,
        project_ok = 0x11,
        client_run = 0x20,
        sockets = 0x21,
        query_clients = 0x32,
        clients = 0x33,
        soft_exit = 0x40,
        ack = 0x41,
        sync_clients = 0x50, // the worker kills any client not listed
        drop_session = 0x51, // payload: label (u32-len + bytes)
        cancel_client = 0x52, // payload: client id, evaluation (u32 each; 0 if unknown); no reply
        start_peek = 0x60, // no reply; the report follows as a `peek_report` notification
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

// Notifications → Conductor: connect, send magic + type + subject (u32) +
// the sender's key (u64) + payload, close. The subject is the client id,
// except as noted.
pub const notification = struct {
    pub const magic: u32 = 0x4A444E02; // "JDN\x02"

    pub const Type = enum(u8) {
        client_done = 0x01, // from its worker
        client_exit = 0x04,
        client_interrupt = 0x05, // then the evaluation it's meant for (u32; 0 if unknown)
        peek_report = 0x06, // the worker's id, then the report: u32 length + bytes
        interrupted = 0x07, // the worker's id: it read a cancel_client
    };
};

pub const KeyKind = enum(u8) { client, worker };

/// A client's or worker's key: a MAC of its id, which only the conductor,
/// holding `secret`, can make.
pub fn keyFor(secret: *const [16]u8, kind: KeyKind, id: u32) u64 {
    var msg: [5]u8 = undefined;
    msg[0] = @intFromEnum(kind);
    std.mem.writeInt(u32, msg[1..5], id, .little);
    return std.crypto.auth.siphash.SipHash64(2, 4).toInt(&msg, secret);
}

// Signals (Worker → Client): id:u8 + len:u8 + data
pub const signals = struct {
    pub const exit: u8 = 0x01;
    pub const raw_mode: u8 = 0x02;   // data: 0x00 = cooked, 0x01 = raw
    pub const query_size: u8 = 0x03; // response: height(u16) + width(u16)
    pub const nodelay: u8 = 0x04;
    pub const executing: u8 = 0x05;  // data: 0x00 = at prompt, 0x01 = evaluating (+ its number, u32)
    pub const suspend_client: u8 = 0x06; // acked once the client runs again
};

// Event keys >= 0x1000 are pointers with tag bits: a pending record's (a
// connection, spawn, stderr pipe or view) is 2-7 in the low three, as
// `Conductor` names them; a worker's is bit 0 alone, set for a health check
// rather than its pong.
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

/// As `readExact`, but all of it within `timeout_ms`, however slowly the
/// peer sends.
pub fn readExactWithin(io: Io, fd: std.posix.socket_t, buf: []u8, timeout_ms: u32) !void {
    const deadline = Io.Clock.now(.awake, io).nanoseconds + @as(i96, timeout_ms) * std.time.ns_per_ms;
    var total: usize = 0;
    while (total < buf.len) {
        const left_ms = @divTrunc(deadline - Io.Clock.now(.awake, io).nanoseconds, std.time.ns_per_ms);
        if (left_ms <= 0 or !platform.waitReadable(fd, @intCast(left_ms))) return error.Timeout;
        total += platform.recvNonBlocking(fd, buf[total..]) orelse return error.EndOfStream;
    }
}

/// The longest socket path or `:port` a client is sent, and takes.
pub const max_socket_path = 256;

/// Reads a payload already received, whose lengths are its sender's word.
pub const SliceReader = struct {
    bytes: []const u8,
    pos: usize = 0,

    pub fn take(self: *SliceReader, n: usize) error{Truncated}![]const u8 {
        if (n > self.bytes.len - self.pos) return error.Truncated;
        defer self.pos += n;
        return self.bytes[self.pos..][0..n];
    }

    pub fn int(self: *SliceReader, comptime T: type) error{Truncated}!T {
        return std.mem.readInt(T, (try self.take(@sizeOf(T)))[0..@sizeOf(T)], .little);
    }

    pub fn lenPrefixed(self: *SliceReader, comptime T: type) error{Truncated}![]const u8 {
        return self.take(try self.int(T));
    }
};

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
    free: std.bit_set.Static(max_port_sets),

    pub const max_port_sets = 2048;
    pub const none: u16 = 0xFFFF;

    pub fn init(base: u16, count: u16) PortPool {
        std.debug.assert(count <= max_port_sets);
        var free = std.bit_set.Static(max_port_sets).empty;
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
    if (std.mem.find(u8, raw, "://")) |sep| {
        if (std.mem.eql(u8, raw[0..sep], "tcp"))
            return .{ .mode = .tcp, .addr = raw[sep + 3 ..] };
        return error.UnsupportedScheme;
    }
    if (raw.len > 0 and raw[0] != '/' and raw[0] != '\\' and raw[0] != '.' and
        std.mem.findAny(u8, raw, "/\\") == null)
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
        const end = std.mem.findScalar(u8, addr, ']') orelse return error.InvalidAddress;
        host = addr[1..end];
        const rest = addr[end + 1 ..];
        if (rest.len > 0) {
            if (rest[0] != ':') return error.InvalidAddress;
            port_text = rest[1..];
        }
    } else if (std.mem.findScalarLast(u8, addr, ':')) |colon| {
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

/// 127.0.0.0/8, ::1, or an IPv4-mapped 127.x.
pub fn isLoopback(address: Io.net.IpAddress) bool {
    const v4_mapped = [12]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };
    return switch (address) {
        .ip4 => |a| a.bytes[0] == 127,
        .ip6 => |a| std.mem.eql(u8, &a.bytes, &Io.net.Ip6Address.loopback(0).bytes) or
            (std.mem.eql(u8, a.bytes[0..12], &v4_mapped) and a.bytes[12] == 127),
    };
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
            var buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
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
    return Listener.fromServer(server, .tcp, try std.mem.print(&buf, ":{d}", .{actual_port}));
}
