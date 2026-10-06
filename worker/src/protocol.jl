# SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
# SPDX-License-Identifier: MPL-2.0

const PROTOCOL_MAGIC = 0x4A445705  # "JDW\x05" little-endian
const NOTIFICATION_MAGIC = 0x4A444E02  # "JDN\x02" little-endian

# Notifications, over the conductor's main socket
const NOTIF_TYPE = (
    client_done = 0x01,
    peek_report = 0x06,
    interrupted = 0x07,  # a `cancel_client` read: the worker's id
)

const MSG_TYPE = (
    ping        = 0x01,
    pong        = 0x02,
    set_project = 0x10,
    project_ok  = 0x11,
    client_run  = 0x20,
    sockets     = 0x21,
    query_clients = 0x32,
    clients     = 0x33,
    soft_exit   = 0x40,
    ack         = 0x41,
    sync_clients = 0x50,
    drop_session = 0x51,
    cancel_client = 0x52,
    start_peek  = 0x60,
    error       = 0xFF,
)

const ERR_CODE = (
    unknown         = 0x0000,
    invalid_message = 0x0001,
    project_not_found = 0x0002,
    worker_busy     = 0x0003,
    internal_error  = 0x0004,
    stale_code      = 0x0005,
)

struct MessageHeader
    msg_type::UInt8
    payload_len::UInt32
end

# The conductor's greeting: its magic, then our key.
function read_greeting(conn::IO)
    magic = read(conn, UInt32)
    magic == PROTOCOL_MAGIC || error("Invalid protocol magic: $(repr(magic))")
    read(conn, UInt64)
end

function read_header(conn::IO)
    msg_type = read(conn, UInt8)
    payload_len = read(conn, UInt32)
    MessageHeader(msg_type, payload_len)
end

function write_header(conn::IO, msg_type::UInt8, payload_len::Integer)
    write(conn, msg_type)
    write(conn, UInt32(payload_len))
end

function read_string(conn::IO)
    len = read(conn, UInt32)
    String(read(conn, len))
end

function write_string(conn::IO, s::AbstractString)
    write(conn, UInt32(ncodeunits(s)))
    write(conn, s)
end

function send_pong(conn::IO, seq::UInt8, active_clients::Integer)
    write_header(conn, MSG_TYPE.pong, 3)
    write(conn, seq, UInt16(active_clients))
    flush(conn)
end

# --- Dual transport ---

# The conductor passes `tcp://host:port`, an IPv6 host bracketed, or a local path.
function split_host_port(address::AbstractString)
    host, port = rsplit(chopprefix(address, "tcp://"), ':', limit=2)
    String(strip(host, ('[', ']'))), parse(Int, port)
end

# Prefers IPv4, as the conductor does when it listens on a name.
function resolve_host(host::AbstractString)
    try
        Sockets.parse(IPAddr, host)
    catch
        try Sockets.getaddrinfo(host, IPv4) catch; Sockets.getaddrinfo(host) end
    end
end

function connect_to(address::AbstractString)
    if startswith(address, "tcp://")
        host, port = split_host_port(address)
        sock = Sockets.connect(resolve_host(host), port)
        Sockets.nagle(sock, false)
        sock
    else
        Sockets.connect(address)
    end
end

# `subject` is a client's id, or ours for a peek.
function send_notification(address::AbstractString, type::UInt8, subject::UInt32, payload...)
    try
        conn = connect_to(address)
        write(conn, NOTIFICATION_MAGIC, type, subject, WORKER_KEY[], payload...)
        close(conn)
    catch
        # The conductor may have shut down.
    end
end

function send_sockets(conn::IO, stdin_path::AbstractString, stdout_path::AbstractString,
                      stderr_path::AbstractString, signals_path::AbstractString,
                      active_clients::Integer)
    paths = (stdin_path, stdout_path, stderr_path, signals_path)
    write_header(conn, MSG_TYPE.sockets, 4 + sum(p -> 4 + ncodeunits(p), paths))
    write(conn, UInt32(active_clients))
    foreach(p -> write_string(conn, p), paths)
    flush(conn)
end

function send_error(conn::IO, code::UInt16, message::AbstractString)
    payload_len = 2 + 4 + ncodeunits(message)
    write_header(conn, MSG_TYPE.error, payload_len)
    write(conn, code)
    write_string(conn, message)
    flush(conn)
end

struct ClientInfo
    tty::Bool
    color::Bool
    force::Bool  # bypass capacity (labelled sessions, watchers)
    size::Union{Nothing, Tuple{Int, Int}}  # its terminal's, as it started; nothing without one
    id::Int      # conductor-assigned
    key::UInt64  # which it gives on each of its stdio connections
    cwd::String
    env::Vector{Pair{String, String}}
    switches::Vector{Tuple{String, String}}
    programfile::Union{Nothing, String}
    args::Vector{String}
    port_set::Int  # 0xFFFF when unmanaged
end

# A terminal's rows and columns, each a u16 (LE), as a client tells them:
# nothing for zeros, from a client without one.
function told_size(data::AbstractVector{UInt8})
    length(data) == 4 || return nothing
    rows, cols = ltoh.(reinterpret(UInt16, data))
    if iszero(rows) || iszero(cols) nothing else (Int(rows), Int(cols)) end
end

function read_client_run(conn::IO)
    flags = read(conn, UInt8)
    id = Int(read(conn, UInt32))
    key = read(conn, UInt64)
    size = told_size(read(conn, 4))
    cwd = read_string(conn)
    env = Pair{String, String}[read_string(conn) => read_string(conn) for _ in 1:read(conn, UInt32)]
    switches = Tuple{String, String}[(read_string(conn), read_string(conn)) for _ in 1:read(conn, UInt32)]
    programfile = if read(conn, UInt8) != 0 read_string(conn) end
    args = String[read_string(conn) for _ in 1:read(conn, UInt32)]
    port_set = Int(read(conn, UInt16))
    ClientInfo((flags & 0x01) != 0, (flags & 0x02) != 0, (flags & 0x04) != 0,
               size, id, key, cwd, env, switches, programfile, args, port_set)
end

