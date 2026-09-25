# SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
# SPDX-License-Identifier: MPL-2.0

const PROTOCOL_MAGIC = 0x4A445703  # "JDW\x03" little-endian
const NOTIFICATION_MAGIC = 0x4A444E01  # "JDN\x01" little-endian

# Notifications, over the conductor's main socket
const NOTIF_TYPE = (
    client_done = 0x01,
    worker_unresponsive = 0x02,
    worker_exit = 0x03,
)

const MSG_TYPE = (
    ping        = 0x01,
    pong        = 0x02,
    set_project = 0x10,
    project_ok  = 0x11,
    client_run  = 0x20,
    sockets     = 0x21,
    query_state = 0x30,
    state       = 0x31,
    query_clients = 0x32,
    clients     = 0x33,
    soft_exit   = 0x40,
    ack         = 0x41,
    sync_clients = 0x50,
    drop_session = 0x51,
    error       = 0xFF,
)

const ERR_CODE = (
    unknown         = 0x0000,
    invalid_message = 0x0001,
    project_not_found = 0x0002,
    worker_busy     = 0x0003,
    internal_error  = 0x0004,
)

struct MessageHeader
    msg_type::UInt8
    payload_len::UInt16
end

function verify_magic(conn::IO)
    magic = read(conn, UInt32)
    magic == PROTOCOL_MAGIC || error("Invalid protocol magic: $(repr(magic))")
end

function read_header(conn::IO)
    msg_type = read(conn, UInt8)
    payload_len = read(conn, UInt16)
    MessageHeader(msg_type, payload_len)
end

function write_header(conn::IO, msg_type::UInt8, payload_len::Integer)
    write(conn, msg_type)
    write(conn, UInt16(payload_len))
end

function read_string(conn::IO)
    len = read(conn, UInt16)
    String(read(conn, len))
end

function write_string(conn::IO, s::AbstractString)
    write(conn, UInt16(ncodeunits(s)))
    write(conn, s)
end

function send_pong(conn::IO, seq::UInt8, active_clients::Integer)
    write_header(conn, MSG_TYPE.pong, 3)
    write(conn, seq, UInt16(active_clients))
    flush(conn)
end

# --- Dual transport ---

is_tcp_address(addr::AbstractString) =
    !startswith(addr, '/') && !startswith(addr, '\\') && !startswith(addr, '.') &&
    !contains(addr, '/') && !contains(addr, '\\') && contains(addr, ':')

function split_host_port(address::AbstractString)
    host, port = rsplit(address, ':', limit=2)
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
    if is_tcp_address(address)
        host, port = split_host_port(address)
        sock = Sockets.connect(resolve_host(host), port)
        Sockets.nagle(sock, false)
        sock
    else
        Sockets.connect(address)
    end
end

function send_notification(address::AbstractString, type::UInt8, payload...)
    try
        conn = connect_to(address)
        write(conn, NOTIFICATION_MAGIC, type, payload...)
        close(conn)
    catch
        # The conductor may have shut down.
    end
end

function send_sockets(conn::IO, stdin_path::AbstractString, stdout_path::AbstractString,
                      stderr_path::AbstractString, signals_path::AbstractString,
                      active_clients::Integer)
    payload_len = 4 + 2 + ncodeunits(stdin_path) + 2 + ncodeunits(stdout_path) +
                      2 + ncodeunits(stderr_path) + 2 + ncodeunits(signals_path)
    write_header(conn, MSG_TYPE.sockets, payload_len)
    write(conn, UInt32(active_clients))
    write_string(conn, stdin_path)
    write_string(conn, stdout_path)
    write_string(conn, stderr_path)
    write_string(conn, signals_path)
    flush(conn)
end

function send_state(conn::IO, active_clients::Integer, last_client_ts::Integer, soft_exit::Bool)
    write_header(conn, MSG_TYPE.state, 13)
    write(conn, UInt32(active_clients))
    write(conn, UInt64(last_client_ts))
    write(conn, UInt8(ifelse(soft_exit, 1, 0)))
    flush(conn)
end

function send_error(conn::IO, code::UInt16, message::AbstractString)
    payload_len = 2 + 2 + ncodeunits(message)
    write_header(conn, MSG_TYPE.error, payload_len)
    write(conn, code)
    write_string(conn, message)
    flush(conn)
end

struct ClientInfo
    tty::Bool
    color::Bool
    force::Bool  # bypass capacity (labeled sessions)
    id::Int      # conductor-assigned
    pid::Int     # as our kernel reports it; 0 = unchecked
    cwd::String
    env::Vector{Pair{String, String}}
    switches::Vector{Tuple{String, String}}
    programfile::Union{Nothing, String}
    args::Vector{String}
    port_set::Int  # 0xFFFF when unmanaged
end

function read_client_run(conn::IO)
    flags = read(conn, UInt8)
    tty = (flags & 0x01) != 0
    color = (flags & 0x02) != 0
    force = (flags & 0x04) != 0
    id = Int(read(conn, UInt32))
    pid = Int(read(conn, UInt32))
    cwd = read_string(conn)
    env_count = read(conn, UInt16)
    env = Vector{Pair{String, String}}(undef, env_count)
    for i in 1:env_count
        key = read_string(conn)
        val = read_string(conn)
        env[i] = key => val
    end
    switch_count = read(conn, UInt16)
    switches = Vector{Tuple{String, String}}(undef, switch_count)
    for i in 1:switch_count
        name = read_string(conn)
        value = read_string(conn)
        switches[i] = (name, value)
    end
    has_pf = read(conn, UInt8)
    programfile = if has_pf != 0
        read_string(conn)
    else
        nothing
    end
    arg_count = read(conn, UInt16)
    args = Vector{String}(undef, arg_count)
    for i in 1:arg_count
        args[i] = read_string(conn)
    end
    port_set = Int(read(conn, UInt16))
    ClientInfo(tty, color, force, id, pid, cwd, env, switches, programfile, args, port_set)
end

