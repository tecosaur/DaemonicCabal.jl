# SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
# SPDX-License-Identifier: MPL-2.0

# Binary protocol for Conductor ↔ Worker communication

const PROTOCOL_MAGIC = 0x4A445701  # "JDW\x01" little-endian
const NOTIFICATION_MAGIC = 0x4A444E01  # "JDN\x01" little-endian

# Notification types (sent via main conductor socket)
const NOTIF_TYPE = (
    client_done = 0x01,
    worker_unresponsive = 0x02,
    worker_exit = 0x03,
)

# Message types
const MSG_TYPE = (
    ping        = 0x01,
    pong        = 0x02,
    set_project = 0x10,
    project_ok  = 0x11,
    client_run  = 0x20,
    sockets     = 0x21,
    query_state = 0x30,
    state       = 0x31,
    soft_exit   = 0x40,
    ack         = 0x41,
    sync_clients = 0x50,  # Conductor sends list of active PIDs; worker kills any not in list
    error       = 0xFF,
)

# Error codes
const ERR_CODE = (
    unknown         = 0x0000,
    invalid_message = 0x0001,
    project_not_found = 0x0002,
    worker_busy     = 0x0003,
    internal_error  = 0x0004,
)

struct MessageHeader
    msg_type::UInt8
    payload_len::UInt32
end

# Verify protocol magic at connection start
function verify_magic(conn::IO)
    magic = read(conn, UInt32)
    magic == PROTOCOL_MAGIC || error("Invalid protocol magic: $(repr(magic))")
end

# Read a message header (type + length, 5 bytes)
function read_header(conn::IO)
    msg_type = read(conn, UInt8)
    payload_len = read(conn, UInt32)
    MessageHeader(msg_type, payload_len)
end

# Write a message header (type + length, 5 bytes)
function write_header(conn::IO, msg_type::UInt8, payload_len::Integer)
    write(conn, msg_type)
    write(conn, UInt32(payload_len))
end

# Read a length-prefixed string (u16 length)
function read_string(conn::IO)
    len = read(conn, UInt16)
    String(read(conn, len))
end

# Write a length-prefixed string (u16 length)
function write_string(conn::IO, s::AbstractString)
    write(conn, UInt16(ncodeunits(s)))
    write(conn, s)
end

# Send PONG response with active client count
function send_pong(conn::IO, active_clients::Integer)
    write_header(conn, MSG_TYPE.pong, 2)
    write(conn, UInt16(active_clients))
    flush(conn)
end

# Send PROJECT_OK response
function send_project_ok(conn::IO)
    write_header(conn, MSG_TYPE.project_ok, 0)
    flush(conn)
end

# Send ACK response with client count
function send_ack(conn::IO, client_count::Integer)
    write_header(conn, MSG_TYPE.ack, 2)
    write(conn, UInt16(client_count))
    flush(conn)
end

# Send notification to conductor via main socket
function send_notification(socket_path::AbstractString, type::UInt8, payload...)
    try
        conn = Sockets.connect(socket_path)
        write(conn, NOTIFICATION_MAGIC, type, payload...)
        close(conn)
    catch
        # Conductor may have shut down, ignore
    end
end

send_client_done(socket_path::AbstractString, pid::Integer) =
    send_notification(socket_path, NOTIF_TYPE.client_done, UInt32(pid))

send_worker_exit(socket_path::AbstractString) =
    send_notification(socket_path, NOTIF_TYPE.worker_exit, UInt32(getpid()))

# Send SOCKETS response with socket paths and active client count
function send_sockets(conn::IO, stdio_path::AbstractString, signals_path::AbstractString, active_clients::Integer)
    payload_len = 4 + 2 + ncodeunits(stdio_path) + 2 + ncodeunits(signals_path)
    write_header(conn, MSG_TYPE.sockets, payload_len)
    write(conn, UInt32(active_clients))
    write_string(conn, stdio_path)
    write_string(conn, signals_path)
    flush(conn)
end

# Send STATE response
function send_state(conn::IO, active_clients::Integer, last_client_ts::Integer, soft_exit::Bool)
    write_header(conn, MSG_TYPE.state, 13)
    write(conn, UInt32(active_clients))
    write(conn, UInt64(last_client_ts))
    write(conn, UInt8(soft_exit ? 1 : 0))
    flush(conn)
end

# Send ERROR response
function send_error(conn::IO, code::UInt16, message::AbstractString)
    payload_len = 2 + 2 + ncodeunits(message)
    write_header(conn, MSG_TYPE.error, payload_len)
    write(conn, code)
    write_string(conn, message)
    flush(conn)
end

# Read SET_PROJECT payload
function read_set_project(conn::IO, payload_len::Integer)
    read_string(conn)
end

# Client info from CLIENT_RUN message
struct ClientInfo
    tty::Bool
    force::Bool  # Bypass capacity check (for labeled sessions)
    pid::Int
    cwd::String
    env::Vector{Pair{String, String}}
    switches::Vector{Tuple{String, String}}
    programfile::Union{Nothing, String}
    args::Vector{String}
end

# Read CLIENT_RUN payload
function read_client_run(conn::IO, payload_len::Integer)
    flags = read(conn, UInt8)
    tty = (flags & 0x01) != 0
    force = (flags & 0x02) != 0  # Bypass capacity check
    pid = Int(read(conn, UInt32))
    cwd = read_string(conn)
    # Env
    env_count = read(conn, UInt16)
    env = Vector{Pair{String, String}}(undef, env_count)
    for i in 1:env_count
        key = read_string(conn)
        val = read_string(conn)
        env[i] = key => val
    end
    # Switches
    switch_count = read(conn, UInt16)
    switches = Vector{Tuple{String, String}}(undef, switch_count)
    for i in 1:switch_count
        name = read_string(conn)
        value = read_string(conn)
        switches[i] = (name, value)
    end
    # Programfile
    has_pf = read(conn, UInt8)
    programfile = if has_pf != 0
        read_string(conn)
    else
        nothing
    end
    # Args
    arg_count = read(conn, UInt16)
    args = Vector{String}(undef, arg_count)
    for i in 1:arg_count
        args[i] = read_string(conn)
    end
    ClientInfo(tty, force, pid, cwd, env, switches, programfile, args)
end

