# SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
# SPDX-License-Identifier: MPL-2.0

# Remote-call frames (REMOTE.md), shared by DaemonicCabal and DaemonWorker:
# a u64 LE length, then a message serialized through its direction's own
# serializer, which remembers the types it has received.

# Protocol, Julia and serialization versions, a serving worker's first frame.
const REMOTE_HELLO = (UInt32(1), VERSION, Serialization.ser_version)

function write_frame(io::IO, s::AbstractSerializer, message)
    s.io = IOBuffer()
    try
        serialize(s, message)
    finally
        Serialization.reset_state(s)
    end
    payload = take!(s.io)
    write(io, htol(UInt64(length(payload))), payload)
    flush(io)
end

function read_frame(io::IO)
    payload_length = ltoh(read(io, UInt64))
    payload = read(io, payload_length)
    length(payload) == payload_length || throw(EOFError())
    payload
end

function decode_frame(s::AbstractSerializer, payload::Vector{UInt8})
    s.io = IOBuffer(payload)
    try
        deserialize(s)
    finally
        Serialization.reset_state(s)
    end
end
