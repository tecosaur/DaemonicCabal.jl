# SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
# SPDX-License-Identifier: MPL-2.0

# Remote-call frames (REMOTE.md), shared by DaemonicCabal and DaemonWorker:
# a u64 LE length, then a message serialized through its direction's own
# serializer, which remembers the types it has received.

# Protocol, Julia and serialization versions, a serving worker's first frame.
const REMOTE_HELLO = (UInt32(1), VERSION, Serialization.ser_version)

# Stock `Serializer`'s fields, its `io` swapped per frame. `mod` stands in for
# the far side's `Main`, both ways; a package named, but not loaded, is.
mutable struct ModuleSerializer <: AbstractSerializer
    io::IOBuffer
    counter::Int
    table::IdDict{Any, Any}
    pending_refs::Vector{Int}
    known_object_data::Dict{UInt64, Any}
    version::Int
    const mod::Module
end
ModuleSerializer(mod::Module) =
    ModuleSerializer(IOBuffer(), 0, IdDict{Any, Any}(), Int[], Dict{UInt64, Any}(), Serialization.ser_version, mod)

Serialization.lookup_object_number(s::ModuleSerializer, n::UInt64) = get(s.known_object_data, n, nothing)
function Serialization.remember_object(s::ModuleSerializer, @nospecialize(o), n::UInt64)
    s.known_object_data[n] = o
    nothing
end

Serialization.serialize_mod_names(s::ModuleSerializer, m::Module) =
    invoke(Serialization.serialize_mod_names, Tuple{AbstractSerializer, Module}, s, if m === s.mod Main else m end)

# Stock's test for Main's anonymous functions, whose types go whole.
function Serialization.should_send_whole_type(s::ModuleSerializer, t::DataType)
    tn = t.name
    tn.module === s.mod || return invoke(Serialization.should_send_whole_type, Tuple{Any, DataType}, s, t)
    name = @static if hasfield(Core.TypeName, :singletonname) tn.singletonname else tn.mt.name end
    t.super === Function && startswith(String(tn.name), '#') &&
        (!isdefined(s.mod, name) || t != typeof(getglobal(s.mod, name)))
end

# Stock's, the current format only.
function Serialization.deserialize_module(s::ModuleSerializer)
    uuid = deserialize(s)
    pkg = Base.PkgId(if isnothing(uuid) nothing else Base.UUID(uuid) end, String(deserialize(s)::Symbol))
    mod = if pkg == Base.PkgId("Main") s.mod else get(() -> Base.require(pkg), Base.loaded_modules, pkg) end
    while (inner = deserialize(s)) !== ()
        mod = getglobal(mod, inner)::Module
    end
    mod
end

# Whole, so that one write sends it all, however it is interrupted.
function encode_frame(s::ModuleSerializer, message)
    s.io = IOBuffer()
    write(s.io, UInt64(0))
    try
        serialize(s, message)
    finally
        Serialization.reset_state(s)
    end
    frame = take!(s.io)
    frame[1:8] = reinterpret(UInt8, [htol(UInt64(length(frame) - 8))])
    frame
end

function read_frame(io::IO)
    payload_length = ltoh(read(io, UInt64))
    payload = read(io, payload_length)
    length(payload) == payload_length || throw(EOFError())
    payload
end

function decode_frame(s::ModuleSerializer, payload::Vector{UInt8})
    s.io = IOBuffer(payload)
    try
        deserialize(s)
    finally
        Serialization.reset_state(s)
    end
end
