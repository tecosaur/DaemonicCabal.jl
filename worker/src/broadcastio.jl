# SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
# SPDX-License-Identifier: MPL-2.0

mutable struct BroadcastWriter{T} <: IO
    @atomic writers::Vector{T}  # replaced whole, so iterated safely while it changes
    const screen::Recording  # the sync session's shared run
    const stream::Symbol
end

Base.iswritable(b::BroadcastWriter) = any(iswritable, @atomic b.writers)
Base.isopen(b::BroadcastWriter) = any(isopen, @atomic b.writers)
Base.isreadable(::BroadcastWriter) = false
Base.bytesavailable(::BroadcastWriter) = 0

for (f, params) in [
    (:flush,        ()),
    (:close,        ()),
    (:closewrite,   ()),
    (:reseteof,     ()),
    (:buffer_writes, (:(args...),)),
    ]
    @eval Base.$(f)(io::BroadcastWriter, $(params...)) =
        broadcast_to_writers(Base.$(f), io, $(params...))
end

function broadcast_to_writers(op::F, io::BroadcastWriter, args...) where {F}
    ret = nothing
    for w in @atomic io.writers
        try
            ret = op(w, args...)
        catch e
            e isa Base.IOError || rethrow()
        end
    end
    ret
end

function Base.write(io::BroadcastWriter, byte::UInt8)
    record!(io.screen, io.stream, UInt8[byte])
    broadcast_to_writers(write, io, byte)
    1
end

function Base.unsafe_write(io::BroadcastWriter, p::Ptr{UInt8}, nb::UInt)
    record!(io.screen, io.stream, unsafe_wrap(Array, p, Int(nb)))
    broadcast_to_writers(Base.unsafe_write, io, p, nb)
    Int(nb)
end
