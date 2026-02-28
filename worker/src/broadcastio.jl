# SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
# SPDX-License-Identifier: MPL-2.0

struct BroadcastWriter{T} <: IO
    writers::Vector{T}
end

Base.iswritable(b::BroadcastWriter) = any(iswritable, b.writers)
Base.isopen(b::BroadcastWriter) = any(isopen, b.writers)
Base.isreadable(::BroadcastWriter) = false
Base.bytesavailable(::BroadcastWriter) = 0

# Error-tolerant broadcast: dead sockets must not crash the broadcast.
# Dead clients are cleaned up separately during disconnect processing.
#
# Extract parameter names from typed expressions like :(x::T) → :x
_param_name(e::Expr) = if e.head === :(::) e.args[1] else e end
_param_name(s::Symbol) = s

for (f, params) in [
    (:flush,        ()),
    (:close,        ()),
    (:closewrite,   ()),
    (:reseteof,     ()),
    (:write,        (:(byte::UInt8),)),
    (:unsafe_write, (:(p::Ptr{UInt8}), :(nb::UInt))),
    (:buffer_writes, (:(args...),)),
    ]
    fwd = map(_param_name, collect(params))
    @eval function Base.$(f)(io::BroadcastWriter, $(params...))
        local ret
        for w in io.writers
            try
                ret = Base.$(f)(w, $(fwd...))
            catch e
                e isa Base.IOError || rethrow()
            end
        end
        ret
    end
end
