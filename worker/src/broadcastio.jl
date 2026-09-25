# SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
# SPDX-License-Identifier: MPL-2.0

# Index `maxlines` lines back from the end (or `firstindex` if fewer); 0 = no limit.
function line_limited_start(bytes::Vector{UInt8}, maxlines::Int)
    maxlines > 0 || return firstindex(bytes)
    seen = 0
    for i in lastindex(bytes):-1:firstindex(bytes)
        bytes[i] == UInt8('\n') || continue
        seen += 1
        seen > maxlines && return i + 1
    end
    firstindex(bytes)
end

# Start index plus whether scrollback was lost. Un-cycled: the front is genuine,
# replay all. Cycled: the earliest prompt boundary within the `maxlines` budget,
# else the budget's first line boundary; a later `\e[2J` overrides.
function replay_start(bytes::Vector{UInt8}, overflowed::Bool, maxlines::Int)
    overflowed || return firstindex(bytes), false
    cutoff = line_limited_start(bytes, maxlines)
    start = nothing
    for i in cutoff:lastindex(bytes)
        if i + 4 <= lastindex(bytes) &&
            bytes[i] == UInt8('\r') && bytes[i+1] == UInt8('\e') && bytes[i+2] == UInt8('[') &&
            bytes[i+3] in (UInt8('2'), UInt8('0')) && bytes[i+4] == UInt8('K')
            start = i
            break
        elseif isnothing(start) && bytes[i] == UInt8('\n')
            start = i + 1
        end
    end
    start = @something(start, cutoff)
    clear = findlast(UInt8['\e', '[', '2', 'J'], bytes)
    isnothing(clear) || (start = max(start, last(clear) + 1))
    start, true
end

# A sync session's screen so far: its shared run's output, from its transcript.
function replay_history(dest::IO, screen::Recording; maxlines::Int=0)
    events, dropped = transcript_events(screen.transcript)
    bytes = UInt8[]
    for e in events
        e.run == screen.run && e.kind ∈ (:stdout, :stderr, :prompt) && append!(bytes, e.data)
    end
    start, truncated = replay_start(bytes, dropped > 0, maxlines)
    if truncated
        omitted = dropped + (start - firstindex(bytes))
        write(dest, "\r\e[2K\e[2m── ($(Base.format_bytes(omitted))) of earlier output omitted ──\e[m\r\n")
    end
    write(dest, @view bytes[start:end])
    nothing
end

struct BroadcastWriter{T} <: IO
    writers::Vector{T}
    screen::Recording  # the sync session's shared run
    stream::Symbol
end

Base.iswritable(b::BroadcastWriter) = any(iswritable, b.writers)
Base.isopen(b::BroadcastWriter) = any(isopen, b.writers)
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
    for w in io.writers
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
