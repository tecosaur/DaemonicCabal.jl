# SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
# SPDX-License-Identifier: MPL-2.0

# Circular buffer of the most recent bytes written to a sync session, so a newly
# attaching client can be shown recent context. A session's stdout and stderr
# BroadcastWriters tee into one shared history, recording both streams interleaved
# in write order — the byte stream a terminal would have displayed. `bytes` is
# allocated once at capacity; `pos` is the next write slot (0-based, wraps) and
# `total` the count of all bytes ever written, from which the live byte count
# (`min(total, cap)`) and the dropped count (`total - cap`) derive.
mutable struct OutputHistory
    const bytes::Vector{UInt8}
    const lock::SpinLock
    pos::Int
    total::Int
end

OutputHistory(cap::Int) = OutputHistory(Vector{UInt8}(undef, cap), SpinLock(), 0, 0)

function capture!(h::OutputHistory, data)
    cap = length(h.bytes)
    iszero(cap) && return
    nb = length(data)
    n = min(nb, cap)  # only the last cap bytes of an oversized write survive
    soff = lastindex(data) - n + 1
    @lock h.lock begin
        first_run = min(n, cap - h.pos)
        copyto!(h.bytes, h.pos + 1, data, soff, first_run)
        first_run < n && copyto!(h.bytes, 1, data, soff + first_run, n - first_run)
        h.pos = (h.pos + n) % cap
        h.total += nb
    end
    nothing
end

# The valid bytes oldest-first, plus how many earlier bytes were dropped (0 if the
# ring has not yet cycled). The live region is at most two contiguous runs — from
# the oldest byte to the end of the buffer, then from the start up to `pos`.
function linearise(h::OutputHistory)
    @lock h.lock begin
        cap = length(h.bytes)
        len = min(h.total, cap)
        iszero(len) && return UInt8[], 0
        out = Vector{UInt8}(undef, len)
        start = mod(h.pos - len, cap)  # 0-based index of the oldest byte
        first_run = min(len, cap - start)
        copyto!(out, 1, h.bytes, start + 1, first_run)
        first_run < len && copyto!(out, first_run + 1, h.bytes, 1, len - first_run)
        out, h.total - len
    end
end

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
        # prompt boundary-like check
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

function replay_history(dest::IO, h::OutputHistory; maxlines::Int=0)
    bytes, dropped = linearise(h)
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
    history::OutputHistory
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
    capture!(io.history, (byte,))
    broadcast_to_writers(write, io, byte)
    1
end

function Base.unsafe_write(io::BroadcastWriter, p::Ptr{UInt8}, nb::UInt)
    capture!(io.history, unsafe_wrap(Array, p, Int(nb)))
    broadcast_to_writers(Base.unsafe_write, io, p, nb)
    Int(nb)
end
