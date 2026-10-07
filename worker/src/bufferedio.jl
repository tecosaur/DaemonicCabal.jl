# SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
# SPDX-License-Identifier: MPL-2.0

const OUTPUT_BUFFER_THRESHOLD = 8192
const OUTPUT_FLUSH_DELAY_S = 0.01  # the longest output waits for more to join it
# A REPL's: flushed as it waits for a key, this is only for output while it
# waits (a completion hint, drawn in parts), to go as one write.
const REPL_FLUSH_DELAY_S = 0.002

const OutputBuffer = @static if VERSION >= v"1.11-" Memory{UInt8} else Vector{UInt8} end
# Buffers whose writes were interrupted, which libuv may still be reading.
const IN_FLIGHT = (lock = ReentrantLock(), buffers = OutputBuffer[])

# Locked as stock stdout is, whole operations at a time: a `print` holds it
# across its parts, and a flush while the sink writes.
mutable struct BufferedOutput{S <: IO} <: IO
    const sink::S
    buf::OutputBuffer
    pos::Int
    armed::Bool  # a deadline flush is pending
    const delay::Float64  # how long output waits for more to join it
    const lock::ReentrantLock
end

BufferedOutput(sink::IO; delay::Float64=OUTPUT_FLUSH_DELAY_S) =
    BufferedOutput(sink, OutputBuffer(undef, OUTPUT_BUFFER_THRESHOLD), 0, false, delay, ReentrantLock())

Base.lock(o::BufferedOutput) = lock(o.lock)
Base.unlock(o::BufferedOutput) = unlock(o.lock)

function Base.flush(o::BufferedOutput)
    @lock o.lock begin
        n = o.pos
        # Emptied first, so a failed write isn't retried by every later flush.
        o.pos = 0
        if n > 0
            try
                GC.@preserve o unsafe_write(o.sink, pointer(o.buf), UInt(n))
            catch err
                # Interrupted, the write may go on in libuv, from this buffer.
                if !(err isa Base.IOError)
                    @lock IN_FLIGHT.lock push!(IN_FLIGHT.buffers, o.buf)
                    o.buf = OutputBuffer(undef, OUTPUT_BUFFER_THRESHOLD)
                end
                rethrow()
            end
        end
        flush(o.sink)
    end
end

function Base.unsafe_write(o::BufferedOutput, p::Ptr{UInt8}, n::UInt)
    ni = Int(n)
    @lock o.lock begin
        o.pos + ni > OUTPUT_BUFFER_THRESHOLD && flush(o)
        if ni >= OUTPUT_BUFFER_THRESHOLD
            unsafe_write(o.sink, p, n)
            flush(o.sink)
        else
            o.armed || arm_deadline!(o)
            GC.@preserve o unsafe_copyto!(pointer(o.buf, o.pos + 1), p, ni)
            o.pos += ni
        end
    end
    ni
end

function Base.write(o::BufferedOutput, b::UInt8)
    @lock o.lock begin
        o.pos == OUTPUT_BUFFER_THRESHOLD && flush(o)
        o.armed || arm_deadline!(o)
        @inbounds o.buf[o.pos + 1] = b
        o.pos += 1
    end
    1
end

# Under `o.lock`.
function arm_deadline!(o::BufferedOutput)
    o.armed = true
    Timer(o.delay) do _
        @lock o.lock begin
            o.armed = false
            o.pos > 0 && isopen(o.sink) && flush(o)
        end
    end
end

function Base.close(o::BufferedOutput)
    flush(o)
    close(o.sink)
    nothing
end
Base.isopen(o::BufferedOutput) = isopen(o.sink)
Base.displaysize(o::BufferedOutput) = displaysize(o.sink)
Base.get(o::BufferedOutput, key::Symbol, default) = get(o.sink, key, default)
