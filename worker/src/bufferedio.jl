# SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
# SPDX-License-Identifier: MPL-2.0

const OUTPUT_BUFFER_THRESHOLD = 8192
const OUTPUT_FLUSH_DELAY_S = 0.01  # the longest output waits for more to join it

const OutputBuffer = @static if VERSION >= v"1.11-" Memory{UInt8} else Vector{UInt8} end

# A flush yields while the sink writes, so it hands the sink one buffer while
# writers fill the other, and waits out any flush still writing.
mutable struct BufferedOutput{S <: IO} <: IO
    const sink::S
    buf::OutputBuffer
    spare::OutputBuffer
    pos::Int
    flushing::Bool
    armed::Bool  # a deadline flush is pending
    const flushed::Threads.Condition
end

BufferedOutput(sink::IO) = BufferedOutput(sink, OutputBuffer(undef, OUTPUT_BUFFER_THRESHOLD),
                                          OutputBuffer(undef, OUTPUT_BUFFER_THRESHOLD), 0, false, false,
                                          Threads.Condition())

function Base.flush(o::BufferedOutput)
    @lock o.flushed while o.flushing
        wait(o.flushed)
    end
    if o.pos > 0
        data, n = o.buf, o.pos
        o.buf, o.spare, o.pos = o.spare, data, 0
        o.flushing = true
        try
            GC.@preserve data unsafe_write(o.sink, pointer(data), UInt(n))
        finally
            o.flushing = false
            @lock o.flushed notify(o.flushed)
        end
    end
    flush(o.sink)
end

function Base.unsafe_write(o::BufferedOutput, p::Ptr{UInt8}, n::UInt)
    ni = Int(n)
    if ni >= OUTPUT_BUFFER_THRESHOLD
        flush(o)
        unsafe_write(o.sink, p, n)
        flush(o.sink)
        return ni
    end
    # Other tasks may write while a flush yields.
    while o.pos + ni > OUTPUT_BUFFER_THRESHOLD
        flush(o)
    end
    o.armed || arm_deadline!(o)
    GC.@preserve o unsafe_copyto!(pointer(o.buf, o.pos + 1), p, ni)
    o.pos += ni
    ni
end

function Base.write(o::BufferedOutput, b::UInt8)
    while o.pos == OUTPUT_BUFFER_THRESHOLD
        flush(o)
    end
    o.armed || arm_deadline!(o)
    @inbounds o.buf[o.pos + 1] = b
    o.pos += 1
    1
end

# The timer's task shares the writer's thread, so it interleaves only at yields.
function arm_deadline!(o::BufferedOutput)
    o.armed = true
    Timer(OUTPUT_FLUSH_DELAY_S) do _
        o.armed = false
        o.pos > 0 && isopen(o.sink) && flush(o)
    end
end

Base.close(o::BufferedOutput) = (flush(o); close(o.sink); nothing)
Base.isopen(o::BufferedOutput) = isopen(o.sink)
Base.displaysize(o::BufferedOutput) = displaysize(o.sink)
Base.get(o::BufferedOutput, key::Symbol, default) = get(o.sink, key, default)
