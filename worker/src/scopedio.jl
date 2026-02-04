using Base.ScopedValues

mutable struct VirtualTerm
    const stdin::Base.PipeEndpoint
    const stdout::Base.PipeEndpoint
    const stderr::Base.PipeEndpoint
    const signals::Base.PipeEndpoint
    const term::String
    terminfo::Union{Nothing, Base.TermInfo}
    have_color::Union{Nothing, Bool}
    have_truecolor::Union{Nothing, Bool}
end

function unsafe_pipe!(pipe::Base.PipeEndpoint, tty::Base.TTY)
    Base.disassociate_julia_struct(pipe.handle)
    Base.disassociate_julia_struct(tty.handle)
    pipe.handle = tty.handle
    pipe.status = tty.status
    pipe.buffer = tty.buffer
    pipe.cond = tty.cond
    pipe.readerror = tty.readerror
    pipe.sendbuf = tty.sendbuf
    pipe.lock = tty.lock
    pipe.throttle = tty.throttle
    Base.associate_julia_struct(pipe.handle, pipe)
    pipe
end

function unsafe_pipe!(pipe::Base.PipeEndpoint, stream::IOStream)
    unsafe_pipe!(pipe, Base.PipeEndpoint(fd(stream)))
end

function unsafe_pipe!(pipe::Base.PipeEndpoint, pipe2::Base.PipeEndpoint)
    Base.disassociate_julia_struct(pipe.handle)
    pipe.handle = pipe2.handle
    pipe.status = pipe2.status
    pipe.buffer = pipe2.buffer
    pipe.cond = pipe2.cond
    pipe.readerror = pipe2.readerror
    pipe.lock = pipe2.lock
    Base.associate_julia_struct(pipe.handle, pipe)
    pipe
end

const WORKER_TERM = VirtualTerm(
    Base.PipeEndpoint(),
    Base.PipeEndpoint(),
    Base.PipeEndpoint(),
    Base.PipeEndpoint(),
    "Unknown",
    nothing,
    nothing,
    nothing
)

const ACTIVE_TERM = ScopedValue{VirtualTerm}(WORKER_TERM)

struct ScopedStdin <: Base.AbstractPipe end
struct ScopedStdout <: Base.AbstractPipe end
struct ScopedStderr <: Base.AbstractPipe end

Base.pipe_reader(::ScopedStdin) = ACTIVE_TERM[].stdin
Base.pipe_writer(::ScopedStdout) = ACTIVE_TERM[].stdout
Base.pipe_writer(::ScopedStderr) = ACTIVE_TERM[].stderr

# See `overrides.jl` for terminfo/color functions

const TERMINFOS = Dict{String, Base.TermInfo}()

function Base.get(::Union{ScopedStdout, ScopedStderr}, key::Symbol, default)
    if key === :color
        @static if VERSION >= v"1.12"
            Base.get_have_color()
        else
            something(ACTIVE_TERM[].have_color, false)
        end
    else
        default
    end
end

function Base.displaysize(::Union{ScopedStdout, ScopedStderr})
    term = ACTIVE_TERM[]
    isopen(term.signals) || return (24, 80)
    send_signal(term.signals, SIGNAL_QUERY_SIZE, UInt8[])
    # Response: id(1) + len(2) + height(2) + width(2)
    resp = read(term.signals, 7)
    height = reinterpret(UInt16, resp[4:5])[1]
    width = reinterpret(UInt16, resp[6:7])[1]
    (Int(height), Int(width))
end
