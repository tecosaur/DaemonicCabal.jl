# SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
# SPDX-License-Identifier: MPL-2.0

using Base.ScopedValues

const OutputIO = Union{Base.PipeEndpoint, Sockets.TCPSocket, BroadcastWriter{StreamIO}, BufferedOutput{Base.PipeEndpoint}, BufferedOutput{Sockets.TCPSocket}}

mutable struct VirtualTerm
    const stdin::StreamIO
    const stdout::OutputIO
    const stderr::OutputIO
    const signals::StreamIO
    const term::String
    const sync_session::Union{Nothing, SyncSession}
    terminfo::Union{Nothing, Base.TermInfo}
    have_color::Union{Nothing, Bool}
    have_truecolor::Union{Nothing, Bool}
    redirect_in::Union{Nothing, IO}
    redirect_out::Union{Nothing, IO}
    redirect_err::Union{Nothing, IO}
end
VirtualTerm(stdin, stdout, stderr, signals, term, sync_session, terminfo, have_color, have_truecolor) =
    VirtualTerm(stdin, stdout, stderr, signals, term, sync_session,
                terminfo, have_color, have_truecolor, nothing, nothing, nothing)

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
    unsafe_pipe!(pipe, Base.PipeEndpoint(Base.RawFD(fd(stream))))
end

function unsafe_pipe!(pipe::Base.PipeEndpoint, pipe2::Base.PipeEndpoint)
    Base.disassociate_julia_struct(pipe.handle)
    pipe.handle = pipe2.handle
    pipe.status = pipe2.status
    pipe.buffer = pipe2.buffer
    pipe.cond = pipe2.cond
    pipe.readerror = pipe2.readerror
    pipe.sendbuf = pipe2.sendbuf
    pipe.lock = pipe2.lock
    pipe.throttle = pipe2.throttle
    Base.associate_julia_struct(pipe.handle, pipe)
    pipe
end

const WORKER_TERM = VirtualTerm(
    Base.PipeEndpoint(),
    Base.PipeEndpoint(),
    Base.PipeEndpoint(),
    Base.PipeEndpoint(),
    "Unknown",
    nothing, nothing, nothing, nothing
)

const ACTIVE_TERM = ScopedValue{VirtualTerm}(WORKER_TERM)
const CLIENT_MODULE = ScopedValue{Module}(Main)
const CLIENT_REPL = ScopedValue(Ref{REPL.LineEditREPL}())
const REPLAY_TARGET = ScopedValue{Union{Nothing, Tuple{StreamIO, SyncSession}}}(nothing)

struct ScopedStdin <: Base.AbstractPipe end
struct ScopedStdout <: Base.AbstractPipe end
struct ScopedStderr <: Base.AbstractPipe end

Base.pipe_reader(::ScopedStdin) = @something(ACTIVE_TERM[].redirect_in, ACTIVE_TERM[].stdin)
Base.pipe_writer(::ScopedStdout) = @something(ACTIVE_TERM[].redirect_out, ACTIVE_TERM[].stdout)
Base.pipe_writer(::ScopedStderr) = @something(ACTIVE_TERM[].redirect_err, ACTIVE_TERM[].stderr)

# A `ScopedStd*` argument is the worker installing its own globals, not a client
# redirect, so it clears the slot.
function set_redirect!(f::Base.RedirectStdStream, io)
    slot, wrapper = if f.unix_fd == 0
        :redirect_in, ScopedStdin
    elseif f.unix_fd == 1
        :redirect_out, ScopedStdout
    else
        :redirect_err, ScopedStderr
    end
    setfield!(ACTIVE_TERM[], slot, io isa wrapper ? nothing : io)
    io
end

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

const DEFAULT_DISPLAYSIZE = (24, 80)

function query_displaysize(signals::StreamIO)
    send_signal(signals, SIGNAL_QUERY_SIZE, UInt8[])
    # Response: id(1) + len(1) + height(2) + width(2)
    resp = read(signals, 6)
    length(resp) == 6 || return DEFAULT_DISPLAYSIZE
    height = reinterpret(UInt16, resp[3:4])[1]
    width = reinterpret(UInt16, resp[5:6])[1]
    (if iszero(height) first(DEFAULT_DISPLAYSIZE) else Int(height) end,
     if iszero(width) last(DEFAULT_DISPLAYSIZE) else Int(width) end)
end
# In sync mode, query all clients and return component-wise minimum (like tmux).
function Base.displaysize(::Union{ScopedStdout, ScopedStderr})
    term = ACTIVE_TERM[]
    session = term.sync_session
    if !isnothing(session)
        min_h, min_w = typemax(Int), typemax(Int)
        for sig in session.signals
            isopen(sig) || continue
            h, w = try query_displaysize(sig) catch; continue end
            min_h = min(min_h, h)
            min_w = min(min_w, w)
        end
        if min_h == typemax(Int)
            DEFAULT_DISPLAYSIZE
        else
            (min_h, min_w)
        end
    else
        isopen(term.signals) || return DEFAULT_DISPLAYSIZE
        query_displaysize(term.signals)
    end
end
