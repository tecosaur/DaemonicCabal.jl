# SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
# SPDX-License-Identifier: MPL-2.0

using Base.ScopedValues

const OutputIO = Union{Base.PipeEndpoint, Sockets.TCPSocket, BroadcastWriter{StreamIO}, BufferedOutput{Base.PipeEndpoint}, BufferedOutput{Sockets.TCPSocket}, RecordedOutput, BufferedOutput{RecordedOutput}}

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
    tty.handle = C_NULL # or its finalizer frees the handle under us
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
    pipe2.handle = C_NULL # or its finalizer frees the handle under us
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
const CLIENT_INTERACTIVE = ScopedValue(false)
const CLIENT_REPL = ScopedValue(Ref{REPL.LineEditREPL}())
const CLIENT_RECORDING = ScopedValue{Union{Nothing, Recording}}(nothing)
# `replay_history`'s arguments, for the client starting a sync session's REPL.
const REPLAY_TARGET = ScopedValue{Union{Nothing, Tuple{StreamIO, Recording, Tuple{Int, Int}, Int}}}(nothing)

struct ScopedStdin <: Base.AbstractPipe end
struct ScopedStdout <: Base.AbstractPipe end
struct ScopedStderr <: Base.AbstractPipe end

Base.pipe_reader(::ScopedStdin) = @something(ACTIVE_TERM[].redirect_in, ACTIVE_TERM[].stdin)
Base.pipe_writer(::ScopedStdout) = @something(ACTIVE_TERM[].redirect_out, ACTIVE_TERM[].stdout)
Base.pipe_writer(::ScopedStderr) = @something(ACTIVE_TERM[].redirect_err, ACTIVE_TERM[].stderr)

# Stderr is unbuffered, so it would overtake what stdout still holds.
function flush_pending_stdout()
    out = ACTIVE_TERM[].stdout
    out isa BufferedOutput && out.pos > 0 && flush(out)
end
function Base.unsafe_write(io::ScopedStderr, p::Ptr{UInt8}, n::UInt)
    flush_pending_stdout()
    unsafe_write(Base.pipe_writer(io), p, n)
end
function Base.write(io::ScopedStderr, byte::UInt8)
    flush_pending_stdout()
    write(Base.pipe_writer(io), byte)
end

# A recorded REPL's terminal writes stdout through this, so its line editing
# can be told from the output of other tasks.
struct TerminalStdout <: Base.AbstractPipe end
const TERMINAL_WRITE = ScopedValue(false)
Base.pipe_writer(::TerminalStdout) = Base.pipe_writer(ScopedStdout())
Base.unsafe_write(::TerminalStdout, p::Ptr{UInt8}, n::UInt) =
    with(() -> unsafe_write(ScopedStdout(), p, n), TERMINAL_WRITE => true)
Base.write(::TerminalStdout, byte::UInt8) = with(() -> write(ScopedStdout(), byte), TERMINAL_WRITE => true)

# As stock stdio's, so a `print` holds together across threads: the client's
# own stream, not a redirect, which could change while held.
Base.lock(::Union{ScopedStdout, TerminalStdout}) = lock(ACTIVE_TERM[].stdout)
Base.unlock(::Union{ScopedStdout, TerminalStdout}) = unlock(ACTIVE_TERM[].stdout)
Base.lock(::ScopedStderr) = lock(ACTIVE_TERM[].stderr)
Base.unlock(::ScopedStderr) = unlock(ACTIVE_TERM[].stderr)

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

const TERMINFOS = Dict{String, Base.TermInfo}()

# The client terminal's, for Base's `current_terminfo` and colour queries as the
# worker overrides them. The worker's code calls these, not Base's: an edge to an
# overridden method is invalidated with it.
@static if VERSION >= v"1.12"
    function client_terminfo()
        term = ACTIVE_TERM[]
        isnothing(term.terminfo) || return term.terminfo
        terminfo = Base.load_terminfo(term.term)
        if !haskey(terminfo, :setaf) && startswith(term.term, "xterm")
            terminfo[:setaf] = "\e[3%p1%dm"
        end
        term.terminfo = TERMINFOS[term.term] = terminfo
    end

    function client_have_color()
        term = ACTIVE_TERM[]
        isnothing(term.have_color) || return term.have_color
        term.have_color = haskey(client_terminfo(), :setaf)  # as `Base.ttyhascolor`
    end

    function client_have_truecolor()
        term = ACTIVE_TERM[]
        isnothing(term.have_truecolor) || return term.have_truecolor
        term.have_truecolor = Base.ttyhastruecolor()
    end
end

function Base.get(::Union{ScopedStdout, ScopedStderr, TerminalStdout}, key::Symbol, default)
    if key === :color
        @static if VERSION >= v"1.12"
            client_have_color()
        else
            something(ACTIVE_TERM[].have_color, false)
        end
    else
        client_module_default(key, default)
    end
end

# Base prints a name qualified unless it is visible from the printing IO's
# `:module`, by default the worker's Main: for the client, that is its own.
# These answer an `IOContext` (through its dictionary) and a bare buffer, as
# `repr` and `string` use; the scoped streams answer in `get` above.
function Base.get(d::Base.ImmutableDict{Symbol, Any}, key::Symbol, default::Module)
    invoke(get, Tuple{Base.ImmutableDict, Any, Any}, d, key, client_module_default(key, default))
end
Base.get(::Base.GenericIOBuffer, key::Symbol, default::Module) = client_module_default(key, default)
client_module_default(key::Symbol, default) =
    if key === :module && default === Main CLIENT_MODULE[] else default end

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
# A sync session takes the smallest of its clients' sizes, like tmux.
function Base.displaysize(::Union{ScopedStdout, ScopedStderr, TerminalStdout})
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
        term === WORKER_TERM && return DEFAULT_DISPLAYSIZE # no client to ask
        isopen(term.signals) || return DEFAULT_DISPLAYSIZE
        query_displaysize(term.signals)
    end
end
