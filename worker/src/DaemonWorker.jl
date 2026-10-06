# SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
# SPDX-License-Identifier: MPL-2.0

module DaemonWorker

using Base.Threads
using InteractiveUtils
using Logging
using Profile
using REPL
using Sockets

const WORKER_ID = Ref("")
const CONDUCTOR_WORKER_ID = Ref(0)  # as the conductor numbers its workers
const WORKER_KEY = Ref(UInt64(0))  # the conductor's, proving our notifications ours
const StreamIO = Union{Base.PipeEndpoint, Sockets.TCPSocket}

include("terminaltext.jl")
include("transcript.jl")
include("broadcastio.jl")
include("replay.jl")
include("terminalinput.jl")

# How a client's run asked to end: `exit`'s code, which a `catch` can't take
# back, and its `atexit` hooks, newest first, run as it ends.
mutable struct RunEnd
    const lock::ReentrantLock
    const hooks::Vector{Function}
    code::Union{Nothing, Int}
    ended::Bool  # its hooks have run
end

# A client's signals stream, which it sends on unasked. One task reads it
# (`read_signals`): its terminal's size is known as it changes, and its
# resuming after a suspension can be waited on.
mutable struct ClientSignals
    const io::StreamIO
    const replied::Threads.Condition
    const gone::Base.Event  # the client has stopped sending
    suspended::Bool  # it was sent a suspension, and has yet to ack it
    size::Union{Nothing, Tuple{Int, Int}}  # its terminal's rows and columns; nothing without one
end

# A --sync client.
struct Participant
    stdout::StreamIO
    stderr::StreamIO
    signals::ClientSignals
end

mutable struct SyncSession
    const label::String
    const input::TerminalInput  # its participants' input, merged
    const out::BroadcastWriter{StreamIO}
    const err::BroadcastWriter{StreamIO}
    @atomic participants::Vector{Participant}  # replaced whole, under `STATE.lock`
    const screen::Recording  # the shared run, whose output a joiner is replayed
    const repl::Base.RefValue{REPL.LineEditREPL}
    const executing::Base.RefValue{Tuple{Bool, UInt32}}  # the REPL's evaluation, as its clients are told
    const executing_lock::ReentrantLock  # held telling them, so a joiner is told in order
    repl_started::Bool  # by its first interactive client, before `repl` is set; message loop only
end

include("bufferedio.jl")
@static VERSION >= v"1.11" && include("scopedio.jl")
include("protocol.jl")
include("setup.jl")
include("peek.jl")
include("run.jl")

function __init__()
    !haskey(ENV, "JULIA_DAEMON_SANDBOXED") && isyes(get(ENV, "JULIA_DAEMON_REVISE", "no")) && load_revise()
    push!(Base.package_callbacks, record_package_sources)
    WORKER_ID[] = String(rand('a':'z', 6))
    include(joinpath(@__DIR__, "overrides.jl"))
    @static if VERSION >= v"1.11"
        unsafe_pipe!(WORKER_TERM.stdin, Base.stdin)
        unsafe_pipe!(WORKER_TERM.stdout, Base.stdout)
        unsafe_pipe!(WORKER_TERM.stderr, Base.stderr)
        WORKER_TERM.terminfo = @static if VERSION >= v"1.12"
            Base.current_terminfo()
        else
            Base.current_terminfo
        end
        WORKER_TERM.have_color = Base.get_have_color()
        setglobal!(Base, :stdin, ScopedStdin())
        setglobal!(Base, :stdout, ScopedStdout())
        setglobal!(Base, :stderr, ScopedStderr())
        # The default logger and display still hold the objects whose handles moved.
        global_logger(ConsoleLogger(Base.stderr))
        Base.Multimedia.reinit_displays()
    end
end

include("precompile.jl")

end
