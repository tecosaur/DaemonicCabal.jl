# SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
# SPDX-License-Identifier: MPL-2.0

module DaemonWorker

using Base.Threads
using InteractiveUtils
using Logging
using REPL
using Sockets

const WORKER_ID = Ref("")
const StreamIO = Union{Base.PipeEndpoint, Sockets.TCPSocket}

include("terminaltext.jl")
include("transcript.jl")
include("broadcastio.jl")

struct SyncSession
    mergedin::Base.PipeEndpoint
    writesink::Base.PipeEndpoint
    out::BroadcastWriter{StreamIO}
    err::BroadcastWriter{StreamIO}
    signals::Vector{StreamIO}
    screen::Recording  # the shared run, whose output a joiner is replayed
    repl::Base.RefValue{REPL.LineEditREPL}
end

include("bufferedio.jl")
@static VERSION >= v"1.11" && include("scopedio.jl")
include("protocol.jl")
include("setup.jl")
include("run.jl")

function __init__()
    isyes(get(ENV, "JULIA_DAEMON_REVISE", "no")) && load_revise()
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
