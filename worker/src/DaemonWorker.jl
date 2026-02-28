# SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
# SPDX-License-Identifier: MPL-2.0

module DaemonWorker

using Base.Threads
using InteractiveUtils
using REPL
using Sockets

const WORKER_ID = Ref("")
const StreamIO = Union{Base.PipeEndpoint, Sockets.TCPSocket}

include("broadcastio.jl")

mutable struct SyncSession
    const mergedin::Base.PipeEndpoint
    const writesink::Base.PipeEndpoint
    const out::BroadcastWriter{StreamIO}
    const err::BroadcastWriter{StreamIO}
    const signals::Vector{StreamIO}
    interactive_count::Int
    const repl::Base.RefValue{REPL.LineEditREPL}
end

@static if VERSION >= v"1.11"
    include("scopedio.jl")
end

include("protocol.jl")
include("setup.jl")
include("run.jl")

function __init__()
    try_load_revise()
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
        redirect_stdin(ScopedStdin())
        redirect_stdout(ScopedStdout())
        redirect_stderr(ScopedStderr())
    end
end

include("precompile.jl")

end
