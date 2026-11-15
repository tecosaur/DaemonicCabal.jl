# SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
# SPDX-License-Identifier: MPL-2.0

const SERVE_REMOTE = """
    let worker = Base.root_module(Base.PkgId(Base.UUID("73b1f5ce-f66a-45c6-8f4e-ee74572d910a"), "DaemonWorker"))
        isdefined(worker, :serve_remote) || error("this daemon's worker predates remote calls: update DaemonicCabal there and run `DaemonicCabal.install()`")
        worker.serve_remote()
    end"""

"""
    Connection

A daemon worker serving remote calls, through a `juliaclient` of its own;
made by [`connect`](@ref), and closed with `close`.
"""
struct Connection
    address::Union{Nothing, String}
    project::Union{Nothing, String}
    session::Union{Nothing, String}
    process::Base.Process
    lock::ReentrantLock
    outgoing::ModuleSerializer
    incoming::ModuleSerializer
end

"""
    RemoteException <: Exception

A remote call's exception: `exception` itself where it could be
deserialized here (else `nothing`), and always `text`, its rendering with
the remote backtrace.
"""
struct RemoteException <: Exception
    connection::String
    text::String
    exception::Any
end

"""
    ConnectionError <: Exception

A connection whose `juliaclient` ended, exiting with `exitcode`.
"""
struct ConnectionError <: Exception
    connection::String
    exitcode::Int
end

"""
    VersionMismatch <: Exception

A worker whose remote-call protocol, Julia, or `Serialization` format
version (`theirs`) is incompatible with ours.
"""
struct VersionMismatch <: Exception
    connection::String
    ours::typeof(REMOTE_HELLO)
    theirs::Any
end

"""
    connect(address = nothing; project, session, threads) -> Connection
    connect(f, address = nothing; kw...)

Connect to a warm daemon worker for remote calls: at the conductor at
`address` (anything `juliaclient -a` takes), or the local one. The worker
runs `project` (a path on its machine), in the `session` of that label if
given (else in a module of the connection's own), from the pool of
`threads`, on our Julia's minor version: the daemon's own Julia where that
matches, else JuliaUp's channel for it. State persists from call to call.
Given `f`, call `f(conn)` and close it after.

# Examples
```julia
conn = DaemonicCabal.connect("server.example.com:9591"; project = "~/work/Analysis")
@remote conn using Statistics
@remote conn mean(data)
close(conn)
```
"""
function connect(address = nothing; project = nothing, session = nothing, threads = nothing)
    switches = String[]
    isnothing(address) || append!(switches, ("-a", address))
    isnothing(project) || push!(switches, "--project=$project")
    isnothing(session) || push!(switches, "--session=$session")
    isnothing(threads) || append!(switches, ("-t", string(threads)))
    # Last, so a client predating it still reads the switches before.
    push!(switches, "--julia=$(VERSION.major).$(VERSION.minor)")
    Connection(`$(client_symlink_path()) $switches -e $SERVE_REMOTE`; address, project, session)
end

function connect(f::Function, address = nothing; kw...)
    conn = connect(address; kw...)
    try
        f(conn)
    finally
        close(conn)
    end
end

"""
    remotecall_fetch(conn::Connection, f, args...; kwargs...)

Call `f(args...; kwargs...)` in `conn`'s worker, returning its value. A
named `f` goes by name, so must exist there.
"""
remotecall_fetch(conn::Connection, f, args...; kwargs...) = request(conn, (:call, f, args, values(kwargs)))

"""
    @remote conn expr

Evaluate `expr` in `conn`'s worker, returning its value. `\$x` is `x`'s
value here, spliced in. A call's arguments are ours, as if `\$`'d, and its
function too where we have it (a bare or dotted name bound here), else
theirs. Anything else is evaluated there, at top level.

# Examples
```julia
@remote conn using Statistics
@remote conn mean(data)                # our `data`
@remote conn begin                     # their `samples`, our `cutoff`
    kept = filter(>(\$cutoff), samples)
    (mean(kept), length(kept))
end
```
"""
macro remote(conn, ex)
    remote_ex = if Meta.isexpr(ex, :call) remote_call(ex) else splice_values(ex) end
    :($request($(esc(conn)), (:eval, $(esc(Expr(:quote, remote_ex))))))
end

function Connection(cmd::Cmd; address = nothing, project = nothing, session = nothing)
    process = open(pipeline(detach(cmd); stderr), "r+")
    conn = Connection(address, project, session, process, ReentrantLock(), ModuleSerializer(Main), ModuleSerializer(Main))
    payload = try
        read_frame(process)
    catch err
        err isa EOFError && throw(ended(conn))
        kill(process)
        rethrow()
    end
    hello = try
        decode_frame(conn.incoming, payload)
    catch err
        kill(process)
        err isa InterruptException && rethrow()
        # Undecodable, it is no hello of ours.
        throw(VersionMismatch(description(conn), REMOTE_HELLO, nothing))
    end
    is_compatible = hello isa typeof(REMOTE_HELLO) && hello[[1, 3]] == REMOTE_HELLO[[1, 3]] &&
        Base.thisminor(hello[2]) == Base.thisminor(VERSION)
    is_compatible && return conn
    close(conn)
    throw(VersionMismatch(description(conn), REMOTE_HELLO, hello))
end

Base.isopen(conn::Connection) = process_running(conn.process)

function Base.close(conn::Connection)
    close(conn.process.in)
    wait(conn.process)
    nothing
end

Base.show(io::IO, conn::Connection) =
    print(io, "Connection(", description(conn), ", ", if isopen(conn) "open" else "closed" end, ")")

function Base.showerror(io::IO, e::RemoteException)
    print(io, "RemoteException on ", e.connection, ":\n", e.text)
end

function Base.showerror(io::IO, e::ConnectionError)
    print(io, "ConnectionError: the connection to ", e.connection, " ended, its juliaclient exiting with code ",
          e.exitcode, "; connect again to carry on")
end

function Base.showerror(io::IO, e::VersionMismatch)
    print(io, "VersionMismatch: the worker at ", e.connection, " can't serve this DaemonicCabal: ")
    theirs = e.theirs
    if !(theirs isa typeof(REMOTE_HELLO)) || first(theirs) != first(e.ours)
        print(io, "its remote-call protocol differs; run `DaemonicCabal.install()` with the same DaemonicCabal on both machines")
    else
        print(io, "it runs Julia ", theirs[2], " (serialization format ", theirs[3], "), this ", e.ours[2],
              " (", e.ours[3], "); use the same Julia minor version on both, or a daemon there whose",
              " worker executable is JuliaUp's `julia`, which runs ours")
    end
end

function request(conn::Connection, message)
    @lock conn.lock begin
        isopen(conn) || throw(ended(conn))
        frame = encode_frame(conn.outgoing, message)
        payload = try
            exchange(conn, frame)
        catch err
            err isa Union{EOFError, Base.IOError} && throw(ended(conn))
            # Anything else leaves the stream out of step, for good.
            if !(err isa InterruptException)
                kill(conn.process)
                wait(conn.process)
            end
            rethrow()
        end
        reply = decode_frame(conn.incoming, payload)
        first(reply) === :value && return last(reply)
        _, text, exception_payload = reply
        # The text stands in for an exception that won't deserialize here.
        exception = try
            decode_frame(ModuleSerializer(Main), exception_payload)
        catch err
            err isa InterruptException && rethrow()
            nothing
        end
        throw(RemoteException(description(conn), text, exception))
    end
end

# Each frame sent has its reply read whole, a Ctrl-C meanwhile interrupting
# the remote call instead, so the stream stays in step.
function exchange(conn::Connection, frame::Vector{UInt8})
    interrupted = false
    unsent = true
    while true
        try
            if unsent
                unsent = false
                write(conn.process, frame)
            end
            eof(conn.process)
            break
        catch err
            err isa InterruptException || rethrow()
            interrupted = true
            if Sys.iswindows()
                kill(conn.process)
                rethrow()
            end
            kill(conn.process, Base.SIGINT)
        end
    end
    payload = disable_sigint(() -> read_frame(conn.process))
    interrupted && throw(InterruptException())
    payload
end

function ended(conn::Connection)
    wait(conn.process)
    ConnectionError(description(conn), conn.process.exitcode)
end

function description(conn::Connection)
    fields = [something(conn.address, "local")]
    isnothing(conn.project) || push!(fields, "project=$(conn.project)")
    isnothing(conn.session) || push!(fields, "session=$(conn.session)")
    join(fields, ", ")
end

# `@remote`'s expression, as sent: `$x` becomes `x`'s value, here; a nested
# quote's `$` is the far side's.
splice_values(ex) = ex
function splice_values(ex::Expr)
    Meta.isexpr(ex, :$) && return here(only(ex.args))
    Meta.isexpr(ex, :quote) && return ex
    Expr(ex.head, map(splice_values, ex.args)...)
end

here(ex) = Expr(:$, Expr(:call, GlobalRef(Core, :QuoteNode), if Meta.isexpr(ex, :$) only(ex.args) else ex end))

function remote_call(ex::Expr)
    f, args... = ex.args
    Expr(:call, remote_function(f), map(remote_argument, args)...)
end

function remote_function(f)
    root = if f isa Symbol f elseif Meta.isexpr(f, :.) && first(f.args) isa Symbol first(f.args) end
    isnothing(root) && return splice_values(f)
    Expr(:$, Expr(:if, Expr(:isdefined, root), Expr(:call, GlobalRef(Core, :QuoteNode), f), QuoteNode(f)))
end

function remote_argument(arg)
    if Meta.isexpr(arg, :parameters)
        Expr(:parameters, map(remote_keyword, arg.args)...)
    elseif Meta.isexpr(arg, :kw)
        remote_keyword(arg)
    elseif Meta.isexpr(arg, :...)
        Expr(:..., here(only(arg.args)))
    else
        here(arg)
    end
end

# A keyword's shorthand spelled out, as Julia reads it: `a.b` is `b = a.b`.
function remote_keyword(arg)
    if arg isa Symbol
        Expr(:kw, arg, here(arg))
    elseif Meta.isexpr(arg, :kw)
        Expr(:kw, first(arg.args), here(last(arg.args)))
    elseif Meta.isexpr(arg, :.) && last(arg.args) isa QuoteNode
        Expr(:kw, last(arg.args).value, here(arg))
    elseif Meta.isexpr(arg, :call) && first(arg.args) === :(=>)
        Expr(:call, :(=>), map(here, arg.args[2:end])...)
    else
        remote_argument(arg)
    end
end
