# SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
# SPDX-License-Identifier: MPL-2.0

# * Set up REPL-related overrides
# Within `REPL`, `check_open` is called on our `stdout` IOContext,
# and we need to add this method to make it work.
# Core.eval(mod, :(Base.check_open(ioc::IOContext) = Base.check_open(ioc.io)))

# Create a fresh module with MainInclude and DaemonClientExit pre-defined (expensive)
function create_module()::Module
    mod = Module(:Main)
    # MainInclude (taken from base/client.jl)
    maininclude = quote
        baremodule MainInclude
        using ..Base
        include(mapexpr::Function, fname::AbstractString) = Base._include(mapexpr, $mod, fname)
        function include(fname::AbstractString)
            isa(fname, String) || (fname = Base.convert(String, fname)::String)
            Base._include(identity, $mod, fname)
        end
        eval(x) = Core.eval($mod, x)
        end
        import .MainInclude: eval, include
    end
    maininclude.head = :toplevel
    Core.eval(mod, maininclude)
    Core.eval(mod, :(using InteractiveUtils))
    mod
end

# Get a module, using standby if available
function get_module()::Module
    mod = @lock STATE.lock begin
        m = STATE.standby_module[]
        STATE.standby_module[] = nothing
        m
    end
    if isnothing(mod) create_module() else mod end
end

# Ensure standby module exists (called after client disconnect or on startup)
function ensure_standby_module()
    @lock STATE.lock begin
        if isnothing(STATE.standby_module[])
            STATE.standby_module[] = create_module()
        end
    end
end

# Pre-warm the REPL frontend with a throwaway session: its Base/REPL-overriding methods
# can't be precompiled, but the JIT'd code is process-global so real sessions reuse it.
function warm_repl_path()
    @static if VERSION < v"1.11"
        return nothing
    else
        get(ENV, "JULIA_DAEMON_PREWARM", "1") ∈ ("no", "false", "0") && return nothing
        try
            cin  = Pipe(); Base.link_pipe!(cin;  reader_supports_async=true, writer_supports_async=true)
            cout = Pipe(); Base.link_pipe!(cout; reader_supports_async=true, writer_supports_async=true)
            cerr = Pipe(); Base.link_pipe!(cerr; reader_supports_async=true, writer_supports_async=true)
            # Closed signals so raw!/displaysize short-circuit (no client round-trip).
            sig = Pipe(); Base.link_pipe!(sig); close(sig.in); close(sig.out)
            dout = errormonitor(@async try read(cout.out) catch end)
            derr = errormonitor(@async try read(cerr.out) catch end)
            feeder = errormonitor(@async try write(cin.in, "1+1\n"); close(cin.in) catch end)
            histfile = tempname()
            client = ClientInfo(true, false, 0, pwd(),
                                ["TERM" => "xterm-256color", "JULIA_HISTORY" => histfile,
                                 "JULIA_DAEMON_REVISE" => "no"],
                                Tuple{String, String}[],
                                nothing, String[], 0xFFFF)
            runclient(client, cin.out, cout.in, cerr.in, sig.out; owned_streams=())
            close(cout.in); close(cerr.in)
            wait(dout); wait(derr); wait(feeder)
            rm(histfile; force=true)
        catch e
            @debug "REPL pre-warm failed" exception=(e, catch_backtrace())
        end
        ensure_standby_module()
        return nothing
    end
end

# Finalize module for a specific client (cheap)
function prepare_module(client::ClientInfo)
    mod = if any(p -> first(p) == "--session", client.switches)
        Main
    else
        get_module()
    end
    # State
    Core.eval(mod, :(cd($(client.cwd))))
    if !isempty(client.args)
        Core.eval(mod, :(ARGS = $(client.args)))
    end
    if getval(client.switches, "--revise", get(ENV, "JULIA_DAEMON_REVISE", "no")) ∈ ("yes", "true", "1", "")
        if isdefined(Main, :Revise)
            Main.Revise.revise()
        elseif !isnothing(Base.locate_package(REVISE_PKG))
            Core.eval(Main, :(using Revise))
            Main.Revise.revise()
        end
    end
    mod
end

function Base.display(d::REPL.REPLDisplay, ::MIME"text/plain", exit::DaemonClientExit)
    REPL.LineEdit.transition(d.repl.mistate, :abort)
end

function getval(pairlist, key, default)
    index = findfirst(p -> first(p) == key, pairlist)
    if isnothing(index) default else last(pairlist[index]) end
end

function clienthascolor(client::ClientInfo)
    cs = getval(client.switches, "--color", nothing)
    if cs !== nothing
        cs ∈ ("yes", "true", "1", "")
    elseif client.tty
        term = getval(client.env, "TERM", "")
        @static if VERSION >= v"1.11"
            haskey(Base.load_terminfo(term), :setaf)
        else
            startswith(term, "xterm")
        end
    else
        false
    end
end

function runclient(client::ClientInfo, client_stdin::StreamIO,
                   client_stdout::IO, client_stderr::IO,
                   signals::StreamIO;
                   owned_streams::Tuple=(client_stdout, client_stderr),
                   sync_session::Union{Nothing, SyncSession}=nothing,
                   repl_ref::Base.RefValue{REPL.LineEditREPL}=Ref{REPL.LineEditREPL}(),
                   broadcast::Union{Nothing, BroadcastWriter{StreamIO}}=nothing,
                   replay::Union{Nothing, Tuple{StreamIO, SyncSession}}=nothing)
    hascolor = clienthascolor(client)
    stdoutx = IOContext(client_stdout, :color => hascolor)
    stderrx = IOContext(client_stderr, :color => hascolor)
    mod = prepare_module(client)
    exit_code = 0
    try
        withenv(client.env...) do
            @static if VERSION < v"1.11"
                CLIENT_SIGNALS[] = signals
                try
                    redirect_stdio(stdin=client_stdin, stdout=stdoutx, stderr=stderrx) do
                        runclient(mod, client; stdout=stdoutx, broadcast)
                    end
                finally
                    CLIENT_SIGNALS[] = nothing
                end
            else
                term = get(ENV, "TERM", @static if Sys.iswindows() "" else "dumb" end)
                color = @static if VERSION < v"1.12"
                    let color_switch = getval(client.switches, "--color", nothing)
                        if isnothing(color_switch)
                        elseif color_switch ∈ ("yes", "true", "1", "")
                            true
                        else
                            false
                        end
                    end
                else
                    hascolor
                end
                client_vterm = VirtualTerm(
                    client_stdin, client_stdout, client_stderr, signals,
                    term, sync_session,
                    get(TERMINFOS, term, nothing), color, nothing)
                with(ACTIVE_TERM => client_vterm,
                     CLIENT_MODULE => mod,
                     CLIENT_REPL => repl_ref,
                     REPLAY_TARGET => replay) do
                    runclient(mod, client; stdout=stdoutx, broadcast)
                end
            end
        end
    catch err
        if err isa DaemonClientExit
            exit_code = err.code
        elseif isopen(client_stdout)
            # TODO trim the stacktrace
            Base.invokelatest(
                Base.display_error,
                stderrx,
                Base.scrub_repl_backtrace(
                    current_exceptions()))
            exit_code = 1
        end
    finally
        # disable_sigint: a force-thrown SIGINT (from interrupting a tight loop)
        # landing mid uv_write in teardown would siglongjmp out of libuv and
        # corrupt the task fiber, so the stream I/O must be async-interrupt-atomic.
        Base.disable_sigint() do
            teardown_client(client, client_stdin, client_stdout, client_stderr,
                            signals, owned_streams, exit_code)
        end
    end
end

# Flush and close a finished client's streams, signal its exit, and unregister.
# Outputs are flushed first so the client drains them before the EOF/exit signal.
# owned_streams is empty for a sync REPL task (per-client cleanup happens in its
# stdin_copy_loop instead), so the exit signal / unregister are skipped there.
function teardown_client(client::ClientInfo, client_stdin::IO, client_stdout::IO,
                         client_stderr::IO, signals::IO, owned_streams::Tuple, exit_code::Int)
    try flush(client_stdout) catch end
    try flush(client_stderr) catch end
    for io in owned_streams
        try close(io) catch end
    end
    try close(client_stdin) catch end
    isempty(owned_streams) && return
    if isopen(signals)
        send_signal(signals, SIGNAL_EXIT, UInt8[exit_code % UInt8])
        try close(signals) catch end
    end
    unregister_client!(client)
end

# Basically a bootleg version of `exec_options` from `base/client.jl`. In a sync
# session, `broadcast` is the session's shared writer: --print shows the result
# plainly to this client's stdout and also renders it REPL-style to the broadcast.
function runclient(mod::Module, client::ClientInfo; stdout::IO=stdout,
                   broadcast::Union{Nothing, BroadcastWriter{StreamIO}}=nothing)
    set_switches = [s for (s, _) in client.switches]
    runrepl = "-i" ∈ set_switches ||
        (isnothing(client.programfile) && "--eval" ∉ set_switches &&
        "--print" ∉ set_switches)
    for (switch, value) in client.switches
        if switch == "--eval"
            Core.eval(mod, Base.parse_input_line(value))
        elseif switch == "--print"
            res = Core.eval(mod, Base.parse_input_line(value))
            Base.invokelatest(show, stdout, res)
            println(stdout)
            isnothing(broadcast) || display_result(broadcast, res)
        elseif switch == "--load"
            Base.include(mod, value)
        end
    end
    if !isnothing(client.programfile)
        try
            if client.programfile == "-"
                Base.include_string(mod, read(stdin, String), "stdin")
            else
                Base.include(mod, client.programfile)
            end
        catch
            Base.invokelatest(
                Base.display_error,
                Base.scrub_repl_backtrace(
                    current_exceptions()))
            runrepl || throw(DaemonClientExit(1))
        end
    end
    if runrepl
        interactiveinput = client.tty
        hascolor = get(stdout, :color, clienthascolor(client))
        quiet = "-q" ∈ set_switches || "--quiet" ∈ set_switches
        # The atreplinit hook emits the banner itself when replaying scrollback, so
        # suppress the REPL's own to avoid a duplicate.
        banner = if REPLAY_TARGET[] !== nothing
            :no
        else
            Symbol(getval(client.switches, "--banner", ifelse(interactiveinput, "yes", "no")))
        end
        histfile = getval(client.switches, "--history-file", "yes") != "no"
        @static if VERSION < v"1.11"
            setglobal!(Base, :have_color, hascolor)
            Base.run_main_repl(interactiveinput, quiet, banner != :no, histfile, hascolor)
        elseif VERSION < v"1.12"
            Base.run_main_repl(interactiveinput, quiet, banner, histfile, hascolor)
        else
            Base.run_main_repl(interactiveinput, quiet, banner, histfile)
        end
    end
end
