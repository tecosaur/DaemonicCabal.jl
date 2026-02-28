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

function runclient(client::ClientInfo, client_stdin::StreamIO,
                   client_stdout::IO, client_stderr::IO,
                   signals::StreamIO;
                   owned_streams::Tuple=(client_stdout, client_stderr),
                   sync_session::Union{Nothing, SyncSession}=nothing,
                   repl_ref::Base.RefValue{REPL.LineEditREPL}=Ref{REPL.LineEditREPL}())
    hascolor = getval(client.switches, "--color",
                      ifelse(startswith(getval(client.env, "TERM", ""), "xterm"),
                             "yes", "")) == "yes"
    stdoutx = IOContext(client_stdout, :color => hascolor)
    stderrx = IOContext(client_stderr, :color => hascolor)
    mod = prepare_module(client)
    exit_code = 0
    try
        withenv(client.env...) do
            @static if VERSION < v"1.11"
                redirect_stdio(stdin=client_stdin, stdout=stdoutx, stderr=stderrx) do
                    runclient(mod, client; stdout=stdoutx)
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
                     CLIENT_REPL => repl_ref) do
                    runclient(mod, client; stdout=stdoutx)
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
        # Close output streams first to ensure all output is flushed before sending
        # exit signal. Client waits for stdout+stderr EOF to guarantee output is drained.
        try flush(client_stdout) catch end
        try flush(client_stderr) catch end
        for stream in owned_streams
            try close(stream) catch end
        end
        try close(client_stdin) catch end
        # Sync REPL task passes owned_streams=() — cleanup is per-client via stdin_copy_loop
        if !isempty(owned_streams)
            if isopen(signals)
                send_signal(signals, SIGNAL_EXIT, UInt8[exit_code % UInt8])
                try close(signals) catch end
            end
            unregister_client!(client)
        end
    end
end

# Basically a bootleg version of `exec_options` from `base/client.jl`.
function runclient(mod::Module, client::ClientInfo; stdout::IO=stdout)
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
            println()
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
        hascolor = get(stdout, :color, false)
        quiet = "-q" ∈ set_switches || "--quiet" ∈ set_switches
        banner = Symbol(getval(client.switches, "--banner", ifelse(interactiveinput, "yes", "no")))
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
