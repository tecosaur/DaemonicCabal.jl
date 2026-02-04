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
    mod
end

# Get a module, using standby if available
function get_module()::Module
    mod = @lock STATE.lock begin
        m = STATE.standby_module[]
        STATE.standby_module[] = nothing
        m
    end
    isnothing(mod) ? create_module() : mod
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
    mod = if haskey(client.switches, "--session")
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

haskey(pairlist, key) = !isnothing(findfirst(p -> first(p) == key, pairlist))

function runclient(client::ClientInfo, stdio::Base.PipeEndpoint, signals::Base.PipeEndpoint)
    hascolor = getval(client.switches, "--color",
                      ifelse(startswith(getval(client.env, "TERM", ""),
                                        "xterm"),
                             "yes", "")) == "yes"
    stdiox = IOContext(stdio, :color => hascolor)
    mod = prepare_module(client)
    exit_code = 0
    try
        withenv(client.env...) do
            @static if VERSION < v"1.11"
                redirect_stdio(stdin=stdiox, stdout=stdiox, stderr=stdiox) do
                    runclient(mod, client; stdout=stdiox)
                end
            else
                term = get(ENV, "TERM", @static Sys.iswindows() ? "" : "dumb")
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
                    stdio, stdio, stdio, signals,
                    term, get(TERMINFOS, term, nothing),
                    color, nothing)
                with(ACTIVE_TERM => client_vterm) do
                    runclient(mod, client; stdout=stdiox)
                end
            end
        end
    catch err
        if err isa DaemonClientExit
            exit_code = err.code
        elseif isopen(stdio)
            # TODO trim the stacktrace
            Base.invokelatest(
                Base.display_error,
                stdiox,
                Base.scrub_repl_backtrace(
                    current_exceptions()))
            exit_code = 1
        end
    finally
        # Close stdio first to ensure all output is flushed before sending exit signal.
        # Client waits for stdio EOF to guarantee output is drained.
        if isopen(stdio)
            try flush(stdio) catch end
            try close(stdio) catch end
            send_signal(signals, SIGNAL_EXIT, UInt8[exit_code % UInt8])
        end
        try close(signals) catch end
        @lock STATE.lock begin
            client_index = findfirst(e -> last(e) === client, STATE.clients)
            if !isnothing(client_index)
                deleteat!(STATE.clients, client_index)
            end
            delete!(STATE.client_tasks, client.pid)
            STATE.lastclient[] = time()
            if STATE.soft_exit[] && isempty(STATE.clients)
                real_exit(0)
            end
        end
        # Notify conductor that client is done
        send_client_done(STATE.conductor_socket[], client.pid)
        ensure_standby_sockets()
        ensure_standby_module()
        queue_ttl_check()
    end
end

function runclient(mod::Module, client::ClientInfo; stdout::IO=stdout)
    runrepl = "-i" ∈ client.switches ||
        (isnothing(client.programfile) && "--eval" ∉ first.(client.switches) &&
        "--print" ∉ first.(client.switches))
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
            Core.eval(mod, quote
                          Base.invokelatest(
                              Base.display_error,
                              Base.scrub_repl_backtrace(
                                  current_exceptions()))
                          if !$(runrepl)
                              exit(1)
                          end
                      end)
        end
    end
    if runrepl
        interactiveinput = runrepl && client.tty
        hascolor = get(stdout, :color, false)
        quiet = "-q" in first.(client.switches) || "--quiet" in first.(client.switches)
        banner = Symbol(getval(client.switches, "--banner", ifelse(interactiveinput, "yes", "no")))
        histfile = getval(client.switches, "--history-file", "yes") != "no"
        replcall = if VERSION < v"1.11"
            :(Base.run_main_repl($interactiveinput, $quiet, $(banner != :no), $histfile, $hascolor))
        elseif VERSION < v"1.12"
            :(Base.run_main_repl($interactiveinput, $quiet, $(QuoteNode(banner)), $histfile, $hascolor))
        else
            :(Base.run_main_repl($interactiveinput, $quiet, $(QuoteNode(banner)), $histfile))
        end
        Core.eval(mod, quote
                      setglobal!(Base, :have_color, $hascolor)
                      $replcall
                  end)
    end
end
