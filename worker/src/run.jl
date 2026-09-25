# SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
# SPDX-License-Identifier: MPL-2.0

function create_module()::Module
    mod = Module(:Main)
    # From base/client.jl
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
        using Base.MainInclude: ans, err
    end
    maininclude.head = :toplevel
    Core.eval(mod, maininclude)
    Core.eval(mod, :(using InteractiveUtils))
    mod
end

function get_module()::Module
    mod = @lock STATE.lock begin
        m = STATE.standby_module[]
        STATE.standby_module[] = nothing
        m
    end
    if isnothing(mod) create_module() else mod end
end

function ensure_standby_module()
    @lock STATE.lock begin
        if isnothing(STATE.standby_module[])
            STATE.standby_module[] = create_module()
        end
    end
end

# The REPL overrides can't be precompiled, but JIT'd code is process-global.
function warm_repl_path()
    @static if VERSION < v"1.11"
        return nothing
    else
        get(ENV, "JULIA_DAEMON_PREWARM", "1") ∈ ("no", "false", "0") && return nothing
        try
            cin  = Pipe(); Base.link_pipe!(cin;  reader_supports_async=true, writer_supports_async=true)
            cout = Pipe(); Base.link_pipe!(cout; reader_supports_async=true, writer_supports_async=true)
            cerr = Pipe(); Base.link_pipe!(cerr; reader_supports_async=true, writer_supports_async=true)
            # Closed, so raw!/displaysize skip the client round-trip.
            sig = Pipe(); Base.link_pipe!(sig); close(sig.in); close(sig.out)
            dout = errormonitor(@async try read(cout.out) catch end)
            derr = errormonitor(@async try read(cerr.out) catch end)
            feeder = errormonitor(@async try write(cin.in, "1+1\n"); close(cin.in) catch end)
            client = ClientInfo(true, true, false, 0, 0, pwd(),
                                ["TERM" => "xterm-256color", "JULIA_DAEMON_REVISE" => "no"],
                                [("--history-file", "no")],
                                nothing, String[], 0xFFFF)
            runclient(client, cin.out, cout.in, cerr.in, sig.out; owned_streams=())
            close(cout.in); close(cerr.in)
            wait(dout); wait(derr); wait(feeder)
        catch e
            @debug "REPL pre-warm failed" exception=(e, catch_backtrace())
        end
        ensure_standby_module()
        return nothing
    end
end

function prepare_module(client::ClientInfo)
    mod = if any(p -> first(p) == "--session", client.switches)
        Main
    else
        get_module()
    end
    Core.eval(mod, :(cd($(client.cwd))))
    if !isempty(client.args)
        Core.eval(mod, :(ARGS = $(client.args)))
    end
    mod
end

function revise_code()
    load_revise() || return
    # A binding `using` creates is invisible to the frame that ran it, hence the
    # separate eval. Revise warns of a failed revision only when it first
    # fails, and later runs would silently run the outdated code.
    unapplied = Core.eval(Main, quote
        let failing = !isempty(Revise.queue_errors)
            Revise.revise()
            if failing
                [joinpath(Revise.basedir(pkg), file) for (pkg, file) in keys(Revise.queue_errors)]
            else
                String[]
            end
        end
    end)
    isempty(unapplied) || @warn join(["Running outdated code: Revise could not apply the saved edits to";
                                      map(f -> "  " * f, unapplied)], '\n') _module=nothing _file=nothing
end

function Base.display(d::REPL.REPLDisplay, ::MIME"text/plain", exit::DaemonClientExit)
    REPL.LineEdit.transition(d.repl.mistate, :abort)
end

function getval(pairlist, key, default)
    index = findfirst(p -> first(p) == key, pairlist)
    if isnothing(index) default else last(pairlist[index]) end
end

# The client judges its own stdout, as terminfo misjudges terminals that set
# no TERM (as on Windows).
function clienthascolor(client::ClientInfo)
    cs = getval(client.switches, "--color", nothing)
    if isnothing(cs) client.color else isyes(cs) end
end

function is_repl_client(client::ClientInfo)
    switches = (s for (s, _) in client.switches)
    "-i" ∈ switches || (isnothing(client.programfile) && "--eval" ∉ switches && "--print" ∉ switches)
end

function command_line(client::ClientInfo)
    words = String[]
    for (name, value) in client.switches
        name ∈ ("--session", "--watch") && continue
        push!(words, name)
        isempty(value) || push!(words, value)
    end
    isnothing(client.programfile) || push!(words, client.programfile)
    append!(words, client.args)
    Base.shell_escape(words...)
end

function runclient(client::ClientInfo, client_stdin::StreamIO,
                   client_stdout::IO, client_stderr::IO,
                   signals::StreamIO;
                   owned_streams::Tuple=(client_stdout, client_stderr),
                   sync_session::Union{Nothing, SyncSession}=nothing,
                   repl_ref::Base.RefValue{REPL.LineEditREPL}=Ref{REPL.LineEditREPL}(),
                   broadcast::Union{Nothing, BroadcastWriter{StreamIO}}=nothing,
                   replay::Union{Nothing, Tuple{StreamIO, SyncSession}}=nothing)
    watch = getval(client.switches, "--watch", nothing)
    if !isnothing(watch)
        exit_code = try
            @static if VERSION >= v"1.11"
                watch_session(getval(client.switches, "--session", ""), watch, client_stdout, client.color; until=signals)
            else
                println(client_stderr, "--watch needs the session's worker to run Julia 1.11 or later.")
                1
            end
        catch
            isopen(client_stderr) && Base.invokelatest(Base.display_error, client_stderr, current_exceptions())
            1
        end
        return Base.disable_sigint() do
            teardown_client(client, client_stdin, client_stdout, client_stderr, signals, owned_streams, exit_code)
        end
    end
    hascolor = clienthascolor(client)
    # Pre-1.11 output goes through redirected fds, which cannot be copied. A
    # sync session's broadcast writers record its screen as one shared run.
    session = getval(client.switches, "--session", nothing)  # "" when unlabelled
    own_run = if VERSION >= v"1.11" && isnothing(sync_session) && isnothing(broadcast) && !isnothing(session)
        begin_run(session, command_line(client); interactive = client.tty && is_repl_client(client))
    end
    recording = if isnothing(sync_session) own_run else sync_session.screen end
    recorded(io, stream) = if isnothing(own_run) io else RecordedOutput(io, own_run, stream) end
    run_stderr = recorded(client_stderr, :stderr)
    # Buffering would strand a REPL prompt written just before the frontend
    # blocks on stdin. Pre-1.11 `redirect_stdio` needs a stream owning an fd.
    # Recording sits under the buffer, so it copies whole chunks.
    run_stdout, owned_streams = if VERSION >= v"1.11" && !is_repl_client(client) && client_stdout isa StreamIO
        buffered = BufferedOutput(recorded(client_stdout, :stdout))
        buffered, map(s -> if s === client_stdout; buffered else s end, owned_streams)
    else
        recorded(client_stdout, :stdout), owned_streams
    end
    stdoutx = IOContext(run_stdout, :color => hascolor)
    stderrx = IOContext(run_stderr, :color => hascolor)
    exit_code = 0
    try
        mod = prepare_module(client)
        withenv(client.env...) do
            @static if VERSION < v"1.11"
                CLIENT_SIGNALS[] = signals
                try
                    redirect_stdio(stdin=client_stdin, stdout=stdoutx, stderr=stderrx) do
                        # Base's display holds the stdout the worker started with.
                        client_display = TextDisplay(stdoutx)
                        pushdisplay(client_display)
                        try
                            runclient(mod, client; stdout=stdoutx, broadcast)
                        finally
                            popdisplay(client_display)
                        end
                    end
                finally
                    CLIENT_SIGNALS[] = nothing
                end
            else
                term = get(ENV, "TERM", @static if Sys.iswindows() "" else "dumb" end)
                color = @static if VERSION < v"1.12"
                    let color_switch = getval(client.switches, "--color", nothing)
                        if isnothing(color_switch) nothing else isyes(color_switch) end
                    end
                else
                    hascolor
                end
                client_vterm = VirtualTerm(
                    client_stdin, run_stdout, run_stderr, signals,
                    term, sync_session,
                    get(TERMINFOS, term, nothing), color, nothing)
                with(ACTIVE_TERM => client_vterm,
                     CLIENT_MODULE => mod,
                     CLIENT_REPL => repl_ref,
                     CLIENT_RECORDING => recording,
                     REPLAY_TARGET => replay) do
                    runclient(mod, client; stdout=stdoutx, broadcast)
                end
            end
        end
    catch err
        if err isa DaemonClientExit
            exit_code = err.code
        elseif isopen(client_stdout)
            Base.invokelatest(Base.display_error, stderrx, scrub_backtrace(current_exceptions()))
            exit_code = 1
        end
    finally
        # After the run's last output, which may still be buffered.
        if !isnothing(recording)
            try flush(run_stdout) catch end
            record!(recording, :exit, string(exit_code))
        end
        # A force-thrown SIGINT mid uv_write would siglongjmp out of libuv and
        # corrupt the task fiber.
        Base.disable_sigint() do
            teardown_client(client, client_stdin, run_stdout, client_stderr,
                            signals, owned_streams, exit_code)
        end
    end
end

# Stock julia's trace ends where it entered user code; ours would run on
# through the worker, from the entry point in this file outward.
function scrub_backtrace(stack::Base.ExceptionStack)
    function scrub(bt)
        bt isa Vector{Base.StackTraces.StackFrame} || return bt
        entry = findfirst(f -> String(f.file) == @__FILE__, bt)
        if isnothing(entry) bt else bt[1:entry-1] end
    end
    Base.ExceptionStack(Any[(; x.exception, backtrace = scrub(x.backtrace))
                            for x in Base.scrub_repl_backtrace(stack)])
end

# Base's fallback REPL, for input that is not a terminal, evaluates in the
# process-wide Main; this one evaluates in the client's module.
function run_piped_repl(mod::Module)
    while !eof(stdin)
        try
            line = ""
            ex = nothing
            while !eof(stdin)
                line *= readline(stdin, keep=true)
                ex = Base.parse_input_line(line)
                Meta.isexpr(ex, :incomplete) || break
            end
            @static if VERSION >= v"1.11"
                recording = CLIENT_RECORDING[]
                isnothing(recording) || record!(recording, :input, "julia\n" * chomp(line))
            end
            value = Core.eval(mod, ex)
            setglobal!(Base.MainInclude, :ans, value)
            isnothing(value) || Base.invokelatest(display, value)
        catch err
            err isa DaemonClientExit && rethrow()
            stack = scrub_backtrace(current_exceptions())
            setglobal!(Base.MainInclude, :err, stack)
            Base.invokelatest(Base.display_error, stderr, stack)
        end
    end
end

# A sync REPL task owns no streams; its clients are cleaned up by stdin_copy_loop.
function teardown_client(client::ClientInfo, client_stdin::IO, client_stdout::IO,
                         client_stderr::IO, signals::IO, owned_streams::Tuple, exit_code::Int)
    try flush(client_stdout) catch end
    try flush(client_stderr) catch end
    for io in owned_streams
        try close(io) catch end
    end
    try close(client_stdin) catch end
    isempty(owned_streams) && return
    # `isopen` lags a peer close; unregister regardless or the worker stays at capacity.
    try
        if isopen(signals)
            send_signal(signals, SIGNAL_EXIT, UInt8[exit_code % UInt8])
            close(signals)
        end
    finally
        unregister_client!(client)
    end
end

# After `exec_options` in base/client.jl.
function runclient(mod::Module, client::ClientInfo; stdout::IO=stdout,
                   broadcast::Union{Nothing, BroadcastWriter{StreamIO}}=nothing)
    wants_revise(client) && revise_code()
    # A session keeps its state, so it is warned rather than moved to a fresh worker.
    if client.force
        stale = stale_files(client)
        isempty(stale) || @warn join(["Running outdated code: these changed on disk after this session loaded them";
                                      map(f -> "  " * f, stale)], '\n') _module=nothing _file=nothing
    end
    set_switches = [s for (s, _) in client.switches]
    runrepl = is_repl_client(client)
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
        catch err
            # `exit(n)` is not a failure; `include` wraps it on the way out.
            thrown = if err isa LoadError err.error else err end
            thrown isa DaemonClientExit && throw(thrown)
            Base.invokelatest(Base.display_error, scrub_backtrace(current_exceptions()))
            runrepl || throw(DaemonClientExit(1))
        end
    end
    if runrepl && !client.tty
        run_piped_repl(mod)
    elseif runrepl
        interactiveinput = client.tty
        hascolor = get(stdout, :color, clienthascolor(client))
        quiet = "-q" ∈ set_switches || "--quiet" ∈ set_switches
        # The atreplinit hook prints the banner itself when replaying.
        banner = if VERSION >= v"1.11" && REPLAY_TARGET[] !== nothing
            :no
        else
            Symbol(getval(client.switches, "--banner", if interactiveinput && !quiet "yes" else "no" end))
        end
        histfile = getval(client.switches, "--history-file", "yes") != "no"
        @static if VERSION < v"1.11"
            setglobal!(Base, :have_color, hascolor)
            Base.run_main_repl(interactiveinput, quiet, banner != :no, histfile, hascolor)
        elseif VERSION < v"1.12"
            Base.run_main_repl(interactiveinput, quiet, banner, histfile, hascolor)
        else
            # run_main_repl restores the backend it installs into a local, and
            # later runs would take the dead one for a live REPL (Infiltrator
            # then refuses to infiltrate). Before 1.12 Base takes any assigned
            # backend as usable, so it has to stay.
            backend = Base.active_repl_backend
            try
                Base.run_main_repl(interactiveinput, quiet, banner, histfile)
            finally
                setglobal!(Base, :active_repl_backend, backend)
            end
        end
    end
end
