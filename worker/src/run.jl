# SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
# SPDX-License-Identifier: MPL-2.0

function create_module()::Module
    # Its own parent, as Main is, so it prints as "Main" (before 1.12 a NULL
    # parent stays NULL, and an override prints it).
    mod = @static if VERSION >= v"1.12"
        ccall(:jl_new_module, Ref{Module}, (Any, Ptr{Cvoid}), :Main, C_NULL)
    else
        Module(:Main)
    end
    # From base/client.jl
    maininclude = quote
        using Base
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

# Made outside the lock, as `using` waits on any package a client is loading.
ensure_standby_module() = fill_standby!(Returns(nothing), create_module, STATE.standby_module)

# The REPL overrides can't be precompiled, but JIT'd code is process-global.
function warm_repl_path()
    @static if VERSION < v"1.11"
        return nothing
    else
        get(ENV, "JULIA_DAEMON_PREWARM", "1") ∈ ("no", "false", "0") && return nothing
        try
            cin, cout, cerr, sig = linked_pipe(), linked_pipe(), linked_pipe(), linked_pipe()
            # Closed, so raw!/displaysize skip the client round-trip.
            foreach(close, (sig.in, sig.out))
            drains = [errormonitor(@async try read(p.out) catch end) for p in (cout, cerr)]
            feeder = errormonitor(@async try
                write(cin.in, "1+1\n")
                close(cin.in)
            catch end)
            client = ClientInfo(true, true, false, 0, 0, pwd(),
                                ["TERM" => "xterm-256color", "JULIA_DAEMON_REVISE" => "no"],
                                [("--history-file", "no")],
                                nothing, String[], PORT_SET_NONE)
            runclient(client, cin.out, cout.in, cerr.in, sig.out; owned_streams=())
            foreach(close, (cout.in, cerr.in))
            foreach(wait, [drains; feeder])
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
        @something(take_standby!(STATE.standby_module), create_module())
    end
    # Process-wide, so not left to the next run.
    setglobal!(Base.MainInclude, :ans, nothing)
    setglobal!(Base.MainInclude, :err, nothing)
    # A client module's own shadow Base's. Main (a session) sets Base's: 1.10 and
    # 1.11 won't let Main assign a name it has taken from Base.
    program = something(client.programfile, getval(client.switches, "--module", ""))
    if mod === Main
        append!(empty!(Base.ARGS), client.args)
        setglobal!(Base, :PROGRAM_FILE, program)
    else
        Core.eval(mod, :(ARGS = $(copy(client.args))))
        Core.eval(mod, :(PROGRAM_FILE = $program))
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

@static if VERSION >= v"1.11"
    # `Base.display_error`, as the worker overrides it.
    function display_client_error(@nospecialize(io::IO), stack::Base.ExceptionStack)
        if !isempty(stack) && first(stack).exception isa DaemonClientExit
            # `exit_client` has let the client go, so the REPL just stops.
            Base.invokelatest(display, first(stack).exception)
        else
            # Relayed Ctrl-Cs keep landing after the loop breaks: held off while
            # the interrupt they asked for renders, then dropped, being answered.
            try
                shielded() do
                    printstyled(io, "ERROR: ", bold=true, color=Base.error_color())
                    Base.show_exception_stack(IOContext(io, :limit => true), stack)
                    println(io)
                end
            catch err
                err isa InterruptException || rethrow()
            end
        end
    end

    # As its process would end, whatever the run's code goes on to do, its
    # output going nowhere.
    function let_client_go(code::Int)
        term = ACTIVE_TERM[]
        term.redirect_out = devnull
        term.redirect_err = devnull
        session = term.sync_session
        if isnothing(session)
            release_client(term.stdout, term.stderr, term.signals, code)
        else
            end_sync_session!(session, code)
        end
    end
end

# The last given, as Julia takes a repeated switch.
function getval(pairlist, key, default)
    index = findlast(p -> first(p) == key, pairlist)
    if isnothing(index) default else last(pairlist[index]) end
end

# The client judges its own stdout, as terminfo misjudges terminals that set
# no TERM (as on Windows).
clienthascolor(client::ClientInfo) = something(color_choice(client), client.color)

# `--color`'s, or `nothing` when left to the terminal.
function color_choice(client::ClientInfo)
    choice = getval(client.switches, "--color", nothing)
    if isnothing(choice) nothing else isyes(choice) end
end

function is_repl_client(client::ClientInfo)
    switches = (s for (s, _) in client.switches)
    "--interactive" ∈ switches || (isnothing(client.programfile) && isdisjoint(("--eval", "--print", "--module"), switches))
end

function command_line(client::ClientInfo)
    words = String[]
    for (name, value) in client.switches
        name ∈ ("--session", "--watch", "--address") && continue
        push!(words, name)
        isempty(value) || push!(words, value)
    end
    isnothing(client.programfile) || push!(words, client.programfile)
    append!(words, client.args)
    Base.shell_escape(words...)
end

function runclient(client::ClientInfo, client_stdin::Union{StreamIO, TerminalInput},
                   client_stdout::IO, client_stderr::IO,
                   signals::StreamIO;
                   owned_streams::Tuple=(client_stdout, client_stderr),
                   sync_session::Union{Nothing, SyncSession}=nothing,
                   repl_ref::Base.RefValue{REPL.LineEditREPL}=Ref{REPL.LineEditREPL}(),
                   broadcast::Union{Nothing, BroadcastWriter{StreamIO}}=nothing,
                   replay::Union{Nothing, Tuple{StreamIO, Recording, Tuple{Int, Int}, Int}}=nothing)
    watch = getval(client.switches, "--watch", nothing)
    if !isnothing(watch)
        return watch_client(client, watch, client_stdin, client_stdout, client_stderr, signals, owned_streams)
    end
    hascolor = clienthascolor(client)
    # As Julia's: -i, or a REPL at a terminal.
    interactive = any(s -> first(s) == "--interactive", client.switches) || (client.tty && is_repl_client(client))
    # Pre-1.11 output goes through redirected fds, which cannot be copied. A
    # sync session's broadcast writers record its screen as one shared run.
    session = getval(client.switches, "--session", nothing)  # "" when unlabelled
    own_run = if VERSION >= v"1.11" && isnothing(sync_session) && isnothing(broadcast) && !isnothing(session)
        begin_run(session, command_line(client); interactive)
    end
    recording = if isnothing(sync_session) own_run else sync_session.screen end
    recorded(io, stream) = if isnothing(own_run) io else RecordedOutput(io, own_run, stream) end
    run_stderr = recorded(client_stderr, :stderr)
    # Buffering would strand a REPL prompt written just before the frontend
    # blocks on stdin. Pre-1.11 `redirect_stdio` needs a stream owning an fd.
    # Recording sits under the buffer, so it copies whole chunks.
    run_stdout, owned_streams = if VERSION >= v"1.11" && !is_repl_client(client) && client_stdout isa StreamIO
        buffered = BufferedOutput(recorded(client_stdout, :stdout))
        buffered, map(s -> if s === client_stdout buffered else s end, owned_streams)
    else
        recorded(client_stdout, :stdout), owned_streams
    end
    stdoutx = IOContext(run_stdout, :color => hascolor)
    stderrx = IOContext(run_stderr, :color => hascolor)
    exit_code = 0
    try
        mod = prepare_module(client)
        # Base qualifies names not visible from `:module`. Within the client's scope
        # the worker's `get`s answer for it, but its errors are shown through these.
        stdoutx = IOContext(stdoutx, :module => mod)
        stderrx = IOContext(stderrx, :module => mod)
        ending = RunEnd()
        run_code() = run_until_exit(mod, client, ending, run_stdout, stdoutx, stderrx, broadcast)
        # A terminal's input is read through one a Ctrl-D ends, as a TTY's.
        input = if client.tty && client_stdin isa StreamIO
            copied = TerminalInput()
            errormonitor(@async try
                copy_input(client_stdin, copied)
            finally
                close_input!(copied)
            end)
            copied
        else
            client_stdin
        end
        enter_environment!(client)
        try
            exit_code = @static if VERSION < v"1.11"
                CLIENT_SIGNALS[] = signals
                CLIENT_INPUT[] = input
                CLIENT_INTERACTIVE[] = interactive
                CLIENT_END[] = ending
                try
                    # An input at its end may be closed already, with no fd to redirect;
                    # nor can it be taken past a Ctrl-D, as the fd stays the one reader's.
                    client_in = current_reader(input)
                    redirect_stdio(stdin=if isopen(client_in) client_in else devnull end, stdout=stdoutx, stderr=stderrx) do
                        # Base's display holds the stdout the worker started with.
                        client_display = TextDisplay(stdoutx)
                        pushdisplay(client_display)
                        try
                            with_client_scope(run_code, client)
                        finally
                            popdisplay(client_display)
                        end
                    end
                finally
                    CLIENT_SIGNALS[] = nothing
                    CLIENT_INPUT[] = nothing
                    CLIENT_INTERACTIVE[] = false
                    CLIENT_END[] = nothing
                end
            else
                term = get(ENV, "TERM", @static if Sys.iswindows() "" else "dumb" end)
                color = @static if VERSION < v"1.12"
                    color_choice(client)
                else
                    hascolor
                end
                # The client's colour is whether its stdout is a terminal, unless its environment chose.
                stdout_is_terminal = client.color ||
                    any(((key, value),) -> key ∈ ("FORCE_COLOR", "NO_COLOR") && !isempty(value), client.env)
                client_vterm = VirtualTerm(
                    input, run_stdout, run_stderr, signals,
                    term, sync_session,
                    get(TERMINFOS, term, nothing), color, nothing; stdout_is_terminal)
                @with(ACTIVE_TERM => client_vterm,
                      CLIENT_MODULE => mod,
                      CLIENT_INTERACTIVE => interactive,
                      CLIENT_REPL => repl_ref,
                      CLIENT_RECORDING => recording,
                      REPLAY_TARGET => replay,
                      CLIENT_END => ending,
                      with_client_scope(run_code, client))
            end
        finally
            leave_environment!(client)
        end
    catch
        # The worker's own failure to run it.
        display_run_error(run_stdout, stderrx)
        exit_code = 1
    finally
        # Process-wide, as `runworker` leaves it.
        Base.exit_on_sigint(false)
        # After the run's last output, which may still be buffered.
        if !isnothing(recording)
            try flush(run_stdout) catch end
            record!(recording, :exit, string(exit_code))
        end
        # A force-thrown SIGINT mid uv_write would siglongjmp out of libuv and
        # corrupt the task fiber.
        shielded() do
            teardown_client(client, client_stdin, run_stdout, client_stderr,
                            signals, owned_streams, exit_code)
        end
    end
    exit_code
end

# Following a session's transcript, in place of running code.
function watch_client(client::ClientInfo, watch::String, client_stdin, client_stdout::IO,
                      client_stderr::IO, signals::StreamIO, owned_streams::Tuple)
    exit_code = try
        @static if VERSION >= v"1.11"
            watch_session(getval(client.switches, "--session", ""), watch, client_stdout;
                          color=color_choice(client), terminal=client.color, until=signals)
        else
            println(client_stderr, "--watch needs the session's worker to run Julia 1.11 or later.")
            1
        end
    catch
        isopen(client_stderr) && Base.invokelatest(Base.display_error, client_stderr, current_exceptions())
        1
    end
    shielded() do
        teardown_client(client, client_stdin, client_stdout, client_stderr, signals, owned_streams, exit_code)
    end
    exit_code
end

# The error being handled, after what stdout still holds, unless the client is gone.
function display_run_error(run_stdout::IO, stderrx::IO)
    isopen(run_stdout) || return
    try flush(run_stdout) catch end
    Base.invokelatest(Base.display_error, stderrx, scrub_backtrace(current_exceptions()))
end

# A run's code, then its `atexit` hooks, as stock julia runs them on its way
# out; its exit code.
function run_until_exit(mod::Module, client::ClientInfo, ending::RunEnd, run_stdout::IO,
                        stdoutx::IO, stderrx::IO, broadcast::Union{Nothing, BroadcastWriter{StreamIO}})
    code = try
        runclient(mod, client; stdout=stdoutx, broadcast)
        0
    catch err
        if err isa DaemonClientExit
            err.code
        else
            display_run_error(run_stdout, stderrx)
            1
        end
    end
    # An `exit` caught on the way stands.
    @lock ending.lock begin
        if isnothing(ending.code)
            ending.code = code
        end
    end
    ending.ended || run_exit_hooks!(ending)
    something(ending.code)
end

# As stock julia's `_atexit`: newest first, each given the exit code if it
# takes one, and an error shown before the next; an `exit` in one sets the code.
function run_exit_hooks!(ending::RunEnd)
    while true
        hook = @lock ending.lock begin
            if isempty(ending.hooks)
                ending.ended = true
                nothing
            else
                popfirst!(ending.hooks)
            end
        end
        isnothing(hook) && return
        try
            code = Cint(something(ending.code, 0))
            # In the latest world, as the hook is newer than this frame.
            if hasmethod(hook, Tuple{Cint}; world=Base.get_world_counter())
                Base.invokelatest(hook, code)
            else
                Base.invokelatest(hook)
            end
        catch err
            err isa DaemonClientExit && continue
            (; exception, backtrace) = last(scrub_backtrace(current_exceptions()))
            showerror(stderr, exception)
            Base.show_backtrace(stderr, backtrace)
            println(stderr)
        end
    end
end

# The process's cwd and ENV, which its clients' runs share. Each run's are set
# as it starts; as it ends, its variables and the cwd go to the latest run still
# going, else back to what they were before any set them.
const ENVIRONS = (
    lock = ReentrantLock(),
    runs = ClientInfo[],  # oldest first
    cwd = Ref(""),  # before the runs
    env = Dict{String, Union{Nothing, String}}())  # the runs' variables before them; `nothing` unset

function enter_environment!(client::ClientInfo)
    @lock ENVIRONS.lock begin
        if isempty(ENVIRONS.runs)
            ENVIRONS.cwd[] = pwd()
        end
        cd(client.cwd)
        for (key, value) in client.env
            get!(() -> get(ENV, key, nothing), ENVIRONS.env, key)
            ENV[key] = value
        end
        push!(ENVIRONS.runs, client)
    end
end

function leave_environment!(client::ClientInfo)
    @lock ENVIRONS.lock begin
        filter!(run -> run !== client, ENVIRONS.runs)
        for (key, _) in client.env
            holder = findlast(run -> any(((k, _),) -> k == key, run.env), ENVIRONS.runs)
            value = if isnothing(holder) ENVIRONS.env[key] else getval(ENVIRONS.runs[holder].env, key, nothing) end
            if isnothing(value) delete!(ENV, key) else ENV[key] = value end
        end
        dir = if isempty(ENVIRONS.runs) ENVIRONS.cwd[] else last(ENVIRONS.runs).cwd end
        isempty(ENVIRONS.runs) && empty!(ENVIRONS.env)
        try
            cd(dir)
        catch err
            @warn "Could not return to $dir after a client's run" exception=err
        end
    end
end

# Stock julia's trace ends where it entered user code; ours would run on
# through the worker, from the entry point in this file outward.
function scrub_backtrace(stack::Base.ExceptionStack)
    function scrub(bt)
        bt isa Vector{Base.StackTraces.StackFrame} || return bt
        entry = findfirst(f -> String(f.file) == @__FILE__, bt)
        isnothing(entry) && return bt
        bt = bt[1:entry-1]
        # As Julia leaves out, from 1.14, the `eval` it runs the code through.
        @static if isdefined(Base, :is_driver_machinery)
            while !isempty(bt) && Base.is_driver_machinery(bt[end])
                pop!(bt)
            end
        end
        bt
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
            value = as_client_code(() -> Core.eval(mod, ex))
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

# A sync REPL task owns no streams; its clients are cleaned up as they leave.
function teardown_client(client::ClientInfo, client_stdin::IO, client_stdout::IO,
                         client_stderr::IO, signals::IO, owned_streams::Tuple, exit_code::Int)
    @nospecialize client_stdin client_stdout client_stderr signals owned_streams
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
@static if VERSION >= v"1.11"
    # The terminal REPLs running, oldest first. Base's globals name one REPL and
    # backend, and each `run_main_repl` leaves them as it found them, which may
    # be a REPL since ended.
    const LIVE_REPLS = (lock = ReentrantLock(), repls = Pair{REPL.LineEditREPL, REPL.REPLBackend}[])

    function repl_started!(backend::REPL.REPLBackend)
        repl = CLIENT_REPL[]
        isassigned(repl) && @lock LIVE_REPLS.lock push!(LIVE_REPLS.repls, repl[] => backend)
    end

    # After `run_main_repl`, as it resets the globals on its way out.
    function repl_ended!(ended::Ref{REPL.LineEditREPL})
        @lock LIVE_REPLS.lock begin
            isassigned(ended) && filter!(((repl, _),) -> repl !== ended[], LIVE_REPLS.repls)
            if !isempty(LIVE_REPLS.repls)
                repl, backend = last(LIVE_REPLS.repls)
                setglobal!(Base, :active_repl, repl)
                setglobal!(Base, :active_repl_backend, backend)
            elseif VERSION >= v"1.12"
                # Before 1.12 Base takes any assigned global as live, so the last stays.
                setglobal!(Base, :active_repl, nothing)
                setglobal!(Base, :active_repl_backend, nothing)
            end
        end
    end
end

function runclient(mod::Module, client::ClientInfo; @nospecialize(stdout::IO=stdout),
                   broadcast::Union{Nothing, BroadcastWriter{StreamIO}}=nothing)
    wants_revise(client) && revise_code()
    # A session keeps its state, so it is warned rather than moved to a fresh worker.
    if client.force
        stale = stale_files(client)
        isempty(stale) || @warn join(["Running outdated code: these changed on disk after this session loaded them";
                                      map(f -> "  " * f, stale)], '\n') _module=nothing _file=nothing
    end
    runrepl = is_repl_client(client)
    as_client_code() do
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
            elseif switch == "--module"
                # As julia's -m: its package's `main`, which must be its entry point.
                Core.eval(mod, Expr(:import, Expr(:., Symbol.(split(value, "."))..., :main)))
                if isnothing(Base.invokelatest(main_entrypoint, mod))
                    error("`main` in `$value` not declared as entry point (use `@main` to do so)")
                end
                break
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
        # As julia runs an `@main` its code defined, unless interactive.
        entrypoint = Base.invokelatest(main_entrypoint, mod)
        if !isnothing(entrypoint) && !isinteractive()
            code = main_exit_code(Base.invokelatest(entrypoint, Base.invokelatest(getglobal, mod, :ARGS)))
            code == 0 || throw(DaemonClientExit(code))
        end
    end
    if runrepl && !client.tty
        run_piped_repl(mod)
    elseif runrepl
        Base.invokelatest(run_terminal_repl, client, stdout)
    end
end

# The `main` marked by `@main` that `mod` sees, if any.
function main_entrypoint(mod::Module)
    isdefined(mod, :main) || return nothing
    owner = Base.binding_module(mod, :main)
    flag = Symbol("#__main_is_entrypoint__#")
    if isdefined(owner, flag) && getglobal(owner, flag) === true
        getglobal(mod, :main)
    end
end

# As julia's: `nothing` is 0, and anything not a `Cint` an error.
function main_exit_code(ret)
    isnothing(ret) && return 0
    try
        Int(Cint(ret))
    catch
        @error "The return value of `main` should be `nothing` or convertible to `Cint`"
        1
    end
end

# Called through `invokelatest`: loading packages calls `isinteractive`, whose
# override would otherwise invalidate `runclient`, and so every run's code.
function run_terminal_repl(client::ClientInfo, stdout::IO)
    interactiveinput = client.tty
    hascolor = get(stdout, :color, clienthascolor(client))
    quiet = any(((s, _),) -> s == "--quiet", client.switches)
    requested = Symbol(getval(client.switches, "--banner", if interactiveinput && !quiet "yes" else "no" end))
    # The atreplinit hook prints the banner itself when replaying.
    banner = if VERSION >= v"1.11" && REPLAY_TARGET[] !== nothing
        :no
    else
        requested
    end
    histfile = getval(client.switches, "--history-file", "yes") != "no"
    @static if VERSION < v"1.11"
        setglobal!(Base, :have_color, hascolor)
        Base.run_main_repl(interactiveinput, quiet, banner != :no, histfile, hascolor)
    else
        try
            @with REPLAY_BANNER => requested @static if VERSION < v"1.12"
                Base.run_main_repl(interactiveinput, quiet, banner, histfile, hascolor)
            else
                Base.run_main_repl(interactiveinput, quiet, banner, histfile)
            end
        finally
            repl_ended!(CLIENT_REPL[])
        end
    end
end
