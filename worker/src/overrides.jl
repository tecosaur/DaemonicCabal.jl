# SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
# SPDX-License-Identifier: MPL-2.0

@eval Base.isinteractive() = CLIENT_INTERACTIVE[]

# An override invalidates its callers, to be recompiled against it: those with
# many are shims into the package's precompiled functions.
@static if VERSION >= v"1.12"
    @eval Base.current_terminfo() = $client_terminfo()
    @eval Base.get_have_color() = $client_have_color()
    @eval Base.get_have_truecolor() = $client_have_truecolor()
end

@static if VERSION >= v"1.11"
    @eval Base.display_error(io::IO, stack::Base.ExceptionStack) = $display_client_error(io, stack)
    # The display stack is process-wide, but a REPL's display belongs to its
    # own session: not to a concurrent run, nor to the REPL pre-warm.
    @eval Base.Multimedia.xdisplayable(d::REPL.REPLDisplay, @nospecialize args...) =
        isassigned(CLIENT_REPL[]) && d.repl === CLIENT_REPL[][] && applicable(display, d, args...)
    @eval function Base.active_module((; mistate)::REPL.LineEditREPL)
        if mistate !== nothing && mistate.active_module !== Main
            mistate.active_module
        else
            CLIENT_MODULE[]
        end
    end
    # Base checks `mod == Main`, which fails for the per-client Main.
    @eval function REPL.contextual_prompt(repl::REPL.LineEditREPL, prompt::Union{String,Function})
        function ()
            mod = Base.active_module(repl)
            prefix = (mod === Main || mod === CLIENT_MODULE[]) ? "" : string('(', mod, ") ")
            prefix * (prompt isa String ? prompt : prompt())
        end
    end
    # A recording's line editing runs from a response's end to a line's commit,
    # which records the line in its mode, as history does.
    @eval function REPL.prepare_next(repl::REPL.LineEditREPL)
        recording = CLIENT_RECORDING[]
        if !isnothing(recording)
            recording.editing = true
        end
        println(REPL.terminal(repl))
    end
    @eval function REPL.LineEdit.commit_line(s::REPL.LineEdit.MIState)
        LE = REPL.LineEdit
        LE.cancel_beep(s)
        LE.move_input_end(s)
        LE.refresh_line(s)
        println(LE.terminal(s))
        LE.add_history(s)
        LE.state(s, LE.mode(s)).ias = LE.InputAreaState(0, 0)
        recording = CLIENT_RECORDING[]
        if !isnothing(recording)
            mode = LE.mode(s)
            code = rstrip(String(take!(copy(LE.buffer(s)))))
            isempty(code) || record!(recording, :typed, string(LE.mode_idx(mode.hist, mode), '\n', code))
            recording.editing = false
        end
        nothing
    end
    # The per-client Main prints as "Main", not "Main.Main" (from 1.12, being
    # its own parent does this: see `create_module`).
    @static if VERSION < v"1.12"
        @eval function Base.print_fullname(io::IO, m::Module)
            mp = parentmodule(m)
            if m === Main || m === Base || m === Core || mp === m || m === CLIENT_MODULE[]
                Base.show_sym(io, nameof(m))
            else
                Base.print_fullname(io, mp)
                print(io, '.')
                Base.show_sym(io, nameof(m))
            end
        end
    end
    # Replay goes to the client's own stdout, so history doesn't recapture it.
    pushfirst!(Base.repl_hooks, function (repl)
        CLIENT_REPL[][] = repl
        target = REPLAY_TARGET[]
        if target !== nothing
            banner = REPLAY_BANNER[]
            banner == :no ||
                REPL.banner(IOContext(first(target), :color => something(ACTIVE_TERM[].have_color, false));
                            short = banner == :short)
            replay_history(target...)
        end
        recording = CLIENT_RECORDING[]
        if !isnothing(recording) && repl.t isa REPL.Terminals.TTYTerminal
            repl.t.out_stream = TerminalStdout()
            recording.editing = true
        end
    end)
end

@static if VERSION >= v"1.11"
    @eval function REPL.Terminals.raw!(t::REPL.TTYTerminal, raw::Bool)
        term = ACTIVE_TERM[]
        if !isnothing(term.sync_session)
            switch_raw_mode!(term.sync_session, raw)
        elseif isopen(term.signals)
            if term.stdin isa TerminalInput
                @lock term.stdin.lock term.stdin.raw = raw
            end
            send_signal(term.signals, SIGNAL_RAW_MODE, UInt8[raw])
            read(term.signals, 2) # ack
        end
        raw
    end
else
    @eval function REPL.Terminals.raw!(t::REPL.TTYTerminal, raw::Bool)
        sig = CLIENT_SIGNALS[]
        input = CLIENT_INPUT[]
        if input isa TerminalInput
            @lock input.lock input.raw = raw
        end
        if sig !== nothing && isopen(sig)
            try
                send_signal(sig, SIGNAL_RAW_MODE, UInt8[raw])
                read(sig, 2) # ack
            catch end
        end
        raw
    end
end

@static isdefined(Base, :sigint_new_episode!) && install_cancellation()

# `REPL.repl_backend_loop`, each evaluation the client's code, retrying a
# `take!` interrupted by a Ctrl-C still in flight.
@eval REPL function repl_backend_loop(backend::REPLBackend, get_module::Function)
    # Interpolated only where it exists: `@eval` interpolates before `@static`.
    $(if VERSION >= v"1.11"
        :($repl_started!(backend))
    end)
    while true
        tls = task_local_storage()
        tls[:SOURCE_PATH] = nothing
        local ast_or_func, show_value
        while true
            try
                ast_or_func, show_value = take!(backend.repl_channel)
                break
            catch e
                e isa InterruptException || rethrow()
            end
        end
        if show_value == -1
            break
        end
        @static if VERSION >= v"1.11"
            if show_value == 2 # 2 indicates a function to be called
                f = ast_or_func
                try
                    ret = f()
                    put!(backend.response_channel, Pair{Any, Bool}(ret, false))
                catch
                    put!(backend.response_channel, Pair{Any, Bool}(current_exceptions(), true))
                end
                continue
            end
        end
        $as_client_code(() -> eval_user_input(ast_or_func, backend, get_module()))
    end
end

@static if VERSION >= v"1.13-"
    # LineEdit's backspace to the main mode finds it through `Base.active_repl`,
    # which names only one of the worker's REPLs.
    let backspace = REPL.LineEdit.bracket_insert_keymap['\b']
        REPL.LineEdit.bracket_insert_keymap['\b'] = function (s::REPL.LineEdit.MIState, o...)
            LE = REPL.LineEdit
            if LE.is_region_active(s) || !(isempty(s) || position(LE.buffer(s)) == 0)
                return backspace(s, o...)
            end
            main_mode = s.interface.modes[1]
            buf = copy(LE.buffer(s))
            LE.transition(s, main_mode) do
                LE.state(s, main_mode).input_buffer = buf
            end
        end
    end
end

# Ctrl-Z stops the client, as julia stops itself, not the worker its clients
# share; the prompt is drawn afresh once it runs again. A shared REPL's
# participants aren't stopped.
REPL.LineEdit.default_keymap["^Z"] = function (s::REPL.LineEdit.MIState, o...)
    LE = REPL.LineEdit
    suspend_client()
    LE.state(s).ias = LE.InputAreaState(0, 0)
    LE.refresh_line(s)
    :ignore
end

function suspend_client()
    sig = @static if VERSION >= v"1.11"
        isnothing(ACTIVE_TERM[].sync_session) || return
        ACTIVE_TERM[].signals
    else
        CLIENT_SIGNALS[]
    end
    if isnothing(sig) || !isopen(sig)
        return
    end
    send_signal(sig, SIGNAL_SUSPEND, UInt8[])
    read(sig, 2) # ack
    nothing
end

@eval Base.exit(n) = $exit_client(n)
@eval Base.atexit(f::Function) = $register_atexit(f)

# Fds 0/1/2 are the conductor's; a closed stdin would fail a spawn with EINVAL.
function spawn_stdin()
    # Before 1.11 it is the client's own stream, not a scoped stand-in.
    reader = if Base.stdin isa Base.AbstractPipe Base.pipe_reader(Base.stdin) else Base.stdin end
    if reader isa Base.PipeEndpoint && reader.status == Base.StatusClosed
        return devnull
    end
    Base.stdin
end

@eval Base.spawn_opts_inherit(
    in::Base.Redirectable = $(spawn_stdin)(),
    out::Base.Redirectable = Base.stdout,
    err::Base.Redirectable = Base.stderr,
    extra::Base.Redirectable...,
) = Base.Redirectable[in, out, err, extra...]

# `redirect_std*` must not dup onto the conductor's fds 0/1/2. Every Base
# signature needs an override, or its more specific method wins.
@static if VERSION >= v"1.11"
    for T in (:IO, :(Union{Base.LibuvStream, IOStream}), :(Base.AbstractPipe), :(Base.DevNull))
        @eval (f::Base.RedirectStdStream)(io::$T) = set_redirect!(f, io)
    end
    @eval function (f::Base.RedirectStdStream)(p::Base.Pipe)
        if p.in.status == Base.StatusInit && p.out.status == Base.StatusInit
            Base.link_pipe!(p)
        end
        set_redirect!(f, getfield(p, f.writable ? :in : :out))
        p
    end
end
