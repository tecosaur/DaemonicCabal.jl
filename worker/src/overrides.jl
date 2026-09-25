# SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
# SPDX-License-Identifier: MPL-2.0

@eval Base.isinteractive() = CLIENT_INTERACTIVE[]

@static if VERSION >= v"1.12"
    @eval function Base.current_terminfo()
        term = ACTIVE_TERM[]
        isnothing(term.terminfo) || return term.terminfo
        terminfo = Base.load_terminfo(term.term)
        if !haskey(terminfo, :setaf) && startswith(term.term, "xterm")
            terminfo[:setaf] = "\e[3%p1%dm"
        end
        term.terminfo = TERMINFOS[term.term] = terminfo
    end

    @eval function Base.get_have_color()
        term = ACTIVE_TERM[]
        isnothing(term.have_color) || return term.have_color
        has_color = Base.ttyhascolor()
        term.have_color = has_color
    end

    @eval function Base.get_have_truecolor()
        term = ACTIVE_TERM[]
        isnothing(term.have_truecolor) || return term.have_truecolor
        has_truecolor = Base.ttyhastruecolor()
        term.have_truecolor = has_truecolor
    end

end

@static if VERSION >= v"1.11"
    @eval function Base.display_error(io::IO, stack::Base.ExceptionStack)
        if !isempty(stack) && first(stack).exception isa DaemonClientExit
            exit = first(stack).exception
            term = ACTIVE_TERM[]
            try close(term.stdout) catch end
            try close(term.stderr) catch end
            # The REPL still prints its next prompt, which the closed streams would fail.
            term.redirect_out = devnull
            term.redirect_err = devnull
            session = term.sync_session
            if !isnothing(session)
                for sig in session.signals
                    try send_signal(sig, SIGNAL_EXIT, UInt8[exit.code % UInt8]) catch end
                end
            else
                send_signal(term.signals, SIGNAL_EXIT, UInt8[exit.code % UInt8])
            end
            display(exit)
        else
            # Relayed Ctrl-Cs keep landing after the loop breaks, and would cut
            # short the render of the interrupt that prompted them.
            Base.disable_sigint() do
                printstyled(io, "ERROR: ", bold=true, color=Base.error_color())
                Base.show_exception_stack(IOContext(io, :limit => true), stack)
                println(io)
            end
        end
    end
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
        isnothing(recording) || (recording.editing = true)
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
    # The per-client Main prints as "Main", not "Main.Main".
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
    # Replay goes to the client's own stdout, so history doesn't recapture it.
    pushfirst!(Base.repl_hooks, function (repl)
        CLIENT_REPL[][] = repl
        target = REPLAY_TARGET[]
        if target !== nothing
            (stdout, session) = target
            REPL.banner(IOContext(stdout, :color => something(ACTIVE_TERM[].have_color, false)))
            replay_history(stdout, session.screen)
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
            for sig in term.sync_session.signals
                isopen(sig) || continue
                try
                    send_signal(sig, SIGNAL_RAW_MODE, UInt8[raw])
                    read(sig, 2) # ack
                catch end
            end
        elseif isopen(term.signals)
            send_signal(term.signals, SIGNAL_RAW_MODE, UInt8[raw])
            read(term.signals, 2) # ack
        end
        raw
    end
else
    @eval function REPL.Terminals.raw!(t::REPL.TTYTerminal, raw::Bool)
        sig = CLIENT_SIGNALS[]
        if sig !== nothing && isopen(sig)
            try
                send_signal(sig, SIGNAL_RAW_MODE, UInt8[raw])
                read(sig, 2) # ack
            catch end
        end
        raw
    end
end

# `REPL.repl_backend_loop`, retrying a `take!` interrupted by a Ctrl-C still in flight.
@eval REPL function repl_backend_loop(backend::REPLBackend, get_module::Function)
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
        $signal_executing(true)
        try
            eval_user_input(ast_or_func, backend, get_module())
        finally
            $signal_executing(false)
        end
    end
end

@eval Base.exit(n) = throw(DaemonClientExit(n))

# Fds 0/1/2 are the conductor's; a closed stdin would fail a spawn with EINVAL.
function spawn_stdin()
    reader = Base.pipe_reader(Base.stdin)
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
