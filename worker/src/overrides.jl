# SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
# SPDX-License-Identifier: MPL-2.0

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

    @eval function REPL.Terminals.raw!(t::REPL.TTYTerminal, raw::Bool)
        term = ACTIVE_TERM[]
        session = term.sync_session
        if !isnothing(session)
            for sig in session.signals
                isopen(sig) || continue
                try
                    send_signal(sig, SIGNAL_RAW_MODE, UInt8[raw])
                    read(sig, 2)  # ack
                catch end
            end
        elseif isopen(term.signals)
            send_signal(term.signals, SIGNAL_RAW_MODE, UInt8[raw])
            read(term.signals, 2)  # ack: id(1) + len(1), len=0
        end
        raw
    end

    @eval function Base.display_error(io::IO, stack::Base.ExceptionStack)
        if !isempty(stack) && first(stack).exception isa DaemonClientExit
            exit = first(stack).exception
            term = ACTIVE_TERM[]
            try close(term.stdout) catch end
            try close(term.stderr) catch end
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
            printstyled(io, "ERROR: ", bold=true, color=Base.error_color())
            Base.show_exception_stack(IOContext(io, :limit => true),stack)
            println(io)
        end
    end
else
    # With `REPL.Terminals.raw!`, there are two invocations incompatible
    # with an `IOContext`: `check_open` and `.handle`. However, `raw!` isn't
    # able to work normally anyway, so we may as well override it.
    @eval REPL.Terminals.raw!(t::REPL.TTYTerminal, raw::Bool) = raw
end

# Override active_module to use the per-client scoped module for REPL
# evaluation, and install an atreplinit hook that records the REPL
# object into the client's scoped ref.
@static if VERSION >= v"1.11"
    @eval function Base.active_module((; mistate)::REPL.LineEditREPL)
        if mistate !== nothing && mistate.active_module !== Main
            mistate.active_module
        else
            CLIENT_MODULE[]
        end
    end
    # Override contextual_prompt so the module prefix is suppressed when
    # the active module is the client's own Main (the standard version
    # checks `mod == Main` by identity, which fails for our per-client module).
    @eval function REPL.contextual_prompt(repl::REPL.LineEditREPL, prompt::Union{String,Function})
        function ()
            mod = Base.active_module(repl)
            prefix = (mod === Main || mod === CLIENT_MODULE[]) ? "" : string('(', mod, ") ")
            prefix * (prompt isa String ? prompt : prompt())
        end
    end
    # Override print_fullname so the client's per-session Main module
    # prints as just "Main" rather than "Main.Main", and submodules
    # defined within it print relative to it (e.g. "Main.Foo").
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
    pushfirst!(Base.repl_hooks, repl -> CLIENT_REPL[][] = repl)
end

@eval Base.exit(n) = throw(DaemonClientExit(n))
