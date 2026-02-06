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
        if isopen(term.signals)
            send_signal(term.signals, SIGNAL_RAW_MODE, UInt8[raw])
            read(term.signals, 2)  # ack: id(1) + len(1), len=0
        end
        raw
    end

    @eval function Base.display_error(io::IO, stack::Base.ExceptionStack)
        if !isempty(stack) && first(stack).exception isa DaemonClientExit
            exit = first(stack).exception
            close(ACTIVE_TERM[].stdout)
            send_signal(ACTIVE_TERM[].signals, SIGNAL_EXIT, UInt8[exit.code % UInt8])
            display(exit)
        else
            printstyled(io, "ERROR: ", bold=true, color=Base.error_color())
            Base.show_exception_stack(IOContext(io, :limit => true),stack)
            println(io)
        end
    end
else
    # With `REPL.Terminals.raw!`, there are to invocations incompatable
    # with an `IOContext`: `check_open` and `.handle`. However, `raw!` isn't
    # able to work normally anyway, so we may as well override it.
    @eval REPL.Terminals.raw!(t::REPL.TTYTerminal, raw::Bool) = raw
end

@eval Base.exit(n) = throw(DaemonClientExit(n))
