# SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
# SPDX-License-Identifier: MPL-2.0

# Requests are `(:call, f, args, kwargs)` or `(:eval, expr)`; replies
# `(:value, v)` or `(:error, text, exception)`, the exception serialized
# apart so a caller lacking its type still has the text. Only a request is
# the client's code: a Ctrl-C reaching the loop around it is passed on.

"""
    serve_remote()

Serve `DaemonicCabal.connect`'s remote calls on this client's stdin and
stdout until its stdin ends, what they print going to its stderr.
"""
function serve_remote()
    term = ACTIVE_TERM[]
    output = CLIENT_RAW_STDOUT[]
    term.stdin isa StreamIO && !isnothing(output) ||
        error("serve_remote needs a juliaclient run with piped stdin and stdout, not a terminal or --sync")
    # Its stdout is its stderr, so no redirect a call makes, or undoes, reaches the replies.
    replyless = VirtualTerm(term.stdin, term.stderr, term.stderr, term.signals, term.term, term.sync_session,
                            term.terminfo, term.have_color, term.have_truecolor;
                            stdout_is_terminal = term.stderr_is_terminal, term.stderr_is_terminal)
    @with ACTIVE_TERM => replyless serve_remote(term.stdin, output, CLIENT_MODULE[])
end

"""
    serve_remote(input::IO, output::IO, mod::Module; evaluate = as_client_code)

Serve remote calls from `input` on `output` until `input` ends, `mod` being
the caller's `Main`. Each request runs in `evaluate(thunk)`.
"""
function serve_remote(input::IO, output::IO, mod::Module; evaluate = as_client_code)
    incoming = ModuleSerializer(mod)
    outgoing = ModuleSerializer(mod)
    send_frame(output, encode_frame(outgoing, REMOTE_HELLO))
    while (payload = receive_frame(input)) !== nothing
        # The latest world throughout, so what a request defines is seen as its reply is made.
        reply = try
            (:value, evaluate(() -> perform_request(Base.invokelatest(decode_frame, incoming, payload), mod)))
        catch
            unbroken(() -> Base.invokelatest(error_reply, mod))
        end
        send_frame(output, unbroken(() -> Base.invokelatest(encode_reply, outgoing, reply, mod)))
    end
end

function perform_request(request::Tuple, mod::Module)
    kind = first(request)
    if kind === :call
        _, f, args, kwargs = request
        Base.invokelatest(f, args...; kwargs...)
    elseif kind === :eval
        ex = last(request)
        value = Core.eval(mod, if Meta.isexpr(ex, :block) Expr(:toplevel, ex.args...) else ex end)
        # A definition's function would go by a name the caller lacks.
        is_definition = value isa Function && parentmodule(value) === mod && !startswith(String(nameof(value)), '#')
        if is_definition nothing else value end
    else
        throw(ArgumentError("unknown remote request $(repr(kind)): the caller's DaemonicCabal differs from this worker's"))
    end
end

# Within a `catch`; an exception that won't serialize reaches the caller as text.
function error_reply(mod::Module)
    stack = scrub_backtrace(current_exceptions(), @__FILE__)
    exception = try
        s = ModuleSerializer(mod)
        serialize(s, last(stack).exception)
        take!(s.io)
    catch err
        err isa InterruptException && pass_interrupt()
        UInt8[]
    end
    (:error, sprint(Base.show_exception_stack, stack; context = :module => mod), exception)
end

function encode_reply(s::ModuleSerializer, reply::Tuple, mod::Module)
    try
        encode_frame(s, reply)
    catch
        encode_frame(s, error_reply(mod))
    end
end

# Nothing at the input's end. Only the waits can be interrupted, and are
# retried, so a frame is never half read.
function receive_frame(input::IO)
    await(n) = uninterrupted(() -> shielded(() -> Base.wait_readnb(input, n)))
    await(8)
    bytesavailable(input) < 8 && return nothing
    payload_length = Int(ltoh(read(input, UInt64)))
    await(payload_length)
    bytesavailable(input) < payload_length && return nothing
    read(input, payload_length)
end

# One write queues the frame whole, so an interrupted wait for it loses
# nothing, but libuv writes on from `frame`: kept until a flush finds it sent.
function send_frame(output::IO, frame::Vector{UInt8})
    GC.@preserve frame try
        shielded(() -> write(output, frame))
    catch err
        err isa InterruptException || rethrow()
        pass_interrupt()
        uninterrupted(() -> shielded(() -> flush(output)))
    end
end

# `f` run to its end, a Ctrl-C held off it passed on after.
function unbroken(f)
    result = Ref{Any}()
    try
        shielded(() -> result[] = f())
    catch err
        err isa InterruptException && isassigned(result) || rethrow()
        pass_interrupt()
    end
    result[]
end
