# SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
# SPDX-License-Identifier: MPL-2.0

# Requests are `(:call, f, args, kwargs)` or `(:eval, expr)`; replies
# `(:value, v)` or `(:error, text, exception)`, the exception serialized
# apart so a caller lacking its type still has the text.

# Stock `Serializer`'s fields: the caller's `Main` is `mod`, both ways.
mutable struct ModuleSerializer <: AbstractSerializer
    io::IOBuffer
    counter::Int
    table::IdDict{Any, Any}
    pending_refs::Vector{Int}
    known_object_data::Dict{UInt64, Any}
    version::Int
    const mod::Module
end
ModuleSerializer(mod::Module) =
    ModuleSerializer(IOBuffer(), 0, IdDict{Any, Any}(), Int[], Dict{UInt64, Any}(), Serialization.ser_version, mod)

Serialization.lookup_object_number(s::ModuleSerializer, n::UInt64) = get(s.known_object_data, n, nothing)
function Serialization.remember_object(s::ModuleSerializer, @nospecialize(o), n::UInt64)
    s.known_object_data[n] = o
    nothing
end

Serialization.serialize_mod_names(s::ModuleSerializer, m::Module) =
    invoke(Serialization.serialize_mod_names, Tuple{AbstractSerializer, Module}, s, if m === s.mod Main else m end)

# Stock's test for Main's anonymous functions, whose types go whole.
function Serialization.should_send_whole_type(s::ModuleSerializer, t::DataType)
    (; name, singletonname) = t.name
    t.name.module === s.mod || return invoke(Serialization.should_send_whole_type, Tuple{Any, DataType}, s, t)
    t.super === Function && startswith(String(name), '#') &&
        (!isdefined(s.mod, singletonname) || t != typeof(getglobal(s.mod, singletonname)))
end

# Stock's, the current format only, but an unloaded package is required.
function Serialization.deserialize_module(s::ModuleSerializer)
    uuid = deserialize(s)
    pkg = Base.PkgId(if isnothing(uuid) nothing else Base.UUID(uuid) end, String(deserialize(s)::Symbol))
    mod = if pkg == Base.PkgId("Main") s.mod else get(() -> Base.require(pkg), Base.loaded_modules, pkg) end
    while (inner = deserialize(s)) !== ()
        mod = getglobal(mod, inner)::Module
    end
    mod
end

"""
    serve_remote()

Serve `DaemonicCabal.connect`'s remote calls on this client's stdin and
stdout until its stdin ends, what they print going to its stderr.
"""
function serve_remote()
    input = ACTIVE_TERM[].stdin
    output = CLIENT_RAW_STDOUT[]
    input isa StreamIO && !isnothing(output) ||
        error("serve_remote needs a juliaclient run with piped stdin and stdout, not a terminal or --sync")
    redirect_stdout(() -> serve_remote(input, output, CLIENT_MODULE[]), stderr)
end

"""
    serve_remote(input::IO, output::IO, mod::Module; evaluate = as_client_code)

Serve remote calls from `input` on `output` until `input` ends, `mod` being
the caller's `Main`. Each request runs in `evaluate(thunk)`.
"""
function serve_remote(input::IO, output::IO, mod::Module; evaluate = as_client_code)
    incoming = ModuleSerializer(mod)
    outgoing = ModuleSerializer(mod)
    write_frame(output, outgoing, REMOTE_HELLO)
    while !eof(input)
        payload = read_frame(input)
        reply = evaluate() do
            try
                (:value, perform_request(Base.invokelatest(decode_frame, incoming, payload), mod))
            catch
                error_reply(mod)
            end
        end
        try
            write_frame(output, outgoing, reply)
        catch err
            err isa Base.IOError && rethrow()
            write_frame(output, outgoing, error_reply(mod))
        end
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
    catch
        UInt8[]
    end
    (:error, sprint(Base.show_exception_stack, stack; context = :module => mod), exception)
end
