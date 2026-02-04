# SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
# SPDX-License-Identifier: MPL-2.0

precompile(Tuple{typeof(try_load_revise)})
precompile(Tuple{typeof(queue_ttl_check)})
precompile(Tuple{typeof(perform_ttl_check), Base.Timer})
precompile(Tuple{typeof(prepare_module), ClientInfo})
precompile(Tuple{typeof(getval), Vector{Pair{String, String}}, String, String})
precompile(Tuple{typeof(runclient), ClientInfo, Base.PipeEndpoint, Base.PipeEndpoint})
precompile(Tuple{typeof(Core.kwcall), NamedTuple{(:signal_exit,), Tuple{Function}}, typeof(runclient), Module, ClientInfo})
precompile(Tuple{typeof(create_socket)})
precompile(Tuple{typeof(get_client_sockets)})
precompile(Tuple{typeof(ensure_standby_sockets)})
precompile(Tuple{typeof(create_module)})
precompile(Tuple{typeof(get_module)})
precompile(Tuple{typeof(ensure_standby_module)})
precompile(Tuple{typeof(runworker), String})
# Protocol functions
precompile(Tuple{typeof(read_header), Base.PipeEndpoint})
precompile(Tuple{typeof(read_client_run), Base.PipeEndpoint, Integer})
precompile(Tuple{typeof(send_pong), Base.PipeEndpoint})
precompile(Tuple{typeof(send_sockets), Base.PipeEndpoint, String, String})
# Scoped I/O
@static if VERSION >= v"1.11"
    precompile(Tuple{typeof(Base.get), ScopedStdout, Symbol, Bool})
    precompile(Tuple{typeof(Base.unsafe_write), ScopedStdout, Ptr{UInt8}, UInt64})
    precompile(Tuple{typeof(Base.reseteof), ScopedStdin})
    precompile(Tuple{typeof(Base.write), ScopedStdout, String})
    precompile(Tuple{typeof(Base.displaysize), ScopedStdout})
    precompile(Tuple{typeof(Base.eof), ScopedStdin})
    precompile(Tuple{typeof(Base.peek), ScopedStdin, Type{UInt8}})
    precompile(Tuple{typeof(Base.read), ScopedStdin, Type{UInt8}})
    precompile(Tuple{Type{Base.IOContext{IO_t} where IO_t<:IO}, ScopedStdout, Pair{Symbol, Array{Tuple{String, Int64}, 1}}})
    precompile(Tuple{Type{Base.IOContext{IO_t} where IO_t<:IO}, Base.IOContext{ScopedStdout}, Pair{Symbol, Module}})
    precompile(Tuple{Type{Base.IOContext{IO_t} where IO_t<:IO}, Base.IOContext{ScopedStdout}, Pair{Symbol, Bool}, Pair{Symbol, Module}})
    precompile(Tuple{typeof(Base.print), Base.IOContext{ScopedStdout}, String})
    precompile(Tuple{typeof(Base.write), Base.IOContext{ScopedStdout}, String})
    precompile(Tuple{typeof(Core.kwcall), NamedTuple{(:init,), Tuple{Base.IOContext{ScopedStdout}}}, typeof(Base.foldl), Type, Base.Dict{Symbol, Any}})
    precompile(Tuple{typeof(Base.mapfoldl_impl), typeof(Base.identity), Type{Base.IOContext{IO_t} where IO_t<:IO}, Base.IOContext{ScopedStdout}, Base.Dict{Symbol, Any}})
    @static if VERSION >= v"1.12"
        precompile(Tuple{Type{Base.IOContext{IO_t} where IO_t<:IO}, REPL.LimitIO{ScopedStdout}, Base.IOContext{ScopedStdout}})
        precompile(Tuple{typeof(Base.show), Base.IOContext{REPL.LimitIO{ScopedStdout}}, Base.Multimedia.MIME{:var"text/plain"}, Int64})
    end
    precompile(Tuple{typeof(Base.print), Base.IOContext{ScopedStdout}})
    precompile(Tuple{typeof(Base.println), Base.IOContext{ScopedStdout}})
end
