# SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
# SPDX-License-Identifier: MPL-2.0

# Mock workload that exercises real code paths during precompilation.
# Wrapping in `let` keeps all bindings local. The `jl_generating_output`
# guard ensures the workload only runs during precompilation.
if ccall(:jl_generating_output, Cint, ()) == 1
let
    # Helper: write a u16-length-prefixed string into an IOBuffer
    _ws(io, s) = (write(io, UInt16(ncodeunits(s))); write(io, s))
    # -- Build mock conductor message stream ----------------------------------
    buf = IOBuffer()
    write(buf, UInt32(PROTOCOL_MAGIC))
    # ping (type=0x01, len=0)
    write(buf, UInt8(MSG_TYPE.ping), UInt16(0))
    # set_project (type=0x10)
    proj = "/tmp/test"
    write(buf, UInt8(MSG_TYPE.set_project), UInt16(2 + ncodeunits(proj)))
    _ws(buf, proj)
    # query_state (type=0x30, len=0)
    write(buf, UInt8(MSG_TYPE.query_state), UInt16(0))
    # client_run (type=0x20): build payload separately to compute length
    cr = IOBuffer()
    write(cr, UInt8(0x00))                        # flags: tty=false, force=false
    write(cr, UInt32(12345))                      # pid
    _ws(cr, "/tmp")                               # cwd
    write(cr, UInt16(2))                          # env_count
    _ws(cr, "TERM"); _ws(cr, "xterm-256color")
    _ws(cr, "HOME"); _ws(cr, "/home/test")
    write(cr, UInt16(2))                          # switch_count
    _ws(cr, "--eval"); _ws(cr, "1+1")
    _ws(cr, "--color"); _ws(cr, "yes")
    write(cr, UInt8(0))                           # has_programfile=false
    write(cr, UInt16(1))                          # arg_count
    _ws(cr, "arg1")
    write(cr, UInt16(0xFFFF))                     # port_set=NONE
    cr_data = take!(cr)
    write(buf, UInt8(MSG_TYPE.client_run), UInt16(length(cr_data)))
    write(buf, cr_data)
    # sync_clients (type=0x50)
    write(buf, UInt8(MSG_TYPE.sync_clients), UInt16(2 + 4))
    write(buf, UInt16(1), UInt32(12345))
    # soft_exit (type=0x40, len=0)
    write(buf, UInt8(MSG_TYPE.soft_exit), UInt16(0))
    seekstart(buf)
    # -- Exercise protocol reading --------------------------------------------
    verify_magic(buf)
    read_header(buf)                              # ping
    h = read_header(buf)                          # set_project
    read_string(buf)
    read_header(buf)                              # query_state
    h = read_header(buf)                          # client_run
    client = read_client_run(buf)
    read_header(buf)                              # sync_clients
    read(buf, UInt16); read(buf, UInt32)
    read_header(buf)                              # soft_exit
    # -- Exercise protocol writing --------------------------------------------
    out = IOBuffer()
    send_pong(out, 0)
    send_sockets(out, "/a", "/b", "/c", "/d", 1)
    send_state(out, 0, round(Int, time()), false)
    send_state(out, 1, round(Int, time()), true)
    send_error(out, ERR_CODE.unknown, "test error")
    write_header(out, MSG_TYPE.project_ok, 0)
    write_header(out, MSG_TYPE.ack, 2)
    write_string(out, "test")
    send_signal(out, SIGNAL_EXIT, UInt8[0])
    send_signal(out, SIGNAL_RAW_MODE, UInt8[true])
    send_signal(out, SIGNAL_QUERY_SIZE, UInt8[])
    # send_notification takes an address string, not an IO — exercise via explicit directive
    # -- Exercise helpers -----------------------------------------------------
    getval(client.switches, "--eval", "")
    getval(client.switches, "--missing", "default")
    getval(client.env, "TERM", "")
    getval(client.env, "MISSING", "fallback")
    is_tcp_address("127.0.0.1:8080")
    is_tcp_address("/tmp/test.sock")
    sync_session_label(client)
    # create_module/prepare_module/runclient use Core.eval(Module(:Main), ...)
    # which is forbidden during precompilation — covered by explicit directives below
    # -- Exercise BroadcastWriter ---------------------------------------------
    bw = BroadcastWriter([IOBuffer(), IOBuffer()])
    iswritable(bw); isopen(bw); isreadable(bw); bytesavailable(bw)
    write(bw, UInt8(0x41))
    Base.unsafe_write(bw, pointer("test"), UInt(4))
    flush(bw)
    # -- Exercise ScopedIO (>= 1.11) -----------------------------------------
    @static if VERSION >= v"1.11"
        scoped_out = ScopedStdout()
        scoped_err = ScopedStderr()
        scoped_in = ScopedStdin()
        # Base.get dispatches
        Base.get(scoped_out, :color, false)
        Base.get(scoped_err, :color, false)
        Base.get(scoped_out, :other, 42)
        # pipe_reader/pipe_writer (resolves via ACTIVE_TERM)
        Base.pipe_reader(scoped_in)
        Base.pipe_writer(scoped_out)
        Base.pipe_writer(scoped_err)
        # IOContext construction
        ioc = IOContext(scoped_out, :color => true)
        IOContext(ioc, :module => Main)
        IOContext(scoped_out, :color => true, :module => Main)
        # Write operations (WORKER_TERM pipes are unconnected, but methods still compile)
        try write(scoped_out, "test") catch end
        try print(ioc, "hello") catch end
        try write(ioc, "world") catch end
        try println(ioc) catch end
        try Base.unsafe_write(scoped_out, pointer("test"), UInt(4)) catch end
        try displaysize(scoped_out) catch end
        try displaysize(scoped_err) catch end
        @static if VERSION >= v"1.12"
            try
                lio = REPL.LimitIO(scoped_out, 1000)
                show(IOContext(lio, ioc), MIME"text/plain"(), 42)
            catch end
        end
    end
end # let
end # if jl_generating_output

# Explicit precompile directives for PipeEndpoint/TCPSocket specialisations
# (these runtime types cannot be safely instantiated during precompilation)
precompile(verify_magic, (Base.PipeEndpoint,))
precompile(read_header, (Base.PipeEndpoint,))
precompile(read_client_run, (Base.PipeEndpoint,))
precompile(read_string, (Base.PipeEndpoint,))
precompile(write_header, (Base.PipeEndpoint, UInt8, Int))
precompile(write_string, (Base.PipeEndpoint, String))
precompile(send_pong, (Base.PipeEndpoint, Int))
precompile(send_sockets, (Base.PipeEndpoint, String, String, String, String, Int))
precompile(send_state, (Base.PipeEndpoint, Int, Int, Bool))
precompile(send_error, (Base.PipeEndpoint, UInt16, String))
precompile(send_signal, (Base.PipeEndpoint, UInt8, Vector{UInt8}))
precompile(send_signal, (Sockets.TCPSocket, UInt8, Vector{UInt8}))
precompile(send_notification, (String, UInt8, UInt32))
precompile(runclient, (ClientInfo, Base.PipeEndpoint, Base.PipeEndpoint, Base.PipeEndpoint, Base.PipeEndpoint))
precompile(prepare_module, (ClientInfo,))
precompile(create_module, ())
@static if VERSION >= v"1.11"
    precompile(Base.unsafe_write, (ScopedStdout, Ptr{UInt8}, UInt64))
    precompile(Base.write, (ScopedStdout, String))
    precompile(Base.displaysize, (ScopedStdout,))
    precompile(Base.displaysize, (ScopedStderr,))
    precompile(Base.reseteof, (ScopedStdin,))
    precompile(Base.eof, (ScopedStdin,))
    precompile(Base.peek, (ScopedStdin, Type{UInt8}))
    precompile(Base.read, (ScopedStdin, Type{UInt8}))
end
