# SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
# SPDX-License-Identifier: MPL-2.0

if ccall(:jl_generating_output, Cint, ()) == 1
let
    # -- Conductor messages ------------------------------------------------------
    buf = IOBuffer()
    write(buf, UInt32(PROTOCOL_MAGIC))
    write(buf, UInt8(MSG_TYPE.ping), UInt16(1), UInt8(1))
    proj = "/tmp/test"
    write(buf, UInt8(MSG_TYPE.set_project), UInt16(2 + ncodeunits(proj)))
    write_string(buf, proj)
    write(buf, UInt8(MSG_TYPE.query_state), UInt16(0))
    cr = IOBuffer()
    write(cr, UInt8(0x00))                        # flags: tty=false, force=false
    write(cr, UInt32(7))                          # client id
    write(cr, UInt32(12345))                      # pid
    write_string(cr, "/tmp")                               # cwd
    write(cr, UInt16(2))                          # env_count
    write_string(cr, "TERM"); write_string(cr, "xterm-256color")
    write_string(cr, "HOME"); write_string(cr, "/home/test")
    write(cr, UInt16(2))                          # switch_count
    write_string(cr, "--eval"); write_string(cr, "1+1")
    write_string(cr, "--color"); write_string(cr, "yes")
    write(cr, UInt8(0))                           # has_programfile=false
    write(cr, UInt16(1))                          # arg_count
    write_string(cr, "arg1")
    write(cr, UInt16(0xFFFF))                     # port_set=NONE
    cr_data = take!(cr)
    write(buf, UInt8(MSG_TYPE.client_run), UInt16(length(cr_data)))
    write(buf, cr_data)
    write(buf, UInt8(MSG_TYPE.sync_clients), UInt16(2 + 4))
    write(buf, UInt16(1), UInt32(12345))
    write(buf, UInt8(MSG_TYPE.soft_exit), UInt16(0))
    seekstart(buf)
    # -- Protocol reading ------------------------------------------------------
    verify_magic(buf)
    read_header(buf)                              # ping
    read(buf, UInt8)
    h = read_header(buf)                          # set_project
    read_string(buf)
    read_header(buf)                              # query_state
    h = read_header(buf)                          # client_run
    client = read_client_run(buf)
    read_header(buf)                              # sync_clients
    read(buf, UInt16); read(buf, UInt32)
    read_header(buf)                              # soft_exit
    # -- Protocol writing ------------------------------------------------------
    out = IOBuffer()
    send_pong(out, 0x01, 0)
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
    # -- Helpers ---------------------------------------------------------------
    getval(client.switches, "--eval", "")
    getval(client.switches, "--missing", "default")
    getval(client.env, "TERM", "")
    getval(client.env, "MISSING", "fallback")
    is_tcp_address("127.0.0.1:8080")
    is_tcp_address("/tmp/test.sock")
    sync_session_label(client)
    # create_module/prepare_module/runclient can't run here: Core.eval is forbidden.
    # -- BroadcastWriter + OutputHistory ---------------------------------------
    history = OutputHistory(SYNC_HISTORY_BYTES)
    bw = BroadcastWriter(IO[IOBuffer(), IOBuffer()], history)
    iswritable(bw); isopen(bw); isreadable(bw); bytesavailable(bw)
    write(bw, UInt8(0x41))
    Base.unsafe_write(bw, pointer("test\n"), UInt(5))
    flush(bw)
    replay_history(IOBuffer(), history)
    # -- ScopedIO --------------------------------------------------------------
    @static if VERSION >= v"1.11"
        scoped_out = ScopedStdout()
        scoped_err = ScopedStderr()
        scoped_in = ScopedStdin()
        Base.get(scoped_out, :color, false)
        Base.get(scoped_err, :color, false)
        Base.get(scoped_out, :other, 42)
        Base.pipe_reader(scoped_in)
        Base.pipe_writer(scoped_out)
        Base.pipe_writer(scoped_err)
        ioc = IOContext(scoped_out, :color => true)
        IOContext(ioc, :module => Main)
        IOContext(scoped_out, :color => true, :module => Main)
        # WORKER_TERM's pipes are unconnected, but the methods still compile.
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

# Stream types that cannot be instantiated during precompilation
precompile(verify_magic, (Base.PipeEndpoint,))
precompile(read_header, (Base.PipeEndpoint,))
precompile(read_client_run, (Base.PipeEndpoint,))
precompile(read_string, (Base.PipeEndpoint,))
precompile(write_header, (Base.PipeEndpoint, UInt8, Int))
precompile(write_string, (Base.PipeEndpoint, String))
precompile(send_pong, (Base.PipeEndpoint, UInt8, Int))
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
