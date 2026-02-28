# SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
# SPDX-License-Identifier: MPL-2.0

const STATE = (
    ctime = time(),
    worker_number = Ref(-1),
    clients = Vector{Tuple{Float64, ClientInfo}}(),
    client_tasks = Dict{Int, Task}(),
    project = Ref(""),
    lastclient = Ref(time()),
    lock = SpinLock(),
    soft_exit = Ref(false),
    conductor_conn = Ref{Union{IO, Nothing}}(nothing),
    conductor_socket = Ref(""),
    standby_sockets = Ref{Union{Nothing, NTuple{4, Pair{Union{Sockets.PipeServer, Sockets.TCPServer}, String}}}}(nothing),
    standby_module = Ref{Union{Nothing, Module}}(nothing),
    sync_sessions = Dict{String, SyncSession}())

# Configuration (set during runworker from environment)
RUNTIME_DIR::String = ""
MAX_CLIENTS::Int = 1
WORKER_TTL::Int = 0
PORT_BASE::Int = 0  # Base port for managed port range (from JULIA_DAEMON_PORTS)

# Exiting

struct DaemonClientExit <: Exception code::Int end

real_exit(n::Int) = ccall(:jl_exit, Union{}, (Int32,), n)

# Revise

const REVISE_PKG =
    Base.PkgId(Base.UUID("295af30f-e4ad-537b-8983-00126c2a3abe"), "Revise")

function try_load_revise()
    if !isnothing(Base.locate_package(REVISE_PKG))
        Core.eval(Main, :(using Revise))
    end
end

# TTL checking

function queue_ttl_check()
    if WORKER_TTL > 0
        Timer(perform_ttl_check, WORKER_TTL)
    end
end

function perform_ttl_check(::Timer)
    if WORKER_TTL > 0 && time() - (@lock STATE.lock STATE.lastclient[]) >= WORKER_TTL
        send_notification(STATE.conductor_socket[], NOTIF_TYPE.worker_exit, UInt32(getpid()))
        real_exit(0)
    end
end

# Kill client tasks whose PIDs are not in the active set (conductor thinks they're gone)
function kill_stuck_clients(active_pids::Set{Int})
    orphan_tasks = @lock STATE.lock [
        task for (pid, task) in STATE.client_tasks
        if pid ∉ active_pids && !istaskdone(task)
    ]
    for task in orphan_tasks
        Base.schedule(task, InterruptException(); error=true)
    end
    for task in orphan_tasks
        try wait(task) catch end
    end
end

# Signal protocol (Worker → Client via signals socket)
const SIGNAL_EXIT = 0x01
const SIGNAL_RAW_MODE = 0x02   # data: 0x00 = cooked, 0x01 = raw
const SIGNAL_QUERY_SIZE = 0x03 # response: height(u16) + width(u16)
const SIGNAL_NODELAY = 0x04    # disable Nagle on stdin+signals (low-latency connection)

function send_signal(io::IO, id::UInt8, data::Vector{UInt8})
    write(io, id, UInt8(length(data)), data)
end

# Copied from `init_active_project()` in `base/initdefs.jl`.
function set_project(project)
    Base.set_active_project(
        project === nothing ? nothing :
        project == "" ? nothing :
        startswith(project, "@") ? Base.load_path_expand(project) :
        abspath(expanduser(project)))
end

# Worker management

function create_socket(port::Integer=0)::Pair{Union{Sockets.PipeServer, Sockets.TCPServer}, String}
    if is_tcp_address(STATE.conductor_socket[])
        bind_addr = get(ENV, "JULIA_DAEMON_BIND", "0.0.0.0")
        server = Sockets.listen(Sockets.IPv4(bind_addr), port)
        _, actual_port = Sockets.getsockname(server)
        # Report just :port — the client prepends the conductor's host,
        # which is correct for both local and remote connections.
        # Reporting the bind address (e.g. 0.0.0.0) would fail for remote clients.
        server => ":$(actual_port)"
    else
        sockfile = string("worker-", WORKER_ID[], '-', String(rand('a':'z', 8)), ".sock")
        path = joinpath(RUNTIME_DIR, sockfile)
        Sockets.listen(path) => path
    end
end

function ports_for_index(port_set::Int)::NTuple{4, Int}
    start = PORT_BASE + port_set * 4
    (start, start + 1, start + 2, start + 3)
end

const PORT_SET_NONE = 0xFFFF

# Get sockets for a new client (stdin, stdout, stderr, signals), using standby if available
function get_client_sockets(port_set::Int)::NTuple{4, Pair{Union{Sockets.PipeServer, Sockets.TCPServer}, String}}
    # With a managed port range, we must use the assigned ports (no standby)
    if port_set != PORT_SET_NONE
        p1, p2, p3, p4 = ports_for_index(port_set)
        return (create_socket(p1), create_socket(p2), create_socket(p3), create_socket(p4))
    end
    sockets = @lock STATE.lock begin
        s = STATE.standby_sockets[]
        STATE.standby_sockets[] = nothing
        s
    end
    if isnothing(sockets)
        (create_socket(), create_socket(), create_socket(), create_socket())
    else
        sockets
    end
end
# Ensure standby sockets exist (called after client disconnect or on startup).
# Standby is disabled when a managed port range is active, since the port set
# index is not known until the conductor sends a client_run message.
function ensure_standby_sockets()
    PORT_BASE > 0 && return
    @lock STATE.lock begin
        if isnothing(STATE.standby_sockets[])
            STATE.standby_sockets[] = (create_socket(), create_socket(), create_socket(), create_socket())
        end
    end
end

# Detect --sync + --session=<label> from client switches.
# Returns the session label if sync mode is active, nothing otherwise.
function sync_session_label(client::ClientInfo)
    any(p -> first(p) == "--sync", client.switches) || return nothing
    idx = findfirst(p -> first(p) == "--session", client.switches)
    isnothing(idx) && return nothing
    label = last(client.switches[idx])
    if !isempty(label) label end
end

# Handle disconnect of an interactive sync client. Closes the client's own
# streams, removes them from the session vectors, sends exit signal, and
# unregisters. When the last interactive client leaves, closes the merged pipe
# write end (causing REPL EOF) and removes the session.
function sync_client_disconnect!(client::ClientInfo, client_stdin::StreamIO,
                                 client_stdout::StreamIO, client_stderr::StreamIO,
                                 signals::StreamIO, session::SyncSession, label::String)
    @lock STATE.lock begin
        filter!(s -> s !== client_stdout, session.outs)
        filter!(s -> s !== client_stderr, session.errs)
        filter!(s -> s !== signals, session.signals)
        session.interactive_count -= 1
    end
    # Newline so the client's terminal exits cleanly (terminal is in raw mode)
    try write(client_stdout, "\r\n") catch end
    try close(client_stdout) catch end
    try close(client_stderr) catch end
    try
        send_signal(signals, SIGNAL_EXIT, UInt8[0])
        close(signals)
    catch end
    try close(client_stdin) catch end
    # If last interactive client, tear down the session
    last_client = @lock STATE.lock session.interactive_count <= 0
    if last_client
        try close(session.writesink) catch end
        @lock STATE.lock delete!(STATE.sync_sessions, label)
    end
    unregister_client!(client)
end

# Echo -e/-E expressions to REPL observers via the session's stdout vectors.
function sync_echo_expressions(session::SyncSession, client::ClientInfo)
    for (switch, value) in client.switches
        suffix = if switch == "--eval" ";\n"
        elseif switch == "--print" "\n"
        else continue end
        for w in session.outs
            try write(w, "\r\e[2K\e[1;32mjulia>\e[m ", value, suffix) catch end
        end
    end
end

# Copy client_stdin → merged_write until EOF or error.
# When `intercept_eof` is set (sync interactive clients), Ctrl-D (0x04) is not
# forwarded — it detaches this client instead of killing the shared REPL.
function stdin_copy_loop(client_stdin::StreamIO, merged_write::Base.PipeEndpoint;
                         intercept_eof::Bool=false)
    buf = Vector{UInt8}(undef, 64 * 1024)
    try
        while true
            Base.wait_readnb(client_stdin, 1)
            avail = bytesavailable(client_stdin)
            if avail == 0
                eof(client_stdin) && return
                continue
            end
            n = min(avail, length(buf))
            GC.@preserve buf unsafe_read(client_stdin, pointer(buf), n)
            if intercept_eof && n == 1 && buf[1] == 0x04
                return
            end
            write(merged_write, @view buf[1:n])
        end
    catch e
        e isa Base.IOError || e isa EOFError || rethrow()
    end
end

function spawn_sync_client!(client::ClientInfo, client_stdin::StreamIO,
                            client_stdout::StreamIO, client_stderr::StreamIO,
                            signals::StreamIO, label::String)
    is_interactive = client.tty &&
        isnothing(client.programfile) &&
        !any(p -> first(p) ∈ ("--eval", "--print"), client.switches)
    session = get(STATE.sync_sessions, label, nothing)
    if is_interactive
        new_session = isnothing(session)
        if new_session
            # First interactive client: create session with merged stdin pipe
            pipe = Pipe()
            Base.link_pipe!(pipe; reader_supports_async=true, writer_supports_async=true)
            outs = StreamIO[client_stdout]
            errs = StreamIO[client_stderr]
            sigs = StreamIO[signals]
            session = SyncSession(pipe.out, pipe.in, outs, errs, sigs, 1)
            STATE.sync_sessions[label] = session
        else
            # Additional interactive client: attach to existing session
            @lock STATE.lock begin
                push!(session.outs, client_stdout)
                push!(session.errs, client_stderr)
                push!(session.signals, signals)
                filter!(isopen, session.outs)
                filter!(isopen, session.errs)
                filter!(isopen, session.signals)
                session.interactive_count += 1
            end
            # Tell the client that the REPL is in raw mode so it forwards
            # keystrokes immediately instead of activating cooked emulation.
            send_signal(signals, SIGNAL_RAW_MODE, UInt8[true])
            read(signals, 2)
            # Nudge the REPL to redraw its prompt
            try write(session.writesink, " \x7f") catch end
        end
        task = Threads.@spawn begin
            stdin_copy_loop(client_stdin, session.writesink; intercept_eof=true)
            sync_client_disconnect!(client, client_stdin, client_stdout,
                                    client_stderr, signals, session, label)
        end
        @lock STATE.lock STATE.client_tasks[client.pid] = task
        if new_session
            out = BroadcastWriter(session.outs)
            err = BroadcastWriter(session.errs)
            # Session-owned: exits when mergedin reaches EOF (last client disconnected)
            Threads.@spawn try
                runclient(client, session.mergedin, out, err, signals;
                          owned_streams=(), sync_session=session)
            catch end
        end
    else
        # Non-interactive: broadcast output to session observers
        out, err = if !isnothing(session)
            (BroadcastWriter(StreamIO[client_stdout; session.outs]),
             BroadcastWriter(StreamIO[client_stderr; session.errs]))
        else
            (client_stdout, client_stderr)
        end
        task = Threads.@spawn begin
            if !isnothing(session)
                sync_echo_expressions(session, client)
            end
            try
                runclient(client, client_stdin, out, err, signals;
                          owned_streams=(client_stdout, client_stderr))
            catch
                isopen(client_stdout) && rethrow()
            end
            # Nudge REPL to redraw prompt
            if !isnothing(session)
                for w in session.outs try write(w, "\n") catch end end
                try write(session.writesink, " \x7f") catch end
            end
        end
        @lock STATE.lock STATE.client_tasks[client.pid] = task
    end
end

function unregister_client!(client::ClientInfo)
    @lock STATE.lock begin
        idx = findfirst(e -> last(e) === client, STATE.clients)
        !isnothing(idx) && deleteat!(STATE.clients, idx)
        delete!(STATE.client_tasks, client.pid)
        STATE.lastclient[] = time()
        if STATE.soft_exit[] && isempty(STATE.clients)
            real_exit(0)
        end
    end
    send_notification(STATE.conductor_socket[], NOTIF_TYPE.client_done,
                      UInt32(client.pid))
    ensure_standby_sockets()
    ensure_standby_module()
    queue_ttl_check()
end

function spawn_client!(conn::IO, client::ClientInfo)
    (stdin_srv, stdin_path), (stdout_srv, stdout_path),
        (stderr_srv, stderr_path), (signals_srv, signals_path) = get_client_sockets(client.port_set)
    active_count = @lock STATE.lock begin
        push!(STATE.clients, (time(), client))
        length(STATE.clients)
    end
    send_sockets(conn, stdin_path, stdout_path, stderr_path, signals_path, active_count)
    is_tcp = stdin_srv isa Sockets.TCPServer
    t0 = time_ns()
    client_stdin = accept(stdin_srv)
    client_stdout = accept(stdout_srv)
    client_stderr = accept(stderr_srv)
    signals = accept(signals_srv)
    if is_tcp
        Sockets.nagle(signals, false)
        if time_ns() - t0 < 40_000_000
            Sockets.nagle(client_stdout, false)
            Sockets.nagle(client_stderr, false)
            send_signal(signals, SIGNAL_NODELAY, UInt8[])
        end
    end
    close(stdin_srv); close(stdout_srv); close(stderr_srv); close(signals_srv)
    label = sync_session_label(client)
    if isnothing(label)
        task = Threads.@spawn try
            runclient(client, client_stdin, client_stdout, client_stderr, signals)
        catch
            isopen(client_stdout) && rethrow()
        end
        @lock STATE.lock STATE.client_tasks[client.pid] = task
    else
        spawn_sync_client!(client, client_stdin, client_stdout, client_stderr, signals, label)
    end
end

function runworker(socketpath::String, worker_number::Int=-1, conductor_address::String="")
    # Disable Julia's default SIGINT handling which throws uncatchable InterruptException
    # This allows us to exit cleanly when the conductor shuts down
    Base.exit_on_sigint(false)
    conn = connect_to(socketpath)
    STATE.conductor_conn[] = conn
    STATE.worker_number[] = worker_number
    STATE.conductor_socket[] = if !isempty(conductor_address)
        conductor_address
    else
        joinpath(dirname(socketpath), "conductor.sock")
    end
    global RUNTIME_DIR = is_tcp_address(STATE.conductor_socket[]) ? "" : dirname(socketpath)
    global MAX_CLIENTS = parse(Int, get(ENV, "JULIA_DAEMON_WORKER_MAXCLIENTS", "1"))
    global WORKER_TTL = parse(Int, get(ENV, "JULIA_DAEMON_WORKER_TTL", "0"))
    global PORT_BASE = if haskey(ENV, "JULIA_DAEMON_PORTS")
        parse(Int, split(ENV["JULIA_DAEMON_PORTS"], '-')[1])
    else 0 end
    ensure_standby_sockets()
    ensure_standby_module()
    try
        verify_magic(conn)
        while isopen(conn)
            header = read_header(conn)
            if header.msg_type == MSG_TYPE.ping
                active = @lock STATE.lock length(STATE.clients)
                send_pong(conn, active)
            elseif header.msg_type == MSG_TYPE.set_project
                project = read_string(conn)
                try
                    set_project(project)
                    STATE.project[] = project
                    write_header(conn, MSG_TYPE.project_ok, 0)
                    flush(conn)
                catch err
                    send_error(conn, ERR_CODE.project_not_found,
                               "Failed to set project: $(sprint(showerror, err))")
                end
            elseif header.msg_type == MSG_TYPE.client_run
                client = read_client_run(conn, header.payload_len)
                # Check capacity first (force flag bypasses limit for labeled sessions)
                active_count = @lock STATE.lock length(STATE.clients)
                if !client.force && MAX_CLIENTS > 0 && active_count >= MAX_CLIENTS
                    # Reject: send empty paths with current count
                    send_sockets(conn, "", "", "", "", active_count)
                else
                    try
                        spawn_client!(conn, client)
                    catch err
                        send_error(conn, ERR_CODE.internal_error,
                                   "Failed to start client: $(sprint(showerror, err))")
                    end
                end
            elseif header.msg_type == MSG_TYPE.query_state
                active, last_ts, soft_exit = @lock STATE.lock (
                    length(STATE.clients),
                    round(Int, STATE.lastclient[]),
                    STATE.soft_exit[]
                )
                send_state(conn, active, last_ts, soft_exit)
            elseif header.msg_type == MSG_TYPE.soft_exit
                @lock STATE.lock begin
                    if isempty(STATE.clients)
                        ccall(:_exit, Cvoid, (Cint,), 0)
                    else
                        STATE.soft_exit[] = true
                    end
                end
            elseif header.msg_type == MSG_TYPE.sync_clients
                # Read list of PIDs that conductor believes are active
                pid_count = read(conn, UInt16)
                active_pids = Set{Int}()
                for _ in 1:pid_count
                    push!(active_pids, Int(read(conn, UInt32)))
                end
                kill_stuck_clients(active_pids)
                remaining = @lock STATE.lock length(STATE.clients)
                write_header(conn, MSG_TYPE.ack, 2)
                write(conn, UInt16(remaining))
                flush(conn)
            else
                # Skip unknown message payload
                read(conn, header.payload_len)
                send_error(conn, ERR_CODE.invalid_message,
                           "Unknown message type: $(header.msg_type)")
            end
        end
    catch err
        if !(err isa EOFError || err isa Base.IOError || err isa InterruptException)
            @error "Worker error" exception=(err, catch_backtrace())
        end
    finally
        # Ensure clean exit - this handles cases where the conductor disconnects
        # or sends SIGINT during shutdown
        real_exit(0)
    end
end
