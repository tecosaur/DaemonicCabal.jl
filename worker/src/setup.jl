# SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
# SPDX-License-Identifier: MPL-2.0

# A running client: its task plus the streams to close to unwind it on teardown.
struct ClientTask
    task::Task
    streams::NTuple{4, StreamIO}  # stdin, stdout, stderr, signals
end

const STATE = (
    ctime = time(),
    worker_number = Ref(-1),
    clients = Vector{Tuple{Float64, ClientInfo}}(),
    client_tasks = Dict{Int, ClientTask}(),
    project = Ref(""),
    lastclient = Ref(time()),
    last_contact = Ref(time()),
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
PORT_BASE::Int = 0  # Base port for managed port range (from JULIA_DAEMON_PORTS)
ORPHAN_FAILSAFE::Int = 0  # seconds of conductor silence before self-exit (0 = off)

# Exiting

struct DaemonClientExit <: Exception code::Int end

real_exit(n::Int) = ccall(:jl_exit, Union{}, (Int32,), n)

# Revise

const REVISE_PKG =
    Base.PkgId(Base.UUID("295af30f-e4ad-537b-8983-00126c2a3abe"), "Revise")

function try_load_revise()
    get(ENV, "JULIA_DAEMON_REVISE", "no") ∈ ("yes", "true", "1", "") || return
    isdefined(Main, :Revise) && return
    if !isdefined(Main, :Revise) && !isnothing(Base.locate_package(REVISE_PKG))
        Core.eval(Main, :(using Revise))
    end
end

# Orphan failsafe: exit if the conductor has gone silent too long. Not an idle
# policy (the conductor owns that) — only fires when the conductor truly died
# without pdeathsig catching it (non-Linux, or an unclean crash). `last_contact`
# is refreshed on every conductor message (see runworker).

function queue_orphan_check()
    ORPHAN_FAILSAFE > 0 || return
    Timer(perform_orphan_check, ORPHAN_FAILSAFE; interval = ORPHAN_FAILSAFE)
end

function perform_orphan_check(::Timer)
    ORPHAN_FAILSAFE > 0 || return
    if time() - (@lock STATE.lock STATE.last_contact[]) >= ORPHAN_FAILSAFE
        real_exit(0)
    end
end

# On Linux, ask the kernel to SIGKILL us the moment our parent (the conductor)
# dies — the airtight orphan guard the coarse failsafe backstops elsewhere.
function set_parent_death_signal()
    @static if Sys.islinux()
        PR_SET_PDEATHSIG = Cint(1)
        @ccall prctl(PR_SET_PDEATHSIG::Cint, Base.SIGKILL::Culong, 0::Culong, 0::Culong, 0::Culong)::Cint
    end
end

# Kill client tasks the conductor no longer lists. Closing the client's streams
# makes the task unwind via EOF on its own thread — no cross-thread exception
# injection (which is fatal when the task runs on another interactive thread).
function kill_stuck_clients(active_pids::Set{Int})
    stuck = @lock STATE.lock [
        ct for (pid, ct) in STATE.client_tasks
        if pid ∉ active_pids && !istaskdone(ct.task)
    ]
    for ct in stuck, io in ct.streams
        try close(io) catch end
    end
    # Bounded wait: closing streams unwinds an I/O-blocked task, but a CPU-bound
    # one only dies to the conductor's SIGINT — don't freeze the message loop on it.
    deadline = time() + 2.0
    for ct in stuck
        while !istaskdone(ct.task) && time() < deadline
            sleep(0.01)
        end
    end
end

# Track a client's task + streams for interrupt/teardown, keyed by client pid.
function register_client!(pid::Int, task::Task, streams::StreamIO...)
    @lock STATE.lock STATE.client_tasks[pid] = ClientTask(task, streams)
end

# Active client's signals socket for the pre-1.11 path, which lacks the
# ScopedValues-based ACTIVE_TERM that carries it on newer versions. Set around the
# session in run.jl; read by the raw! override. The pre-1.11 redirect_stdio path is
# single-client (it redirects process-global stdio), so a plain Ref is sufficient.
@static if VERSION < v"1.11"
    const CLIENT_SIGNALS = Ref{Union{Nothing, StreamIO}}(nothing)
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
function set_project(project::String)
    resolved = if startswith(project, "@")
        Base.load_path_expand(project)
    elseif !isempty(project)
        abspath(expanduser(project))
    end
    Base.set_active_project(resolved)
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
        # Use a more compact filename on MacOS since it has a shorter max path length
        # and a deeper default runtime directory.
        sockfile = string(@static(if Sys.isapple() "w-" else "worker-" end),
                          WORKER_ID[], '-', String(rand('a':'z', 8)), ".sock")
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

# Handle disconnect of an interactive sync client: detach its streams from the
# session broadcast and unregister. The session (and its REPL) is kept alive for
# reattachment; the conductor drops it (drop_session) once the worker's expired
# label is reclaimed — by then the worker has been idle past JULIA_DAEMON_LABEL_TTL.
function sync_client_disconnect!(client::ClientInfo, client_stdin::StreamIO,
                                 client_stdout::StreamIO, client_stderr::StreamIO,
                                 signals::StreamIO, session::SyncSession)
    @lock STATE.lock begin
        filter!(s -> s !== client_stdout, session.out.writers)
        filter!(s -> s !== client_stderr, session.err.writers)
        filter!(s -> s !== signals, session.signals)
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
    unregister_client!(client)
end

# Tear down a session whose label the conductor has expired: end its REPL (close
# the merged-input pipe → EOF) and drop it from the registry.
function teardown_session!(label::String)
    session = @lock STATE.lock get(STATE.sync_sessions, label, nothing)
    isnothing(session) && return
    try close(session.writesink) catch end
    @lock STATE.lock delete!(STATE.sync_sessions, label)
end

# Echo -e/-E expressions to REPL observers via the session's stdout vectors.
function sync_echo_expressions(session::SyncSession, client::ClientInfo)
    for (switch, value) in client.switches
        suffix = if switch == "--eval" ";\n"
        elseif switch == "--print" "\n"
        else continue end
        write(session.out, "\r\e[2K\e[1;32mjulia>\e[m ", value, suffix)
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

# Look up the session for `label`, creating it (and attaching this client's
# output streams to the broadcast) if absent. Atomic under STATE.lock so two
# clients racing the same label can't both create one. `attach` adds the client
# to the broadcast writers — interactive clients observe the shared REPL; a
# non-interactive (-E) client renders its result itself, so it doesn't attach.
function get_or_create_session(label::String, client_stdout::StreamIO,
                               client_stderr::StreamIO, signals::StreamIO; attach::Bool)::SyncSession
    # Build outside the lock (link_pipe! can yield); install only if we won the race.
    fresh = build_sync_session(client_stdout, client_stderr, signals; attach)
    @lock STATE.lock begin
        session = get(STATE.sync_sessions, label, nothing)
        if isnothing(session)
            STATE.sync_sessions[label] = fresh
            return fresh
        end
        if attach
            push!(session.out.writers, client_stdout)
            push!(session.err.writers, client_stderr)
            push!(session.signals, signals)
            filter!(isopen, session.out.writers)
            filter!(isopen, session.err.writers)
            filter!(isopen, session.signals)
        end
        session
    end
end

function build_sync_session(client_stdout::StreamIO, client_stderr::StreamIO,
                            signals::StreamIO; attach::Bool)::SyncSession
    pipe = Pipe()
    Base.link_pipe!(pipe; reader_supports_async=true, writer_supports_async=true)
    history = OutputHistory(SYNC_HISTORY_BYTES)
    out = BroadcastWriter(StreamIO[], history)
    err = BroadcastWriter(StreamIO[], history)
    sigs = StreamIO[]
    if attach
        push!(out.writers, client_stdout)
        push!(err.writers, client_stderr)
        push!(sigs, signals)
    end
    SyncSession(pipe.out, pipe.in, out, err, sigs, history, Ref{REPL.LineEditREPL}())
end

# Render a value the way the REPL would (text/plain, size-limited) into the shared
# scrollback. No repl object needed — a -E-created session may not have one yet.
function display_result(io::IO, value)
    show(IOContext(io, :limit => true), MIME"text/plain"(), value)
    println(io)
end

function spawn_sync_client!(client::ClientInfo, client_stdin::StreamIO,
                            client_stdout::StreamIO, client_stderr::StreamIO,
                            signals::StreamIO, label::String)
    is_interactive = client.tty &&
        isnothing(client.programfile) &&
        !any(p -> first(p) ∈ ("--eval", "--print"), client.switches)
    session = get_or_create_session(label, client_stdout, client_stderr, signals;
                                    attach=is_interactive)
    if is_interactive
        spawn_interactive_sync_client!(client, client_stdin, client_stdout,
                                       client_stderr, signals, session)
    else
        spawn_eval_sync_client!(client, client_stdin, client_stdout,
                                client_stderr, signals, session)
    end
end

# Interactive sync client: drive the shared REPL, starting it the first time the
# session gains a REPL. The starter defers its history replay to the atreplinit
# hook (post-banner, via REPLAY_TARGET); a later joiner replays inline.
function spawn_interactive_sync_client!(client::ClientInfo, client_stdin::StreamIO,
                                        client_stdout::StreamIO, client_stderr::StreamIO,
                                        signals::StreamIO, session::SyncSession)
    if isassigned(session.repl)
        # Joining a live REPL: replay scrollback, announce raw mode, reposition the
        # cursor so the REPL's refresh lands correctly on this fresh terminal.
        height = first(query_displaysize(signals))
        maxlines = 3 * if iszero(height) 24 else height end
        replay_history(client_stdout, session.history; maxlines)
        send_signal(signals, SIGNAL_RAW_MODE, UInt8[true])
        read(signals, 2)
        if session.repl[].mistate !== nothing
            let mi = session.repl[].mistate::REPL.LineEdit.MIState
                ps = mi.mode_state[mi.current_mode]::REPL.LineEdit.PromptState
                write(client_stdout, "\n" ^ (ps.ias.curs_row - 1))
                put!(mi.async_channel, s -> (REPL.LineEdit.refresh_line(s); :ok))
            end
        end
    else
        # First REPL: run the shared REPL frontend on this client, replaying prior
        # scrollback after the banner (REPLAY_TARGET → atreplinit hook).
        Threads.@spawn :interactive try
            runclient(client, session.mergedin, session.out, session.err, signals;
                      owned_streams=(), sync_session=session, repl_ref=session.repl,
                      replay=(client_stdout, session))
        catch end
    end
    task = Threads.@spawn begin
        stdin_copy_loop(client_stdin, session.writesink; intercept_eof=true)
        sync_client_disconnect!(client, client_stdin, client_stdout,
                                client_stderr, signals, session)
    end
    register_client!(client.pid, task, client_stdin, client_stdout, client_stderr, signals)
end

# Non-interactive (-E / --eval) sync client: run against the session broadcast so
# evaluated output lands in history (and any attached clients). The result is shown
# plainly to the -E client's own terminal and REPL-style into the shared scrollback.
function spawn_eval_sync_client!(client::ClientInfo, client_stdin::StreamIO,
                                 client_stdout::StreamIO, client_stderr::StreamIO,
                                 signals::StreamIO, session::SyncSession)
    has_repl = isassigned(session.repl) && session.repl[].mistate !== nothing
    task = Threads.@spawn :interactive begin
        clear_repl_input(session, has_repl)
        sync_echo_expressions(session, client)
        try
            # Result + incidental output go to this client; the result is also
            # broadcast REPL-style to the shared scrollback (other clients + history).
            runclient(client, client_stdin, client_stdout, client_stderr, signals;
                      broadcast=session.out)
        catch
            isopen(client_stdout) && rethrow()
        end
        write(session.out, "\n")
        restore_repl_prompt(session, has_repl)
    end
    register_client!(client.pid, task, client_stdin, client_stdout, client_stderr, signals)
end

# Clear the in-progress REPL input line so eval output starts on a clean row.
function clear_repl_input(session::SyncSession, has_repl::Bool)
    has_repl || return
    let mi = session.repl[].mistate::REPL.LineEdit.MIState
        ps = mi.mode_state[mi.current_mode]::REPL.LineEdit.PromptState
        write(session.out, ps.ias.curs_row > 1 ? "\e[$(ps.ias.curs_row - 1)A\e[J" : "\e[J")
        ps.ias = REPL.LineEdit.InputAreaState(0, 0)
    end
end

# Redraw the REPL prompt below freshly-written eval output (or nudge a redraw
# through the merged-input pipe when no live REPL is attached yet).
function restore_repl_prompt(session::SyncSession, has_repl::Bool)
    if has_repl
        let mi = session.repl[].mistate::REPL.LineEdit.MIState
            put!(mi.async_channel, s -> (REPL.LineEdit.refresh_line(s); :ok))
        end
    else
        try write(session.writesink, " \x7f") catch end
    end
end

function unregister_client!(client::ClientInfo)
    exiting = @lock STATE.lock begin
        idx = findfirst(e -> last(e) === client, STATE.clients)
        !isnothing(idx) && deleteat!(STATE.clients, idx)
        delete!(STATE.client_tasks, client.pid)
        STATE.lastclient[] = time()
        STATE.soft_exit[] && isempty(STATE.clients)
    end
    send_notification(STATE.conductor_socket[], NOTIF_TYPE.client_done,
                      UInt32(client.pid))
    exiting && real_exit(0)
    ensure_standby_sockets()
    ensure_standby_module()
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
    client_stdin, client_stdout, client_stderr, signals = try
        accept(stdin_srv), accept(stdout_srv), accept(stderr_srv), accept(signals_srv)
    catch
        @lock STATE.lock filter!(e -> last(e) !== client, STATE.clients)
        rethrow()
    finally
        foreach(close, (stdin_srv, stdout_srv, stderr_srv, signals_srv))
    end
    if is_tcp
        Sockets.nagle(signals, false)
        if time_ns() - t0 < 40_000_000
            Sockets.nagle(client_stdout, false)
            Sockets.nagle(client_stderr, false)
            send_signal(signals, SIGNAL_NODELAY, UInt8[])
        end
    end
    label = sync_session_label(client)
    if isnothing(label)
        task = Threads.@spawn :interactive try
            runclient(client, client_stdin, client_stdout, client_stderr, signals)
        catch
            isopen(client_stdout) && rethrow()
        end
        register_client!(client.pid, task, client_stdin, client_stdout, client_stderr, signals)
    else
        spawn_sync_client!(client, client_stdin, client_stdout, client_stderr, signals, label)
    end
end

# Dispatch one conductor message. A client is interrupted purely via the
# process SIGINT the conductor sends (Julia's force-throw breaks the running
# task); there is no separate interrupt message.
function serve_message(conn::IO, header::MessageHeader)
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
        client = read_client_run(conn)
        active_count, draining = @lock STATE.lock (length(STATE.clients), STATE.soft_exit[])
        # force bypasses capacity (labeled sessions) but never the drain.
        if draining || (!client.force && MAX_CLIENTS > 0 && active_count >= MAX_CLIENTS)
            send_sockets(conn, "", "", "", "", active_count)  # reject: empty paths + count
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
    elseif header.msg_type == MSG_TYPE.query_clients
        pids = @lock STATE.lock Int[last(e).pid for e in STATE.clients]
        write_header(conn, MSG_TYPE.clients, 2 + 4 * length(pids))
        write(conn, UInt16(length(pids)))
        for pid in pids
            write(conn, UInt32(pid))
        end
        flush(conn)
    elseif header.msg_type == MSG_TYPE.drop_session
        teardown_session!(read_string(conn))
    else
        read(conn, header.payload_len)  # skip unknown payload
        send_error(conn, ERR_CODE.invalid_message,
                   "Unknown message type: $(header.msg_type)")
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
    global RUNTIME_DIR = if is_tcp_address(STATE.conductor_socket[]) "" else dirname(socketpath) end
    global MAX_CLIENTS = parse(Int, get(ENV, "JULIA_DAEMON_WORKER_MAXCLIENTS", "1"))
    max_ttl = parse(Int, get(ENV, "JULIA_DAEMON_MAX_TTL",
                             get(ENV, "JULIA_DAEMON_WORKER_TTL", "7200")))
    global ORPHAN_FAILSAFE = max_ttl > 0 ? max_ttl * 4 : 0
    global PORT_BASE = if haskey(ENV, "JULIA_DAEMON_PORTS")
        parse(Int, split(ENV["JULIA_DAEMON_PORTS"], '-')[1])
    else 0 end
    set_parent_death_signal()
    queue_orphan_check()
    ensure_standby_sockets()
    ensure_standby_module()
    errormonitor(Threads.@spawn warm_repl_path())
    exit_code = 0
    try
        verify_magic(conn)
        while isopen(conn)
            # A trailing force-thrown SIGINT (from interrupting a client's tight
            # loop) can land anywhere in an iteration after the client task ended.
            # Swallow it and keep serving — only conductor disconnect / soft_exit
            # ends the worker.
            try
                header = read_header(conn)
                @lock STATE.lock STATE.last_contact[] = time()
                serve_message(conn, header)
            catch err
                err isa InterruptException || rethrow()
            end
        end
    catch err
        # Conductor disconnect is a clean end; anything else is a worker fault.
        if !(err isa EOFError || err isa Base.IOError || err isa InterruptException)
            @error "Worker error" exception=(err, catch_backtrace())
            exit_code = 1
        end
    finally
        real_exit(exit_code)
    end
end
