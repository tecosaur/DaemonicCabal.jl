# SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
# SPDX-License-Identifier: MPL-2.0

struct ClientTask
    task::Task
    streams::NTuple{4, StreamIO}  # stdin, stdout, stderr, signals
end

const STATE = (
    clients = Vector{ClientInfo}(),
    client_tasks = Dict{Int, ClientTask}(),
    lastclient = Ref(time()),
    last_contact = Ref(time()),
    lock = SpinLock(),
    soft_exit = Ref(false),
    conductor_socket = Ref(""),
    standby_sockets = Ref{Union{Nothing, NTuple{4, Pair{Union{Sockets.PipeServer, Sockets.TCPServer}, String}}}}(nothing),
    standby_module = Ref{Union{Nothing, Module}}(nothing),
    sync_sessions = Dict{String, SyncSession}())

# Configuration, set by `runworker`
RUNTIME_DIR::String = ""
MAX_CLIENTS::Int = 1
PORT_BASE::Int = 0
ORPHAN_FAILSAFE::Int = 0  # seconds; 0 = off
HISTORY_BYTES::Int = 1 << 20  # per session transcript
# Which sessions record from their start; --sync ones always do, and any from its first watch.
@enum RecordLevel record_sync record_interactive record_session
RECORD_LEVEL::RecordLevel = record_session

# "64K", "1M" and the like, or plain bytes; at most 4G, as records carry a UInt32 length.
function history_bytes(value::AbstractString)
    scale = if isempty(value) nothing else findfirst(==(uppercase(last(value))), "KMG") end
    n = tryparse(Int, if isnothing(scale) value else chop(value) end)
    if isnothing(n) || n < 0
        @warn "Ignoring JULIA_DAEMON_HISTORY_BYTES=$value, which should be bytes, optionally with K, M or G"
        return HISTORY_BYTES
    end
    min(n << (10 * something(scale, 0)), typemax(UInt32))
end

function record_level(value::AbstractString)
    for level in instances(RecordLevel)
        value == chopprefix(string(level), "record_") && return level
    end
    @warn "Ignoring JULIA_DAEMON_RECORD=$value, which should be sync, interactive or session"
    RECORD_LEVEL
end

# A switch or variable given with no value counts as yes.
isyes(value::AbstractString) = value ∈ ("yes", "true", "1", "")

# Exiting

struct DaemonClientExit <: Exception code::Int end

real_exit(n::Int) = ccall(:jl_exit, Union{}, (Int32,), n)

# Revise

const REVISE_PKG =
    Base.PkgId(Base.UUID("295af30f-e4ad-537b-8983-00126c2a3abe"), "Revise")

# The warning reaches the logger in scope: the conductor's log at startup, the client in a run.
function load_revise()
    isdefined(Main, :Revise) && return true
    if isnothing(Base.locate_package(REVISE_PKG))
        @warn "Running without Revise, which is not installed" _module=nothing _file=nothing
        return false
    end
    try
        Core.eval(Main, :(using Revise))
        true
    catch err
        @warn "Running without Revise, which failed to load" exception=err _module=nothing _file=nothing
        false
    end
end

wants_revise(client::ClientInfo) = isyes(getval(client.switches, "--revise",
    getval(client.env, "JULIA_DAEMON_REVISE", get(ENV, "JULIA_DAEMON_REVISE", "no"))))

# Staleness: a reused worker must not run code that differs from what is on
# disk, as a fresh `julia` never would.

const STALENESS = (
    lock = ReentrantLock(),
    manifests = Dict{String, Float64}(),  # path => mtime when first loaded from
    sources = Dict{String, Float64}())    # dev'd packages' files

# A `package_callbacks` hook. Stdlibs ship with Julia, and registered packages
# sit in a depot's `packages/`, which never changes.
function record_package_sources(id::Base.PkgId)
    origin = get(Base.pkgorigins, id, nothing)
    (isnothing(origin) || isnothing(origin.path)) && return
    (Base.in_sysimage(id) || startswith(origin.path, Sys.STDLIB)) && return
    manifests = filter!(!isnothing, [Base.project_file_manifest_path(p) for p in Base.load_path() if isfile(p)])
    registered = any(d -> startswith(origin.path, joinpath(d, "packages", "")), DEPOT_PATH)
    files = if registered String[] else package_files(origin) end
    @lock STALENESS.lock begin
        for m in manifests get!(() -> mtime(m), STALENESS.manifests, m) end
        for f in files STALENESS.sources[f] = mtime(f) end
    end
end

# The precompile cache lists what the package included; without one, its tree.
function package_files(origin::Base.PkgOrigin)
    if !isnothing(origin.cachepath)
        try
            return [inc.filename for inc in Base.parse_cache_header(origin.cachepath)[2][1]]
        catch
        end
    end
    [joinpath(dir, f) for (dir, _, fs) in walkdir(dirname(origin.path)) for f in fs if endswith(f, ".jl")]
end

# Revise applies source edits itself, but not a changed manifest.
function stale_files(client::ClientInfo)
    @lock STALENESS.lock begin
        changed = [m for (m, t) in STALENESS.manifests if mtime(m) != t]
        wants_revise(client) || append!(changed, (f for (f, t) in STALENESS.sources if mtime(f) != t))
        changed
    end
end

# Orphan failsafe, for a conductor death pdeathsig misses (non-Linux, unclean crash).

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

function set_parent_death_signal()
    @static if Sys.islinux()
        PR_SET_PDEATHSIG = Cint(1)
        @ccall prctl(PR_SET_PDEATHSIG::Cint, Base.SIGKILL::Culong, 0::Culong, 0::Culong, 0::Culong)::Cint
    end
end

# Closing streams unwinds a task blocked on them, but not one looping on
# other waits (`sleep`, timers), which needs the exception injected.
function kill_stuck_clients(active_ids::Set{Int})
    stuck = @lock STATE.lock [
        ct for (id, ct) in STATE.client_tasks
        if id ∉ active_ids && !istaskdone(ct.task)
    ]
    for ct in stuck, io in ct.streams
        try close(io) catch end
    end
    for ct in stuck
        # Injecting into a task on another thread is fatal.
        Threads.threadid(ct.task) == Threads.threadid() || continue
        try schedule(ct.task, InterruptException(); error=true) catch end
    end
    # A CPU-bound task only dies to the conductor's SIGINT, so bound the wait.
    deadline = time() + 2.0
    for ct in stuck
        while !istaskdone(ct.task) && time() < deadline
            sleep(0.01)
        end
    end
end

function register_client!(id::Int, task::Task, streams::StreamIO...)
    @lock STATE.lock STATE.client_tasks[id] = ClientTask(task, streams)
end

# Pre-1.11 stand-in for ACTIVE_TERM's signals; that path is single-client.
@static if VERSION < v"1.11"
    const CLIENT_SIGNALS = Ref{Union{Nothing, StreamIO}}(nothing)
end

# Signal protocol (Worker → Client)
const SIGNAL_EXIT = 0x01
const SIGNAL_RAW_MODE = 0x02   # data: 0x00 = cooked, 0x01 = raw
const SIGNAL_QUERY_SIZE = 0x03 # response: height(u16) + width(u16)
const SIGNAL_NODELAY = 0x04    # disable Nagle on stdin + signals
const SIGNAL_EXECUTING = 0x05  # data: 0x00 = at prompt, 0x01 = evaluating

# One write per frame: a multi-argument `write` yields between arguments, so
# concurrent senders could interleave mid-frame.
function send_signal(io::IO, id::UInt8, data::Vector{UInt8})
    frame = Vector{UInt8}(undef, 2 + length(data))
    frame[1], frame[2] = id, length(data)
    copyto!(frame, 3, data)
    write(io, frame)
end

"""
    signal_executing(executing::Bool)

Tell the active client whether user code is evaluating, so it can route Ctrl-C.
Raw mode cannot stand in: LineEdit holds the terminal raw across evaluation.
"""
@static if VERSION >= v"1.11"
    function signal_executing(executing::Bool)
        term = ACTIVE_TERM[]
        isnothing(term.sync_session) || return
        # Outside a client session this is WORKER_TERM, whose pipe is never opened.
        isopen(term.signals) || return
        # `isopen` lags a peer close, so a client leaving mid-evaluation throws here.
        try send_signal(term.signals, SIGNAL_EXECUTING, UInt8[executing])
        catch err
            err isa Base.IOError || rethrow()
        end
    end
else
    function signal_executing(executing::Bool)
        sig = CLIENT_SIGNALS[]
        isnothing(sig) && return
        isopen(sig) || return
        try send_signal(sig, SIGNAL_EXECUTING, UInt8[executing])
        catch err
            err isa Base.IOError || rethrow()
        end
    end
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
        bind_host = get(() -> first(split_host_port(STATE.conductor_socket[])), ENV, "JULIA_DAEMON_BIND")
        server = Sockets.listen(resolve_host(bind_host), port)
        _, actual_port = Sockets.getsockname(server)
        # The client dials the conductor's host; a bind address like 0.0.0.0 would fail remotely.
        server => ":$(actual_port)"
    else
        # macOS has a shorter socket path limit and a deeper runtime directory.
        sockfile = string(@static(if Sys.isapple() "w-" else "worker-" end),
                          WORKER_ID[], '-', String(rand('a':'z', 8)), ".sock")
        path = joinpath(RUNTIME_DIR, sockfile)
        Sockets.listen(path) => path
    end
end

const PORT_SET_NONE = 0xFFFF

function get_client_sockets(port_set::Int)::NTuple{4, Pair{Union{Sockets.PipeServer, Sockets.TCPServer}, String}}
    if port_set != PORT_SET_NONE
        return ntuple(i -> create_socket(PORT_BASE + 4port_set + i - 1), 4)
    end
    sockets = @lock STATE.lock begin
        s = STATE.standby_sockets[]
        STATE.standby_sockets[] = nothing
        s
    end
    if isnothing(sockets) ntuple(_ -> create_socket(), 4) else sockets end
end
# None with a managed port range: the port set is unknown until `client_run`.
function ensure_standby_sockets()
    PORT_BASE > 0 && return
    @lock STATE.lock begin
        if isnothing(STATE.standby_sockets[])
            STATE.standby_sockets[] = ntuple(_ -> create_socket(), 4)
        end
    end
end

function sync_session_label(client::ClientInfo)
    any(p -> first(p) == "--sync", client.switches) || return nothing
    idx = findfirst(p -> first(p) == "--session", client.switches)
    isnothing(idx) && return nothing
    label = last(client.switches[idx])
    if !isempty(label) label end
end

# The session and its REPL outlive the client for reattachment, until the
# conductor sends `drop_session` for its expired label.
function sync_client_disconnect!(client::ClientInfo, client_stdin::StreamIO,
                                 client_stdout::StreamIO, client_stderr::StreamIO,
                                 signals::StreamIO, session::SyncSession)
    @lock STATE.lock begin
        filter!(s -> s !== client_stdout, session.out.writers)
        filter!(s -> s !== client_stderr, session.err.writers)
        filter!(s -> s !== signals, session.signals)
    end
    # The terminal is raw, so end the line ourselves.
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

# Closing the merged input ends the session's REPL.
function teardown_session!(label::String)
    drop_transcript!(label)
    session = @lock STATE.lock get(STATE.sync_sessions, label, nothing)
    isnothing(session) && return
    try close(session.writesink) catch end
    @lock STATE.lock delete!(STATE.sync_sessions, label)
end

function sync_echo_expressions(session::SyncSession, client::ClientInfo)
    for (switch, value) in client.switches
        suffix = if switch == "--eval" ";\n"
        elseif switch == "--print" "\n"
        else continue end
        write(session.out, "\r\e[2K\e[1;32mjulia>\e[m ", value, suffix)
    end
end

# Under `intercept_eof`, Ctrl-D detaches this client rather than ending the shared REPL.
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

# A non-interactive (-E) client renders its own result, so it doesn't `attach`.
function get_or_create_session(label::String, client_stdout::StreamIO,
                               client_stderr::StreamIO, signals::StreamIO; attach::Bool)::SyncSession
    # Build outside the lock (link_pipe! can yield); install only if we won the race.
    fresh = build_sync_session(label, client_stdout, client_stderr, signals; attach)
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

# A sync session is always recorded: a joiner is replayed its screen.
function build_sync_session(label::String, client_stdout::StreamIO, client_stderr::StreamIO,
                            signals::StreamIO; attach::Bool)::SyncSession
    pipe = Pipe()
    Base.link_pipe!(pipe; reader_supports_async=true, writer_supports_async=true)
    start_recording!(session_transcript(label))
    screen = begin_run(label, "--sync")
    out = BroadcastWriter(StreamIO[], screen, :stdout)
    err = BroadcastWriter(StreamIO[], screen, :stderr)
    sigs = StreamIO[]
    if attach
        push!(out.writers, client_stdout)
        push!(err.writers, client_stderr)
        push!(sigs, signals)
    end
    SyncSession(pipe.out, pipe.in, out, err, sigs, screen, Ref{REPL.LineEditREPL}())
end

# REPL-style without a repl object, which an -E-created session may lack.
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

# The REPL's starter replays history after the banner (REPLAY_TARGET); a joiner
# replays inline.
function spawn_interactive_sync_client!(client::ClientInfo, client_stdin::StreamIO,
                                        client_stdout::StreamIO, client_stderr::StreamIO,
                                        signals::StreamIO, session::SyncSession)
    if isassigned(session.repl)
        # Reposition the cursor so the REPL's refresh lands right on a fresh terminal.
        height = first(query_displaysize(signals))
        maxlines = 3 * height
        replay_history(client_stdout, session.screen; maxlines)
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
        @async try # thread 0 for Ctrl-C; see `spawn_client!`
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
    register_client!(client.id, task, client_stdin, client_stdout, client_stderr, signals)
end

# The result goes plainly to this client and REPL-style to the shared scrollback.
function spawn_eval_sync_client!(client::ClientInfo, client_stdin::StreamIO,
                                 client_stdout::StreamIO, client_stderr::StreamIO,
                                 signals::StreamIO, session::SyncSession)
    has_repl = isassigned(session.repl) && session.repl[].mistate !== nothing
    task = @async begin # thread 0 for Ctrl-C; see `spawn_client!`
        clear_repl_input(session, has_repl)
        sync_echo_expressions(session, client)
        try
            runclient(client, client_stdin, client_stdout, client_stderr, signals;
                      broadcast=session.out)
        catch
            isopen(client_stdout) && rethrow()
        end
        write(session.out, "\n")
        restore_repl_prompt(session, has_repl)
    end
    register_client!(client.id, task, client_stdin, client_stdout, client_stderr, signals)
end

function clear_repl_input(session::SyncSession, has_repl::Bool)
    has_repl || return
    let mi = session.repl[].mistate::REPL.LineEdit.MIState
        ps = mi.mode_state[mi.current_mode]::REPL.LineEdit.PromptState
        write(session.out, ps.ias.curs_row > 1 ? "\e[$(ps.ias.curs_row - 1)A\e[J" : "\e[J")
        ps.ias = REPL.LineEdit.InputAreaState(0, 0)
    end
end

# Without a live REPL, nudge a redraw through the merged input.
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
    idle = @lock STATE.lock begin
        idx = findfirst(c -> c === client, STATE.clients)
        !isnothing(idx) && deleteat!(STATE.clients, idx)
        delete!(STATE.client_tasks, client.id)
        STATE.lastclient[] = time()
        isempty(STATE.clients)
    end
    send_notification(STATE.conductor_socket[], NOTIF_TYPE.client_done,
                      UInt32(client.id))
    idle && STATE.soft_exit[] && real_exit(0)
    ensure_standby_sockets()
    ensure_standby_module()
    # An idle worker allocates nothing, so no collection would free the run's garbage.
    idle && Timer(_ -> (@lock STATE.lock isempty(STATE.clients)) && GC.gc(true), IDLE_COLLECT_DELAY_S)
end

const CLIENT_ACCEPT_TIMEOUT_S = 30.0
const IDLE_COLLECT_DELAY_S = 0.5
const TCP_KEEPALIVE_IDLE_S = 60

# A bare `accept` would stall pings on a client that died after getting its
# paths. Only the named client may connect (`pid` as our kernel reports it;
# 0 = any): anything reaching the runtime dir could take over the terminal.
function accept_client_sockets(servers, pid::Integer)
    want = expected_peer(pid)
    deadline = Timer(_ -> foreach(close, servers), CLIENT_ACCEPT_TIMEOUT_S)
    try
        map(servers) do srv
            while true
                sock = accept(srv)
                peer = peer_pid(sock)
                (pid == 0 || isnothing(peer) || peer == want) && return sock
                @warn "Dropped a client socket connection from an unexpected process" expected=want actual=peer
                close(sock)
            end
        end
    catch
        isopen(deadline) && rethrow()
        throw(ErrorException("client did not connect within $(CLIENT_ACCEPT_TIMEOUT_S)s"))
    finally
        close(deadline)
    end
end

# SO_PEERCRED reports the client's pid within our pid namespace, or 0 from outside
# it. A conductor-sandboxed worker is init of its own namespace with its client
# outside; a client-spawned worker shares its client's, so there 0 is an outsider.
expected_peer(pid) = getpid() == 1 ? 0 : pid

# `nothing` where the platform offers no credentials (TCP, non-Linux).
@static if Sys.islinux()
    function peer_pid(sock)
        sock isa Sockets.TCPSocket && return nothing
        cred = Ref((Cint(0), Cuint(0), Cuint(0)))  # struct ucred: pid, uid, gid
        len = Ref{Cuint}(sizeof(cred[]))
        SOL_SOCKET, SO_PEERCRED = 1, 17
        rc = ccall(:getsockopt, Cint, (Cint, Cint, Cint, Ptr{Cvoid}, Ptr{Cuint}),
                   Base._fd(sock), SOL_SOCKET, SO_PEERCRED, cred, len)
        rc == 0 ? Int(cred[][1]) : nothing
    end
else
    peer_pid(::Any) = nothing
end

function spawn_client!(conn::IO, client::ClientInfo, replied::Ref{Bool})
    (stdin_srv, stdin_path), (stdout_srv, stdout_path),
        (stderr_srv, stderr_path), (signals_srv, signals_path) = get_client_sockets(client.port_set)
    active_count = @lock STATE.lock begin
        push!(STATE.clients, client)
        length(STATE.clients)
    end
    send_sockets(conn, stdin_path, stdout_path, stderr_path, signals_path, active_count)
    replied[] = true
    is_tcp = stdin_srv isa Sockets.TCPServer
    t0 = time_ns()
    client_stdin, client_stdout, client_stderr, signals = try
        accept_client_sockets((stdin_srv, stdout_srv, stderr_srv, signals_srv), client.pid)
    catch
        @lock STATE.lock filter!(c -> c !== client, STATE.clients)
        # Or the conductor keeps counting it, port set and all.
        send_notification(STATE.conductor_socket[], NOTIF_TYPE.client_done, UInt32(client.id))
        rethrow()
    finally
        foreach(close, (stdin_srv, stdout_srv, stderr_srv, signals_srv))
    end
    if is_tcp
        # A client gone without closing would otherwise hold its session forever.
        for sock in (client_stdin, client_stdout, client_stderr, signals)
            ccall(:uv_tcp_keepalive, Cint, (Ptr{Cvoid}, Cint, Cuint), sock.handle, 1, TCP_KEEPALIVE_IDLE_S)
        end
        Sockets.nagle(signals, false)
        if time_ns() - t0 < 40_000_000
            Sockets.nagle(client_stdout, false)
            Sockets.nagle(client_stderr, false)
            send_signal(signals, SIGNAL_NODELAY, UInt8[])
        end
    end
    label = sync_session_label(client)
    if isnothing(label)
        # @async, not Threads.@spawn: jl_try_deliver_sigint only ever targets
        # thread 0, so a client task anywhere else can never be Ctrl-C'd.
        task = @async try
            runclient(client, client_stdin, client_stdout, client_stderr, signals)
        catch
            isopen(client_stdout) && rethrow()
        end
        register_client!(client.id, task, client_stdin, client_stdout, client_stderr, signals)
    else
        spawn_sync_client!(client, client_stdin, client_stdout, client_stderr, signals, label)
    end
end

# Clients are interrupted by the conductor's SIGINT alone; there is no message.
function serve_message(conn::IO, header::MessageHeader)
    if header.msg_type == MSG_TYPE.ping
        seq = read(conn, UInt8)
        active = @lock STATE.lock length(STATE.clients)
        send_pong(conn, seq, active)
    elseif header.msg_type == MSG_TYPE.set_project
        project = read_string(conn)
        try
            set_project(project)
            write_header(conn, MSG_TYPE.project_ok, 0)
            flush(conn)
        catch err
            send_error(conn, ERR_CODE.project_not_found,
                       "Failed to set project: $(sprint(showerror, err))")
        end
    elseif header.msg_type == MSG_TYPE.client_run
        client = read_client_run(conn)
        @static if VERSION >= v"1.11"
            WORKER_TERM.have_color = client.color  # our own stdio is piped
        end
        # A watcher takes no capacity, but the reply's count, which the conductor
        # keeps, includes them.
        active_count, working, draining = @lock STATE.lock (
            length(STATE.clients),
            count(c -> isnothing(getval(c.switches, "--watch", nothing)), STATE.clients),
            STATE.soft_exit[])
        # force bypasses capacity (labelled sessions, watchers) but never the drain.
        stale = stale_files(client)
        if draining || (!client.force && MAX_CLIENTS > 0 && working >= MAX_CLIENTS)
            send_sockets(conn, "", "", "", "", active_count)  # reject: empty paths + count
        elseif !isempty(stale) && !client.force
            # The conductor retires this worker and starts a fresh one.
            send_error(conn, ERR_CODE.stale_code, "changed on disk since loaded: " * join(stale, ", "))
        else
            replied = Ref(false)
            try
                spawn_client!(conn, client, replied)
            catch err
                # `sockets` is a complete reply; a trailing `err` would be read as
                # the next message header and desync the stream for good.
                replied[] || send_error(conn, ERR_CODE.internal_error,
                                        "Failed to start client: $(sprint(showerror, err))")
                @error "Failed to start client" exception=(err, catch_backtrace())
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
        id_count = read(conn, UInt16)
        active_ids = Set{Int}()
        for _ in 1:id_count
            push!(active_ids, Int(read(conn, UInt32)))
        end
        kill_stuck_clients(active_ids)
        remaining = @lock STATE.lock length(STATE.clients)
        write_header(conn, MSG_TYPE.ack, 2)
        write(conn, UInt16(remaining))
        flush(conn)
    elseif header.msg_type == MSG_TYPE.query_clients
        ids = @lock STATE.lock Int[c.id for c in STATE.clients]
        write_header(conn, MSG_TYPE.clients, 2 + 4 * length(ids))
        write(conn, UInt16(length(ids)))
        for id in ids
            write(conn, UInt32(id))
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

function runworker(socketpath::String, conductor_address::String)
    Base.exit_on_sigint(false)
    conn = connect_to(socketpath)
    STATE.conductor_socket[] = conductor_address
    global RUNTIME_DIR = if is_tcp_address(STATE.conductor_socket[]) "" else dirname(socketpath) end
    global MAX_CLIENTS = parse(Int, get(ENV, "JULIA_DAEMON_WORKER_MAXCLIENTS", "1"))
    max_ttl = parse(Int, get(ENV, "JULIA_DAEMON_MAX_TTL",
                             get(ENV, "JULIA_DAEMON_WORKER_TTL", "7200")))
    global ORPHAN_FAILSAFE = max_ttl > 0 ? max_ttl * 4 : 0
    global HISTORY_BYTES = history_bytes(get(ENV, "JULIA_DAEMON_HISTORY_BYTES", "1M"))
    global RECORD_LEVEL = record_level(get(ENV, "JULIA_DAEMON_RECORD", "session"))
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
            # A client's Ctrl-C may land on this task.
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
        if !(err isa EOFError || err isa Base.IOError)
            @error "Worker error" exception=(err, catch_backtrace())
            exit_code = 1
        end
    finally
        real_exit(exit_code)
    end
end
