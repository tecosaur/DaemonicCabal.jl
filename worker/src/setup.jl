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
    standby_sockets = Ref{Union{Nothing, NTuple{2, Pair{Sockets.PipeServer, String}}}}(nothing),
    standby_module = Ref{Union{Nothing, Module}}(nothing))

# Configuration (set during runworker from environment)
RUNTIME_DIR::String = ""
MAX_CLIENTS::Int = 1
WORKER_TTL::Int = 0

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
        send_worker_exit(STATE.conductor_socket[])
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

# Basically a bootleg version of `exec_options`.
# Note: client is already registered in STATE.clients before this is called
const SIGNAL_EXIT = 0x01
const SIGNAL_RAW_MODE = 0x02   # data: 0x00 = cooked, 0x01 = raw
const SIGNAL_QUERY_SIZE = 0x03 # response: height(u16) + width(u16)

function send_signal(io::IO, id::UInt8, data::Vector{UInt8})
    write(io, id, UInt16(length(data)), data)
end

# Copied from `init_active_project()` in `base/initdefs.jl`.
function set_project(project)
    Base.set_active_project(
        project === nothing ? nothing :
        project == "" ? nothing :
        startswith(project, "@") ? load_path_expand(project) :
        abspath(expanduser(project)))
end

# Worker management

function create_socket()::Pair{Sockets.PipeServer, String}
    sockfile = string("worker-", WORKER_ID[], '-', String(rand('a':'z', 8)), ".sock")
    path = joinpath(RUNTIME_DIR, sockfile)
    Sockets.listen(path) => path
end

# Get sockets for a new client, using standby if available
function get_client_sockets()::NTuple{2, Pair{Sockets.PipeServer, String}}
    sockets = @lock STATE.lock begin
        s = STATE.standby_sockets[]
        STATE.standby_sockets[] = nothing
        s
    end
    isnothing(sockets) ? (create_socket(), create_socket()) : sockets
end

# Ensure standby sockets exist (called after client disconnect or on startup)
function ensure_standby_sockets()
    @lock STATE.lock begin
        if isnothing(STATE.standby_sockets[])
            STATE.standby_sockets[] = (create_socket(), create_socket())
        end
    end
end

function runworker(socketpath::String, worker_number::Int=-1)
    # Disable Julia's default SIGINT handling which throws uncatchable InterruptException
    # This allows us to exit cleanly when the conductor shuts down
    Base.exit_on_sigint(false)
    conn = Sockets.connect(socketpath)
    STATE.conductor_conn[] = conn
    # Configuration from environment
    STATE.worker_number[] = worker_number
    global RUNTIME_DIR = dirname(socketpath)
    global MAX_CLIENTS = parse(Int, get(ENV, "JULIA_DAEMON_WORKER_MAXCLIENTS", "1"))
    global WORKER_TTL = parse(Int, get(ENV, "JULIA_DAEMON_WORKER_TTL", "0"))
    STATE.conductor_socket[] = joinpath(RUNTIME_DIR, "conductor.sock")
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
                project = read_set_project(conn, header.payload_len)
                try
                    set_project(project)
                    STATE.project[] = project
                    send_project_ok(conn)
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
                    send_sockets(conn, "", "", active_count)
                else
                    try
                        (stdio_server, stdio_path), (signals_server, signals_path) = get_client_sockets()
                        # Register client and get count (before sending response)
                        active_count = @lock STATE.lock begin
                            push!(STATE.clients, (time(), client))
                            length(STATE.clients)
                        end
                        send_sockets(conn, stdio_path, signals_path, active_count)
                        # Accept connections and spawn client handler
                        stdio = accept(stdio_server)
                        signals = accept(signals_server)
                        # Clean up server sockets (paths remain for client to connect)
                        close(stdio_server)
                        close(signals_server)
                        task = Threads.@spawn try
                            runclient(client, stdio, signals)
                        catch
                            isopen(stdio) && rethrow()
                        end
                        @lock STATE.lock STATE.client_tasks[client.pid] = task
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
                send_ack(conn, remaining)
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
