const SOCKET_NAME = "conductor.sock"
const MAIN_SOCKET = Ref{String}()

function mainsocket()
    if isassigned(MAIN_SOCKET)
        MAIN_SOCKET[]
    else
        path = get(
            ENV, "JULIA_DAEMON_SERVER",
            BaseDirs.runtime(RUNTIME_DIR, SOCKET_NAME))
        file = if startswith(path, '/') # Absolute socket file
            path
        elseif startswith(path, '~') # User-local socket file
            expanduser(path)
        end
        if !isnothing(file) && ispath(file)
            if startswith(file, BaseDirs.runtime(RUNTIME_DIR))
                rm(BaseDirs.runtime(RUNTIME_DIR), recursive=true)
            else
                rm(file)
            end
        end
        MAIN_SOCKET[] = something(file, path)
    end
end

"""
    create_server(socket)

Create a server socket based on the socket path/address format.
Returns a `PipeServer` for Unix sockets or `TCPServer` for network addresses.
"""
function create_server(socket::AbstractString)
    if startswith(socket, '/')
        isdir(dirname(socket)) || mkpath(dirname(socket))
        Sockets.listen(socket)
    elseif match(r"^(?:localhost)?:\d+$", socket) |> !isnothing # Port only
        _, port = split(socket, ':')
        Sockets.listen(parse(Int, port))
    elseif match(r"^\[[0-9a-f:]+\]:\d+$", socket) |> !isnothing # IPv6 address
        addr, port = split(socket[2:end], "]:")
        Sockets.listen(parse(IPv6, addr), parse(Int, port))
    elseif match(r"^\d+\.\d+\.\d+\.\d+:\d+$", socket) |> !isnothing # IPv4 address
        addr, port = split(socket, ':')
        Sockets.listen(parse(IPv4, addr), parse(Int, port))
    else
        error("Socket form $(sprint(show, socket)) did not match any recognised format.")
    end
end

function start()
    socket = mainsocket()
    server = create_server(socket)

    try
        @log "Preparing worker environment"
        ensure_worker_env()
        revise_setting = if haskey(ENV, "JULIA_DAEMON_REVISE")
            "JULIA_DAEMON_REVISE=$(ENV["JULIA_DAEMON_REVISE"])"
        else
            "revise: no (default)"
        end
        @log "Running on $socket ($revise_setting)"
        @async create_reserve_worker()
        while true
            serveonce(server)
        end
    finally # Cleanup
        @log "Killing $(length(WORKER_POOL)) workers"
        for (key, _) in WORKER_POOL
            # These /need/ to be deleted and killed to avoid
            # potential pipe issues should `start()` be reinvoked.
            delete!(WORKER_POOL, key)
        end
        if !isnothing(RESERVE_WORKER[])
            kill(RESERVE_WORKER[])
            RESERVE_WORKER[] = nothing
        end
        # Clean up the server socket
        close(server)
        socket_path = mainsocket()
        if startswith(socket_path, '/') && ispath(socket_path)
            rm(socket_path)
        end
        @log "Stopped"
    end
end

function serveonce(server)
    try
        # This blocks until a client connects
        conn = accept(server)
        serveclient(conn)
    catch err
        if err isa Base.IOError
            @warn "Client disconnected during setup"
        elseif err isa InterruptException
        else
            rethrow(err)
        end
    end
end

const client_counter = Ref(0)
function serveclient(connection::Base.PipeEndpoint)
    client = readclientinfo(connection)
    @log "Client $(client_counter[] += 1); " *
        "pid: $(client.pid), project: $(projectpath(client))"
    function servestring(content)
        # Setup sockets
        rand_id = String(rand('a':'z', 16))
        stdio_sockfile = BaseDirs.runtime(RUNTIME_DIR, string(rand_id, "-stdio", ".sock"))
        signals_sockfile = BaseDirs.runtime(RUNTIME_DIR, string(rand_id, "-signals", ".sock"))
        stdio_sock = Sockets.listen(stdio_sockfile)
        signals_sock = Sockets.listen(signals_sockfile)
        # Inform client about them using binary protocol
        send_socket_paths(connection, stdio_sockfile, signals_sockfile)
        # Connect to the client
        stdio = accept(stdio_sock)
        signals = accept(signals_sock)
        # Send `content` and exit code 0.
        write(stdio, content)
        write(signals, "\x01exit\x020\x04")
        close(stdio); close(signals)
        close(stdio_sock); close(signals_sock)
    end
    switchnames = map(first, client.switches)
    if "-h" in switchnames || "--help" in switchnames
        servestring(CLIENT_HELP)
    elseif "-v" in switchnames || "--version" in switchnames
        # REVIEW: Should this get the Julia version from the worker?
        servestring("julia version $VERSION, juliaclient $PACKAGE_VERSION\n")
    elseif "--restart" in switchnames
        project = projectpath(client)
        nkilled = 0
        if haskey(WORKER_POOL, project)
            nkilled = length(WORKER_POOL.workers[project])
            delete!(WORKER_POOL, project)
        end
        @log "Restart: killed $nkilled worker(s) for $project"
        servestring("Reset: killed $nkilled worker(s) for project\n")
    else
        stdio_sock, signals_sock = runclient(client)
        try
            send_socket_paths(connection, stdio_sock, signals_sock)
        catch err
            if err isa Base.IOError
                @warn "Client disconnected during setup"
                if ispath(stdio_sock)
                    close(Sockets.connect(stdio_sock))
                    rm(stdio_sock)
                end
                if ispath(signals_sock)
                    close(Sockets.connect(signals_sock))
                    rm(signals_sock)
                end
            else
                rethrow(err)
            end
        end
    end
    close(connection)
end
