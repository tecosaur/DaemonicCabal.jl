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
    lock = ReentrantLock(),  # never held across blocking work: the message loop takes it
    soft_exit = Ref(false),
    conductor_socket = Ref(""),
    standby_sockets = Ref{Union{Nothing, NTuple{4, Pair{Union{Sockets.PipeServer, Sockets.TCPServer}, String}}}}(nothing),
    standby_module = Ref{Union{Nothing, Module}}(nothing),
    repl_warmed = Threads.Atomic{Bool}(false),
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
SYNC_REPLAY_PAGES::Int = 3  # of a sync session's screen, replayed to a joiner; 0 for all

# "64K", "1M" and the like, or plain bytes; at most 4G, as records carry a UInt32 length.
function history_bytes(value::AbstractString)
    scale = if isempty(value) nothing else findfirst(==(uppercase(last(value))), "KMG") end
    n = tryparse(Int, if isnothing(scale) value else chop(value) end)
    if isnothing(n) || n < 0
        @warn "Ignoring JULIA_DAEMON_HISTORY_BYTES=$value, which should be bytes, optionally with K, M or G"
        return HISTORY_BYTES
    end
    min(min(n, typemax(UInt32)) << (10 * something(scale, 0)), typemax(UInt32))
end

function record_level(value::AbstractString)
    for level in instances(RecordLevel)
        value == chopprefix(string(level), "record_") && return level
    end
    @warn "Ignoring JULIA_DAEMON_RECORD=$value, which should be sync, interactive or session"
    RECORD_LEVEL
end

function replay_pages(value::AbstractString)
    pages = tryparse(Int, value)
    !isnothing(pages) && pages >= 0 && return pages
    @warn "Ignoring JULIA_DAEMON_SYNC_REPLAY_PAGES=$value, which should be a whole number of pages, 0 for all"
    SYNC_REPLAY_PAGES
end

# A switch or variable given with no value counts as yes.
isyes(value::AbstractString) = value ∈ ("yes", "true", "1", "")

# Exiting

struct DaemonClientExit <: Exception code::Int end

function real_exit(n::Int)
    remove_standby_files()
    ccall(:jl_exit, Union{}, (Int32,), n)
end

# A local socket's path is only for a client to connect by, so goes with it;
# a named pipe, Windows' local socket, goes by itself once closed.
remove_socket_file(path::AbstractString) = startswith(path, ':') || Sys.iswindows() || rm(path; force=true)

function remove_standby_files()
    standby = @lock STATE.lock STATE.standby_sockets[]
    isnothing(standby) || foreach(((_, path),) -> remove_socket_file(path), standby)
end

RunEnd() = RunEnd(ReentrantLock(), Function[], nothing, false)

"""
    exit_client(code)

`exit`, as the worker overrides it. Within a client's run, the run ends with
`code` (the first asked, or a hook's), its `atexit` hooks run, and its client
is let go at once, whatever its code does after catching the thrown
`DaemonClientExit`; before 1.11, such a client waits for the run to end.
"""
function exit_client(code)
    ending = CLIENT_END[]
    if !isnothing(ending)
        first = @lock ending.lock begin
            asked = isnothing(ending.code)
            if !ending.ended
                ending.code = code
            end
            asked
        end
        if first
            run_exit_hooks!(ending)
            @static if VERSION >= v"1.11"
                let_client_go(something(ending.code))
            end
        end
    end
    throw(DaemonClientExit(code))
end

# `atexit`, as the worker overrides it: within a run, the hook runs as the run
# ends, as stock julia's does as its process ends. A package's `__init__`
# registers the worker's, the package being loaded for good.
function register_atexit(hook::Function)
    ending = CLIENT_END[]
    loading = !isnothing(ending) && @lock Base.require_lock begin
        any(((_, (task, _)),) -> task === current_task(), Base.package_locks)
    end
    if isnothing(ending) || loading
        @lock Base._atexit_hooks_lock begin
            Base._atexit_hooks_finished && error("cannot register new atexit hook; already exiting.")
            pushfirst!(Base.atexit_hooks, hook)
        end
    else
        @lock ending.lock begin
            ending.ended && error("cannot register new atexit hook; already exiting.")
            pushfirst!(ending.hooks, hook)
        end
    end
    nothing
end

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

# Never in a sandbox the conductor built, whose filesystem is ephemeral.
wants_revise(client::ClientInfo) = !haskey(ENV, "JULIA_DAEMON_SANDBOXED") &&
    isyes(getval(client.switches, "--revise",
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
    Timer(ORPHAN_FAILSAFE; interval = ORPHAN_FAILSAFE) do _
        if time() - (@lock STATE.lock STATE.last_contact[]) >= ORPHAN_FAILSAFE
            real_exit(0)
        end
    end
end

function set_parent_death_signal()
    @static if Sys.islinux()
        PR_SET_PDEATHSIG = Cint(1)
        @ccall prctl(PR_SET_PDEATHSIG::Cint, Base.SIGKILL::Culong, 0::Culong, 0::Culong, 0::Culong)::Cint
    end
end

# A client's run is `with_client_scope`, each evaluation of its code
# `as_client_code`, and the worker's rendering of what it asked `shielded`.
# From 1.14 a Ctrl-C cancels a scope (cancellation.jl), reaching the worker as
# `interrupt_client`; before, it is a SIGINT thrown into whichever task thread 0
# runs, passed on (`pass_interrupt`) when it lands on the worker's own.
@static if isdefined(Base, :sigint_new_episode!)
    include("cancellation.jl")
else
    with_client_scope(f, ::ClientInfo) = f()
    # The conductor's SIGINT does it, but Windows has none, so it is passed on.
    interrupt_client(::Integer, ::Integer) = @static if Sys.iswindows() pass_interrupt() end
    const EXECUTING = Task[]  # running a client's code, under `STATE.lock`
    function as_client_code(f)
        task = current_task()
        @lock STATE.lock push!(EXECUTING, task)
        signal_executing(true)
        try
            f()
        finally
            signal_executing(false)
            @lock STATE.lock filter!(!=(task), EXECUTING)
        end
    end
    shielded(f) = Base.disable_sigint(f)
    function pass_interrupt()
        for task in @lock STATE.lock copy(EXECUTING)
            # A task not held to thread 0 (the REPL pre-warm's) is none a Ctrl-C was for.
            task.sticky && task !== current_task() && inject_interrupt(task)
        end
    end
end

# A client's Ctrl-C reaches whichever task thread 0 runs, perhaps one of the
# worker's own, which carries on (`f` again), passing it on.
function uninterrupted(f)
    while true
        try
            return f()
        catch err
            err isa InterruptException || rethrow()
            pass_interrupt()
        end
    end
end

# Injecting into a task on another thread is fatal.
function inject_interrupt(task::Task)
    Threads.threadid(task) == Threads.threadid() || return
    try schedule(task, InterruptException(); error=true) catch end
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
        inject_interrupt(ct.task)
    end
    # A CPU-bound task only dies to the conductor's SIGINT, so bound the wait.
    deadline = time() + 2.0
    for ct in stuck
        while !istaskdone(ct.task) && time() < deadline
            # That SIGINT may land here, and the conductor still awaits the reply.
            uninterrupted(() -> sleep(0.01))
        end
    end
end

function register_client!(id::Int, task::Task, streams::StreamIO...)
    @lock STATE.lock STATE.client_tasks[id] = ClientTask(task, streams)
end

# Pre-1.11 stand-ins for the scoped values scopedio.jl defines; that path is
# single-client.
@static if VERSION < v"1.11"
    const CLIENT_SIGNALS = Ref{Union{Nothing, StreamIO}}(nothing)
    const CLIENT_INPUT = Ref{Union{Nothing, StreamIO, TerminalInput}}(nothing)
    const CLIENT_INTERACTIVE = Ref(false)
    const CLIENT_END = Ref{Union{Nothing, RunEnd}}(nothing)
end

# Signal protocol (Worker → Client)
const SIGNAL_EXIT = 0x01
const SIGNAL_RAW_MODE = 0x02   # data: 0x00 = cooked, 0x01 = raw
const SIGNAL_QUERY_SIZE = 0x03 # response: height(u16) + width(u16)
const SIGNAL_NODELAY = 0x04    # disable Nagle on stdin + signals
const SIGNAL_EXECUTING = 0x05  # data: 0x00 = at prompt, 0x01 = evaluating; evaluation number (u32 LE)
const SIGNAL_SUSPEND = 0x06    # acked once the client runs again

const DEFAULT_DISPLAYSIZE = (24, 80)

# A size query's answer: height and width, each a u16 (LE), 0 when unknown.
function answered_size(data::Vector{UInt8})
    height, width = ltoh.(reinterpret(UInt16, data))
    (if iszero(height) first(DEFAULT_DISPLAYSIZE) else Int(height) end,
     if iszero(width) last(DEFAULT_DISPLAYSIZE) else Int(width) end)
end

# One write per frame: a multi-argument `write` yields between arguments, so
# concurrent senders could interleave mid-frame.
function send_signal(io::IO, id::UInt8, data::Vector{UInt8})
    frame = Vector{UInt8}(undef, 2 + length(data))
    frame[1], frame[2] = id, length(data)
    copyto!(frame, 3, data)
    write(io, frame)
end

# Closed before the exit is sent, so the client has all its output. Any of
# them may be gone already, with the client.
function release_client(stdout::IO, stderr::IO, signals::IO, code::Integer)
    try close(stdout) catch end
    try close(stderr) catch end
    try
        send_signal(signals, SIGNAL_EXIT, UInt8[code % UInt8])
        close(signals)
    catch end
end

function send_executing(signals::StreamIO, executing::Bool, evaluation::UInt32)
    isopen(signals) || return
    # `isopen` lags a peer close, so a client leaving mid-evaluation throws here.
    try send_signal(signals, SIGNAL_EXECUTING, [UInt8(executing); reinterpret(UInt8, [htol(evaluation)])])
    catch err
        err isa Base.IOError || rethrow()
    end
end

"""
    signal_executing(executing::Bool, evaluation::UInt32=0)

Tell the active client whether user code is evaluating, so it can route Ctrl-C,
and which evaluation (0 if unnumbered), for its Ctrl-C to name. Raw mode cannot
stand in: LineEdit holds the terminal raw across evaluation.
"""
@static if VERSION >= v"1.11"
    function signal_executing(executing::Bool, evaluation::UInt32=UInt32(0))
        term = ACTIVE_TERM[]
        # Outside a client session there's no client, and the pipe was never opened.
        term === WORKER_TERM && return
        session = term.sync_session
        isnothing(session) && return send_executing(term.signals, executing, evaluation)
        @lock session.executing_lock begin
            session.executing[] = (executing, evaluation)
            foreach(p -> send_executing(p.signals, executing, evaluation), @atomic session.participants)
        end
    end
else
    function signal_executing(executing::Bool, evaluation::UInt32=UInt32(0))
        sig = CLIENT_SIGNALS[]
        isnothing(sig) || send_executing(sig, executing, evaluation)
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
    if startswith(STATE.conductor_socket[], "tcp://")
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
    @something(take_standby!(STATE.standby_sockets), ntuple(_ -> create_socket(), 4))
end

# None with a managed port range: the port set is unknown until `client_run`.
# Made outside the lock, as a name may need resolving.
function ensure_standby_sockets()
    PORT_BASE > 0 && return
    fill_standby!(() -> ntuple(_ -> create_socket(), 4), STATE.standby_sockets) do sockets
        foreach(close ∘ first, sockets)
    end
end

# A standby, made ahead so that no client waits on it, is taken whole.
function take_standby!(slot::Ref)
    @lock STATE.lock begin
        taken = slot[]
        slot[] = nothing
        taken
    end
end

# Made outside `STATE.lock`, which the message loop takes; should another
# fill `slot` meanwhile, this one is `discard`ed.
function fill_standby!(discard::Function, make::Function, slot::Ref)
    (@lock STATE.lock isnothing(slot[])) || return
    made = make()
    installed = @lock STATE.lock begin
        vacant = isnothing(slot[])
        if vacant
            slot[] = made
        end
        vacant
    end
    installed || discard(made)
    nothing
end

function sync_session_label(client::ClientInfo)
    any(p -> first(p) == "--sync", client.switches) || return nothing
    label = getval(client.switches, "--session", "")
    if !isempty(label) label end
end

# The session and its REPL outlive the client for reattachment, until the
# conductor sends `drop_session` for its expired label.
function sync_client_disconnect!(client::ClientInfo, client_stdin::StreamIO,
                                 participant::Participant, session::SyncSession)
    detach!(session, participant)
    # The terminal is raw, so end the line ourselves.
    try write(participant.stdout, "\r\n") catch end
    release_client(participant.stdout, participant.stderr, participant.signals, 0)
    try close(client_stdin) catch end
    unregister_client!(client)
end

function teardown_session!(label::String)
    drop_transcript!(label)
    session = @lock STATE.lock get(STATE.sync_sessions, label, nothing)
    isnothing(session) || end_sync_session!(session, 0)
end

# The session ends with its REPL, its participants let go with `code`, and a
# later --sync starts afresh. Closing the merged input ends the REPL, and tells
# a joiner attaching late that the session is over.
function end_sync_session!(session::SyncSession, code::Int)
    @lock STATE.lock begin
        if get(STATE.sync_sessions, session.label, nothing) === session
            delete!(STATE.sync_sessions, session.label)
        end
    end
    close_input!(session.input)
    participants = @lock STATE.lock begin
        taken = @atomic session.participants
        set_participants!(session, Participant[])
        taken
    end
    for p in participants
        release_client(p.stdout, p.stderr, p.signals, code)
    end
end

function sync_echo_expressions(session::SyncSession, client::ClientInfo)
    for (switch, value) in client.switches
        suffix = if switch == "--eval" ";\n"
        elseif switch == "--print" "\n"
        else continue end
        write(session.out, "\r\e[2K\e[1;32mjulia>\e[m ", value, suffix)
    end
end

# Made only by the message loop, so never twice for a label.
function sync_session!(label::String)::SyncSession
    session = @lock STATE.lock get(STATE.sync_sessions, label, nothing)
    isnothing(session) || return session
    session = build_sync_session(label)
    @lock STATE.lock STATE.sync_sessions[label] = session
end

# A sync session is always recorded: a joiner is replayed its screen.
function build_sync_session(label::String)::SyncSession
    start_recording!(session_transcript(label))
    screen = begin_run(label, "--sync")
    out = BroadcastWriter(StreamIO[], screen, :stdout)
    err = BroadcastWriter(StreamIO[], screen, :stderr)
    SyncSession(label, TerminalInput(), out, err, Participant[], screen,
                Ref{REPL.LineEditREPL}(), Ref((false, UInt32(0))), ReentrantLock(), false)
end

# Participants

const SYNC_REPLY_TIMEOUT_S = 1.0  # the longest a participant's answer is waited for

function Participant(stdout::StreamIO, stderr::StreamIO, signals::StreamIO)
    participant = Participant(stdout, stderr, signals, Threads.Condition(), 0, 0, nothing)
    errormonitor(Threads.@spawn read_replies(participant))
    participant
end

# Its client answers each raw-mode switch with an ack and each size query
# with its size, framed as the signals it answers.
function read_replies(p::Participant)
    sig = p.signals
    try
        while true
            uninterrupted(() -> Base.wait_readnb(sig, 2))
            bytesavailable(sig) >= 2 || break
            id, len = read(sig, UInt8), Int(read(sig, UInt8))
            uninterrupted(() -> Base.wait_readnb(sig, len))
            bytesavailable(sig) >= len || break
            data = read(sig, len)
            @lock p.replied begin
                if id == SIGNAL_RAW_MODE
                    p.acks_due = max(p.acks_due - 1, 0)
                elseif id == SIGNAL_QUERY_SIZE
                    p.sizes_due = max(p.sizes_due - 1, 0)
                    if length(data) == 4
                        p.size = answered_size(data)
                    end
                end
                notify(p.replied)
            end
        end
    catch err
        err isa Base.IOError || err isa EOFError || rethrow()
    finally
        # No more answers are coming, so none is waited for.
        @lock p.replied begin
            p.acks_due = 0
            p.sizes_due = 0
            notify(p.replied)
        end
    end
end

# Until each of `participants` has none `due`, or the timeout passes.
function await_replies(due::Function, participants)
    deadline = time() + SYNC_REPLY_TIMEOUT_S
    for p in participants
        expired = Ref(false)
        timer = Timer(max(deadline - time(), 0.0)) do _
            @lock p.replied begin
                expired[] = true
                notify(p.replied)
            end
        end
        try
            uninterrupted() do
                @lock p.replied while due(p) > 0 && !expired[]
                    wait(p.replied)
                end
            end
        finally
            close(timer)
        end
    end
end

# The broadcast writers follow the participants.
function set_participants!(session::SyncSession, participants::Vector{Participant})
    @lock STATE.lock begin
        @atomic session.participants = participants
        @atomic session.out.writers = StreamIO[p.stdout for p in participants]
        @atomic session.err.writers = StreamIO[p.stderr for p in participants]
    end
end

attach!(session::SyncSession, p::Participant) =
    set_participants!(session, push!(filter(q -> isopen(q.signals), @atomic session.participants), p))

detach!(session::SyncSession, p::Participant) =
    set_participants!(session, filter(q -> q !== p, @atomic session.participants))

# Every participant is switched, but one yet to acknowledge an earlier switch
# is not waited on.
function switch_raw_mode!(session::SyncSession, raw::Bool)
    @lock session.input.lock session.input.raw = raw
    waited = Participant[]
    for p in @atomic session.participants
        isopen(p.signals) || continue
        due = @lock p.replied p.acks_due += 1
        try
            send_signal(p.signals, SIGNAL_RAW_MODE, UInt8[raw])
        catch err
            err isa Base.IOError || rethrow()
            @lock p.replied p.acks_due -= 1
            continue
        end
        due == 1 && push!(waited, p)
    end
    await_replies(p -> p.acks_due, waited)
end

# Unless it has yet to answer an earlier query.
function ask_size!(p::Participant)
    isopen(p.signals) || return false
    asking = @lock p.replied begin
        idle = p.sizes_due == 0
        if idle
            p.sizes_due = 1
        end
        idle
    end
    asking || return false
    try
        send_signal(p.signals, SIGNAL_QUERY_SIZE, UInt8[])
        true
    catch err
        err isa Base.IOError || rethrow()
        @lock p.replied p.sizes_due = 0
        false
    end
end

function participant_size(p::Participant)
    ask_size!(p) && await_replies(q -> q.sizes_due, (p,))
    something(p.size, DEFAULT_DISPLAYSIZE)
end

# The smallest of its participants', like tmux; one slow to answer counts at
# its last answer.
function session_displaysize(session::SyncSession)
    participants = @atomic session.participants
    await_replies(p -> p.sizes_due, filter(ask_size!, participants))
    sizes = [p.size for p in participants if !isnothing(p.size)]
    if isempty(sizes) DEFAULT_DISPLAYSIZE else (minimum(first, sizes), minimum(last, sizes)) end
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
    session = sync_session!(label)
    if is_interactive
        spawn_interactive_sync_client!(client, client_stdin, client_stdout,
                                       client_stderr, signals, session)
    else
        spawn_eval_sync_client!(client, client_stdin, client_stdout,
                                client_stderr, signals, session)
    end
end

# The REPL's starter replays history after the banner (REPLAY_TARGET); a joiner
# replays inline. Off the message loop, which must not wait on a client.
function spawn_interactive_sync_client!(client::ClientInfo, client_stdin::StreamIO,
                                        client_stdout::StreamIO, client_stderr::StreamIO,
                                        signals::StreamIO, session::SyncSession)
    participant = Participant(client_stdout, client_stderr, signals)
    # Its `--sync=N`, or the daemon's setting.
    pages = something(tryparse(Int, getval(client.switches, "--sync", "")), SYNC_REPLAY_PAGES)
    if session.repl_started
        errormonitor(@async join_sync_repl(session, participant, pages))
    else
        session.repl_started = true
        attach!(session, participant)
        errormonitor(@async begin # thread 0 for Ctrl-C; see `spawn_client!`
            replay = (client_stdout, session.screen, participant_size(participant), pages)
            code = 1
            try
                code = runclient(client, session.input, session.out, session.err, signals;
                                 owned_streams=(), sync_session=session, repl_ref=session.repl, replay)
            finally
                end_sync_session!(session, code)
            end
        end)
    end
    task = Threads.@spawn begin
        copy_input(client_stdin, session.input; leaves = () -> is_line_empty(session))
        sync_client_disconnect!(client, client_stdin, participant, session)
    end
    register_client!(client.id, task, client_stdin, client_stdout, client_stderr, signals)
end

# Attached once replayed, so the live output can't come before it.
function join_sync_repl(session::SyncSession, p::Participant, pages::Int)
    try
        # Leaves the cursor where the REPL's is, for its refresh to redraw the line.
        replay_history(p.stdout, session.screen, participant_size(p), pages)
        attach!(session, p)
        @lock(session.input.lock, isopen(session.input.writer)) || return end_sync_session!(session, 0)
        @lock p.replied p.acks_due += 1
        send_signal(p.signals, SIGNAL_RAW_MODE, UInt8[@lock session.input.lock session.input.raw])
        await_replies(q -> q.acks_due, (p,))
        # Joining mid-evaluation, its Ctrl-C is to interrupt it.
        @lock session.executing_lock send_executing(p.signals, session.executing[]...)
    catch err
        # It left while joining, and its disconnect tidies up.
        err isa Base.IOError || rethrow()
        return
    end
    # A REPL yet to start draws its prompt for all as it does.
    mi = repl_mistate(session)
    isnothing(mi) || redraw_prompt(mi)
end

# The shared REPL's line editing, once it has started.
function repl_mistate(session::SyncSession)
    isassigned(session.repl) || return nothing
    session.repl[].mistate
end

# Taken only at a prompt, so after any evaluation running.
function redraw_prompt(mi::REPL.LineEdit.MIState)
    put!(mi.async_channel, function (s)
        REPL.LineEdit.refresh_line(s)
        :ok
    end)
end

# Whether the shared REPL's line is empty, where a Ctrl-D is a participant
# leaving, not a key deleting forward.
function is_line_empty(session::SyncSession)
    mi = repl_mistate(session)
    isnothing(mi) || REPL.LineEdit.buffer(mi).size == 0
end

# The result goes plainly to this client and REPL-style to the shared scrollback.
function spawn_eval_sync_client!(client::ClientInfo, client_stdin::StreamIO,
                                 client_stdout::StreamIO, client_stderr::StreamIO,
                                 signals::StreamIO, session::SyncSession)
    mi = repl_mistate(session)
    task = errormonitor(@async begin # thread 0 for Ctrl-C; see `spawn_client!`
        # Only the shared screen's tidiness rides on these; the run goes ahead.
        try
            clear_repl_input(session, mi)
            sync_echo_expressions(session, client)
        catch err
            @error "Failed to echo a client's code to its sync session" exception=(err, catch_backtrace())
        end
        try
            runclient(client, client_stdin, client_stdout, client_stderr, signals;
                      broadcast=session.out)
        catch
            isopen(client_stdout) && rethrow()
        end
        write(session.out, "\n")
        restore_repl_prompt(session, mi)
    end)
    register_client!(client.id, task, client_stdin, client_stdout, client_stderr, signals)
end

function clear_repl_input(session::SyncSession, mi::Union{Nothing, REPL.LineEdit.MIState})
    isnothing(mi) && return
    # Whatever the mode, a history search included.
    state = mi.mode_state[mi.current_mode]
    hasfield(typeof(state), :ias) || return
    rows = state.ias.curs_row
    write(session.out, rows > 1 ? "\e[$(rows - 1)A\e[J" : "\e[J")
    state.ias = REPL.LineEdit.InputAreaState(0, 0)
end

# Without a live REPL, nudge a redraw through the merged input.
function restore_repl_prompt(session::SyncSession, mi::Union{Nothing, REPL.LineEdit.MIState})
    if isnothing(mi)
        try feed_input!(session.input, codeunits(" \x7f")) catch end
    else
        redraw_prompt(mi)
    end
end

function unregister_client!(client::ClientInfo)
    idle = @lock STATE.lock begin
        filter!(c -> c !== client, STATE.clients)
        delete!(STATE.client_tasks, client.id)
        STATE.lastclient[] = time()
        isempty(STATE.clients)
    end
    send_notification(STATE.conductor_socket[], NOTIF_TYPE.client_done,
                      UInt32(client.id))
    idle && STATE.soft_exit[] && real_exit(0)
    ensure_standby_sockets()
    ensure_standby_module()
    idle && Timer(_ -> settle(), SETTLE_DELAY_S)
end

# Work for a worker left without clients for `SETTLE_DELAY_S`, so that no client
# waits on it: the REPL pre-warm (once), then collecting the garbage, which an
# idle worker, allocating nothing, would otherwise keep.
function settle()
    quiet = @lock STATE.lock isempty(STATE.clients) && time() - STATE.lastclient[] >= SETTLE_DELAY_S
    quiet || return
    # Off thread 0, which answers the conductor.
    errormonitor(Threads.@spawn begin
        Threads.atomic_xchg!(STATE.repl_warmed, true) || warm_repl_path()
        GC.gc(true)
        @static if Sys.islinux()
            # glibc keeps what is freed (largely the compiler's) until asked; musl has no malloc_trim.
            trim = ccall(:dlsym, Ptr{Cvoid}, (Ptr{Cvoid}, Cstring), C_NULL, "malloc_trim")
            trim == C_NULL || ccall(trim, Cint, (Csize_t,), 0)
        end
    end)
end

const CLIENT_ACCEPT_TIMEOUT_S = 30.0
const SETTLE_DELAY_S = 2.0
const TCP_KEEPALIVE_IDLE_S = 60

# A bare `accept` would stall pings on a client that died after getting its
# paths. Only the named client may connect, giving its key first: anything
# reaching the runtime dir, or the port, could take over the terminal.
function accept_client_sockets(servers, key::UInt64)
    accepted = Base.IO[]
    deadline = Timer(CLIENT_ACCEPT_TIMEOUT_S) do _
        foreach(close, servers)
        foreach(close, accepted)
    end
    try
        map(servers) do srv
            while true
                sock = uninterrupted(() -> accept(srv))
                push!(accepted, sock)
                uninterrupted(() -> read(sock, UInt64)) == key && return sock
                @warn "Dropped a client socket connection without its client's key"
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

function spawn_client!(conn::IO, client::ClientInfo, replied::Ref{Bool})
    sockets = get_client_sockets(client.port_set)
    servers, paths = first.(sockets), last.(sockets)
    active_count = @lock STATE.lock begin
        push!(STATE.clients, client)
        length(STATE.clients)
    end
    send_sockets(conn, paths..., active_count)
    replied[] = true
    t0 = time_ns()
    streams = try
        accept_client_sockets(servers, client.key)
    catch
        @lock STATE.lock filter!(c -> c !== client, STATE.clients)
        # Or the conductor keeps counting it, port set and all.
        send_notification(STATE.conductor_socket[], NOTIF_TYPE.client_done, UInt32(client.id))
        rethrow()
    finally
        foreach(close, servers)
        foreach(remove_socket_file, paths)
    end
    client_stdin, client_stdout, client_stderr, signals = streams
    if first(servers) isa Sockets.TCPServer
        # A client gone without closing would otherwise hold its session forever.
        for sock in streams
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
        task = errormonitor(@async try
            runclient(client, client_stdin, client_stdout, client_stderr, signals)
        catch
            isopen(client_stdout) && rethrow()
        end)
        register_client!(client.id, task, streams...)
    else
        spawn_sync_client!(client, streams..., label)
    end
end

function serve_client_run(conn::IO)
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
            if err isa InterruptException
                pass_interrupt()
            else
                @error "Failed to start client" exception=(err, catch_backtrace())
            end
        end
    end
end

# A client's Ctrl-C arrives as `cancel_client` (before 1.14, with the conductor's SIGINT).
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
        serve_client_run(conn)
    elseif header.msg_type == MSG_TYPE.soft_exit
        @lock STATE.lock begin
            if isempty(STATE.clients)
                remove_standby_files()
                ccall(:_exit, Cvoid, (Cint,), 0)
            else
                STATE.soft_exit[] = true
            end
        end
    elseif header.msg_type == MSG_TYPE.sync_clients
        kill_stuck_clients(Set{Int}(read(conn, UInt32) for _ in 1:read(conn, UInt16)))
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
    elseif header.msg_type == MSG_TYPE.cancel_client
        interrupt_client(read(conn, UInt32), read(conn, UInt32))
    elseif header.msg_type == MSG_TYPE.start_peek
        start_peek()
    else
        read(conn, header.payload_len)  # skip unknown payload
        send_error(conn, ERR_CODE.invalid_message,
                   "Unknown message type: $(header.msg_type)")
    end
end

function runworker(socketpath::String, conductor_address::String, worker_id::Integer=0)
    Base.exit_on_sigint(false)
    conn = connect_to(socketpath)
    STATE.conductor_socket[] = conductor_address
    CONDUCTOR_WORKER_ID[] = worker_id
    Profile.peek_report[] = send_peek_report
    global RUNTIME_DIR = if startswith(STATE.conductor_socket[], "tcp://") "" else dirname(socketpath) end
    global MAX_CLIENTS = parse(Int, get(ENV, "JULIA_DAEMON_WORKER_MAXCLIENTS", "1"))
    max_ttl = parse(Int, get(ENV, "JULIA_DAEMON_MAX_TTL",
                             get(ENV, "JULIA_DAEMON_WORKER_TTL", "7200")))
    global ORPHAN_FAILSAFE = max_ttl > 0 ? max_ttl * 4 : 0
    global HISTORY_BYTES = history_bytes(get(ENV, "JULIA_DAEMON_HISTORY_BYTES", "1M"))
    global RECORD_LEVEL = record_level(get(ENV, "JULIA_DAEMON_RECORD", "session"))
    global SYNC_REPLAY_PAGES = replay_pages(get(ENV, "JULIA_DAEMON_SYNC_REPLAY_PAGES", "3"))
    global PORT_BASE = if haskey(ENV, "JULIA_DAEMON_PORTS")
        parse(Int, split(ENV["JULIA_DAEMON_PORTS"], '-')[1])
    else 0 end
    set_parent_death_signal()
    queue_orphan_check()
    ensure_standby_sockets()
    ensure_standby_module()
    @lock STATE.lock STATE.lastclient[] = time()
    Timer(_ -> settle(), SETTLE_DELAY_S)
    exit_code = 0
    try
        WORKER_KEY[] = read_greeting(conn)
        while isopen(conn)
            # A client's Ctrl-C may land on this task.
            try
                header = read_header(conn)
                @lock STATE.lock STATE.last_contact[] = time()
                serve_message(conn, header)
            catch err
                err isa InterruptException || rethrow()
                pass_interrupt()
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
