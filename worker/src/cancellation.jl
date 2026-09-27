# SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
# SPDX-License-Identifier: MPL-2.0

# From 1.14 a Ctrl-C cancels a scope, whose tasks' waits then throw
# `CancellationRequest` on whatever thread. Each session has a source, and
# each evaluation of a client's code one under it; a client's Ctrl-C reaches
# the worker as `cancel_client` and cancels its own evaluation's. The process's
# ^C episode stays closed, so a SIGINT finds nothing to cancel.

# Numbered so that a Ctrl-C meant for an earlier evaluation, read late, is let go.
struct Evaluation
    source::Base.CancellationTokenSource
    number::UInt32
end

const SCOPES = (
    lock = ReentrantLock(),
    sessions = Dict{Any, Base.CancellationTokenSource}(),  # by label, or a plain run's client id
    evaluations = Dict{Any, Evaluation}(),                  # by whose Ctrl-C they answer to
    count = Threads.Atomic{UInt32}(0),
)

# A run's session, and whose Ctrl-C its code answers to.
const CANCEL_SCOPE = ScopedValue{Union{Nothing, @NamedTuple{session::Any, interrupts::Any}}}(nothing)

# A --sync REPL answers to any of its participants' Ctrl-C.
function interrupt_key(client::ClientInfo)
    label = sync_session_label(client)
    if isnothing(label) || !is_repl_client(client) client.id else "sync:" * label end
end

# A plain run's session ends with it, cancelling whatever its code left running,
# as its own process would have; a labelled session's lasts as long as the worker.
function with_client_scope(@nospecialize(f), client::ClientInfo)
    session = something(getval(client.switches, "--session", nothing), client.id)
    try
        @with CANCEL_SCOPE => (; session, interrupts = interrupt_key(client)) f()
    finally
        if session isa Int
            source = @lock SCOPES.lock pop!(SCOPES.sessions, session, nothing)
            isnothing(source) || Base.cancel!(source)
        end
    end
end

function as_client_code(@nospecialize(f))
    key = something(CANCEL_SCOPE[]).interrupts
    evaluation = Evaluation(Base.new_evaluation_cancel_source!(), Threads.atomic_add!(SCOPES.count, UInt32(1)) + 1)
    @lock SCOPES.lock SCOPES.evaluations[key] = evaluation
    signal_executing(true, evaluation.number)
    try
        @with Base.CANCEL_TOKEN => Base.CancellationToken(evaluation.source) Base.@as_foreground_task f()
    finally
        # Outside the evaluation, which a Ctrl-C leaves cancelled.
        signal_executing(false)
        @lock SCOPES.lock delete!(SCOPES.evaluations, key)
    end
end

# A repeated Ctrl-C delivers the cancellation again.
function interrupt_client(id::Integer, evaluation::Integer)
    client = @lock STATE.lock begin
        index = findfirst(c -> c.id == id, STATE.clients)
        if isnothing(index) nothing else STATE.clients[index] end
    end
    isnothing(client) && return
    current = @lock SCOPES.lock get(SCOPES.evaluations, interrupt_key(client), nothing)
    isnothing(current) && return
    evaluation == 0 || evaluation == current.number || return
    Base.cancel!(current.source) || Base.redeliver!(current.source)
    nothing
end

# Only a client's code is in a cancelled scope, so nothing else needs holding off.
shielded(@nospecialize(f)) = @with Base.CANCEL_TOKEN => nothing f()

# No Ctrl-C is a signal, so none lands on the worker's own tasks.
pass_interrupt() = nothing

# Base's session source is the process's; a session's is its own, so a
# client's sweep ("cancel all in-flight work") reaches only its session.
function session_cancel_source()
    key = something(CANCEL_SCOPE[], (; session = :worker)).session
    @lock SCOPES.lock get!(Base.CancellationTokenSource, SCOPES.sessions, key)
end

function cancel_session_work()
    scope = CANCEL_SCOPE[]
    isnothing(scope) && return false
    source = @lock SCOPES.lock pop!(SCOPES.sessions, scope.session, nothing)
    isnothing(source) || Base.cancel!(source)
    !isnothing(source)
end

# At load, as Base's methods can only be overridden then: leave `--eval`'s
# ^C episode, which takes in the whole worker.
function install_cancellation()
    Base.sigint_close_episode!()
    @eval Base session_cancel_source!() = $session_cancel_source()
    @eval Base cancel_session_work!() = $cancel_session_work()
end
