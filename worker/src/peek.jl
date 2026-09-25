# SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
# SPDX-License-Identifier: MPL-2.0

# A worker's profile peek (SIGUSR1, SIGINFO on BSD and macOS, or the
# conductor's `start_peek`) goes to the conductor rather than stderr, split
# by client, for `--status=live`'s snapshot. The runtime writes the stacks
# to stderr itself, where the conductor reads them.

const PEEK_REPORT_BYTES = 128 << 10  # within a local socket's buffer, so sent at once
const PEEK_REPORT_WIDTH = 160

"""
    peek_report(clients) -> String

The profile last sampled: a section per client, headed `── client <id> ──`,
for each of `clients` (client id => task), then the whole, by task. Cut to
`PEEK_REPORT_BYTES`. A client's tree starts at its own code.

The profile samples what each thread runs, so a client waiting (on I/O, a
lock, `sleep`) has none: its section is then where it waits, from a brief
sample of every task (Julia 1.12 and later), headed `(waiting)`.
"""
function peek_report(clients)
    # Rendered before any resampling replaces the samples, and only as many
    # as the report has room for.
    ordered = sort!(collect(clients), by = first)
    sections = Dict{Int, Union{Nothing, String}}()
    bytes = 0
    for (id, task) in ordered
        bytes > PEEK_REPORT_BYTES && break
        sections[id] = task_profile(task)
        bytes += sizeof(something(sections[id], ""))
    end
    every = with_logger(NullLogger()) do
        sprint(; context = profile_context()) do io
            Profile.print(io; groupby = [:thread, :task])
        end
    end
    waiting = [id => task for (id, task) in ordered if isnothing(get(sections, id, "")) && !istaskdone(task)]
    isempty(waiting) || merge!(sections, waiting_profiles(waiting))
    io = IOBuffer()
    for (id, _) in ordered
        haskey(sections, id) || break
        section = something(sections[id], "\nNo samples: the client did not run while the profile was taken.\n")
        print(io, "── client ", id, " ──", section)
        println(io)
    end
    io.size <= PEEK_REPORT_BYTES && print(io, "── every task ──\n", every)
    report = take!(io)
    if length(report) > PEEK_REPORT_BYTES
        resize!(report, PEEK_REPORT_BYTES)
        append!(report, codeunits("\n… (cut short)\n"))
    end
    String(report)
end

profile_context() = (:displaysize => (1000, PEEK_REPORT_WIDTH), :color => true)

# The task's part of the samples taken, after a newline; nothing when it has none.
function task_profile(task::Task)
    # Quietly: a task without samples is expected, not worth Profile's warning.
    tree = with_logger(NullLogger()) do
        sprint(; context = profile_context()) do io
            Profile.print(io; tasks = UInt(pointer_from_objref(task)), sortedby = :count)
        end
    end
    occursin("Total snapshots", tree) || return nothing
    "\n" * client_tree(tree)
end

"""
    client_tree(tree) -> String

A profile `tree`, perhaps coloured, from where DaemonWorker hands the
client's code over: its own frames, and the REPL's or `eval`'s it calls
that code through, are dropped and the rest moved up to take their place.
A branch within the dropped frames keeps them, lest it lose its place.
Its total is left alone, without Profile's notes for the whole of it.
"""
function client_tree(tree::AbstractString)
    # Julia 1.12 and later link each location (OSC 8), colour or not.
    plain = replace(tree, r"\e\]8;[^\e]*\e\\\\" => "", r"\e\[[0-9;]*m" => "")
    frames = NamedTuple{(:line, :depth, :location, :name), Tuple{Int, Int, String, String}}[]
    for (i, line) in enumerate(split(plain, '\n'))
        # "   ╎    ╎ 6   @Base/asyncevent.jl:321  sleep": depth is the indent.
        m = match(r"╎([ ╎]*)\d+\s+(\S+:\d+)\s+(.*)$", line)
        isnothing(m) || push!(frames, (line = i, depth = length(m[1]), location = m[2], name = m[3]))
    end
    # The frames before the tree first branches, each the last one's child.
    chain = something(findfirst(i -> frames[i].depth != i - 1, eachindex(frames)), length(frames) + 1) - 1
    dropped = min(handoff(@view frames[1:chain]), minimum(f.depth for f in frames[chain+1:end]; init = chain))
    depths = Dict(f.line => f.depth for f in frames)
    lines = String[]
    for (i, line) in enumerate(split(tree, '\n'))
        depth = get(depths, i, nothing)
        if startswith(line, "Total snapshots")
            push!(lines, replace(line, r"^(Total snapshots: \d+)\..*$" => s"\1"))
        elseif isnothing(depth)
            push!(lines, line)
        elseif depth >= dropped
            m = match(r"^([^╎]*)╎[ ╎]*(.*)$", line)
            push!(lines, string(m[1], "╎", tree_indent(depth - dropped), m[2]))
        end
    end
    join(lines, '\n')
end

# How many of a chain's outer frames are DaemonWorker's, through the REPL's
# or `eval`'s it runs the client's code with, up to the client's code.
function handoff(chain)
    own = findlast(f -> startswith(f.location, "@DaemonWorker/src/"), chain)
    isnothing(own) && return 0
    boot_eval(f) = startswith(f.location, "@Base/boot.jl") && startswith(f.name, "eval")
    dropped = own
    for f in @view chain[own+1:end]
        startswith(f.location, "@REPL/") || boot_eval(f) || break
        dropped += 1
        (startswith(f.name, "__repl_entry") || boot_eval(f)) && break
    end
    dropped
end

# As Profile indents a tree's level `depth`, a guide every fifth column.
tree_indent(depth::Int) = if depth == 0 "" else string(first("    ╎"^cld(depth, 5), depth - 1), " ") end

# Sampling every task for a moment catches each waiting one many times over.
const WAITING_SAMPLE_S = 0.1

# Replaces the samples taken, which the report has already rendered.
function waiting_profiles(waiting)
    @static if VERSION >= v"1.12"
        Profile.clear()
        Profile.start_timer(true)
        sleep(WAITING_SAMPLE_S)
        Profile.stop_timer()
        waited(task) = let profile = task_profile(task)
            if isnothing(profile) nothing else " (waiting)" * profile end
        end
        Dict(id => waited(task) for (id, task) in waiting)
    else
        Dict(id => " (waiting)\nIt was waiting, not running; its stack needs Julia 1.12 or later.\n"
             for (id, _) in waiting)
    end
end

function send_peek_report()
    clients = @lock STATE.lock begin
        watchers = Set(c.id for c in STATE.clients if !isnothing(getval(c.switches, "--watch", nothing)))
        Dict(id => ct.task for (id, ct) in STATE.client_tasks if id ∉ watchers)
    end
    report = codeunits(peek_report(clients))
    send_notification(STATE.conductor_socket[], NOTIF_TYPE.peek_report,
                      UInt32(CONDUCTOR_WORKER_ID[]), UInt32(length(report)), report)
end

# Where Julia takes no signal for it, as the signal's peek would.
function start_peek()
    errormonitor(@async begin
        Profile.clear()
        Profile.start_timer()
        sleep(Profile.get_peek_duration())
        Profile.stop_timer()
        Profile.peek_report[]()
    end)
end
