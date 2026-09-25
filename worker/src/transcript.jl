# SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
# SPDX-License-Identifier: MPL-2.0

# Session transcripts, for `--watch` and a sync session's joiners: each run in
# a labelled session, with its REPL input, output and exit, as records framed
# in an OutputHistory ring.

# A ring of recent bytes, used under its transcript's lock. `pos` is the
# 0-based next write slot; `total` counts every byte ever written, so the
# live and dropped counts derive from it. Until full it grows rather than
# wrapping, so a quiet session holds little of its `cap`.
mutable struct OutputHistory
    const bytes::Vector{UInt8}
    const cap::Int
    pos::Int
    total::Int
end

OutputHistory(cap::Int) = OutputHistory(Vector{UInt8}(undef, min(cap, 4096)), cap, 0, 0)

function capture!(h::OutputHistory, data)
    nb = length(data)
    # Not yet wrapped, the ring is a plain prefix, which grows in place. It wraps
    # only at its full `cap`: filled below it, its end would wrap `pos` early.
    h.total + nb >= length(h.bytes) < h.cap &&
        resize!(h.bytes, min(h.cap, max(2 * length(h.bytes), h.total + nb)))
    cap = length(h.bytes)
    iszero(cap) && return
    n = min(nb, cap)  # only the last cap bytes of an oversized write survive
    soff = lastindex(data) - n + 1
    first_run = min(n, cap - h.pos)
    copyto!(h.bytes, h.pos + 1, data, soff, first_run)
    first_run < n && copyto!(h.bytes, 1, data, soff + first_run, n - first_run)
    h.pos = (h.pos + n) % cap
    h.total += nb
    nothing
end

# Rewrites the bytes from absolute offset `at`, unless the ring has moved past it.
function overwrite!(h::OutputHistory, at::Int, data)
    cap = length(h.bytes)
    at >= h.total - cap || return
    for (i, byte) in enumerate(data)
        h.bytes[mod(at + i - 1, cap) + 1] = byte
    end
end

# The live bytes oldest-first, plus how many earlier bytes were dropped.
function linearise(h::OutputHistory)
    cap = length(h.bytes)
    len = min(h.total, cap)
    iszero(len) && return UInt8[], 0
    out = Vector{UInt8}(undef, len)
    start = mod(h.pos - len, cap)  # 0-based index of the oldest byte
    first_run = min(len, cap - start)
    copyto!(out, 1, h.bytes, start + 1, first_run)
    first_run < len && copyto!(out, first_run + 1, h.bytes, 1, len - first_run)
    out, h.total - len
end

# A record is a header, then `length` bytes of data: the command (:run), the
# mode and code, a newline apart (:input, piped; :typed, at a terminal REPL),
# the REPL's line editing (:prompt, stdout), output, or exit code.
const RECORD_KINDS = (:run, :input, :typed, :prompt, :stdout, :stderr, :exit)
const RECORD_HEADER_BYTES = 17  # kind::UInt8, run::UInt32, time::Float64, length::UInt32

struct TranscriptEvent
    time::Float64
    run::Int
    kind::Symbol
    data::Vector{UInt8}
end

# For a plain destination, what a terminal would have shown: one screen for
# text, as a terminal shows both streams, one per stream for JSON's fields.
mutable struct PlainScreens
    const stdout::TerminalText{IOBuffer}
    const stderr::TerminalText{IOBuffer}
    last_run::Int  # of the latest output the screens hold
    last_time::Float64
    prompting::Bool  # the REPL's latest writes are its line editing
end

struct Watcher
    json::Bool
    plain::Union{Nothing, PlainScreens}
    queue::Channel{Vector{UInt8}}
end

function Watcher(json::Bool, color::Bool)
    plain = if json || !color
        screen = TerminalText(IOBuffer())
        PlainScreens(screen, if json TerminalText(IOBuffer()) else screen end, 0, 0.0, false)
    end
    Watcher(json, plain, Channel{Vector{UInt8}}(Inf))
end

const WATCHER_BACKLOG = 4096  # chunks queued before a stalled watcher is dropped
const QUIET_ROWS_S = 0.5  # how long a live plain watch holds rows left untouched

# Whole records start at each of `starts`, oldest first; the ring's wrap may
# tear the record before them. The newest grows in place while its run keeps
# writing the same stream.
mutable struct Transcript
    const lock::ReentrantLock
    @atomic history::Union{Nothing, OutputHistory}  # from when recording starts
    const starts::Vector{Int}
    const watchers::Vector{Watcher}
    last_kind::Symbol
    last_run::Int
    last_length::Int
    runs::Int
end

Transcript() = Transcript(ReentrantLock(), nothing, Int[], Watcher[], :none, 0, 0, 0)

isrecording(t::Transcript) = !isnothing(@atomic t.history)

# A capacity that cannot hold a header records nothing.
function start_recording!(t::Transcript)
    HISTORY_BYTES > RECORD_HEADER_BYTES || return
    @lock t.lock begin
        isrecording(t) || @atomic t.history = OutputHistory(HISTORY_BYTES)
    end
end

# A run's handle on its session's transcript. Its header is recorded with its
# first event, so a run that began before recording started still appears.
mutable struct Recording
    const transcript::Transcript
    const run::Int
    const started::Float64
    const command::String
    announced::Bool
    editing::Bool  # a terminal REPL's line, so its terminal draws the prompt
end

Recording(t::Transcript, run::Int, started::Float64, command::String) =
    Recording(t, run, started, command, false, false)

const TRANSCRIPTS = (lock = ReentrantLock(), sessions = Dict{String, Transcript}())

# `interactive`: the session's first run is, as `isinteractive()` tells.
function session_transcript(label::String; interactive::Bool=false)
    @lock TRANSCRIPTS.lock get!(TRANSCRIPTS.sessions, label) do
        transcript = Transcript()
        if RECORD_LEVEL >= record_session || (interactive && RECORD_LEVEL >= record_interactive)
            start_recording!(transcript)
        end
        transcript
    end
end

# The session's end: its watchers finish, and its memory is freed.
function drop_transcript!(label::String)
    transcript = @lock TRANSCRIPTS.lock pop!(TRANSCRIPTS.sessions, label, nothing)
    isnothing(transcript) && return
    @lock transcript.lock begin
        foreach(w -> close(w.queue), transcript.watchers)
        empty!(transcript.watchers)
    end
end

function begin_run(label::String, command::String; interactive::Bool=false)
    transcript = session_transcript(label; interactive)
    run = @lock transcript.lock transcript.runs += 1
    Recording(transcript, run, time(), command)
end

function record!(r::Recording, kind::Symbol, data)
    t = r.transcript
    isrecording(t) || return
    @lock t.lock begin
        if !r.announced
            r.announced = true
            append_record!(t, TranscriptEvent(r.started, r.run, :run, codeunits(r.command)))
        end
        if kind === :stdout && r.editing && TERMINAL_WRITE[]
            kind = :prompt
        end
        append_record!(t, TranscriptEvent(time(), r.run, kind, if data isa AbstractString codeunits(data) else data end))
    end
end

# Under `t.lock`, with `t` recording.
function append_record!(t::Transcript, event::TranscriptEvent)
    history = @atomic t.history
    n = length(event.data)
    # Pruning below leaves every listed record whole, the newest included.
    extends = !isempty(t.starts) && event.kind ∈ (:stdout, :stderr) &&
        event.kind === t.last_kind && event.run == t.last_run
    if extends
        capture!(history, event.data)
        t.last_length += n
        overwrite!(history, last(t.starts) + RECORD_HEADER_BYTES - 4, reinterpret(UInt8, [UInt32(t.last_length)]))
    else
        push!(t.starts, history.total)
        header = IOBuffer(sizehint=RECORD_HEADER_BYTES)
        write(header, UInt8(findfirst(==(event.kind), RECORD_KINDS)), UInt32(event.run), event.time, UInt32(n))
        capture!(history, take!(header))
        capture!(history, event.data)
        t.last_kind, t.last_run, t.last_length = event.kind, event.run, n
    end
    # After the writes, which may have grown the ring.
    while !isempty(t.starts) && first(t.starts) < history.total - length(history.bytes)
        popfirst!(t.starts)
    end
    filter!(t.watchers) do w
        if Base.n_avail(w.queue) >= WATCHER_BACKLOG
            close(w.queue)
            return false
        end
        bytes = render(w, event)
        isempty(bytes) || put!(w.queue, bytes)
        true
    end
end

# The whole records, oldest first, plus how many earlier bytes were dropped.
function transcript_events(t::Transcript)
    @lock t.lock begin
        isrecording(t) || return TranscriptEvent[], 0
        bytes, dropped = linearise(@atomic t.history)
        io = IOBuffer(bytes)
        events = map(t.starts) do start
            seek(io, start - dropped)
            kind = RECORD_KINDS[read(io, UInt8)]
            run, time, n = read(io, UInt32), read(io, Float64), read(io, UInt32)
            TranscriptEvent(time, run, kind, read(io, n))
        end
        events, dropped
    end
end

# A session run's stdout or stderr, copied into its transcript once recording.
struct RecordedOutput <: IO
    sink::IO
    recording::Recording
    stream::Symbol
end

# The recording check comes first, sparing an unrecorded write the byte view.
function Base.unsafe_write(io::RecordedOutput, p::Ptr{UInt8}, n::UInt)
    isrecording(io.recording.transcript) && record!(io.recording, io.stream, unsafe_wrap(Array, p, Int(n)))
    unsafe_write(io.sink, p, n)
end

function Base.write(io::RecordedOutput, byte::UInt8)
    isrecording(io.recording.transcript) && record!(io.recording, io.stream, UInt8[byte])
    write(io.sink, byte)
end

for f in (:flush, :close, :closewrite, :isopen, :iswritable, :reseteof)
    @eval Base.$f(io::RecordedOutput) = $f(io.sink)
end
Base.isreadable(::RecordedOutput) = false
Base.bytesavailable(::RecordedOutput) = 0
Base.buffer_writes(io::RecordedOutput, args...) = Base.buffer_writes(io.sink, args...)

"""
    watch_session(label, format, out, color; until) -> exit code

Write the transcript of session `label` to `out`, then follow it until
`until` ends: the watcher's signals socket, which it holds until it exits
(its stdin may end at once). The comma-separated `format` may hold `once`,
to stop after the transcript so far, and `json`, for one JSON object per
line. An unrecorded session is recorded from the first watch on.
"""
function watch_session(label::String, format::String, out::IO, color::Bool; until::IO)
    options = split(format, ',', keepempty=false)
    unknown = setdiff(options, ("json", "once"))
    if !isempty(unknown)
        println(out, "--watch: unknown option ", join(unknown, ", "), "; expected json and/or once")
        return 1
    end
    json = "json" ∈ options
    transcript = session_transcript(label)
    if !isrecording(transcript)
        start_recording!(transcript)
        json || println(out, if isempty(label) "This worker's session" else "Session '$label'" end,
                        " was not being recorded; it is from now on.")
    end
    watcher = Watcher(json, color)
    # Replay and subscription under one lock, so no event falls between them.
    @lock transcript.lock begin
        for event in first(transcript_events(transcript))
            bytes = render(watcher, event)
            isempty(bytes) || put!(watcher.queue, bytes)
        end
        if "once" ∈ options
            put!(watcher.queue, released(watcher, finish!))
            close(watcher.queue)
        else
            push!(transcript.watchers, watcher)
            isnothing(watcher.plain) || Timer(QUIET_ROWS_S; interval = QUIET_ROWS_S) do timer
                @lock transcript.lock begin
                    if watcher ∈ transcript.watchers
                        bytes = released(watcher, release_quiet!)
                        isempty(bytes) || put!(watcher.queue, bytes)
                    else
                        close(timer)
                    end
                end
            end
            Threads.@spawn begin
                try
                    while !eof(until) readavailable(until) end
                catch
                end
                @lock transcript.lock filter!(w -> w !== watcher, transcript.watchers)
                close(watcher.queue)
            end
        end
    end
    for chunk in watcher.queue
        write(out, chunk)
        flush(out)
    end
    0
end

# Nothing while a plain destination's output is still held. Every other event
# settles the screens, so output is complete before the next input. JSON
# leaves out the line editing, having the input, but a REPL prompting again
# has finished its response, so settles it.
function render(w::Watcher, event::TranscriptEvent)
    plain = w.plain
    isnothing(plain) && return format_event(w, event, true)
    if w.json && event.kind === :prompt
        settled = if plain.prompting UInt8[] else released(w, finish!) end
        plain.prompting = true
        return settled
    end
    if event.kind ∈ (:stdout, :stderr, :prompt)
        plain.prompting = event.kind === :prompt
        stream = ifelse(event.kind === :prompt, :stdout, event.kind)
        plain.last_run, plain.last_time = event.run, event.time
        screen = getfield(plain, stream)
        write(screen, event.data)
        data = take!(screen.sink)
        isempty(data) && return UInt8[]
        return format_event(w, TranscriptEvent(event.time, event.run, stream, data), false)
    end
    vcat(released(w, finish!), format_event(w, event, false))
end

format_event(w::Watcher, event::TranscriptEvent, color::Bool) =
    if w.json json_event(event) else render_text(event, color) end

# The rows `release!` lets go from a plain destination's screens.
function released(w::Watcher, release!)
    out = UInt8[]
    plain = w.plain
    isnothing(plain) && return out
    streams = if plain.stdout === plain.stderr
        (:stdout,)
    else
        (:stdout, :stderr)
    end
    for stream in streams
        screen = getfield(plain, stream)
        release!(screen)
        data = take!(screen.sink)
        isempty(data) || append!(out, format_event(w, TranscriptEvent(plain.last_time, plain.last_run, stream, data), false))
    end
    out
end

# Each kind's JSON event name, and the field its data goes in.
const JSON_SHAPES = (run = ("run", "command"), input = ("input", "code"), typed = ("input", "code"),
                     stdout = ("output", "data"), stderr = ("output", "data"), exit = ("exit", "code"))

function json_event(event::TranscriptEvent)
    io = IOBuffer()
    name, field = JSON_SHAPES[event.kind]
    print(io, "{\"event\":\"", name, "\",\"run\":", event.run, ",\"time\":", event.time)
    event.kind ∈ (:stdout, :stderr) && print(io, ",\"stream\":\"", event.kind, '"')
    data = if event.kind ∈ (:input, :typed)
        mode, code = input_parts(event)
        print(io, ",\"mode\":")
        write_json_string(io, mode)
        code
    else
        event.data
    end
    print(io, ",\"", field, "\":")
    if event.kind === :exit
        write(io, data)  # the code, a number
    else
        write_json_string(io, data)
    end
    println(io, '}')
    take!(io)
end

function render_text(event::TranscriptEvent, color::Bool)
    dim(text) = if color "\e[2m$text\e[22m" else text end
    io = IOBuffer()
    if event.kind === :run
        println(io, dim("── run $(event.run) · $(Libc.strftime("%H:%M:%S", event.time)) · juliaclient $(String(copy(event.data)))"))
    elseif event.kind === :exit
        code = String(copy(event.data))
        code == "0" || println(io, dim("── run $(event.run) exited with code $code"))
    elseif event.kind === :input  # piped, so at the julia> prompt
        println(io, if color "\e[32;1mjulia>\e[m " else "julia> " end, String(copy(input_parts(event)[2])))
    elseif event.kind ∈ (:stdout, :stderr, :prompt)
        write(io, event.data)
    end
    take!(io)
end

function input_parts(event::TranscriptEvent)
    split = something(findfirst(==(UInt8('\n')), event.data), lastindex(event.data) + 1)
    view(event.data, 1:split-1), view(event.data, split+1:lastindex(event.data))
end

const JSON_ESCAPES = Dict('"' => "\\\"", '\\' => "\\\\", '\n' => "\\n", '\r' => "\\r", '\t' => "\\t")

# Invalid UTF-8 (binary output) becomes U+FFFD, as JSON strings must be Unicode.
function write_json_string(io::IO, data::AbstractVector{UInt8})
    print(io, '"')
    for c in String(copy(data))
        print(io, if !isvalid(c)
            "\\ufffd"
        elseif haskey(JSON_ESCAPES, c)
            JSON_ESCAPES[c]
        elseif c < ' '
            "\\u" * string(UInt32(c), base=16, pad=4)
        else
            c
        end)
    end
    print(io, '"')
end
