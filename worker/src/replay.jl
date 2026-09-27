# SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
# SPDX-License-Identifier: MPL-2.0

# What a terminal joining a sync session is shown of its screen so far: its
# latest prompts, and as much of their output as a budget of screen rows
# allows, measured at the joiner's width.

const REPLAY_LEAST_OUTPUT_ROWS = 4  # an output's rows when cut, its marker among them

const CLEARS = r"\e\[[23]J|\ec"
const ALTERNATE_SCREEN = r"\e\[\?(47|1047|1049)h"

# A prompt, as the REPL drew it (its line editing), and the output after it.
struct Exchange
    prompt::Vector{UInt8}
    output::Vector{UInt8}
    whole::Bool  # not begun partway: torn by the ring, or cut at a clear
end

# An exchange as rows of a terminal `columns` wide, styled.
struct ShownExchange
    exchange::Exchange
    prompt::Vector{String}
    output::Vector{String}
    verbatim::Bool  # its bytes can be replayed as they are
end

"""
    replay_history(dest::IO, screen::Recording, displaysize::Tuple{Int, Int}, pages::Int)

Replay a sync session's `screen` to `dest`, a terminal of `displaysize`
(rows, columns), in at most `pages` of its height (0 for all of it).
The latest prompts are shown, the more recent outputs the more fully; a
line notes the prompts left out. Replayed while its REPL edits a line, the
cursor ends where the REPL's is, ready for it to redraw.
"""
function replay_history(dest::IO, screen::Recording, (height, columns)::Tuple{Int, Int}, pages::Int)
    exchanges, lost = screen_exchanges(screen)
    budget = if pages == 0 typemax(Int) else pages * height end
    # Measured only as far back as `allot_rows` reaches, newest first.
    shown = ShownExchange[]
    sizes = Iterators.map(reverse(eachindex(exchanges))) do i
        push!(shown, show_exchange(exchanges[i], columns))
        length(shown[end].prompt), length(shown[end].output)
    end
    allowances = allot_rows(sizes, budget)
    trimmed = length(exchanges) - length(allowances)
    if trimmed > 0 || lost
        write(dest, "\r\e[2K\e[2m── ", trimmed_note(trimmed, lost), " ──\e[m\r\n")
    end
    live = screen.editing && !isempty(exchanges) && isempty(exchanges[end].output)
    for i in reverse(eachindex(allowances))
        replay_exchange(dest, shown[i], allowances[i]; live=live && i == 1)
    end
end

function trimmed_note(trimmed::Int, lost::Bool)
    prompts = string(trimmed, " earlier prompt", if trimmed == 1 "" else "s" end)
    if !lost
        prompts * " not shown"
    elseif trimmed == 0
        "earlier prompts lost"
    else
        prompts * " not shown, and more lost"
    end
end

# The screen's exchanges since it was last cleared, oldest first, and whether
# the ring has lost earlier ones, as it has once the run's header is gone;
# that tears the oldest, whose prompt is left out.
function screen_exchanges(screen::Recording)
    events, dropped = transcript_events(screen.transcript)
    parts = Tuple{Vector{UInt8}, Vector{UInt8}}[]  # each prompt and output
    for e in events
        e.run == screen.run && e.kind ∈ (:prompt, :stdout, :stderr) || continue
        prompting = e.kind === :prompt
        if isempty(parts) || prompting && !isempty(parts[end][2])
            push!(parts, (UInt8[], UInt8[]))
        end
        append!(if prompting parts[end][1] else parts[end][2] end, e.data)
    end
    exchanges = Exchange[]
    for (prompt, output) in Iterators.reverse(parts)
        cut = after_clear(output)
        if !isnothing(cut)
            return pushfirst!(exchanges, Exchange(UInt8[], output[cut:end], false)), false
        end
        cut = after_clear(prompt)
        if !isnothing(cut)
            return pushfirst!(exchanges, Exchange(prompt[cut:end], output, false)), false
        end
        pushfirst!(exchanges, Exchange(prompt, output, true))
    end
    lost = dropped > 0 && !isempty(exchanges) && !any(e -> e.run == screen.run && e.kind === :run, events)
    if lost
        exchanges[1] = Exchange(UInt8[], exchanges[1].output, false)
    end
    exchanges, lost
end

# The index after the last clear in `bytes`, if any.
function after_clear(bytes::Vector{UInt8})
    clears = collect(eachmatch(CLEARS, String(copy(bytes))))
    isempty(clears) && return nothing
    last(clears).offset + ncodeunits(last(clears).match)
end

function show_exchange(exchange::Exchange, columns::Int)
    function rows(bytes)
        io = IOBuffer()
        text = TerminalText(io; styled=true, columns)
        write(text, bytes)
        finish!(text)
        split(String(take!(io)), '\n'; keepempty=true)[1:end-1]
    end
    verbatim = exchange.whole && !any(bytes -> occursin(ALTERNATE_SCREEN, String(copy(bytes))), (exchange.prompt, exchange.output))
    ShownExchange(exchange, rows(exchange.prompt), rows(exchange.output), verbatim)
end

"""
    allot_rows(sizes, budget::Int) -> Vector{Int}

The output rows to replay of each of the latest exchanges, whose `sizes` are
`(prompt_rows, output_rows)` from the newest back. Exchanges are taken while
they fit, each at its least: its prompt, and up to `REPLAY_LEAST_OUTPUT_ROWS`
of its output (the newest is always taken). What is left of `budget` is then
shared among their outputs, the `i`th newest weighted `1/i`, and what one
can't use shared again, until each is whole or none is left.

Only as many `sizes` are taken as are needed.
"""
function allot_rows(sizes, budget::Int)
    outputs, used = Int[], 0
    for (prompt, output) in sizes
        least = prompt + min(output, REPLAY_LEAST_OUTPUT_ROWS)
        used + least > budget && !isempty(outputs) && break
        push!(outputs, output)
        used += least
    end
    allowances = min.(outputs, REPLAY_LEAST_OUTPUT_ROWS)
    spare = budget - used
    wanting = findall(allowances .< outputs)
    while spare > 0 && !isempty(wanting)
        needs = outputs[wanting] .- allowances[wanting]
        grants = if sum(needs) <= spare
            needs
        else
            weights = 1 ./ wanting
            min.(needs, floor.(Int, spare .* weights ./ sum(weights)))
        end
        # Shares too small to be a row go to the newest.
        if all(iszero, grants)
            grants[1] = 1
        end
        allowances[wanting] .+= grants
        spare -= sum(grants)
        filter!(i -> allowances[i] < outputs[i], wanting)
    end
    allowances
end

# Whole and without the alternate screen, an exchange is replayed as it was
# written; otherwise as rows, a cut output keeping a third of its rows
# from its start and the rest from its end. A live prompt ends at its cursor.
function replay_exchange(dest::IO, shown::ShownExchange, allowance::Int; live::Bool)
    if shown.verbatim && allowance == length(shown.output)
        write(dest, shown.exchange.prompt, shown.exchange.output, "\e[m")
        return
    end
    output = if allowance == length(shown.output)
        shown.output
    else
        head = (allowance - 1) ÷ 3
        tail = allowance - 1 - head
        hidden = length(shown.output) - head - tail
        [shown.output[1:head]; "\e[2m⋮ $hidden lines hidden\e[m"; shown.output[end-tail+1:end]]
    end
    rows = [shown.prompt; output]
    join(dest, rows, "\r\n")
    live || isempty(rows) || write(dest, "\r\n")
end
