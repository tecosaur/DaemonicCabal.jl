# SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
# SPDX-License-Identifier: MPL-2.0

const TERMINAL_WINDOW = 32  # rows kept editable before they reach the sink

# A colour is 0 for the default, `PALETTE | n` for palette entry `n`, or
# `DIRECT | rgb`. Attribute bit `n` is SGR `n`, 1 to 9.
const PALETTE = UInt32(1) << 24
const DIRECT = UInt32(2) << 24

const Style = @NamedTuple{foreground::UInt32, background::UInt32, attributes::UInt16}
const UNSTYLED = Style((0, 0, 0))

struct Cell
    char::Char
    style::Style
end

"""
    TerminalText(sink::IO) <: IO

Terminal output as plain text: what a terminal would finally have shown.
The last `TERMINAL_WINDOW` rows stay editable, as cursor movement within
them redraws in place (a progress bar, a multi-line prompt); a row reaches
`sink` once it scrolls out of that window, is left untouched above the
cursor between calls of `release_quiet!`, or at `finish!`. Clearing the
screen releases the window rather than erasing it, so what was cleared is
kept. Escape sequences leave no text, save those moving the cursor, erasing,
or saving and restoring the cursor; absolute positions count from the
window's top, and the cursor never moves past its last row but by a line feed.
What is drawn on the alternate screen, which a terminal discards, is dropped.

When `styled`, each character keeps the colours and attributes (SGR) it was
drawn with, and a released row sets each change of them and ends unstyled.
"""
mutable struct TerminalText{S <: IO} <: IO
    const sink::S
    const styled::Bool
    state::Symbol  # :ground, :escape, :escape_intermediate, :csi, :csi_private, :csi_ignore, :string
    alternate::Bool  # on the alternate screen
    const params::Vector{Int}  # a CSI sequence's parameters
    const rows::Vector{Vector{Cell}}  # the window, oldest first
    row::Int  # the cursor's, in `rows`
    column::Int  # the cursor's, 0-based
    released::Int  # rows already sent to `sink`, so saved rows stay absolute
    saved::Tuple{Int, Int}  # absolute row and column
    edited_top::Int  # the topmost absolute row edited since `release_quiet!`
    style::Style  # what a character is drawn with
    const utf8::Vector{UInt8}  # a character's bytes so far
end

TerminalText(sink::IO; styled::Bool=false) =
    TerminalText(sink, styled, :ground, false, Int[], [Cell[]], 1, 0, 0, (1, 0), typemax(Int), UNSTYLED, UInt8[])

function Base.unsafe_write(t::TerminalText, p::Ptr{UInt8}, n::UInt)
    transform!(t, unsafe_wrap(Array, p, Int(n)))
    Int(n)
end

function Base.write(t::TerminalText, byte::UInt8)
    transform!(t, [byte])
    1
end

# The window stays held: a later cursor movement may redraw it.
Base.flush(t::TerminalText) = flush(t.sink)

"""
    finish!(t::TerminalText)

Release the whole window, as at the end of the output, and leave `t` as new.
"""
function finish!(t::TerminalText)
    end_partial!(t)
    release_window!(t)
    t.column = 0
    t.state = :ground
    t.alternate = false
    t.edited_top = typemax(Int)
    t.style = UNSTYLED
end

"""
    release_quiet!(t::TerminalText)

Release the rows above the cursor's left untouched since the last call, so
output that has settled need not wait to scroll out of the window.
"""
function release_quiet!(t::TerminalText)
    n = max(0, min(t.row, t.edited_top - t.released) - 1)
    foreach(row -> write_row(t, row), view(t.rows, 1:n))
    deleteat!(t.rows, 1:n)
    t.released += n
    t.row -= n
    t.edited_top = typemax(Int)
end

# Only valid, unstyled text appended at the window's end moves as it is, bar
# the rows staying editable.
function transform!(t::TerminalText, data)
    appending = t.state === :ground && !t.alternate && isempty(t.utf8) && t.row == length(t.rows) &&
        t.column == length(t.rows[end]) && (!t.styled || t.style == UNSTYLED)
    if appending && all(b -> b >= 0x20 && b != 0x7f || b == UInt8('\n') || b == UInt8('\t'), data) &&
            isvalid(String, data)
        newlines = findall(==(UInt8('\n')), data)
        if length(newlines) > TERMINAL_WINDOW
            # Everything to this newline scrolls out beyond reach.
            cut = newlines[end - TERMINAL_WINDOW]
            foreach(row -> write_row(t, row), view(t.rows, 1:length(t.rows)-1))
            write_row(t, t.rows[end]; newline=false)
            write(t.sink, view(data, 1:cut))
            t.released += length(t.rows) - 1 + (length(newlines) - TERMINAL_WINDOW)
            empty!(t.rows)
            push!(t.rows, Cell[])
            t.row, t.column = 1, 0
            data = view(data, cut+1:lastindex(data))
        end
    end
    foreach(byte -> step!(t, byte), data)
end

# The transitions of the DEC parser (vt100.net/emu/dec_ansi_parser), with
# the device control and OSC strings alike, and only the sequences acted on.
function step!(t::TerminalText, byte::UInt8)
    state = t.state
    if state === :ground
        ground!(t, byte)
    elseif byte == 0x18 || byte == 0x1a  # CAN and SUB abort a sequence
        t.state = :ground
    elseif byte == 0x1b  # ends a string too, as the start of its ST
        t.state = :escape
    elseif state === :string
        byte == 0x07 && (t.state = :ground)
    elseif byte < 0x20 || byte == 0x7f  # controls act within a sequence
        control!(t, byte)
    elseif state === :escape
        t.state = escape!(t, byte)
    elseif state === :escape_intermediate
        byte >= 0x30 && (t.state = :ground)
    elseif byte >= 0x40  # a CSI's final byte
        if state === :csi
            csi!(t, Char(byte))
        elseif state === :csi_private && byte in b"hl" && any(in((47, 1047, 1049)), t.params)
            t.alternate = byte == UInt8('h')
        end
        t.state = :ground
    elseif state === :csi && isempty(t.params) && byte == UInt8('?')
        t.state = :csi_private
    elseif state !== :csi_ignore && 0x30 <= byte <= 0x3b  # digits, `:` and `;`
        isempty(t.params) && push!(t.params, 0)
        if byte >= 0x3a
            length(t.params) < 16 && push!(t.params, 0)
        else
            t.params[end] = min(10 * t.params[end] + (byte - 0x30), 0xffff)
        end
    else  # a private marker or an intermediate, in no sequence acted on
        t.state = :csi_ignore
    end
end

function ground!(t::TerminalText, byte::UInt8)
    t.alternate && byte != 0x1b && return
    byte & 0xc0 == 0x80 || end_partial!(t)
    if byte == 0x1b
        t.state = :escape
    elseif byte < 0x20 && byte != UInt8('\t') || byte == 0x7f
        control!(t, byte)
    elseif byte < 0x80 && isempty(t.utf8)
        put_char!(t, Char(byte))
    else
        push!(t.utf8, byte)
        lead = t.utf8[1]
        length(t.utf8) < if lead < 0xc0 1 elseif lead < 0xe0 2 elseif lead < 0xf0 3 else 4 end && return
        char = String(copy(t.utf8))
        empty!(t.utf8)
        put_char!(t, if isvalid(char) first(char) else '�' end)
    end
end

# A character cut short by a byte that can't continue it.
function end_partial!(t::TerminalText)
    isempty(t.utf8) && return
    empty!(t.utf8)
    put_char!(t, '�')
end

function control!(t::TerminalText, byte::UInt8)
    t.alternate && return
    if UInt8('\n') <= byte <= 0x0c  # LF, VT and FF
        line_feed!(t)
        t.column = 0
    elseif byte == UInt8('\r')
        t.column = 0
    elseif byte == 0x08
        t.column = max(0, t.column - 1)
    end
end

# The state after ESC and `byte`.
function escape!(t::TerminalText, byte::UInt8)
    if byte == UInt8('[')
        empty!(t.params)
        :csi
    elseif byte in b"]P_^X"  # OSC, DCS, APC, PM, SOS
        :string
    elseif byte < 0x30  # like a charset's designation
        :escape_intermediate
    elseif t.alternate
        :ground
    else
        if byte == UInt8('M')  # reverse index
            t.row = max(1, t.row - 1)
        elseif byte == UInt8('D')  # index
            line_feed!(t)
        elseif byte == UInt8('E')  # next line
            line_feed!(t)
            t.column = 0
        elseif byte == UInt8('7')
            save_cursor!(t)
        elseif byte == UInt8('8')
            restore_cursor!(t)
        end
        :ground
    end
end

function put_char!(t::TerminalText, c::Char)
    t.edited_top = min(t.edited_top, t.released + t.row)
    line = t.rows[t.row]
    if t.column < length(line)
        line[t.column + 1] = Cell(c, t.style)
    else
        append!(line, fill(Cell(' ', UNSTYLED), t.column - length(line)))
        push!(line, Cell(c, t.style))
    end
    t.column += 1
end

# Onto the next row, a new one at the end, releasing the oldest beyond the window.
function line_feed!(t::TerminalText)
    t.row += 1
    t.row <= length(t.rows) && return
    push!(t.rows, Cell[])
    length(t.rows) > TERMINAL_WINDOW || return
    write_row(t, popfirst!(t.rows))
    t.released += 1
    t.row -= 1
end

# Every row to the sink but a last empty one, the cursor's row becoming the first.
function release_window!(t::TerminalText)
    last_row = if isempty(t.rows[end]) length(t.rows) - 1 else length(t.rows) end
    foreach(row -> write_row(t, row), view(t.rows, 1:last_row))
    t.released += length(t.rows)
    empty!(t.rows)
    push!(t.rows, Cell[])
    t.row = 1
end

save_cursor!(t::TerminalText) = t.saved = (t.released + t.row, t.column)

function restore_cursor!(t::TerminalText)
    row, t.column = t.saved
    t.row = clamp(row - t.released, 1, length(t.rows))
end

# The CSI sequences moving the cursor or erasing; the rest leave no text.
function csi!(t::TerminalText, final::Char)
    t.alternate && return
    n = get(t.params, 1, 0)
    count = max(n, 1)
    line = t.rows[t.row]
    final in "KJ" && (t.edited_top = min(t.edited_top, t.released + t.row))
    if final == 'K'  # erase in the row: to its end (0), from its start (1), all (2)
        if n == 0
            resize!(line, min(length(line), t.column))
        elseif n == 1
            fill!(view(line, 1:min(t.column + 1, length(line))), Cell(' ', UNSTYLED))
        else
            empty!(line)
        end
    elseif final == 'J'  # erase below the cursor (0), or clear the screen (2, 3)
        if n == 0
            resize!(line, min(length(line), t.column))
            resize!(t.rows, t.row)
        elseif n >= 2
            release_window!(t)
        end
    elseif final == 'A' || final == 'F'  # up, previous line
        t.row = max(1, t.row - count)
        final == 'F' && (t.column = 0)
    elseif final == 'B' || final == 'E'  # down, next line
        t.row = min(length(t.rows), t.row + count)
        final == 'E' && (t.column = 0)
    elseif final == 'C'
        t.column += count
    elseif final == 'D'
        t.column = max(0, t.column - count)
    elseif final == 'G'
        t.column = count - 1
    elseif final == 'H' || final == 'f'
        t.row = min(length(t.rows), count)
        t.column = max(get(t.params, 2, 0), 1) - 1
    elseif final == 'm'
        sgr!(t)
    elseif final == 's'
        save_cursor!(t)
    elseif final == 'u'
        restore_cursor!(t)
    end
end

# Select Graphic Rendition: its parameters, in order, change the style.
function sgr!(t::TerminalText)
    (; foreground, background, attributes) = t.style
    params = if isempty(t.params)
        [0]
    else
        t.params
    end
    # The colour an extended (38, 48) one names from `i`, and the parameters it spans.
    function extended(i)
        mode = get(params, i + 1, 0)
        if mode == 5
            PALETTE | get(params, i + 2, 0) & 0xff, 3
        elseif mode == 2
            r, g, b = (get(params, i + k, 0) & 0xff for k in 2:4)
            DIRECT | r << 16 | g << 8 | b, 5
        else
            nothing, 2
        end
    end
    i = 1
    while i <= length(params)
        n = params[i]
        span = 1
        if n == 0
            foreground, background, attributes = UNSTYLED.foreground, UNSTYLED.background, UNSTYLED.attributes
        elseif 1 <= n <= 9
            attributes |= UInt16(1) << n
        elseif n == 21  # double underline
            attributes |= UInt16(1) << 4
        elseif n == 22  # neither bold nor dim
            attributes &= ~(UInt16(1) << 1 | UInt16(1) << 2)
        elseif 23 <= n <= 29
            attributes &= ~(UInt16(1) << (n - 20))
        elseif 30 <= n <= 37 || 90 <= n <= 97
            foreground = PALETTE | n % 10 + 8 * (n >= 90)
        elseif 40 <= n <= 47 || 100 <= n <= 107
            background = PALETTE | n % 10 + 8 * (n >= 100)
        elseif n == 38 || n == 48
            colour, span = extended(i)
            if n == 38
                foreground = something(colour, foreground)
            else
                background = something(colour, background)
            end
        elseif n == 39
            foreground = UNSTYLED.foreground
        elseif n == 49
            background = UNSTYLED.background
        end
        i += span
    end
    t.style = (; foreground, background, attributes)
end

# A row to the sink: its text, and when styled, each change of style.
function write_row(t::TerminalText, row::Vector{Cell}; newline::Bool=true)
    style = UNSTYLED
    for cell in row
        if t.styled && cell.style != style
            style = cell.style
            write_sgr(t.sink, style)
        end
        print(t.sink, cell.char)
    end
    style == UNSTYLED || print(t.sink, "\e[0m")
    newline && print(t.sink, '\n')
end

# The whole style, from a reset: so a row can start anywhere.
function write_sgr(io::IO, style::Style)
    print(io, "\e[0")
    foreach(n -> style.attributes >> n & 1 == 1 && print(io, ';', n), 1:9)
    for (colour, base) in ((style.foreground, 30), (style.background, 40))
        kind, value = colour & ~0xffffff, colour & 0xffffff
        if kind == PALETTE && value < 16
            print(io, ';', base + value % 8 + 60 * (value >= 8))
        elseif kind == PALETTE
            print(io, ';', base + 8, ";5;", value)
        elseif kind == DIRECT
            print(io, ';', base + 8, ";2;", value >> 16, ';', value >> 8 & 0xff, ';', value & 0xff)
        end
    end
    print(io, 'm')
end
