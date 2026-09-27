# SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
# SPDX-License-Identifier: MPL-2.0

# A terminal's input, which a Ctrl-D ends without closing, as a TTY's does:
# reads meet its end until `reseteof`, which a REPL calls before it prompts,
# and go on from there. A client sends 0x04 for a Ctrl-D while its terminal
# is cooked; in raw mode it is a key like any other.
mutable struct TerminalInput
    const lock::ReentrantLock
    reader::Base.PipeEndpoint  # what reads see
    writer::Base.PipeEndpoint  # where input goes
    next::Union{Nothing, Base.PipeEndpoint}  # the reader after an end, from `reseteof`
    raw::Bool  # as the REPL last set the terminal
end

function TerminalInput()
    pipe = linked_pipe()
    TerminalInput(ReentrantLock(), pipe.out, pipe.in, nothing, false)
end

function linked_pipe()
    pipe = Pipe()
    Base.link_pipe!(pipe; reader_supports_async=true, writer_supports_async=true)
    pipe
end

# Its bytes, with each 0x04 while cooked taken as a Ctrl-D: a cooked terminal
# passes on no other.
function feed_input!(input::TerminalInput, bytes::AbstractVector{UInt8})
    @lock input.lock begin
        rest = bytes
        while !input.raw
            at = findfirst(==(0x04), rest)
            isnothing(at) && break
            write(input.writer, @view rest[1:at-1])
            end_input!(input)
            rest = @view rest[at+1:end]
        end
        write(input.writer, rest)
    end
end

# A second Ctrl-D before `reseteof` finds the input already ended.
function end_input!(input::TerminalInput)
    @lock input.lock begin
        isnothing(input.next) || return
        close(input.writer)
        pipe = linked_pipe()
        input.writer = pipe.in
        input.next = pipe.out
    end
end

function reset_input!(input::TerminalInput)
    @lock input.lock begin
        next = input.next
        if !isnothing(next)
            input.reader = next
            input.next = nothing
        end
    end
end

function close_input!(input::TerminalInput)
    @lock input.lock close(input.writer)
end

is_input_open(input::TerminalInput) = @lock input.lock isopen(input.writer)

current_reader(input::TerminalInput) = @lock input.lock input.reader
current_reader(stream::StreamIO) = stream

# Copies `source` into `input` until it ends, then ends `input` for good. A
# shared input, a --sync session's, outlives its participants: `leaves` says
# whether a lone Ctrl-D where it ends no one's input, at the prompt, is this
# one leaving.
function copy_input(source::StreamIO, input::TerminalInput; leaves::Union{Nothing, Function}=nothing)
    buf = Vector{UInt8}(undef, 64 * 1024)
    try
        while true
            Base.wait_readnb(source, 1)
            n = min(bytesavailable(source), length(buf))
            if n == 0
                eof(source) && break
                continue
            end
            GC.@preserve buf unsafe_read(source, pointer(buf), n)
            # Before 1.11 a REPL's stdin is fixed, so its input can't go on past an end.
            ctrl_d = n == 1 && buf[1] == 0x04 && (input.raw || VERSION < v"1.11")
            ctrl_d && !isnothing(leaves) && leaves() && break
            feed_input!(input, @view buf[1:n])
        end
    catch err
        err isa Base.IOError || err isa EOFError || rethrow()
    finally
        isnothing(leaves) && close_input!(input)
    end
end
