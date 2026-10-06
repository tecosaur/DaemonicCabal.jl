#!/usr/bin/env -S julia --startup-file=no
using TOML
using Pkg
using SHA

staged::Bool = false
release::Bool = false
rev::Union{String, Nothing} = nothing

while !isempty(ARGS)
    arg = popfirst!(ARGS)
    if arg == "--staged"
        global staged = true
    elseif arg == "--release"
        global release = true
    elseif startswith(arg, "--rev=")
        global rev = chopprefix(arg, "--rev=")
    elseif arg == "--rev"
        if isempty(ARGS)
            @error "Expected a revision after --rev"
            exit(1)
        end
        global rev = popfirst!(ARGS)
    elseif arg ∈ ("--help", "-h")
        print("""
            Usage: build.jl [OPTIONS]
            Options:
              --staged           Use a staged worktree for building
              --release          Build release binaries
              --rev=REV          Build from a specific git revision
              --rev REV          Build from a specific git revision
              -h, --help         Show this help message and exit
            """)
        exit(0)
    else
        @error "Unknown argument: $arg"
        exit(1)
    end
end

if staged && !isnothing(rev)
    @error "Cannot use --staged and specify a revision with --rev"
    exit(1)
end

const ZIG = let vendored = joinpath(@__DIR__, "zig", "zig" * (Sys.iswindows() ? ".exe" : ""))
    isfile(vendored) ? vendored : something(Sys.which("zig"), vendored)
end
const BASE_FLAGS = ["-fsingle-threaded", "-fPIE"]
const BINARIES = [
    ("julia-conductor", "conductor/main.zig"),
    ("juliaclient",     "client/client.zig"),
]
const SERVICE_NAME = "julia-daemon"
const SERVICE_FILE, STOP_SERVICE, START_SERVICE = if Sys.isapple()
    plist = joinpath(homedir(), "Library", "LaunchAgents", "org.julialang.$SERVICE_NAME.plist")
    plist, `launchctl unload $plist`, [`launchctl load $plist`]
else
    joinpath(get(ENV, "XDG_CONFIG_HOME", joinpath(homedir(), ".config")), "systemd", "user", "$SERVICE_NAME.service"),
    `systemctl --user stop $SERVICE_NAME`, [`systemctl --user daemon-reload`, `systemctl --user start $SERVICE_NAME`]
end

function with_srcdir(f)
    staged || !isnothing(rev) || return f(@__DIR__)
    repo = @__DIR__
    if staged
        original_head = readchomp(`git -C $repo rev-parse HEAD`)
        run(`git -C $repo commit --allow-empty -m "tmp staged build"`)
    end
    commit = readchomp(`git -C $repo rev-parse $(something(rev, "HEAD"))`)
    tmpdir = mktempdir()
    try
        run(`git -C $repo worktree add $tmpdir $commit --detach`)
        return f(tmpdir)
    finally
        run(`git -C $repo worktree remove --force $tmpdir`)
        staged && run(`git -C $repo reset --soft $original_head`)
    end
end

function build_binaries(srcdir; outdir, flags, exe=Sys.iswindows() ? ".exe" : "", runner=run)
    map(BINARIES) do (name, src)
        runner(`$ZIG build-exe $flags -femit-bin=$outdir/$name$exe --name $name $srcdir/$src`)
    end
end

# A debug build is run by the service, with this checkout's conductor and worker.
const manage_service = !release && (Sys.isapple() || Sys.islinux() && !isnothing(Sys.which("systemctl")))

stop_service() = manage_service && isfile(SERVICE_FILE) && run(ignorestatus(STOP_SERVICE))

function run_checkout(srcdir)
    if !isfile(SERVICE_FILE)
        run(`$(Base.julia_cmd()) --project=$(@__DIR__) -e 'using Pkg; Pkg.instantiate(); using DaemonicCabal; DaemonicCabal.install()'`)
        stop_service()
    end
    # A build worktree is removed once with_srcdir returns.
    worker_project = joinpath(srcdir, "worker")
    if srcdir != @__DIR__
        dest = joinpath(tempdir(), "julia-worker-" * bytes2hex(rand(UInt8, 4)))
        cp(worker_project, dest)
        worker_project = dest
        @info "Copied worker to $dest"
    end
    conductor, client = joinpath(@__DIR__, "julia-conductor"), joinpath(@__DIR__, "juliaclient")
    edits = if Sys.isapple()
        [r"(<key>ProgramArguments</key>\s*<array>\s*<string>).*?<"s => SubstitutionString("\\1$conductor<"),
         r"(<key>JULIA_DAEMON_WORKER_PROJECT</key>\s*<string>).*?<"s => SubstitutionString("\\1$worker_project<")]
    else
        [r"^ExecStart=.*$"m => "ExecStart=\"$conductor\"",
         r"^Environment=\"JULIA_DAEMON_WORKER_PROJECT=.*\"$"m => "Environment=\"JULIA_DAEMON_WORKER_PROJECT=$worker_project\""]
    end
    content = read(SERVICE_FILE, String)
    all(e -> occursin(first(e), content), edits) || error("$SERVICE_FILE can't be pointed at this checkout; rerun DaemonicCabal.install()")
    write(SERVICE_FILE, replace(content, edits...))
    link = joinpath(get(ENV, "XDG_BIN_HOME", joinpath(homedir(), ".local", "bin")), "juliaclient")
    rm(link; force=true)
    symlink(client, link)
    foreach(run, START_SERVICE)
    # So a client run straight after the build finds the conductor listening.
    timedwait(10; pollint=0.1) do
        occursin("connected to conductor", read(ignorestatus(`$client --version`), String))
    end === :ok || @warn "$SERVICE_NAME isn't answering after 10s; see its log"
    @info "Restarted $SERVICE_NAME with worker at $worker_project, and $link runs this checkout's client; \
           DaemonicCabal.install() restores a release"
end

function build()
    with_srcdir() do srcdir
        if !release
            @info "native (debug)"
            stop_service()
            flags = [BASE_FLAGS; "-O"; "Debug"]
            results = build_binaries(srcdir; outdir=@__DIR__, flags,
                runner=cmd -> success(pipeline(cmd; stdout, stderr)))
            if manage_service
                run_checkout(srcdir)
            else
                @info "To run this build, point a service at $(joinpath(@__DIR__, "julia-conductor"))"
            end
            return Int(any(!, results))
        end
        # Release build
        flags = [BASE_FLAGS; "-fstrip"; "-O"; "ReleaseSmall"]
        version = open(TOML.parse, joinpath(@__DIR__, "Project.toml"))["version"]
        builddir = mkpath(joinpath(@__DIR__, "builds"))
        @info "native"
        build_binaries(srcdir; outdir=mkpath(joinpath(builddir, "native")), flags=[flags; "-flto"])
        BUILD_SPECS = [
            ("linux",   "x86_64",  ["-flto"]),
            ("linux",   "aarch64", ["-flto"]),
            ("macos",   "x86_64",  String[]),
            ("macos",   "aarch64", String[]),
            ("freebsd", "x86_64",  String[]),
            ("freebsd", "aarch64", String[]),
            ("freebsd", "arm",     String[]),
            ("openbsd", "x86_64",  String[]),
            ("openbsd", "aarch64", String[]),
            ("windows", "x86_64",  String[]),
            ("windows", "aarch64", String[]),
        ]
        # A directory per target, so no target's output reaches another's bundle.
        artifacts = map(BUILD_SPECS) do (os, arch, extra)
            @info "$os-$arch"
            mktempdir() do workdir
                build_binaries(srcdir; outdir=workdir, exe=os == "windows" ? ".exe" : "",
                               flags=[flags; extra; "-target"; "$arch-$os"])
                tarball = joinpath(builddir, "$os-$arch.tar.gz")
                run(`tar -czf $tarball -C $workdir .`)
                sha = open(io -> bytes2hex(sha256(io)), tarball)
                treehash = bytes2hex(Pkg.GitTools.tree_hash(workdir))
                Dict{String, Any}(
                    "arch" => arch, "os" => os,
                    "git-tree-sha1" => treehash,
                    "download" => [Dict{String, Any}(
                        "url" => "https://github.com/tecosaur/DaemonicCabal.jl/releases/download/$version/$os-$arch.tar.gz",
                        "sha256" => sha)])
            end
        end
        # Pkg reads an entry without libc as glibc's; the binaries are static.
        append!(artifacts, [merge(a, Dict("libc" => "musl")) for a in artifacts if a["os"] == "linux"])
        open(joinpath(@__DIR__, "Artifacts.toml"), "w") do io
            TOML.print(io, Dict("execbundle" => artifacts))
        end
        @info "Updated Artifacts.toml"
        return 0
    end
end

if abspath(PROGRAM_FILE) == @__FILE__
    exit(build())
end
