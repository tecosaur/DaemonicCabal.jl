#!/usr/bin/env -S julia --startup-file=no
using TOML
using Pkg

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
        global rev = split(arg, "=", limit=2)[2]
    elseif arg == "--rev"
        if isempty(ARGS)
            @error "Expected a revision after --rev"
            exit(1)
        end
        global rev = popfirst!(ARGS)
    elseif arg ∈ ("--help", "-h")
        println("Usage: build.jl [OPTIONS]")
        println("Options:")
        println("  --staged           Use a staged worktree for building")
        println("  --release          Build release binaries")
        println("  --rev=REV          Build from a specific git revision")
        println("  --rev REV          Build from a specific git revision")
        println("  -h, --help         Show this help message and exit")
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

const ZIG = joinpath(@__DIR__, "zig", "zig")
const BASE_FLAGS = ["-fsingle-threaded", "-fPIE"]
const BINARIES = [
    ("julia-conductor", "conductor/main.zig"),
    ("juliaclient",     "client/client.zig"),
]
const SERVICE_NAME = "julia-daemon"
const SERVICE_FILE = joinpath(get(ENV, "XDG_CONFIG_HOME",
    joinpath(homedir(), ".config")),
    "systemd", "user", "$SERVICE_NAME.service")

function with_srcdir(f)
    if staged
        original_head = readchomp(`git -C $(@__DIR__) rev-parse HEAD`)
        run(`git -C $(@__DIR__) commit --allow-empty -m "tmp staged build"`)
        tmpdir = mktempdir()
        try
            run(`git -C $(@__DIR__) worktree add $tmpdir HEAD --detach`)
            return f(tmpdir)
        finally
            run(`git -C $(@__DIR__) worktree remove --force $tmpdir`)
            run(`git -C $(@__DIR__) reset --soft $original_head`)
        end
    elseif !isnothing(rev)
        resolved = readchomp(`git -C $(@__DIR__) rev-parse $rev`)
        tmpdir = mktempdir()
        try
            run(`git -C $(@__DIR__) worktree add $tmpdir $resolved --detach`)
            return f(tmpdir)
        finally
            run(`git -C $(@__DIR__) worktree remove --force $tmpdir`)
        end
    else
        return f(@__DIR__)
    end
end

function build_binaries(srcdir; outdir=".", flags, runner=run)
    map(BINARIES) do (name, src)
        runner(`$ZIG build-exe $flags -femit-bin=$outdir/$name --name $name $srcdir/$src`)
    end
end

const manage_service = Sys.islinux() && !release && isfile(SERVICE_FILE)

function stop_service()
    manage_service || return
    run(ignorestatus(`systemctl --user stop $SERVICE_NAME`))
end

function start_service_with_worker(srcdir)
    manage_service || return
    # If building from a worktree, copy the worker dir to a stable location
    # since the worktree will be cleaned up after with_srcdir returns
    worker_project = joinpath(srcdir, "worker")
    if srcdir != @__DIR__
        id = bytes2hex(rand(UInt8, 4))
        dest = "/tmp/julia-worker-$id"
        cp(worker_project, dest)
        worker_project = dest
        @info "Copied worker to $dest"
    end
    # Update the worker project path in the service file
    content = read(SERVICE_FILE, String)
    content = replace(content,
        r"Environment=\"JULIA_DAEMON_WORKER_PROJECT=.*\"" =>
        "Environment=\"JULIA_DAEMON_WORKER_PROJECT=$worker_project\"")
    write(SERVICE_FILE, content)
    run(`systemctl --user daemon-reload`)
    run(`systemctl --user start $SERVICE_NAME`)
    @info "Restarted $SERVICE_NAME with worker at $worker_project"
end

function build()
    with_srcdir() do srcdir
        if !release
            @info "native (debug)"
            stop_service()
            flags = [BASE_FLAGS; "-O"; "Debug"]
            results = build_binaries(srcdir; flags,
                runner=cmd -> success(pipeline(cmd; stdout, stderr)))
            start_service_with_worker(srcdir)
            return Int(any(!, results))
        end
        # Release build
        flags = [BASE_FLAGS; "-fstrip"; "-O"; "ReleaseSmall"]
        version = open(TOML.parse, joinpath(@__DIR__, "Project.toml"))["version"]
        builddir = mkpath(joinpath(@__DIR__, "builds"))
        @info "native"
        build_binaries(srcdir; flags=[flags; "-flto"])
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
            # ("windows", "x86_64",  String[]),
            # ("windows", "aarch64", String[]),
        ]
        # Cross-compile, package, and collect artifact metadata
        artifacts = mktempdir() do workdir
            map(BUILD_SPECS) do (os, arch, extra)
                @info "$os-$arch"
                build_binaries(srcdir; outdir=workdir,
                               flags=[flags; extra; "-target"; "$arch-$os"])
                tarball = joinpath(builddir, "$os-$arch.tar.gz")
                run(`tar -czf $tarball -C $workdir .`)
                sha = first(eachsplit(readchomp(`sha256sum $tarball`)))
                treehash = bytes2hex(Pkg.GitTools.tree_hash(workdir))
                for (name, _) in BINARIES
                    rm(joinpath(workdir, name), force=true)
                end
                Dict{String, Any}(
                    "arch" => arch, "os" => os,
                    "git-tree-sha1" => treehash,
                    "download" => [Dict{String, Any}(
                        "url" => "https://github.com/tecosaur/DaemonicCabal.jl/releases/download/$version/$os-$arch.tar.gz",
                        "sha256" => sha)])
            end
        end
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
