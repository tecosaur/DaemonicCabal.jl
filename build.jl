#!/usr/bin/env -S julia --startup-file=no
using TOML
using Pkg

const zig = joinpath(@__DIR__, "zig", "zig")

const FLAGS = ["-fsingle-threaded", "-fPIE"]

showsuccess(cmd::Cmd) = success(pipeline(cmd; stdout, stderr))

if !("--release" ∈ ARGS)
    push!(FLAGS, "-O", "Debug")
    ecode = 0
    ecode |= !showsuccess(`$zig build-exe $FLAGS -femit-bin=julia-conductor --name julia-conductor conductor/main.zig`)
    ecode |= !showsuccess(`$zig build-exe $FLAGS -femit-bin=juliaclient --name juliaclient client/client.zig`)
    exit(ecode)
end

push!(FLAGS, "-fstrip", "-O", "ReleaseSmall")

const VERSION = open(TOML.parse, joinpath(@__DIR__, "Project.toml"))["version"]
const ARTIFACTS = Dict{String, Any}[]
const WORKDIR = mktempdir()

@info "native"
run(`$zig build-exe $FLAGS -flto -femit-bin=julia-conductor --name julia-conductor conductor/main.zig`)
run(`$zig build-exe $FLAGS -flto -femit-bin=juliaclient --name juliaclient client/client.zig`)

const BUILD_SPECS = Tuple{String, String, Vector{String}}[
    ("linux", "x86_64", ["-flto"]),
    ("linux", "aarch64", ["-flto"]),
    ("macos", "x86_64", []),
    ("macos", "aarch64", []),
    ("freebsd", "x86_64", []),
    ("freebsd", "aarch64", []),
    ("freebsd", "arm", []),
    ("openbsd", "x86_64", []),
    ("openbsd", "aarch64", []),
    # ("windows", "x86_64", []),
    # ("windows", "aarch64", []),
]

for (os, arch, extra_flags) in BUILD_SPECS
    @info "$os-$arch"
    target = "$arch-$os"
    run(`$zig build-exe $FLAGS $extra_flags -target $target -femit-bin=$WORKDIR/julia-conductor --name julia-conductor conductor/main.zig`)
    run(`$zig build-exe $FLAGS $extra_flags -target $target -femit-bin=$WORKDIR/juliaclient --name juliaclient client/client.zig`)
    tarball = joinpath(@__DIR__, "$os-$arch.tar.gz")
    run(`tar -czf $tarball -C $WORKDIR .`)
    tar256 = first(eachsplit(readchomp(`sha256sum $tarball`)))
    treehash = bytes2hex(Pkg.GitTools.tree_hash(WORKDIR))
    url = "https://github.com/tecosaur/DaemonicCabal.jl/releases/download/$VERSION/$os-$arch.tar.gz"
    push!(ARTIFACTS, Dict{String, Any}(
        "arch" => arch,
        "os" => os,
        "git-tree-sha1" => treehash,
        "download" => [Dict{String, Any}(
            "url" => url,
            "sha256" => tar256)]
    ))
    rm(joinpath(WORKDIR, "julia-conductor"), force=true)
    rm(joinpath(WORKDIR, "juliaclient"), force=true)
end

open(joinpath(@__DIR__, "Artifacts.toml"), "w") do io
    TOML.print(io, Dict("execbundle" => ARTIFACTS))
end

@info "Updated Artifacts.toml"
