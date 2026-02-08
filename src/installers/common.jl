# SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
# SPDX-License-Identifier: MPL-2.0

const SOURCE_WORKER_PROJECT = joinpath(dirname(dirname(@__DIR__)), "worker")

install_dir() = BaseDirs.User.data(BaseDirs.Project("julia-daemon"), create=false)
installed_worker_project() = joinpath(install_dir(), "worker")
installed_conductor() = joinpath(install_dir(), "julia-conductor")
installed_client() = joinpath(install_dir(), "juliaclient")
client_symlink_path() = BaseDirs.User.bin(CLIENT_NAME)

worker_executable() = something(
    get(ENV, "JULIA_DAEMON_WORKER_EXECUTABLE", nothing),
    Sys.which("julia"),
    joinpath(Sys.BINDIR, "julia"))

function install_files()
    dest = install_dir()
    isdir(dest) && rm(dest; recursive=true, force=true)
    @info "Installing to $dest"
    mkpath(dest)
    cp(SOURCE_WORKER_PROJECT, installed_worker_project())
    make_tree_readonly(installed_worker_project())
    hardlink(joinpath(artifact"execbundle", "julia-conductor"), installed_conductor())
    hardlink(joinpath(artifact"execbundle", "juliaclient"), installed_client())
end

function uninstall_files()
    dest = install_dir()
    isdir(dest) || return
    @info "Removing $dest"
    rm(dest; recursive=true)
end

function install_client_symlink()
    binpath = client_symlink_path()
    @info "Symlinking client to $binpath"
    rm(binpath; force=true)
    symlink(installed_client(), binpath)
end

function uninstall_client_symlink()
    binpath = client_symlink_path()
    isfile(binpath) || islink(binpath) || return
    @info "Removing $binpath"
    rm(binpath)
end

"""
    daemon_env(; worker_maxclients, worker_ttl, worker_args, mode, conductor_host, conductor_port, ports, env) -> Dict{String,String}

Build the complete environment variable dict for the conductor process.
"""
function daemon_env(; worker_maxclients::Integer, worker_ttl::Integer,
                    worker_args::AbstractString, mode::Symbol,
                    conductor_host::AbstractString, conductor_port::Integer,
                    ports::UnitRange{Int}, env)
    mode in (:sockets, :tcp) || throw(ArgumentError("mode must be :sockets or :tcp, got :$mode"))
    d = Dict{String,String}(
        "JULIA_DAEMON_SERVER" => mainsocket(),
        "JULIA_DAEMON_WORKER_EXECUTABLE" => worker_executable(),
        "JULIA_DAEMON_WORKER_PROJECT" => installed_worker_project(),
        "JULIA_DAEMON_WORKER_MAXCLIENTS" => string(worker_maxclients),
        "JULIA_DAEMON_WORKER_ARGS" => worker_args,
        "JULIA_DAEMON_WORKER_TTL" => string(worker_ttl))
    if mode === :tcp
        d["JULIA_DAEMON_SERVER"] = "$conductor_host:$conductor_port"
        if !isempty(ports)
            1024 <= first(ports) || throw(ArgumentError("port range must start at 1024 or above"))
            last(ports) <= 65535 || throw(ArgumentError("port range must end at 65535 or below"))
            d["JULIA_DAEMON_PORTS"] = "$(first(ports))-$(last(ports))"
        end
    end
    for (k, v) in env
        d[string(k)] = string(v)
    end
    return d
end

function make_tree_readonly(path::AbstractString)
    for (root, dirs, files) in walkdir(path)
        for f in files
            chmod(joinpath(root, f), 0o444)
        end
        for d in dirs
            chmod(joinpath(root, d), 0o555)
        end
    end
    chmod(path, 0o555)
end
