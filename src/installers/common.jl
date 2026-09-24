# SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
# SPDX-License-Identifier: MPL-2.0

const SOURCE_WORKER_PROJECT = joinpath(dirname(dirname(@__DIR__)), "worker")

install_dir() = Sys.iswindows() ?
        # Local app data is the usual USER installation folder
        # for example, VS Code user installation is installed in
        # %LOCALAPPDATA%/Programs/Microsoft VS Code/
       joinpath(ENV["LOCALAPPDATA"], "Programs", "julia-daemon") :
       BaseDirs.User.data(BaseDirs.App("julia-daemon"), create=false)

installed_worker_project() = joinpath(install_dir(), "worker")
installed_conductor() = joinpath(install_dir(), "julia-conductor$EXE")
installed_client() = joinpath(install_dir(), CLIENT_NAME)
client_symlink_path() = begin
    @static if Sys.iswindows()
        # Here we pick "Microsoft/WindowsApps" because this path should be
        # in the PATH by default. so we don't have to inject PATHs anywhere.
        # It's a bit tongue in cheek and a shortcut, but it somewhat customary
        # and the blast radius is non existent.
        joinpath(ENV["LOCALAPPDATA"],
            "Microsoft", "WindowsApps", CLIENT_NAME
        )
    else
        BaseDirs.User.bin(CLIENT_NAME)
    end
end
worker_executable() = something(
    get(ENV, "JULIA_DAEMON_WORKER_EXECUTABLE", nothing),
    Sys.which("julia"),
    joinpath(Sys.BINDIR, "julia"))

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
        "JULIA_DAEMON_WORKER_EXECUTABLE" => worker_executable(),
        "JULIA_DAEMON_WORKER_PROJECT" => installed_worker_project(),
        "JULIA_DAEMON_WORKER_MAXCLIENTS" => string(worker_maxclients),
        "JULIA_DAEMON_WORKER_ARGS" => worker_args,
        "JULIA_DAEMON_WORKER_TTL" => string(worker_ttl))
    for optkey in ("JULIA_DAEMON_SERVER", "JULIA_NUM_THREADS")
        if haskey(ENV, optkey)
            d[optkey] = ENV[optkey]
        end
    end
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

# File installation

function install_files()
    dest = install_dir()
    if isdir(dest)
        # Windows: Julia's chmod rewrites the DACL (stripping delete rights the
        # owner needs for non-Julia tools to clean up) rather than setting a
        # read-only bit, so skip the permission dance entirely.
        if !Sys.iswindows()
            for (root, _, _) in walkdir(dest; topdown=true)
                chmod(root, 0o755)
            end
        end
        rm(dest; recursive=true, force=true)
    end
    @info "Installing to $dest"
    mkpath(dest)
    cp(SOURCE_WORKER_PROJECT, installed_worker_project())
    make_tree_readonly(installed_worker_project())
    hardlink(joinpath(artifact"execbundle", "julia-conductor$EXE"), installed_conductor())
    hardlink(joinpath(artifact"execbundle", "juliaclient$EXE"), installed_client())
end

function uninstall_files()
    dest = install_dir()
    isdir(dest) || return
    @info "Removing $dest"
    rm(dest; recursive=true)
end

function install_client_symlink()
    binpath = client_symlink_path()
    rm(binpath; force=true)
    @static if Sys.iswindows()
        # symlinking on windows is a pain.
        # we install in %LOCALAPPDATA% so always same drive
        @info "Hardlinking client to $binpath"
        hardlink(installed_client(), binpath)
    else
        @info "Symlinking client to $binpath"
        symlink(installed_client(), binpath)
    end
end

function uninstall_client_symlink()
    binpath = client_symlink_path()
    isfile(binpath) || islink(binpath) || return
    @info "Removing $binpath"
    rm(binpath)
end

function make_tree_readonly(path::AbstractString)
    Sys.iswindows() && return  # chmod → DACL trap, see install_files
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

# Orchestration — platform files provide install_service(env) and uninstall_service()

BaseDirs.@promise_no_assign @doc """
    install(; mode=:$(DEFAULTS.mode), conductor_host="$(DEFAULTS.conductor_host)", conductor_port=$(DEFAULTS.conductor_port), ports=$(DEFAULTS.ports), ...)

Install the daemon and client on this machine.

Installs files to `$(BaseDirs.User.data(BaseDirs.App("julia-daemon"), create=false))`,
sets up a platform-specific service (systemd on Linux, launchd on macOS,
manual instructions on BSD), and symlinks the client to
`$(BaseDirs.User.bin(CLIENT_NAME))`.

Set `mode=:tcp` to use TCP transport instead of unix domain sockets.
`conductor_host`/`conductor_port` set the conductor's listen address, and
`ports` allocates a range for worker connections.
""" install
function install(; worker_maxclients::Integer = DEFAULTS.worker_maxclients,
                 worker_ttl::Integer = DEFAULTS.worker_ttl,
                 worker_args::AbstractString = DEFAULTS.worker_args,
                 mode::Symbol = DEFAULTS.mode,
                 conductor_host::AbstractString = DEFAULTS.conductor_host,
                 conductor_port::Integer = DEFAULTS.conductor_port,
                 ports::UnitRange{Int} = DEFAULTS.ports,
                 env = julia_env())
    install_files()
    denv = daemon_env(; worker_maxclients, worker_ttl, worker_args,
                        mode, conductor_host, conductor_port, ports, env)
    install_service(denv)
    install_client_symlink()
    @info "Done"
end

"""
    uninstall()

Undo `install()`: remove the platform service, client symlink, and installed files.
"""
function uninstall()
    uninstall_service()
    uninstall_client_symlink()
    uninstall_files()
    @info "Done"
end
