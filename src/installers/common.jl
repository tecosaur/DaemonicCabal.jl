# SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
# SPDX-License-Identifier: MPL-2.0

const SOURCE_WORKER_PROJECT = joinpath(dirname(dirname(@__DIR__)), "worker")

install_dir() = Sys.iswindows() ?
       joinpath(ENV["LOCALAPPDATA"], "Programs", "julia-daemon") :
       BaseDirs.User.data(BaseDirs.App("julia-daemon"), create=false)

installed_worker_project() = joinpath(install_dir(), "worker")
installed_conductor() = joinpath(install_dir(), "julia-conductor$EXE")
installed_client() = joinpath(install_dir(), CLIENT_NAME)
# WindowsApps is on PATH by default.
client_symlink_path() = Sys.iswindows() ?
       joinpath(ENV["LOCALAPPDATA"], "Microsoft", "WindowsApps", CLIENT_NAME) :
       BaseDirs.User.bin(CLIENT_NAME)

"""
    daemon_env(settings; worker_maxclients, worker_ttl, worker_args, mode,
               conductor_host, conductor_port, ports, env) -> Dict{String,String}

The service's environment: `settings`, overridden by the arguments given
(not `nothing`), then by `env`, with the worker project installed.

`mode=:tcp` sets the server to `conductor_host:conductor_port` and the worker
`ports` (none when empty); `mode=:sockets` drops any TCP server, bind address
and ports for the default local socket.

Throws an `ArgumentError` for an unknown `mode`, ports outside 1024-65535, or
a value holding a line break.
"""
function daemon_env(settings::Dict{String,String};
                    worker_maxclients::Union{Integer,Nothing}, worker_ttl::Union{Integer,Nothing},
                    worker_args::Union{AbstractString,Nothing}, mode::Union{Symbol,Nothing},
                    conductor_host::AbstractString, conductor_port::Integer,
                    ports::UnitRange{Int}, env)
    d = copy(settings)
    d["JULIA_DAEMON_WORKER_PROJECT"] = installed_worker_project()
    get!(() -> something(Sys.which("julia"), joinpath(Sys.BINDIR, "julia")),
         d, "JULIA_DAEMON_WORKER_EXECUTABLE")
    for (key, value) in ("JULIA_DAEMON_WORKER_MAXCLIENTS" => worker_maxclients,
                         "JULIA_DAEMON_MAX_TTL" => worker_ttl,
                         "JULIA_DAEMON_WORKER_ARGS" => worker_args)
        if !isnothing(value)
            d[key] = string(value)
        end
    end
    if mode === :tcp
        # An IPv6 address is bracketed, as its colons would read as the port's.
        host = occursin(':', conductor_host) ? "[$conductor_host]" : conductor_host
        d["JULIA_DAEMON_SERVER"] = "$host:$conductor_port"
        delete!(d, "JULIA_DAEMON_PORTS")
        if !isempty(ports)
            1024 <= first(ports) || throw(ArgumentError("port range must start at 1024 or above"))
            last(ports) <= 65535 || throw(ArgumentError("port range must end at 65535 or below"))
            d["JULIA_DAEMON_PORTS"] = "$(first(ports))-$(last(ports))"
        end
    elseif mode === :sockets
        for key in ("JULIA_DAEMON_SERVER", "JULIA_DAEMON_BIND", "JULIA_DAEMON_PORTS")
            delete!(d, key)
        end
    elseif !isnothing(mode)
        throw(ArgumentError("mode must be :sockets or :tcp, got :$mode"))
    end
    for (k, v) in env
        d[string(k)] = string(v)
    end
    for (k, v) in d
        occursin(r"[\r\n]", v) &&
            throw(ArgumentError("$k holds a line break, which no service file can hold: $(repr(v))"))
    end
    return d
end

# File installation

function install_files()
    dest = install_dir()
    uninstall_files()
    @info "Installing to $dest"
    mkpath(dest)
    cp(SOURCE_WORKER_PROJECT, installed_worker_project())
    make_tree_readonly(installed_worker_project())
    for (name, path) in (("julia-conductor$EXE", installed_conductor()), ("juliaclient$EXE", installed_client()))
        bundled = joinpath(artifact"execbundle", name)
        try
            hardlink(bundled, path)
        catch err
            err isa Base.IOError && err.code == Base.UV_EXDEV || rethrow()
            cp(bundled, path)
        end
    end
end

function uninstall_files()
    dest = install_dir()
    isdir(dest) || return
    # On Windows, chmod rewrites the DACL and strips the owner's delete rights.
    if !Sys.iswindows()
        for (root, _, _) in walkdir(dest; topdown=true)
            chmod(root, 0o755)
        end
    end
    @info "Removing $dest"
    rm(dest; recursive=true)
end

function install_client_symlink()
    binpath = client_symlink_path()
    mkpath(dirname(binpath))
    rm(binpath; force=true)
    @static if Sys.iswindows()
        # Unprivileged symlinks need developer mode; both paths share a drive.
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

# Orchestration — platform files provide service_environment(), stop_service(),
# install_service(env) and uninstall_service()

BaseDirs.@promise_no_assign @doc """
    install(; worker_maxclients, worker_ttl, worker_args, mode,
            conductor_host="$(DEFAULTS.conductor_host)", conductor_port=$(DEFAULTS.conductor_port), ports=$(DEFAULTS.ports), env)

Install the daemon and client on this machine, replacing any earlier install.

Installs files to `$(install_dir())`, sets up the platform's service (see
[`DaemonicCabal`](@ref)), and links the client to `$(client_symlink_path())`.

The service's settings are, each over the last: those of the service it
replaces (with any `juliaclient --reconfigure` saved), the daemon's variables
set where `install()` runs (see `juliaclient --reconfigure`, and
`JULIA_DEPOT_PATH`), the arguments given, and `env`, of variable => value
pairs. The daemon's defaults stand for the rest.

- `worker_maxclients` sets `JULIA_DAEMON_WORKER_MAXCLIENTS`, `worker_args`
  `JULIA_DAEMON_WORKER_ARGS`, and `worker_ttl` `JULIA_DAEMON_MAX_TTL` (seconds).
- `mode=:tcp` serves clients over TCP at `conductor_host:conductor_port`, with
  workers listening on `ports` (any free when empty); `mode=:sockets` over a
  local socket.

Throws an `ArgumentError` for an unknown `mode`, ports outside 1024-65535, or
a value holding a line break.
""" install
function install(; worker_maxclients::Union{Integer,Nothing} = nothing,
                 worker_ttl::Union{Integer,Nothing} = nothing,
                 worker_args::Union{AbstractString,Nothing} = nothing,
                 mode::Union{Symbol,Nothing} = nothing,
                 conductor_host::AbstractString = DEFAULTS.conductor_host,
                 conductor_port::Integer = DEFAULTS.conductor_port,
                 ports::UnitRange{Int} = DEFAULTS.ports,
                 env = Dict{String,String}())
    # The shell's settings over those saved in the service it replaces: the
    # daemon's own, and JULIA_DEPOT_PATH, as a worker's depot is fixed as it starts.
    settings = filter(merge(service_environment(), ENV)) do (key, _)
        key in ("JULIA_NUM_THREADS", "JULIA_DEPOT_PATH") ||
            startswith(key, "JULIA_DAEMON_") &&
            key ∉ ("JULIA_DAEMON_SERVICE", "JULIA_DAEMON_WORKER_PROJECT", "JULIA_DAEMON_SANDBOXED")
    end
    denv = daemon_env(settings; worker_maxclients, worker_ttl, worker_args,
                      mode, conductor_host, conductor_port, ports, env)
    # First, as Windows can't delete a running executable.
    stop_service()
    install_files()
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
