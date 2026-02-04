# SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
# SPDX-License-Identifier: MPL-2.0

module DaemonicCabal

using BaseDirs
using Pkg.Artifacts

const CLIENT_NAME = "juliaclient"
const DEFAULT_WORKER_TTL = 2*60*60 # 2h
const DEFAULT_WORKER_MAXCLIENTS = 1

mainsocket() = get(ENV, "JULIA_DAEMON_SERVER",
                   BaseDirs.runtime("julia-daemon", "conductor.sock"))

julia_env() = [k => v for (k, v) in ENV if startswith(k, "JULIA_")]

@static if Sys.islinux()
    const SYSTEMD_SERVICE_NAME = "julia-daemon"

    # Use a function instead of a const so that this will correctly
    # adapt to environment changes that affect the config path.
    systemd_service_file_path() =
        BaseDirs.User.config("systemd", "user", SYSTEMD_SERVICE_NAME * ".service",
                             create=true)

    function systemd_service_file_content()
        worker_executable = something(
            get(ENV, "JULIA_DAEMON_WORKER_EXECUTABLE", nothing),
            Sys.which("julia"),
            joinpath(Sys.BINDIR, "julia"))
        worker_args = get(ENV, "JULIA_DAEMON_WORKER_ARGS", "--startup-file=no")
        """
[Unit]
Description=Julia ($(@__MODULE__).jl) daemon conductor service

[Service]
Type=simple
ExecStart=$(joinpath(artifact"execbundle", "julia-conductor"))
Environment="JULIA_DAEMON_SERVER=$(mainsocket())"
Environment="JULIA_DAEMON_WORKER_EXECUTABLE=$(worker_executable)"
Environment="JULIA_DAEMON_WORKER_PROJECT=$(joinpath(dirname(@__DIR__), "worker"))"
$(if !haskey(ENV, "JULIA_DAEMON_WORKER_MAXCLIENTS")
    "Environment=\"JULIA_DAEMON_WORKER_MAXCLIENTS=$DEFAULT_WORKER_MAXCLIENTS\"\n"
else "" end)\
Environment="JULIA_DAEMON_WORKER_ARGS=$(worker_args)"
$(if !haskey(ENV, "JULIA_DAEMON_WORKER_TTL")
    "Environment=\"JULIA_DAEMON_WORKER_TTL=$DEFAULT_WORKER_TTL\"\n"
else "" end)\
$(map(julia_env()) do (key, val)
    string("Environment=\"", key, '=', val, '"', '\n')
end |> join)\
Restart=on-failure

[Install]
WantedBy=default.target
"""
    end

    @doc """
    install()
Setup the daemon and client on this machine.

More specifically this:
- Symlinks the client executable to `$(BaseDirs.User.bin(CLIENT_NAME))`
- Creates a Systemd service called `$SYSTEMD_SERVICE_NAME`, and starts it (when applicable)\n
  Note that the current `JULIA_*` environment variables will be 'baked in' to the service file."
"""
    function install()
        if isnothing(Sys.which("systemctl"))
            @warn "Systemctl not found, skipping service setup"
        else
            if ispath(systemd_service_file_path())
                @info "Stopping existing systemd service"
                run(`systemctl --user stop $SYSTEMD_SERVICE_NAME.service`)
                @info "Re-installing systemd service to $systemd_service_file_path()"
            else
                @info "Installing systemd service to $systemd_service_file_path()"
            end
            write(systemd_service_file_path(), systemd_service_file_content())
            run(`systemctl --user daemon-reload`)
            run(`systemctl --user enable --now $SYSTEMD_SERVICE_NAME.service`)
            @info "Started the daemon"
        end
        binpath = BaseDirs.User.bin(CLIENT_NAME)
        @info "Installing client binary to $binpath"
        (ispath(binpath) || islink(binpath)) && rm(binpath)
        symlink(joinpath(artifact"execbundle", "juliaclient"), binpath)
        chmod(binpath, 0o555)
        @info "Done"
    end

    function uninstall()
        if ispath(systemd_service_file_path())
            @info "Disabling systemd service"
            run(`systemctl --user disable --now $SYSTEMD_SERVICE_NAME.service`)
            @info "Removing systemd service file $systemd_service_file_path()"
            rm(systemd_service_file_path())
            run(`systemctl --user daemon-reload`)
        end
        binpath = BaseDirs.User.bin(CLIENT_NAME)
        @info "Removing binary client $binpath"
        ispath(binpath) && rm(binpath)
        @info "Done"
    end
else
    @doc """
    install()
Setup the daemon and client on this machine.
!!! warning
    This is currently unimplemented for $(Sys.KERNEL)!
"""
    function install()
        @error "This functionality is currently only implemented for Linux.\n" *
            "If you're up for it, consider making a PR to add support for $(Sys.KERNEL) 🙂"
    end

    @doc """
    uninstall()
Undo `install()`.
!!! warning
    This is currently unimplemented for $(Sys.KERNEL)!
"""
    function uninstall()
        @error "This functionality is currently only implemented for Linux.\n" *
            "If you're up for it, consider making a PR to add support for $(Sys.KERNEL) 🙂"
    end
end

BaseDirs.@promise_no_assign @doc """
    DaemonicCabal

# Setup

Install this package anywhere and run `DaemonicCabal.install()`. Re-run this
command after updating `DaemonicCabal`, the configuration env vars, or Julia
itself.

# Configuration

When the daemon starts, it pays attention to the following environmental variables:
- `JULIA_DAEMON_SERVER` [`$(BaseDirs.runtime("julia-daemon", "conductor.sock"))`] \n
  The socket to connect to.
- `JULIA_DAEMON_WORKER_MAXCLIENTS` [`$DEFAULT_WORKER_MAXCLIENTS`]\n
  The maximum number of clients a worker may be attached to at once. Set to `0`
  to disable.
- `JULIA_DAEMON_WORKER_ARGS` [`--startup-file=no`] \n
  Arguments passed to the Julia worker processes.
- `JULIA_DAEMON_WORKER_EXECUTABLE` [`$(joinpath(Sys.BINDIR, "julia"))`] \n
  Path to the Julia executable used by the workers.
- `JULIA_DAEMON_WORKER_TTL` [`$DEFAULT_WORKER_TTL`] \n
  Number of seconds a worker should be kept alive for after the last client disconnects.
""" DaemonicCabal

end
