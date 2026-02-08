# SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
# SPDX-License-Identifier: MPL-2.0

const SYSTEMD_SERVICE_NAME = "julia-daemon"

systemd_service_path() =
    BaseDirs.User.config("systemd", "user", "$SYSTEMD_SERVICE_NAME.service", create=true)

function systemd_service_content(; kw...)
    env_lines = join(["Environment=\"$k=$v\"" for (k, v) in daemon_env(; kw...)], "\n")
    """
    [Unit]
    Description=Julia ($(@__MODULE__).jl) daemon conductor service

    [Service]
    Type=simple
    ExecStart=$(installed_conductor())
    $env_lines
    Restart=on-failure

    [Install]
    WantedBy=default.target
    """
end

@doc """
    install(; mode=:$(DEFAULTS.mode), conductor_host="$(DEFAULTS.conductor_host)", conductor_port=$(DEFAULTS.conductor_port), ports=$(DEFAULTS.ports), ...)

Setup the daemon and client: installs files, creates a systemd service, and symlinks the client to `$(BaseDirs.User.bin(CLIENT_NAME))`.

Set `mode=:tcp` to use TCP transport instead of unix domain sockets.
`conductor_host`/`conductor_port` set the conductor's listen address, and `ports` allocates a range for worker connections.
"""
function install(; worker_maxclients::Integer = DEFAULTS.worker_maxclients,
                 worker_ttl::Integer = DEFAULTS.worker_ttl,
                 worker_args::AbstractString = DEFAULTS.worker_args,
                 mode::Symbol = DEFAULTS.mode,
                 conductor_host::AbstractString = DEFAULTS.conductor_host,
                 conductor_port::Integer = DEFAULTS.conductor_port,
                 ports::UnitRange{Int} = DEFAULTS.ports,
                 env = julia_env())
    install_files()
    if !isnothing(Sys.which("systemctl"))
        ispath(systemd_service_path()) &&
            run(ignorestatus(`systemctl --user stop $SYSTEMD_SERVICE_NAME`))
        @info "Installing systemd service"
        write(systemd_service_path(), systemd_service_content(; worker_maxclients, worker_ttl, worker_args, mode, conductor_host, conductor_port, ports, env))
        run(`systemctl --user daemon-reload`)
        run(`systemctl --user enable --now $SYSTEMD_SERVICE_NAME`)
    else
        @warn "systemctl not found, skipping service setup"
    end
    install_client_symlink()
    @info "Done"
end

"""
    uninstall()

Remove the systemd service, client symlink, and installed files.
"""
function uninstall()
    if ispath(systemd_service_path())
        @info "Removing systemd service"
        run(ignorestatus(`systemctl --user disable --now $SYSTEMD_SERVICE_NAME`))
        rm(systemd_service_path())
        run(`systemctl --user daemon-reload`)
    end
    uninstall_client_symlink()
    uninstall_files()
    @info "Done"
end
