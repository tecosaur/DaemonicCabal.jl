# SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
# SPDX-License-Identifier: MPL-2.0

const SYSTEMD_SERVICE_NAME = "julia-daemon"

systemd_service_path() =
    BaseDirs.User.config("systemd", "user", "$SYSTEMD_SERVICE_NAME.service", create=true)

function systemd_service_content(; worker_maxclients, worker_ttl, worker_args, env)
    env_lines = join(["Environment=\"$k=$v\"" for (k, v) in env], "\n")
    """
    [Unit]
    Description=Julia ($(@__MODULE__).jl) daemon conductor service

    [Service]
    Type=simple
    ExecStart=$(installed_conductor())
    Environment="JULIA_DAEMON_SERVER=$(mainsocket())"
    Environment="JULIA_DAEMON_WORKER_EXECUTABLE=$(worker_executable())"
    Environment="JULIA_DAEMON_WORKER_PROJECT=$(installed_worker_project())"
    Environment="JULIA_DAEMON_WORKER_MAXCLIENTS=$worker_maxclients"
    Environment="JULIA_DAEMON_WORKER_ARGS=$worker_args"
    Environment="JULIA_DAEMON_WORKER_TTL=$worker_ttl"
    $env_lines
    Restart=on-failure

    [Install]
    WantedBy=default.target
    """
end

@doc """
    install(; worker_maxclients=$(DEFAULTS.worker_maxclients), worker_ttl=$(DEFAULTS.worker_ttl), worker_args="$(DEFAULTS.worker_args)", env=julia_env())

Setup the daemon and client: installs files, creates a systemd service, and symlinks the client to `$(BaseDirs.User.bin(CLIENT_NAME))`.
"""
function install(; worker_maxclients::Integer = DEFAULTS.worker_maxclients,
                 worker_ttl::Integer = DEFAULTS.worker_ttl,
                 worker_args::AbstractString = DEFAULTS.worker_args,
                 env = julia_env())
    install_files()
    if !isnothing(Sys.which("systemctl"))
        ispath(systemd_service_path()) &&
            run(ignorestatus(`systemctl --user stop $SYSTEMD_SERVICE_NAME`))
        @info "Installing systemd service"
        write(systemd_service_path(), systemd_service_content(; worker_maxclients, worker_ttl, worker_args, env))
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
