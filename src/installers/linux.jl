# SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
# SPDX-License-Identifier: MPL-2.0

const SYSTEMD_SERVICE_NAME = "julia-daemon"

systemd_service_path() =
    BaseDirs.User.config("systemd", "user", "$SYSTEMD_SERVICE_NAME.service", create=true)
# Where `juliaclient --reconfigure` saves changed settings.
systemd_dropin_path() = systemd_service_path() * ".d/reconfigure.conf"

function systemd_service_content(env::Dict{String,String})
    env_lines = join(["Environment=\"$k=$v\"" for (k, v) in env], "\n")
    """
    [Unit]
    Description=Julia ($(@__MODULE__).jl) daemon conductor service

    [Service]
    Type=simple
    ExecStart=$(installed_conductor())
    $env_lines
    Restart=on-failure
    Delegate=yes

    [Install]
    WantedBy=default.target
    """
end

function install_service(env::Dict{String,String})
    if !isnothing(Sys.which("systemctl"))
        ispath(systemd_service_path()) &&
            run(ignorestatus(`systemctl --user stop $SYSTEMD_SERVICE_NAME`))
        @info "Installing systemd service"
        env = merge(env, Dict("JULIA_DAEMON_SERVICE" => "systemd:" * systemd_service_path()))
        write(systemd_service_path(), systemd_service_content(env))
        rm(systemd_dropin_path(), force=true)
        run(`systemctl --user daemon-reload`)
        run(`systemctl --user enable --now $SYSTEMD_SERVICE_NAME`)
    else
        @warn "systemctl not found, skipping service setup"
    end
end

function uninstall_service()
    if ispath(systemd_service_path())
        @info "Removing systemd service"
        run(ignorestatus(`systemctl --user disable --now $SYSTEMD_SERVICE_NAME`))
        rm(systemd_service_path())
        rm(systemd_dropin_path(), force=true)
        run(`systemctl --user daemon-reload`)
    end
end
