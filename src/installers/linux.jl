# SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
# SPDX-License-Identifier: MPL-2.0

const SYSTEMD_SERVICE_NAME = "julia-daemon"

systemd_service_path() =
    BaseDirs.User.config("systemd", "user", "$SYSTEMD_SERVICE_NAME.service", create=true)
# Where `juliaclient --reconfigure` saves changed settings.
systemd_dropin_path() = systemd_service_path() * ".d/reconfigure.conf"

# A quoted word, as systemd reads it back: C escapes, `%` a specifier.
systemd_quoted(text::AbstractString) =
    '"' * replace(text, '\\' => "\\\\", '"' => "\\\"", '%' => "%%") * '"'

function systemd_service_content(env::Dict{String,String})
    env_lines = join(["Environment=" * systemd_quoted("$k=$v") for (k, v) in env], "\n")
    # ExecStart also expands `$`.
    exec = systemd_quoted(replace(installed_conductor(), '$' => "\$\$"))
    """
    [Unit]
    Description=Julia ($(@__MODULE__).jl) daemon conductor service

    [Service]
    Type=simple
    ExecStart=$exec
    $env_lines
    Restart=on-failure
    # The conductor's exit when another already runs.
    RestartPreventExitStatus=75
    Delegate=yes

    [Install]
    WantedBy=default.target
    """
end

"""
    service_environment() -> Dict{String,String}

What the installed unit sets, with its `--reconfigure` drop-in applied;
empty without a unit. Reads only what an installer or `--reconfigure` wrote.
"""
function service_environment()
    env = Dict{String,String}()
    for path in (systemd_service_path(), systemd_dropin_path())
        isfile(path) || continue
        for line in eachline(path)
            if startswith(line, "UnsetEnvironment=")
                foreach(key -> delete!(env, key), split(chopprefix(line, "UnsetEnvironment=")))
            elseif (set = match(r"^Environment=\"([^=]+)=(.*)\"$", line)) !== nothing
                key, value = (replace(word, r"\\(.)|%(%)" => s"\1\2") for word in set.captures)
                env[key] = value
            end
        end
    end
    env
end

# Installing carries the drop-in's settings into the unit.
function remove_dropin()
    rm(systemd_dropin_path(), force=true)
    dir = dirname(systemd_dropin_path())
    isdir(dir) && isempty(readdir(dir)) && rm(dir)
end

function stop_service()
    if ispath(systemd_service_path()) && !isnothing(Sys.which("systemctl"))
        run(ignorestatus(`systemctl --user stop $SYSTEMD_SERVICE_NAME`))
    end
end

function install_service(env::Dict{String,String})
    if !isnothing(Sys.which("systemctl"))
        @info "Installing systemd service"
        env = merge(env, Dict("JULIA_DAEMON_SERVICE" => "systemd:" * systemd_service_path()))
        write(systemd_service_path(), systemd_service_content(env))
        remove_dropin()
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
        remove_dropin()
        run(`systemctl --user daemon-reload`)
    end
end
