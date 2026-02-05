# SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
# SPDX-License-Identifier: MPL-2.0

const LAUNCHD_LABEL = "net.julialang.julia-daemon"

launchd_plist_path() = joinpath(homedir(), "Library", "LaunchAgents", "$LAUNCHD_LABEL.plist")
launchd_log_path() = joinpath(homedir(), "Library", "Logs", "julia-daemon.log")

function launchd_plist_content(; worker_maxclients, worker_ttl, worker_args, env)
    env_dict = Dict{String,String}(
        "JULIA_DAEMON_SERVER" => mainsocket(),
        "JULIA_DAEMON_WORKER_EXECUTABLE" => worker_executable(),
        "JULIA_DAEMON_WORKER_PROJECT" => installed_worker_project(),
        "JULIA_DAEMON_WORKER_MAXCLIENTS" => string(worker_maxclients),
        "JULIA_DAEMON_WORKER_ARGS" => worker_args,
        "JULIA_DAEMON_WORKER_TTL" => string(worker_ttl),
    )
    for (k, v) in env
        env_dict[k] = v
    end
    env_entries = join(["        <key>$k</key>\n        <string>$v</string>" for (k, v) in env_dict], "\n")
    """
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    <plist version="1.0">
    <dict>
        <key>Label</key>
        <string>$LAUNCHD_LABEL</string>
        <key>ProgramArguments</key>
        <array>
            <string>$(installed_conductor())</string>
        </array>
        <key>EnvironmentVariables</key>
        <dict>
    $env_entries
        </dict>
        <key>RunAtLoad</key>
        <true/>
        <key>KeepAlive</key>
        <dict>
            <key>SuccessfulExit</key>
            <false/>
        </dict>
        <key>StandardOutPath</key>
        <string>$(launchd_log_path())</string>
        <key>StandardErrorPath</key>
        <string>$(launchd_log_path())</string>
    </dict>
    </plist>
    """
end

@doc """
    install(; worker_maxclients=$(DEFAULTS.worker_maxclients), worker_ttl=$(DEFAULTS.worker_ttl), worker_args="$(DEFAULTS.worker_args)", env=julia_env())

Setup the daemon and client: installs files, creates a launchd agent, and symlinks the client to `$(BaseDirs.User.bin(CLIENT_NAME))`.

Logs are written to `~/Library/Logs/julia-daemon.log`.
"""
function install(; worker_maxclients::Integer = DEFAULTS.worker_maxclients,
                 worker_ttl::Integer = DEFAULTS.worker_ttl,
                 worker_args::AbstractString = DEFAULTS.worker_args,
                 env = julia_env())
    install_files()
    plist = launchd_plist_path()
    ispath(plist) && run(ignorestatus(`launchctl unload $plist`))
    @info "Installing launchd agent"
    mkpath(dirname(plist))
    write(plist, launchd_plist_content(; worker_maxclients, worker_ttl, worker_args, env))
    run(`launchctl load $plist`)
    install_client_symlink()
    @info "Done"
end

"""
    uninstall()

Remove the launchd agent, client symlink, and installed files.
"""
function uninstall()
    plist = launchd_plist_path()
    if ispath(plist)
        @info "Removing launchd agent"
        run(ignorestatus(`launchctl unload $plist`))
        rm(plist)
    end
    uninstall_client_symlink()
    uninstall_files()
    @info "Done"
end
