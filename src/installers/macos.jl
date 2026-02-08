# SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
# SPDX-License-Identifier: MPL-2.0

const LAUNCHD_LABEL = "net.julialang.julia-daemon"

launchd_plist_path() = joinpath(homedir(), "Library", "LaunchAgents", "$LAUNCHD_LABEL.plist")
launchd_log_path() = joinpath(homedir(), "Library", "Logs", "julia-daemon.log")

function launchd_plist_content(; kw...)
    env_entries = join(["        <key>$k</key>\n        <string>$v</string>"
                        for (k, v) in daemon_env(; kw...)], "\n")
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
    install(; mode=:$(DEFAULTS.mode), conductor_host="$(DEFAULTS.conductor_host)", conductor_port=$(DEFAULTS.conductor_port), ports=$(DEFAULTS.ports), ...)

Setup the daemon and client: installs files, creates a launchd agent, and symlinks the client to `$(BaseDirs.User.bin(CLIENT_NAME))`.

Set `mode=:tcp` to use TCP transport instead of unix domain sockets.
`conductor_host`/`conductor_port` set the conductor's listen address, and `ports` allocates a range for worker connections.
Logs are written to `~/Library/Logs/julia-daemon.log`.
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
    plist = launchd_plist_path()
    ispath(plist) && run(ignorestatus(`launchctl unload $plist`))
    @info "Installing launchd agent"
    mkpath(dirname(plist))
    write(plist, launchd_plist_content(; worker_maxclients, worker_ttl, worker_args, mode, conductor_host, conductor_port, ports, env))
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
