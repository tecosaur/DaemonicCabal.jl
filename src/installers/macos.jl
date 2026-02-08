# SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
# SPDX-License-Identifier: MPL-2.0

const LAUNCHD_LABEL = "net.julialang.julia-daemon"

launchd_plist_path() = joinpath(homedir(), "Library", "LaunchAgents", "$LAUNCHD_LABEL.plist")
launchd_log_path() = joinpath(homedir(), "Library", "Logs", "julia-daemon.log")

function launchd_plist_content(env::Dict{String,String})
    env_entries = join(["        <key>$k</key>\n        <string>$v</string>"
                        for (k, v) in env], "\n")
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

function install_service(env::Dict{String,String})
    plist = launchd_plist_path()
    ispath(plist) && run(ignorestatus(`launchctl unload $plist`))
    @info "Installing launchd agent"
    mkpath(dirname(plist))
    write(plist, launchd_plist_content(env))
    run(`launchctl load $plist`)
end

function uninstall_service()
    plist = launchd_plist_path()
    if ispath(plist)
        @info "Removing launchd agent"
        run(ignorestatus(`launchctl unload $plist`))
        rm(plist)
    end
end
