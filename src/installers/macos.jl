# SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
# SPDX-License-Identifier: MPL-2.0

const LAUNCHD_LABEL = "org.julialang.julia-daemon"

launchd_plist_path() = joinpath(homedir(), "Library", "LaunchAgents", "$LAUNCHD_LABEL.plist")
launchd_log_path() = joinpath(homedir(), "Library", "Logs", "julia-daemon.log")

conductor_bundle() = joinpath(install_dir(), "julia-conductor.app")
bundled_conductor() = joinpath(conductor_bundle(), "Contents", "MacOS", "julia-conductor")

"""
    install_conductor_bundle()

Wrap the conductor in a minimal `.app` so Login Items shows a name and icon.
`LSUIElement` keeps it out of the Dock and app switcher.
"""
function install_conductor_bundle()
    contents = joinpath(conductor_bundle(), "Contents")
    mkpath(joinpath(contents, "MacOS"))
    mkpath(joinpath(contents, "Resources"))
    hardlink(installed_conductor(), bundled_conductor())
    icon = joinpath(dirname(dirname(@__DIR__)), "julia-conductor.icns")
    isfile(icon) && cp(icon, joinpath(contents, "Resources", "julia-conductor.icns"))
    write(joinpath(contents, "Info.plist"), """
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    <plist version="1.0">
    <dict>
        <key>CFBundleIdentifier</key>
        <string>$LAUNCHD_LABEL</string>
        <key>CFBundleName</key>
        <string>Julia Daemon</string>
        <key>CFBundleDisplayName</key>
        <string>Julia Daemon</string>
        <key>CFBundleExecutable</key>
        <string>julia-conductor</string>
        <key>CFBundleIconFile</key>
        <string>julia-conductor.icns</string>
        <key>CFBundlePackageType</key>
        <string>APPL</string>
        <key>CFBundleInfoDictionaryVersion</key>
        <string>6.0</string>
        <key>CFBundleShortVersionString</key>
        <string>$(pkgversion(@__MODULE__))</string>
        <key>LSUIElement</key>
        <true/>
        <key>LSBackgroundOnly</key>
        <true/>
    </dict>
    </plist>
    """)
end

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
            <string>$(bundled_conductor())</string>
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
    @info "Building conductor app bundle"
    install_conductor_bundle()
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
