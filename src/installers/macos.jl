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

xml_escaped(text::AbstractString) = replace(text, '&' => "&amp;", '<' => "&lt;", '>' => "&gt;")

"""
    service_environment() -> Dict{String,String}

The installed agent's EnvironmentVariables, `--reconfigure`'s changes
included; empty without an agent.
"""
function service_environment()
    plist = launchd_plist_path()
    isfile(plist) || return Dict{String,String}()
    text = read(plist, String)
    envdict = match(r"<key>EnvironmentVariables</key>\s*<dict>(.*?)</dict>"s, text)
    isnothing(envdict) && return Dict{String,String}()
    xml_unescaped(escaped) = replace(escaped, "&lt;" => "<", "&gt;" => ">", "&quot;" => "\"",
                                     "&apos;" => "'", "&amp;" => "&")
    Dict{String,String}(xml_unescaped(m[1]) => xml_unescaped(m[2]) for m in
        eachmatch(r"<key>(.*?)</key>\s*<string>(.*?)</string>"s, envdict[1]))
end

function launchd_plist_content(env::Dict{String,String})
    env_entries = join(["        <key>$(xml_escaped(k))</key>\n        <string>$(xml_escaped(v))</string>"
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
            <string>$(xml_escaped(bundled_conductor()))</string>
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
        <string>$(xml_escaped(launchd_log_path()))</string>
        <key>StandardErrorPath</key>
        <string>$(xml_escaped(launchd_log_path()))</string>
    </dict>
    </plist>
    """
end

function stop_service()
    plist = launchd_plist_path()
    ispath(plist) && run(ignorestatus(`launchctl unload $plist`))
end

function install_service(env::Dict{String,String})
    plist = launchd_plist_path()
    @info "Building conductor app bundle"
    install_conductor_bundle()
    @info "Installing launchd agent"
    mkpath(dirname(plist))
    write(plist, launchd_plist_content(merge(env, Dict("JULIA_DAEMON_SERVICE" => "launchd:" * plist))))
    run(`launchctl load $plist`)
end

function uninstall_service()
    plist = launchd_plist_path()
    if ispath(plist)
        @info "Removing launchd agent"
        stop_service()
        rm(plist)
    end
end
