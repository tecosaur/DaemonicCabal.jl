# SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
# SPDX-License-Identifier: MPL-2.0

const TASK_PATH = "Julia\\JuliaDaemon"

ps1_wrapper() = joinpath(install_dir(), "julia-daemon.ps1")
silent_launch_script() = joinpath(install_dir(), "silent_launch.vbs")

# A PowerShell literal: nothing within is expanded, a quote (U+2018-U+201B
# among them) doubled.
powershell_quoted(text::AbstractString) = "'" * replace(text, r"(['‘-‛])" => s"\1\1") * "'"

"""
    service_environment() -> Dict{String,String}

What the installed script sets, `--reconfigure`'s changes included; empty
without a script.
"""
function service_environment()
    isfile(ps1_wrapper()) || return Dict{String,String}()
    env = Dict{String,String}()
    for line in eachline(ps1_wrapper())
        set = match(r"^\$env:(\w+) = '(.*)'$", chopprefix(line, '﻿'))
        if !isnothing(set)
            env[set[1]] = replace(set[2], r"['‘-‛](['‘-‛])" => s"\1")
        end
    end
    env
end

function powershell_script_content(env::Dict{String,String})
    envs = join(["\$env:$k = $(powershell_quoted(v))" for (k, v) in env], "\n")
    # Within double quotes, a backtick escapes and `$` expands.
    escape_expandable(path) = replace(path, '`' => "``", '$' => "`\$")
    """
    $envs

    & "$(escape_expandable(installed_conductor()))" *>> "$(escape_expandable(joinpath(install_dir(), "conductor.log")))"
    """
end

# Windows PowerShell 5.1 reads a script without a BOM as the ANSI code page.
write_powershell(path::AbstractString, script::AbstractString) = write(path, '﻿' * script)

function install_service(env::Dict{String,String})
    env = merge(env, Dict("JULIA_DAEMON_SERVICE" => "powershell:" * ps1_wrapper()))
    write_powershell(ps1_wrapper(), powershell_script_content(env))
    # Launching powershell directly flashes a console window. WScript reads
    # UTF-16 with a BOM, not UTF-8.
    vbs = """
        Set shell = CreateObject("WScript.Shell")
        shell.CurrentDirectory = "$(install_dir())"
        shell.Run "powershell.exe -NoProfile -ExecutionPolicy Bypass -File ""$(ps1_wrapper())"" ", 0, False
        """
    write(silent_launch_script(), UInt8[0xff, 0xfe], reinterpret(UInt8, htol.(transcode(UInt16, vbs))))
    @info "Installing startup task"
    tmpfile = tempname() * ".ps1"
    write_powershell(tmpfile, """
    \$action = New-ScheduledTaskAction -Execute 'wscript.exe' -Argument $(powershell_quoted("\"$(silent_launch_script())\""))
    \$trigger = New-ScheduledTaskTrigger -AtLogOn -User $(powershell_quoted(ENV["USERNAME"]))
    \$principal = New-ScheduledTaskPrincipal -UserId $(powershell_quoted(ENV["USERNAME"])) -LogonType Interactive
    \$settings = New-ScheduledTaskSettingsSet `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -ExecutionTimeLimit ([TimeSpan]::Zero) `
        -MultipleInstances IgnoreNew `
        -DontStopOnIdleEnd
    Register-ScheduledTask -Force -TaskName JuliaDaemon -TaskPath Julia `
        -Action \$action -Trigger \$trigger -Principal \$principal -Settings \$settings
    """)
    run(`powershell -NoProfile -ExecutionPolicy Bypass -File $tmpfile`)
    rm(tmpfile, force=true)
    @info "Precompiling DaemonWorker"
    run(pipeline(`$(env["JULIA_DAEMON_WORKER_EXECUTABLE"]) --project=$(installed_worker_project()) -e 'using DaemonWorker'`, stdout, stderr))
    @info "Starting service"
    run(`schtasks /run /tn $TASK_PATH`)
end

function uninstall_service()
    stop_service()
    run(ignorestatus(`schtasks /delete /f /tn $TASK_PATH`))
end

function stop_service()
    run(ignorestatus(`schtasks /end /tn $TASK_PATH`))
    run(ignorestatus(`taskkill /F /T /IM julia-conductor.exe`))
end
