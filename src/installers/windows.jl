# SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
# SPDX-License-Identifier: MPL-2.0

const TASK_PATH = "Julia\\JuliaDaemon"

ps1_wrapper() = joinpath(install_dir(), "julia-daemon.ps1")
silent_launch_script() = joinpath(install_dir(), "silent_launch.vbs")

function install_service(env::Dict)
    stop_service()
    env = merge(env, Dict("JULIA_DAEMON_SERVICE" => "powershell:" * ps1_wrapper()))
    open(ps1_wrapper(), "w") do io
        envs = join(["\$env:$k = '$v'" for (k, v) in env], "\n")

        write(io, """
        $envs

        & "$(installed_conductor())" *>> "$(joinpath(install_dir(), "conductor.log"))"
        """)
    end
    # Launching powershell directly flashes a console window.
    open(silent_launch_script(), "w") do io
        write(io, """
        Set shell = CreateObject("WScript.Shell")
        shell.Run "powershell.exe -NoProfile -ExecutionPolicy Bypass -WorkingDirectory ""$(install_dir())"" -File ""$(ps1_wrapper())"" ", 0, False
        """)
    end

    @info "Installing startup task"
    tmpfile = tempname() * ".ps1"
    write(tmpfile, """
    \$action = New-ScheduledTaskAction -Execute 'wscript.exe' -Argument '$(silent_launch_script())'
    \$trigger = New-ScheduledTaskTrigger -AtLogOn -User "$(ENV["USERNAME"])"
    \$principal = New-ScheduledTaskPrincipal -UserId "$(ENV["USERNAME"])" -LogonType Interactive
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
    run(pipeline(`$(worker_executable()) --project=$(installed_worker_project()) -e 'using DaemonWorker'`, stdout, stderr))

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
