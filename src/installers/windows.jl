# SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
# SPDX-License-Identifier: MPL-2.0

const PS1_WRAPPER = joinpath(install_dir(), "julia-daemon.ps1")
const SILENT_LAUNCH_SCRIPT = joinpath(install_dir(), "silent_launch.vbs")

function install_service(env::Dict)
	# this script is the script that actually runs the conductor with the correct environment.
	open(PS1_WRAPPER, "w") do io
		envs = join(["\$env:$k = '$v'" for (k, v) in env], "\n")

		write(io, """
		$envs

		& "$(installed_conductor())" *>> "$(joinpath(install_dir(), "conductor.log"))"
		""")
	end
	# this script is used to invoke the launch script from the scheduled task without
	# flashing a console on the screen. Simple powershell invocation flashes.
	open(SILENT_LAUNCH_SCRIPT, "w") do io
		write(io, """
		Set shell = CreateObject("WScript.Shell")
		shell.Run "powershell.exe -NoProfile -ExecutionPolicy Bypass -WorkingDirectory ""$(install_dir())"" -File ""$PS1_WRAPPER"" ", 0, False
		""")
	end

	@info "Installing startup task"
	# This script is just here to create the Task
	tmpfile = tempname() * ".ps1"
	write(tmpfile, """
	\$action = New-ScheduledTaskAction -Execute 'wscript.exe' -Argument '$SILENT_LAUNCH_SCRIPT'
	\$trigger = New-ScheduledTaskTrigger -AtLogOn -User "$(ENV["USERNAME"])"
	\$principal = New-ScheduledTaskPrincipal -UserId "$(ENV["USERNAME"])" -LogonType Interactive
	\$settings = New-ScheduledTaskSettingsSet `
		-AllowStartIfOnBatteries `
		-DontStopIfGoingOnBatteries `
		-ExecutionTimeLimit ([TimeSpan]::Zero) `
		-MultipleInstances IgnoreNew `
		-DontStopOnIdleEnd
	Register-ScheduledTask -TaskName JuliaDaemon -TaskPath Julia `
		-Action \$action -Trigger \$trigger -Principal \$principal -Settings \$settings
	""")

	run(`powershell -NoProfile -ExecutionPolicy Bypass -File $tmpfile`)
	rm(tmpfile, force=true)

	@info "Precompiling DaemonWorker"
	run(pipeline(`$(worker_executable()) --project=$(installed_worker_project()) -e 'using DaemonWorker'`, stdout, stderr))

	@info "Starting service"
	run(`schtasks /run /tn "Julia\\JuliaDaemon"`)
	
end

function uninstall_service()
	if ispath(PS1_WRAPPER)
		rm(PS1_WRAPPER, force=true)
	end
	run(ignorestatus(`taskkill /F /IM julia-conductor.exe`))
	run(ignorestatus(`schtasks /delete /f /tn "Julia\JuliaDaemon"`))
end
