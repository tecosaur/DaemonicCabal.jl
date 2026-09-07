# SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
# SPDX-License-Identifier: MPL-2.0

const BAT_WRAPPER = joinpath(install_dir(), "julia-daemon.bat")
const RUNKEY = raw"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
function bat_wrapper_contents(env::Dict)
	env_section = replace(join([
		"set \"$k=$v\"" for (k, v) in env
	], "\n"), "\n" => "\r\n")

	"""
	@echo off
	$env_section

	$(installed_conductor())
	"""
end

function install_service(env::Dict)
	open(BAT_WRAPPER, "w") do io
		write(io, bat_wrapper_contents(env))
	end

	@info "Installing startup item"
	exec = "cmd.exe /d /c \"\"$BAT_WRAPPER\"\" "
	run(`reg.exe add $RUNKEY /v JuliaDaemon /t REG_SZ /d $exec /f`)
	@info "Starting"
	run(detach(`cmd.exe /d /c ""$BAT_WRAPPER""`); wait=false)

end

function uninstall_service()
	if ispath(BAT_WRAPPER)
		rm(BAT_WRAPPER, force=true)
	end
	run(ignorestatus(`taskkill /F /IM julia-conductor.exe`))
	run(ignorestatus(`reg.exe delete $RUNKEY /v JuliaDaemon /f`))
end
