# SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
# SPDX-License-Identifier: MPL-2.0

# BSD has no standard user-level service manager.

# A conductor started by hand runs on from its replaced binary.
stop_service() = nothing
service_environment() = Dict{String,String}()

function install_service(env::Dict{String,String})
    assignments = ["$k=$(Base.shell_escape_posixly(v))" for (k, v) in env]
    env_exports = join("export " .* assignments, "\n   ")
    inline_env = join(assignments, " ")
    conductor = Base.shell_escape_posixly(installed_conductor())
    @info """
    To run the daemon:

    1. Manual:
       $env_exports
       $conductor &

    2. Shell profile (~/.profile or ~/.zshrc):
       if ! pgrep -qf julia-conductor; then
           $inline_env $conductor &
       fi

    3. FreeBSD daemon(8), keeping it running (OpenBSD has no such command):
       env $inline_env daemon -r -o "\$HOME/julia-daemon.log" $conductor
    """
end

function uninstall_service()
    @info "Stop any running daemon with: pkill -f julia-conductor"
end
