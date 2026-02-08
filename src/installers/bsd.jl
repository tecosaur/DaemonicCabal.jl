# SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
# SPDX-License-Identifier: MPL-2.0

# BSD systems lack a standard user-level service manager.
# We print instructions for manual daemon setup.

function install_service(env::Dict{String,String})
    env_exports = join(["export $k=\"$v\"" for (k, v) in env], "\n       ")
    inline_env = join(["$k=\"$v\"" for (k, v) in env], " ")
    @info """
    To run the daemon:

    1. Manual:
       $env_exports
       $(installed_conductor()) &

    2. Shell profile (~/.profile or ~/.zshrc):
       if ! pgrep -qf julia-conductor; then
           $inline_env $(installed_conductor()) &
       fi

    3. FreeBSD daemon(8):
       daemon -e $inline_env $(installed_conductor())
    """
end

function uninstall_service()
    @info "Stop any running daemon with: pkill -f julia-conductor"
end
