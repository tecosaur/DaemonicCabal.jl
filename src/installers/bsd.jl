# SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
# SPDX-License-Identifier: MPL-2.0

# BSD systems lack a standard user-level service manager.
# We install files and provide instructions for manual daemon setup.

@doc """
    install(; worker_maxclients=$(DEFAULTS.worker_maxclients), worker_ttl=$(DEFAULTS.worker_ttl), worker_args="$(DEFAULTS.worker_args)")

Install files and symlink the client to `$(BaseDirs.User.bin(CLIENT_NAME))`.

Prints instructions for running the daemon manually since BSD lacks a standard user service manager.
"""
function install(; worker_maxclients::Integer = DEFAULTS.worker_maxclients,
                 worker_ttl::Integer = DEFAULTS.worker_ttl,
                 worker_args::AbstractString = DEFAULTS.worker_args,
                 env = julia_env())
    install_files()
    install_client_symlink()
    env_exports = isempty(env) ? "" : join(["export $k=\"$v\"" for (k, v) in env], "\n       ") * "\n       "
    @info """
    Done. To run the daemon:

    1. Manual:
       export JULIA_DAEMON_WORKER_EXECUTABLE="$(worker_executable())"
       export JULIA_DAEMON_WORKER_PROJECT="$(installed_worker_project())"
       export JULIA_DAEMON_WORKER_MAXCLIENTS=$worker_maxclients
       export JULIA_DAEMON_WORKER_TTL=$worker_ttl
       export JULIA_DAEMON_WORKER_ARGS="$worker_args"
       $(env_exports)$(installed_conductor()) &

    2. Shell profile (~/.profile or ~/.zshrc):
       if ! pgrep -qf julia-conductor; then
           JULIA_DAEMON_WORKER_PROJECT="$(installed_worker_project())" $(installed_conductor()) &
       fi

    3. FreeBSD daemon(8):
       daemon -e JULIA_DAEMON_WORKER_PROJECT="$(installed_worker_project())" $(installed_conductor())
    """
end

"""
    uninstall()

Remove the client symlink and installed files. Stop any running daemon manually with `pkill -f julia-conductor`.
"""
function uninstall()
    uninstall_client_symlink()
    uninstall_files()
    @info "Done. Stop any running daemon with: pkill -f julia-conductor"
end
