# SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
# SPDX-License-Identifier: MPL-2.0

# BSD systems lack a standard user-level service manager.
# We install files and provide instructions for manual daemon setup.

@doc """
    install(; mode=:$(DEFAULTS.mode), conductor_host="$(DEFAULTS.conductor_host)", conductor_port=$(DEFAULTS.conductor_port), ports=$(DEFAULTS.ports), ...)

Install files and symlink the client to `$(BaseDirs.User.bin(CLIENT_NAME))`.

Set `mode=:tcp` to use TCP transport instead of unix domain sockets.
`conductor_host`/`conductor_port` set the conductor's listen address, and `ports` allocates a range for worker connections.
Prints instructions for running the daemon manually since BSD lacks a standard user service manager.
"""
function install(; worker_maxclients::Integer = DEFAULTS.worker_maxclients,
                 worker_ttl::Integer = DEFAULTS.worker_ttl,
                 worker_args::AbstractString = DEFAULTS.worker_args,
                 mode::Symbol = DEFAULTS.mode,
                 conductor_host::AbstractString = DEFAULTS.conductor_host,
                 conductor_port::Integer = DEFAULTS.conductor_port,
                 ports::UnitRange{Int} = DEFAULTS.ports,
                 env = julia_env())
    install_files()
    install_client_symlink()
    denv = daemon_env(; worker_maxclients, worker_ttl, worker_args, mode, conductor_host, conductor_port, ports, env)
    env_exports = join(["export $k=\"$v\"" for (k, v) in denv], "\n       ")
    inline_env = join(["$k=\"$v\"" for (k, v) in denv], " ")
    @info """
    Done. To run the daemon:

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

"""
    uninstall()

Remove the client symlink and installed files. Stop any running daemon manually with `pkill -f julia-conductor`.
"""
function uninstall()
    uninstall_client_symlink()
    uninstall_files()
    @info "Done. Stop any running daemon with: pkill -f julia-conductor"
end
