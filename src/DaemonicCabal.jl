# SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
# SPDX-License-Identifier: MPL-2.0

module DaemonicCabal

using BaseDirs
using Pkg.Artifacts

@static if VERSION >= v"1.11"
    eval(Expr(:public, :install, :uninstall))
end

const CLIENT_NAME = "juliaclient"

const DEFAULTS = (
    worker_maxclients = 1,
    worker_args = "--startup-file=no",
    worker_ttl = 2*60*60, # 2h
)

mainsocket() = get(ENV, "JULIA_DAEMON_SERVER",
                   BaseDirs.runtime("julia-daemon", "conductor.sock"))

julia_env() = [k => v for (k, v) in ENV if startswith(k, "JULIA_")]

# Installation

include("installers/common.jl")

@static if Sys.islinux()
    include("installers/linux.jl")
elseif Sys.isapple()
    include("installers/macos.jl")
elseif Sys.isbsd()
    include("installers/bsd.jl")
else
    @doc """
    install()
Setup the daemon and client on this machine.
!!! warning
    This is currently unimplemented for $(Sys.KERNEL)!
"""
    function install()
        @error "This functionality is currently only implemented for Linux, macOS, and BSD.\n" *
            "If you're up for it, consider making a PR to add support for $(Sys.KERNEL) 🙂"
    end

    @doc """
    uninstall()
Undo `install()`.
!!! warning
    This is currently unimplemented for $(Sys.KERNEL)!
"""
    function uninstall()
        @error "This functionality is currently only implemented for Linux, macOS, and BSD.\n" *
            "If you're up for it, consider making a PR to add support for $(Sys.KERNEL) 🙂"
    end

    __init__() = @warn "DaemonicCabal is not supported on $(Sys.KERNEL) systems (yet)"
end

BaseDirs.@promise_no_assign @doc """
    DaemonicCabal

# Setup

Install this package anywhere and run `DaemonicCabal.install()`. Re-run this
command after updating `DaemonicCabal`, the configuration env vars, or Julia
itself.

## Platform Support

- **Linux**: Installs a systemd user service
- **macOS**: Installs a launchd user agent (logs to `~/Library/Logs/julia-daemon.log`)
- **FreeBSD/OpenBSD**: Installs the client and provides manual daemon setup instructions

# Configuration

When the daemon starts, it pays attention to the following environmental variables:
- `JULIA_DAEMON_SERVER` [`$(BaseDirs.runtime("julia-daemon", "conductor.sock"))`] \n
  The socket to connect to.
- `JULIA_DAEMON_WORKER_MAXCLIENTS` [default: `$(DEFAULTS.worker_maxclients)`]\n
  The maximum number of clients a worker may be attached to at once. Set to `0`
  to disable.
- `JULIA_DAEMON_WORKER_ARGS` [`$(DEFAULTS.worker_args)`] \n
  Arguments passed to the Julia worker processes.
- `JULIA_DAEMON_WORKER_EXECUTABLE` [`$(something(Sys.which("julia"), joinpath(Sys.BINDIR, "julia")))`] \n
  Path to the Julia executable used by the workers.
- `JULIA_DAEMON_WORKER_TTL` [`$(DEFAULTS.worker_ttl)`] \n
  Number of seconds a worker should be kept alive for after the last client disconnects.
""" DaemonicCabal

end
