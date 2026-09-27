# SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
# SPDX-License-Identifier: MPL-2.0

module DaemonicCabal

using BaseDirs
using Pkg.Artifacts

@static if VERSION >= v"1.11"
    eval(Expr(:public, :install, :uninstall))
end

const EXE = Sys.iswindows() ? ".exe" : ""
const CLIENT_NAME = "juliaclient$EXE"

const DEFAULTS = (
    conductor_host = "127.0.0.1",
    conductor_port = 9345,
    ports = 35520:37568,
)

# Installation

include("installers/common.jl")

@static if Sys.islinux()
    include("installers/linux.jl")
elseif Sys.isapple()
    include("installers/macos.jl")
elseif Sys.isbsd()
    include("installers/bsd.jl")
elseif Sys.iswindows()
    include("installers/windows.jl")
else
    stop_service() = nothing
    service_environment() = Dict{String,String}()
    function install_service(::Dict{String,String})
        @error "Service installation is not implemented for $(Sys.KERNEL).\n" *
            "If you're up for it, consider making a PR to add support 🙂"
    end
    function uninstall_service()
        @error "Service removal is not implemented for $(Sys.KERNEL).\n" *
            "If you're up for it, consider making a PR to add support 🙂"
    end
    __init__() = @warn "DaemonicCabal is not supported on $(Sys.KERNEL) systems (yet)"
end

BaseDirs.@promise_no_assign @doc """
    DaemonicCabal

Run Julia code in warm, long-lived workers, through `juliaclient`: a drop-in
replacement for `julia`.

# Setup

Install this package anywhere and run `DaemonicCabal.install()`. Re-run it
after updating `DaemonicCabal` or Julia itself; `DaemonicCabal.uninstall()`
undoes it.

## Platform Support

- **Linux**: a systemd user service
- **macOS**: a launchd user agent (logging to `~/Library/Logs/julia-daemon.log`)
- **Windows**: a Task Scheduler logon task, `Julia\\JuliaDaemon`
- **FreeBSD/OpenBSD**: the client, with instructions to start the daemon by hand

# Configuration

The daemon reads `JULIA_DAEMON_*` environment variables, set in its service.
`juliaclient --reconfigure` lists them all, changes them live, and saves them
to the service. Among them:

- `JULIA_DAEMON_WORKER_EXECUTABLE` [`julia`, as `install()` finds it] \n
  The Julia binary workers run.
- `JULIA_DAEMON_WORKER_ARGS` [`--startup-file=no`] \n
  Arguments passed to the Julia worker processes.
- `JULIA_DAEMON_WORKER_MAXCLIENTS` [`1`] \n
  The maximum number of clients a worker serves at once, `0` for no limit.
- `JULIA_DAEMON_MAX_TTL` [`7200`] \n
  Seconds after which an idle worker is always culled; one may go sooner when
  memory is scarce.
- `JULIA_DAEMON_SERVER` [a local socket] \n
  Where clients reach the conductor: a socket path, or `tcp://host:port`.
""" DaemonicCabal

end
