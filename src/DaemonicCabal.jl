# SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
# SPDX-License-Identifier: MPL-2.0

module DaemonicCabal

using BaseDirs
using Pkg.Artifacts
using Serialization

export @remote, remotecall_fetch

@static if VERSION >= v"1.11"
    eval(Expr(:public, :install, :uninstall, :connect, :Connection, :RemoteException, :ConnectionError, :VersionMismatch))
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

# Remote calls

include(joinpath(dirname(@__DIR__), "worker", "src", "remotewire.jl"))
include("remote.jl")

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

# Remote calls

From any Julia session, [`connect`](@ref) to a worker, local or at a
trusted daemon over TCP, and run code there with [`@remote`](@ref) or
[`remotecall_fetch`](@ref), getting its value back. The worker runs the
caller's Julia minor version: the daemon's own Julia where that matches, else
JuliaUp's channel for it.

# Setup

Install this package anywhere and run `DaemonicCabal.install()`, which sets
the daemon up as a user service (systemd, launchd, or a Windows logon task;
on the BSDs it prints how to start it). Re-run it after updating
`DaemonicCabal` or Julia itself; `DaemonicCabal.uninstall()` undoes it.

# Configuration

The daemon reads `JULIA_DAEMON_*` environment variables, set in its service:
`juliaclient --reconfigure` lists them, changes them live, and saves them.
Where its worker executable is JuliaUp's `julia`, a client can ask for another
Julia with `juliaclient --julia=1.14`.
""" DaemonicCabal

end
