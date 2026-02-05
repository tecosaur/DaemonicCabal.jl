# SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
# SPDX-License-Identifier: MPL-2.0

const SOURCE_WORKER_PROJECT = joinpath(dirname(dirname(@__DIR__)), "worker")

install_dir() = BaseDirs.User.data(BaseDirs.Project("julia-daemon"), create=false)
installed_worker_project() = joinpath(install_dir(), "worker")
installed_conductor() = joinpath(install_dir(), "julia-conductor")
installed_client() = joinpath(install_dir(), "juliaclient")
client_symlink_path() = BaseDirs.User.bin(CLIENT_NAME)

worker_executable() = something(
    get(ENV, "JULIA_DAEMON_WORKER_EXECUTABLE", nothing),
    Sys.which("julia"),
    joinpath(Sys.BINDIR, "julia"))

function install_files()
    dest = install_dir()
    isdir(dest) && rm(dest; recursive=true, force=true)
    @info "Installing to $dest"
    mkpath(dest)
    cp(SOURCE_WORKER_PROJECT, installed_worker_project())
    make_tree_readonly(installed_worker_project())
    hardlink(joinpath(artifact"execbundle", "julia-conductor"), installed_conductor())
    hardlink(joinpath(artifact"execbundle", "juliaclient"), installed_client())
end

function uninstall_files()
    dest = install_dir()
    isdir(dest) || return
    @info "Removing $dest"
    rm(dest; recursive=true)
end

function install_client_symlink()
    binpath = client_symlink_path()
    @info "Symlinking client to $binpath"
    rm(binpath; force=true)
    symlink(installed_client(), binpath)
end

function uninstall_client_symlink()
    binpath = client_symlink_path()
    isfile(binpath) || islink(binpath) || return
    @info "Removing $binpath"
    rm(binpath)
end

function make_tree_readonly(path::AbstractString)
    for (root, dirs, files) in walkdir(path)
        for f in files
            chmod(joinpath(root, f), 0o444)
        end
        for d in dirs
            chmod(joinpath(root, d), 0o555)
        end
    end
    chmod(path, 0o555)
end
