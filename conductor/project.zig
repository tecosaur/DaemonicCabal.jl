// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0

const std = @import("std");
const Io = std.Io;
const args = @import("args.zig");

/// Caller frees; null means the default environment (@v#.#).
pub fn resolve(
    allocator: std.mem.Allocator,
    io: Io,
    parsed: *const args.ParsedArgs,
    julia_project: ?[]const u8,
    home_dir: []const u8,
    cwd: []const u8,
) !?[]const u8 {
    // The last --project wins, then JULIA_PROJECT; a path is the client's, from `cwd`.
    // Empty is the default environment; a bare --project is `@.`.
    const project = parsed.getSwitch("--project") orelse julia_project orelse return null;
    if (project.len == 0) return null;
    // A deleted cwd (sent empty) has no project above it, nor paths from it.
    if (std.mem.eql(u8, project, "@.")) return if (cwd.len == 0) null else findProjectToml(allocator, io, cwd, home_dir);
    if (std.mem.startsWith(u8, project, "@")) return try allocator.dupe(u8, project);
    if ((std.mem.eql(u8, project, "~") or std.mem.startsWith(u8, project, "~/")) and home_dir.len > 0)
        return try allocator.print("{s}{s}", .{ home_dir, project[1..] });
    if (cwd.len == 0 and !std.Io.Dir.path.isAbsolute(project)) return error.CurrentDirUnavailable;
    return try std.Io.Dir.path.resolveAlloc(allocator, &.{ cwd, project });
}

// As Base.project_names; the directory stands for whichever it holds.
const project_names = [_][]const u8{ "JuliaProject.toml", "Project.toml" };

/// As Base.current_project: from `start_dir` up, giving up after `home_dir`.
fn findProjectToml(allocator: std.mem.Allocator, io: Io, start_dir: []const u8, home_dir: []const u8) !?[]const u8 {
    var dir = start_dir;
    var path_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    while (true) {
        for (project_names) |name| {
            const project_path = try std.mem.print(&path_buf, "{s}/{s}", .{ dir, name });
            const file = Io.Dir.openFileAbsolute(io, project_path, .{}) catch continue;
            file.close(io);
            if (isNamedExactly(io, dir, name)) return try allocator.dupe(u8, dir);
        }
        if (std.mem.eql(u8, dir, home_dir)) return null;
        const parent = std.Io.Dir.path.dirname(dir) orelse return null;
        if (std.mem.eql(u8, parent, dir)) return null;
        dir = parent;
    }
}

// As Sys.isfile_casesensitive: a case-insensitive filesystem opens a name
// in any case, so it must be listed as spelt.
fn isNamedExactly(io: Io, dir_path: []const u8, name: []const u8) bool {
    var dir = Io.Dir.openDirAbsolute(io, dir_path, .{ .iterate = true }) catch return false;
    defer dir.close(io);
    var iter = dir.iterate();
    while (iter.next(io) catch return false) |entry| {
        if (std.mem.eql(u8, entry.name, name)) return true;
    }
    return false;
}

test "a project names a path from the client's cwd, or an environment" {
    const gpa = std.testing.allocator;
    const cases = [_]struct { argv: []const []const u8, julia_project: ?[]const u8 = null, want: ?[]const u8 }{
        .{ .argv = &.{ "julia", "--project=.", "-e", "1" }, .want = "/work/app" },
        .{ .argv = &.{ "julia", "--project=sub/", "-e", "1" }, .want = "/work/app/sub" },
        .{ .argv = &.{ "julia", "--project=/srv/x/Project.toml", "-e", "1" }, .want = "/srv/x/Project.toml" },
        .{ .argv = &.{ "julia", "--project=~/p", "-e", "1" }, .want = "/home/me/p" },
        .{ .argv = &.{ "julia", "--project=~", "-e", "1" }, .want = "/home/me" },
        .{ .argv = &.{ "julia", "--project=~p", "-e", "1" }, .want = "/work/app/~p" },
        .{ .argv = &.{ "julia", "--project=", "-e", "1" }, .julia_project = "/b", .want = null },
        .{ .argv = &.{ "julia", "-e", "1" }, .julia_project = "", .want = null },
        .{ .argv = &.{ "julia", "--project=@stdlib", "-e", "1" }, .want = "@stdlib" },
        .{ .argv = &.{ "julia", "-e", "1" }, .julia_project = "..", .want = "/work" },
        .{ .argv = &.{ "julia", "--project=/a", "-e", "1" }, .julia_project = "/b", .want = "/a" },
        .{ .argv = &.{ "julia", "-e", "1" }, .want = null },
    };
    for (cases) |case| {
        const parsed = try args.parse(case.argv);
        const got = try resolve(gpa, std.testing.io, &parsed, case.julia_project, "/home/me", "/work/app");
        defer if (got) |g| gpa.free(g);
        if (case.want) |want| try std.testing.expectEqualStrings(want, got.?) else try std.testing.expect(got == null);
    }
}

test "a deleted cwd, sent empty, names no project" {
    const gpa = std.testing.allocator;
    const cases = [_]struct { argv: []const []const u8, want: anyerror!?[]const u8 }{
        .{ .argv = &.{ "julia", "--project", "-e", "1" }, .want = null },
        .{ .argv = &.{ "julia", "--project=/srv/x", "-e", "1" }, .want = "/srv/x" },
        .{ .argv = &.{ "julia", "--project=~/p", "-e", "1" }, .want = "/home/me/p" },
        .{ .argv = &.{ "julia", "--project=.", "-e", "1" }, .want = error.CurrentDirUnavailable },
    };
    for (cases) |case| {
        const parsed = try args.parse(case.argv);
        const got = resolve(gpa, std.testing.io, &parsed, null, "/home/me", "");
        defer if (got) |g| if (g) |p| gpa.free(p) else {} else |_| {};
        const want = case.want catch |err| {
            try std.testing.expectError(err, got);
            continue;
        };
        if (want) |w| try std.testing.expectEqualStrings(w, (try got).?) else try std.testing.expect((try got) == null);
    }
}

test "@. finds the project above the cwd" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "home/app/src");
    try tmp.dir.writeFile(io, .{ .sub_path = "home/app/Project.toml", .data = "" });
    try tmp.dir.writeFile(io, .{ .sub_path = "home/app/src/project.toml", .data = "" });
    try tmp.dir.writeFile(io, .{ .sub_path = "Project.toml", .data = "" });
    var buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const root = buf[0..try tmp.dir.realPath(io, &buf)];
    const home = try std.Io.Dir.path.join(gpa, &.{ root, "home" });
    defer gpa.free(home);
    const app = try std.Io.Dir.path.join(gpa, &.{ home, "app" });
    defer gpa.free(app);
    const src = try std.Io.Dir.path.join(gpa, &.{ app, "src" });
    defer gpa.free(src);
    const cases = [_]struct { argv: []const []const u8, home: []const u8 = "", cwd: []const u8, want: ?[]const u8 }{
        .{ .argv = &.{ "julia", "--project=@.", "-e", "1" }, .cwd = src, .want = app },
        .{ .argv = &.{ "julia", "--project", "-e", "1" }, .cwd = src, .want = app },
        .{ .argv = &.{ "julia", "-P" }, .cwd = src, .want = app },
        .{ .argv = &.{ "julia", "--project" }, .cwd = home, .want = root },
        // The walk checks the home directory, then gives up.
        .{ .argv = &.{ "julia", "--project" }, .home = home, .cwd = home, .want = null },
        .{ .argv = &.{ "julia", "--project" }, .home = home, .cwd = src, .want = app },
        .{ .argv = &.{ "julia", "--project" }, .home = app, .cwd = app, .want = app },
        // Empty is the default environment.
        .{ .argv = &.{ "julia", "--project=" }, .cwd = src, .want = null },
    };
    for (cases) |case| {
        const parsed = try args.parse(case.argv);
        const got = try resolve(gpa, io, &parsed, null, case.home, case.cwd);
        defer if (got) |g| gpa.free(g);
        if (case.want) |want| try std.testing.expectEqualStrings(want, got.?) else try std.testing.expect(got == null);
    }
    // What a case-insensitive filesystem would open as Project.toml isn't one.
    try std.testing.expect(!isNamedExactly(io, src, "Project.toml"));
    try std.testing.expect(isNamedExactly(io, src, "project.toml"));
}
