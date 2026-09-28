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
    const project = parsed.getSwitch("--project") orelse julia_project orelse return null;
    if (project.len == 0 or std.mem.eql(u8, project, "@.")) return findProjectToml(allocator, io, cwd);
    if (std.mem.startsWith(u8, project, "@")) return try allocator.dupe(u8, project);
    if (std.mem.startsWith(u8, project, "~/") and home_dir.len > 0)
        return try std.fmt.allocPrint(allocator, "{s}{s}", .{ home_dir, project[1..] });
    return try std.fs.path.resolve(allocator, &.{ cwd, project });
}

// As Base.project_names; the directory stands for whichever it holds.
const project_names = [_][]const u8{ "JuliaProject.toml", "Project.toml" };

fn findProjectToml(allocator: std.mem.Allocator, io: Io, start_dir: []const u8) !?[]const u8 {
    var dir = start_dir;
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    while (true) {
        for (project_names) |name| {
            const project_path = try std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ dir, name });
            if (Io.Dir.openFileAbsolute(io, project_path, .{})) |file| {
                file.close(io);
                return try allocator.dupe(u8, dir);
            } else |_| {}
        }
        const parent = std.fs.path.dirname(dir) orelse return null;
        if (std.mem.eql(u8, parent, dir)) return null;
        dir = parent;
    }
}

test "a project names a path from the client's cwd, or an environment" {
    const gpa = std.testing.allocator;
    const cases = [_]struct { argv: []const []const u8, julia_project: ?[]const u8 = null, want: ?[]const u8 }{
        .{ .argv = &.{ "julia", "--project=.", "-e", "1" }, .want = "/work/app" },
        .{ .argv = &.{ "julia", "--project=sub/", "-e", "1" }, .want = "/work/app/sub" },
        .{ .argv = &.{ "julia", "--project=/srv/x/Project.toml", "-e", "1" }, .want = "/srv/x/Project.toml" },
        .{ .argv = &.{ "julia", "--project=~/p", "-e", "1" }, .want = "/home/me/p" },
        .{ .argv = &.{ "julia", "--project=@stdlib", "-e", "1" }, .want = "@stdlib" },
        .{ .argv = &.{ "julia", "-e", "1" }, .julia_project = "..", .want = "/work" },
        .{ .argv = &.{ "julia", "--project=/a", "-e", "1" }, .julia_project = "/b", .want = "/a" },
        .{ .argv = &.{ "julia", "-e", "1" }, .want = null },
    };
    for (cases) |case| {
        var parsed = try args.parse(gpa, case.argv);
        defer parsed.deinit();
        const got = try resolve(gpa, std.testing.io, &parsed, case.julia_project, "/home/me", "/work/app");
        defer if (got) |g| gpa.free(g);
        if (case.want) |want| try std.testing.expectEqualStrings(want, got.?) else try std.testing.expect(got == null);
    }
}

test "@. finds the project above the cwd" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "app/src");
    try tmp.dir.writeFile(io, .{ .sub_path = "app/Project.toml", .data = "" });
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const root = buf[0..try tmp.dir.realPath(io, &buf)];
    const src = try std.fs.path.join(gpa, &.{ root, "app/src" });
    defer gpa.free(src);
    var parsed = try args.parse(gpa, &.{ "julia", "--project=@.", "-e", "1" });
    defer parsed.deinit();
    const got = (try resolve(gpa, io, &parsed, null, "", src)).?;
    defer gpa.free(got);
    try std.testing.expectEqualStrings(std.fs.path.dirname(src).?, got);
}
