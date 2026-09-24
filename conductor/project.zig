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
    // The last --project wins
    if (parsed.getSwitch("--project")) |project| {
        if (project.len == 0 or std.mem.eql(u8, project, "@.")) {
            return findProjectToml(allocator, io, cwd);
        }
        return try allocator.dupe(u8, project);
    }
    if (julia_project) |project| {
        if (project.len == 0 or std.mem.eql(u8, project, "@.")) {
            return findProjectToml(allocator, io, cwd);
        }
        if (std.mem.startsWith(u8, project, "~/") and home_dir.len > 0) {
            return try std.fmt.allocPrint(allocator, "{s}{s}", .{ home_dir, project[1..] });
        }
        if (!std.fs.path.isAbsolute(project)) {
            return try std.fs.path.resolve(allocator, &.{ cwd, project });
        }
        return try allocator.dupe(u8, project);
    }
    return null;
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
