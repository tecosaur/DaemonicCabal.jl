// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0
//
// The environment a service manager starts the conductor with, as the
// installer wrote it: read, and rewritten with changed settings. The
// installer names it in JULIA_DAEMON_SERVICE, `<kind>:<path>`.
//
// A systemd unit is left as installed: the changes go in a drop-in beside
// it, which overrides it, unsetting as well as setting. A launchd plist and
// a PowerShell script are rewritten in place, each only where it holds the
// environment; one not in the installer's shape is refused, not guessed at.
// Nothing here runs a command: the caller runs `Kind.reloadCommand`.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Environ = std.process.Environ;

pub const Kind = enum {
    systemd,
    launchd,
    powershell,

    /// What makes the service manager reread a saved change, if it must be told.
    pub fn reloadCommand(self: Kind) ?[]const []const u8 {
        return switch (self) {
            .systemd => &.{ "systemctl", "--user", "daemon-reload" },
            .launchd, .powershell => null,
        };
    }

    /// When the manager rereads the file, if not as the conductor restarts.
    pub fn rereadNote(self: Kind) ?[]const u8 {
        return switch (self) {
            .launchd => "launchd reads it as it loads the agent: at login, or with launchctl unload then load",
            .systemd, .powershell => null,
        };
    }
};

pub const Service = struct {
    kind: Kind,
    path: []const u8,

    /// `<kind>:<path>`, as JULIA_DAEMON_SERVICE holds it.
    pub fn parse(spec: []const u8) ?Service {
        const colon = std.mem.findScalar(u8, spec, ':') orelse return null;
        const kind = std.meta.stringToEnum(Kind, spec[0..colon]) orelse return null;
        const path = spec[colon + 1 ..];
        if (path.len == 0) return null;
        return .{ .kind = kind, .path = path };
    }

    /// Where saved changes are written.
    pub fn target(self: Service, buf: []u8) error{NameTooLong}![]const u8 {
        return switch (self.kind) {
            .systemd => std.mem.print(buf, "{s}.d/" ++ drop_in, .{self.path}) catch error.NameTooLong,
            .launchd, .powershell => self.path,
        };
    }

    /// The shell command restarting the conductor with what's saved: launchd
    /// rereads a plist only as it loads it, so it's unloaded and loaded again.
    pub fn restartCommand(self: Service, buf: []u8) error{NameTooLong}![]const u8 {
        const quote = if (std.mem.findScalar(u8, self.path, ' ') != null) "'" else "";
        const unit = std.Io.Dir.path.basename(self.path);
        return switch (self.kind) {
            .systemd => std.mem.print(buf, "systemctl --user restart {s}", .{std.mem.cutSuffix(u8, unit, ".service") orelse unit}),
            .launchd => std.mem.print(buf, "launchctl unload {0s}{1s}{0s} && launchctl load {0s}{1s}{0s}", .{ quote, self.path }),
            .powershell => std.mem.print(buf, "taskkill /F /IM julia-conductor.exe & schtasks /run /tn \"Julia\\JuliaDaemon\"", .{}),
        } catch error.NameTooLong;
    }
};

/// A variable set, or unset (null).
pub const Change = struct { key: []const u8, value: ?[]const u8 };

pub const Error = error{
    /// The file isn't as the installer wrote it.
    Unrecognised,
    /// A value no service file could hold (a line break).
    Unwritable,
} || Allocator.Error;

const drop_in = "reconfigure.conf";

/// The environment a service declares: what it sets, and what it unsets
/// (systemd's `UnsetEnvironment=`) of what it would otherwise inherit.
pub const Declared = struct {
    set: Environ.Map,
    unset: std.BufSet,

    pub fn init(gpa: Allocator) Declared {
        return .{ .set = .init(gpa), .unset = .init(gpa) };
    }

    pub fn deinit(self: *Declared) void {
        self.set.deinit();
        self.unset.deinit();
    }

    /// Whether it sets or unsets `key`.
    pub fn declares(self: *const Declared, key: []const u8) bool {
        return self.set.contains(key) or self.unset.contains(key);
    }

    fn put(self: *Declared, key: []const u8, value: ?[]const u8) Allocator.Error!void {
        if (value) |v| {
            try self.set.put(key, v);
            self.unset.remove(key);
        } else {
            _ = self.set.swapRemove(key);
            try self.unset.insert(key);
        }
    }
};

/// What the service declares, into `out`.
pub fn load(gpa: Allocator, io: Io, service: Service, out: *Declared) !void {
    const text = try readFile(gpa, io, service.path);
    defer gpa.free(text);
    try parse(gpa, service.kind, text, out);
    if (service.kind != .systemd) return;
    var buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const extra = try readIfThere(gpa, io, try service.target(&buf)) orelse return;
    defer gpa.free(extra);
    try parse(gpa, .systemd, extra, out);
}

/// Writes `changes` to the service's environment, replacing the file whole
/// (through a symbolic link, the file it names).
pub fn save(gpa: Allocator, io: Io, service: Service, changes: []const Change) !void {
    for (changes) |change| if (change.value) |v| if (std.mem.findAny(u8, v, "\r\n") != null) return error.Unwritable;
    var buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const path = try service.target(&buf);
    const rewritten = switch (service.kind) {
        .systemd => blk: {
            const text = try readFile(gpa, io, service.path);
            defer gpa.free(text);
            var unit = Declared.init(gpa);
            defer unit.deinit();
            try parse(gpa, .systemd, text, &unit);
            var overrides = Declared.init(gpa);
            defer overrides.deinit();
            if (try readIfThere(gpa, io, path)) |existing| {
                defer gpa.free(existing);
                try parse(gpa, .systemd, existing, &overrides);
            }
            for (changes) |change| try overrides.put(change.key, change.value);
            try Io.Dir.cwd().createDirPath(io, std.Io.Dir.path.dirname(path).?);
            break :blk try dropIn(gpa, &unit.set, &overrides);
        },
        .launchd, .powershell => blk: {
            const text = try readFile(gpa, io, path);
            defer gpa.free(text);
            break :blk try rewrite(gpa, service.kind, text, changes);
        },
    };
    defer gpa.free(rewritten);
    try replaceFile(io, path, rewritten);
}

/// What `text`, a service file of `kind`, declares, into `out`: systemd's
/// `Environment=` and `UnsetEnvironment=`, a plist's EnvironmentVariables,
/// a script's `$env:` lines.
pub fn parse(gpa: Allocator, kind: Kind, text: []const u8, out: *Declared) Error!void {
    switch (kind) {
        .systemd => try parseSystemd(gpa, text, out),
        .launchd => try parsePlist(gpa, text, &out.set),
        .powershell => try parsePowershell(gpa, text, &out.set),
    }
}

/// `text`, a plist or script, with `changes` made.
pub fn rewrite(gpa: Allocator, kind: Kind, text: []const u8, changes: []const Change) Error![]u8 {
    for (changes) |change| if (change.value) |v| if (std.mem.findAny(u8, v, "\r\n") != null) return error.Unwritable;
    return switch (kind) {
        .systemd => unreachable, // a drop-in is written whole
        .launchd => rewritePlist(gpa, text, changes),
        .powershell => rewritePowershell(gpa, text, changes),
    };
}

/// A drop-in declaring `overrides`, but for what `unit` sets the same.
pub fn dropIn(gpa: Allocator, unit: *const Environ.Map, overrides: *const Declared) Allocator.Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    try out.appendSlice(gpa, "# Written by juliaclient --reconfigure\n[Service]\n");
    var it = overrides.set.iterator();
    while (it.next()) |entry| {
        const value = entry.value_ptr.*;
        const same = if (unit.get(entry.key_ptr.*)) |was| std.mem.eql(u8, was, value) else false;
        if (same) continue;
        try out.appendSlice(gpa, "Environment=\"");
        try appendSystemdQuoted(&out, gpa, entry.key_ptr.*);
        try out.append(gpa, '=');
        try appendSystemdQuoted(&out, gpa, value);
        try out.appendSlice(gpa, "\"\n");
    }
    // Sorted, as a set has no order of its own.
    var unset: std.ArrayList([]const u8) = .empty;
    defer unset.deinit(gpa);
    var keys = overrides.unset.iterator();
    while (keys.next()) |key| try unset.append(gpa, key.*);
    std.mem.sort([]const u8, unset.items, {}, struct {
        fn lessThan(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    }.lessThan);
    for (unset.items) |key| try out.print(gpa, "UnsetEnvironment={s}\n", .{key});
    return out.toOwnedSlice(gpa);
}

fn applyChanges(env: *Environ.Map, changes: []const Change) !void {
    for (changes) |change| {
        if (change.value) |v| try env.put(change.key, v) else _ = env.swapRemove(change.key);
    }
}

// --- systemd ---

fn parseSystemd(gpa: Allocator, text: []const u8, out: *Declared) Error!void {
    var in_service = false;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (std.mem.startsWith(u8, line, "[")) {
            in_service = std.mem.eql(u8, line, "[Service]");
            continue;
        }
        if (!in_service) continue;
        if (std.mem.startsWith(u8, line, "Environment=")) {
            var words = SystemdWords{ .text = line["Environment=".len..] };
            while (try words.next(gpa)) |word| {
                defer gpa.free(word);
                const eq = std.mem.findScalar(u8, word, '=') orelse continue;
                if (eq == 0) continue;
                try out.put(word[0..eq], word[eq + 1 ..]);
            }
        } else if (std.mem.startsWith(u8, line, "UnsetEnvironment=")) {
            var keys = std.mem.tokenizeAny(u8, line["UnsetEnvironment=".len..], " \t");
            while (keys.next()) |key| try out.put(key, null);
        }
    }
}

// Words of an `Environment=` line: quoted or bare, with C escapes, `%%` a %.
const SystemdWords = struct {
    text: []const u8,
    pos: usize = 0,

    fn next(self: *SystemdWords, gpa: Allocator) Allocator.Error!?[]u8 {
        while (self.pos < self.text.len and (self.text[self.pos] == ' ' or self.text[self.pos] == '\t')) self.pos += 1;
        if (self.pos == self.text.len) return null;
        var word: std.ArrayList(u8) = .empty;
        errdefer word.deinit(gpa);
        var quote: ?u8 = null;
        while (self.pos < self.text.len) : (self.pos += 1) {
            const ch = self.text[self.pos];
            if (quote) |q| {
                if (ch == q) {
                    quote = null;
                    continue;
                }
            } else if (ch == '"' or ch == '\'') {
                quote = ch;
                continue;
            } else if (ch == ' ' or ch == '\t') break;
            if (ch == '\\' and self.pos + 1 < self.text.len) {
                self.pos += 1;
                try word.append(gpa, self.text[self.pos]);
            } else if (ch == '%' and self.pos + 1 < self.text.len and self.text[self.pos + 1] == '%') {
                self.pos += 1;
                try word.append(gpa, '%');
            } else {
                try word.append(gpa, ch);
            }
        }
        return try word.toOwnedSlice(gpa);
    }
};

fn appendSystemdQuoted(out: *std.ArrayList(u8), gpa: Allocator, text: []const u8) Allocator.Error!void {
    for (text) |ch| switch (ch) {
        '"', '\\' => try out.appendSlice(gpa, &.{ '\\', ch }),
        '%' => try out.appendSlice(gpa, "%%"),
        else => try out.append(gpa, ch),
    };
}

// --- launchd ---

const plist_env_key = "<key>EnvironmentVariables</key>";
const plist_indent = "        ";

// The EnvironmentVariables dict's contents, between its tags.
fn plistEnvSpan(text: []const u8) Error!struct { start: usize, end: usize } {
    const key = std.mem.find(u8, text, plist_env_key) orelse return error.Unrecognised;
    const after = key + plist_env_key.len;
    const open = std.mem.findPos(u8, text, after, "<dict>") orelse return error.Unrecognised;
    if (std.mem.trim(u8, text[after..open], " \t\r\n").len != 0) return error.Unrecognised;
    const start = open + "<dict>".len;
    const end = std.mem.findPos(u8, text, start, "</dict>") orelse return error.Unrecognised;
    if (std.mem.find(u8, text[start..end], "<dict>") != null) return error.Unrecognised;
    return .{ .start = start, .end = end };
}

fn parsePlist(gpa: Allocator, text: []const u8, out: *Environ.Map) Error!void {
    const span = try plistEnvSpan(text);
    var rest = text[span.start..span.end];
    while (std.mem.find(u8, rest, "<key>")) |k| {
        const key_end = std.mem.findPos(u8, rest, k, "</key>") orelse return error.Unrecognised;
        const value_start = (std.mem.findPos(u8, rest, key_end, "<string>") orelse return error.Unrecognised) + "<string>".len;
        const value_end = std.mem.findPos(u8, rest, value_start, "</string>") orelse return error.Unrecognised;
        const key = try xmlUnescaped(gpa, rest[k + "<key>".len .. key_end]);
        defer gpa.free(key);
        const value = try xmlUnescaped(gpa, rest[value_start..value_end]);
        defer gpa.free(value);
        try out.put(key, value);
        rest = rest[value_end..];
    }
}

fn rewritePlist(gpa: Allocator, text: []const u8, changes: []const Change) Error![]u8 {
    const span = try plistEnvSpan(text);
    var env = Environ.Map.init(gpa);
    defer env.deinit();
    try parsePlist(gpa, text, &env);
    try applyChanges(&env, changes);
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    try out.appendSlice(gpa, text[0..span.start]);
    try out.append(gpa, '\n');
    var it = env.iterator();
    while (it.next()) |entry| {
        try out.appendSlice(gpa, plist_indent ++ "<key>");
        try appendXmlEscaped(&out, gpa, entry.key_ptr.*);
        try out.appendSlice(gpa, "</key>\n" ++ plist_indent ++ "<string>");
        try appendXmlEscaped(&out, gpa, entry.value_ptr.*);
        try out.appendSlice(gpa, "</string>\n");
    }
    // The closing tag's own indent, as it was.
    const line_start = if (std.mem.findScalarLast(u8, text[0..span.end], '\n')) |nl| nl + 1 else span.end;
    const indent = if (std.mem.trim(u8, text[line_start..span.end], " \t").len == 0) text[line_start..span.end] else "";
    try out.appendSlice(gpa, indent);
    try out.appendSlice(gpa, text[span.end..]);
    return out.toOwnedSlice(gpa);
}

const xml_entities = [_][2][]const u8{
    .{ "&amp;", "&" }, .{ "&lt;", "<" }, .{ "&gt;", ">" }, .{ "&quot;", "\"" }, .{ "&apos;", "'" },
};

fn xmlUnescaped(gpa: Allocator, text: []const u8) Allocator.Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    var i: usize = 0;
    outer: while (i < text.len) {
        for (xml_entities) |entity| if (std.mem.startsWith(u8, text[i..], entity[0])) {
            try out.appendSlice(gpa, entity[1]);
            i += entity[0].len;
            continue :outer;
        };
        try out.append(gpa, text[i]);
        i += 1;
    }
    return out.toOwnedSlice(gpa);
}

fn appendXmlEscaped(out: *std.ArrayList(u8), gpa: Allocator, text: []const u8) Allocator.Error!void {
    for (text) |ch| switch (ch) {
        '&' => try out.appendSlice(gpa, "&amp;"),
        '<' => try out.appendSlice(gpa, "&lt;"),
        '>' => try out.appendSlice(gpa, "&gt;"),
        else => try out.append(gpa, ch),
    };
}

// --- PowerShell ---

/// Windows PowerShell 5.1 reads a script without one as the ANSI code page.
const utf8_bom = "\xEF\xBB\xBF";

// `$env:KEY = 'value'`, a quote within doubled.
fn powershellLine(line: []const u8) ?struct { key: []const u8, quoted: []const u8 } {
    const trimmed = std.mem.trim(u8, std.mem.trimStart(u8, line, utf8_bom), " \t\r");
    if (!std.mem.startsWith(u8, trimmed, "$env:")) return null;
    const eq = std.mem.find(u8, trimmed, " = '") orelse return null;
    if (!std.mem.endsWith(u8, trimmed, "'") or trimmed.len < eq + 5) return null;
    return .{ .key = trimmed["$env:".len..eq], .quoted = trimmed[eq + 4 .. trimmed.len - 1] };
}

fn parsePowershell(gpa: Allocator, text: []const u8, out: *Environ.Map) Error!void {
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        const set = powershellLine(line) orelse continue;
        var value: std.ArrayList(u8) = .empty;
        defer value.deinit(gpa);
        var i: usize = 0;
        while (i < set.quoted.len) {
            var n = @max(singleQuoteLen(set.quoted[i..]), 1);
            // A doubled quote stands for its second.
            if (singleQuoteLen(set.quoted[i..]) > 0 and singleQuoteLen(set.quoted[i + n ..]) > 0) {
                i += n;
                n = singleQuoteLen(set.quoted[i..]);
            }
            try value.appendSlice(gpa, set.quoted[i..][0..n]);
            i += n;
        }
        try out.put(set.key, value.items);
    }
}

// Lines set in place, removed, or added after the last; the conductor's
// launch must follow them.
fn rewritePowershell(gpa: Allocator, script: []const u8, changes: []const Change) Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    const text = if (std.mem.cutPrefix(u8, script, utf8_bom)) |body| body: {
        try out.appendSlice(gpa, utf8_bom);
        break :body body;
    } else script;
    const launch = std.mem.find(u8, text, "\n& \"") orelse return error.Unrecognised;
    var done = try gpa.alloc(bool, changes.len);
    defer gpa.free(done);
    @memset(done, false);
    var last_set: usize = out.items.len; // where in `out` new lines go
    var lines = std.mem.splitScalar(u8, text[0 .. launch + 1], '\n');
    while (lines.next()) |line| {
        if (lines.index == null and line.len == 0) break;
        const set = powershellLine(line);
        const change = if (set) |s| for (changes, 0..) |c, i| {
            if (std.mem.eql(u8, c.key, s.key)) break i;
        } else null else null;
        if (change) |i| {
            done[i] = true;
            if (changes[i].value) |v| try appendPowershellSet(&out, gpa, changes[i].key, v);
        } else {
            try out.appendSlice(gpa, line);
            try out.append(gpa, '\n');
        }
        if (set != null) last_set = out.items.len;
    }
    var added: std.ArrayList(u8) = .empty;
    defer added.deinit(gpa);
    for (changes, done) |c, was_done| {
        if (was_done) continue;
        if (c.value) |v| try appendPowershellSet(&added, gpa, c.key, v);
    }
    try out.insertSlice(gpa, last_set, added.items);
    try out.appendSlice(gpa, text[launch + 1 ..]);
    return out.toOwnedSlice(gpa);
}

fn appendPowershellSet(out: *std.ArrayList(u8), gpa: Allocator, key: []const u8, value: []const u8) Allocator.Error!void {
    try out.print(gpa, "$env:{s} = '", .{key});
    var i: usize = 0;
    while (i < value.len) {
        const quote = singleQuoteLen(value[i..]);
        const n = @max(quote, 1);
        if (quote > 0) try out.appendSlice(gpa, value[i..][0..n]);
        try out.appendSlice(gpa, value[i..][0..n]);
        i += n;
    }
    try out.appendSlice(gpa, "'\n");
}

// The UTF-8 length of the single quote `text` starts with, or 0: PowerShell
// also takes U+2018-U+201B as one.
fn singleQuoteLen(text: []const u8) usize {
    if (std.mem.startsWith(u8, text, "'")) return 1;
    if (text.len >= 3 and text[0] == 0xE2 and text[1] == 0x80 and text[2] >= 0x98 and text[2] <= 0x9B) return 3;
    return 0;
}

// --- Files ---

fn readFile(gpa: Allocator, io: Io, path: []const u8) ![]u8 {
    return Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(1 << 20));
}

// A drop-in not yet written is none.
fn readIfThere(gpa: Allocator, io: Io, path: []const u8) !?[]u8 {
    return readFile(gpa, io, path) catch |err| switch (err) {
        error.FileNotFound => null,
        else => err,
    };
}

// Through a temporary file beside it, so a failure (or a crash) leaves the
// old whole; through a symbolic link, the file it names, so the link stays.
fn replaceFile(io: Io, link: []const u8, data: []const u8) !void {
    const cwd = Io.Dir.cwd();
    var real_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const path = if (cwd.realPathFile(io, link, &real_buf)) |n| real_buf[0..n] else |err| switch (err) {
        error.FileNotFound => link,
        else => return err,
    };
    var buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const temporary = try std.mem.print(&buf, "{s}.new", .{path});
    const file = try cwd.createFile(io, temporary, .{});
    errdefer cwd.deleteFile(io, temporary) catch {};
    {
        defer file.close(io);
        try file.writeStreamingAll(io, data);
        try file.sync(io); // on disk before the rename can be
    }
    try Io.Dir.rename(cwd, temporary, cwd, path, io);
}

test "a service is named by kind and path" {
    const s = Service.parse("systemd:/home/u/.config/systemd/user/julia-daemon.service").?;
    try std.testing.expectEqual(Kind.systemd, s.kind);
    var buf: [256]u8 = undefined;
    try std.testing.expectEqualStrings("/home/u/.config/systemd/user/julia-daemon.service.d/reconfigure.conf", try s.target(&buf));
    // Never the unit itself, where its drop-in's path doesn't fit.
    try std.testing.expectError(error.NameTooLong, s.target(buf[0..64]));
    try std.testing.expect(Service.parse("upstart:/x") == null);
    try std.testing.expect(Service.parse("launchd:") == null);
    try std.testing.expect(Service.parse("nothing") == null);
}

test "a service restarts as its manager has it reread what was saved" {
    var buf: [256]u8 = undefined;
    const unit = Service.parse("systemd:/home/u/.config/systemd/user/julia-daemon.service").?;
    try std.testing.expectEqualStrings("systemctl --user restart julia-daemon", try unit.restartCommand(&buf));
    const plist = Service.parse("launchd:/Users/u/Library/LaunchAgents/org.julialang.julia-daemon.plist").?;
    try std.testing.expectEqualStrings(
        "launchctl unload /Users/u/Library/LaunchAgents/org.julialang.julia-daemon.plist && launchctl load /Users/u/Library/LaunchAgents/org.julialang.julia-daemon.plist",
        try plist.restartCommand(&buf),
    );
    const spaced = Service.parse("launchd:/Users/a b/agent.plist").?;
    try std.testing.expectEqualStrings("launchctl unload '/Users/a b/agent.plist' && launchctl load '/Users/a b/agent.plist'", try spaced.restartCommand(&buf));
    const script = Service.parse("powershell:C:\\Users\\u\\julia-daemon.ps1").?;
    try std.testing.expectEqualStrings("taskkill /F /IM julia-conductor.exe & schtasks /run /tn \"Julia\\JuliaDaemon\"", try script.restartCommand(&buf));
    try std.testing.expectError(error.NameTooLong, plist.restartCommand(buf[0..32]));
}

const unit_text =
    \\[Unit]
    \\Description=Julia daemon
    \\Environment="NOT_THIS=1"
    \\
    \\[Service]
    \\Type=simple
    \\Environment="JULIA_DAEMON_WORKER_TTL=7200"
    \\Environment="JULIA_DAEMON_WORKER_ARGS=--startup-file=no -O2"
    \\Environment=A=1 "B=two words" C=50%%
    \\Restart=on-failure
    \\
;

test "a unit's environment, quoted, bare and escaped" {
    const gpa = std.testing.allocator;
    var env = Declared.init(gpa);
    defer env.deinit();
    try parse(gpa, .systemd, unit_text, &env);
    try std.testing.expectEqual(@as(usize, 5), env.set.count());
    try std.testing.expectEqualStrings("--startup-file=no -O2", env.set.get("JULIA_DAEMON_WORKER_ARGS").?);
    try std.testing.expectEqualStrings("two words", env.set.get("B").?);
    try std.testing.expectEqualStrings("50%", env.set.get("C").?);
    try std.testing.expect(env.set.get("NOT_THIS") == null);
    try parse(gpa, .systemd, "[Service]\nUnsetEnvironment=A B\n", &env);
    try std.testing.expect(env.set.get("A") == null);
    try std.testing.expect(env.declares("A") and env.unset.contains("B"));
}

test "a drop-in holds what differs from the unit, its unsets too, and reads back as declared" {
    const gpa = std.testing.allocator;
    var unit = Declared.init(gpa);
    defer unit.deinit();
    try parse(gpa, .systemd, unit_text, &unit);
    var overrides = Declared.init(gpa);
    defer overrides.deinit();
    try parse(gpa, .systemd, "[Service]\nUnsetEnvironment=JULIA_NUM_THREADS\n", &overrides);
    for ([_]Change{
        .{ .key = "JULIA_DAEMON_MAX_TTL", .value = "3600" },
        .{ .key = "JULIA_DAEMON_WORKER_TTL", .value = null },
        .{ .key = "B", .value = "say \"hi\" \\ 5%" },
        .{ .key = "A", .value = "1" }, // as the unit has it
    }) |change| try overrides.put(change.key, change.value);
    const text = try dropIn(gpa, &unit.set, &overrides);
    defer gpa.free(text);
    try std.testing.expectEqualStrings(
        \\# Written by juliaclient --reconfigure
        \\[Service]
        \\Environment="JULIA_DAEMON_MAX_TTL=3600"
        \\Environment="B=say \"hi\" \\ 5%%"
        \\UnsetEnvironment=JULIA_DAEMON_WORKER_TTL
        \\UnsetEnvironment=JULIA_NUM_THREADS
        \\
    , text);
    // The unit, then the drop-in: as systemd reads them.
    try parse(gpa, .systemd, text, &unit);
    try std.testing.expectEqualStrings("3600", unit.set.get("JULIA_DAEMON_MAX_TTL").?);
    try std.testing.expectEqualStrings("say \"hi\" \\ 5%", unit.set.get("B").?);
    try std.testing.expect(unit.set.get("JULIA_DAEMON_WORKER_TTL") == null);
    // An unset kept, though the unit never set it: what's inherited stays out.
    try std.testing.expect(unit.unset.contains("JULIA_NUM_THREADS"));
}

test "saving over a symbolic link writes the file it names" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "real.plist", .data = plist_text });
    try tmp.dir.symLink(io, "real.plist", "agent.plist", .{});
    var dir_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const dir = dir_buf[0..try tmp.dir.realPath(io, &dir_buf)];
    var path_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const link = try std.mem.print(&path_buf, "{s}/agent.plist", .{dir});
    try save(gpa, io, .{ .kind = .launchd, .path = link }, &.{.{ .key = "JULIA_DAEMON_MAX_TTL", .value = "60" }});
    var target_buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("real.plist", target_buf[0..try tmp.dir.readLink(io, "agent.plist", &target_buf)]);
    const written = try tmp.dir.readFileAlloc(io, "real.plist", gpa, .limited(1 << 16));
    defer gpa.free(written);
    try std.testing.expect(std.mem.find(u8, written, "<string>60</string>") != null);
}

const plist_text =
    \\<?xml version="1.0" encoding="UTF-8"?>
    \\<plist version="1.0">
    \\<dict>
    \\    <key>Label</key>
    \\    <string>org.julialang.julia-daemon</string>
    \\    <key>EnvironmentVariables</key>
    \\    <dict>
    \\        <key>JULIA_DAEMON_WORKER_TTL</key>
    \\        <string>7200</string>
    \\        <key>JULIA_DAEMON_WORKER_ARGS</key>
    \\        <string>--startup-file=no</string>
    \\    </dict>
    \\    <key>RunAtLoad</key>
    \\    <true/>
    \\</dict>
    \\</plist>
    \\
;

test "a plist's environment is rewritten in place" {
    const gpa = std.testing.allocator;
    const text = try rewrite(gpa, .launchd, plist_text, &.{
        .{ .key = "JULIA_DAEMON_WORKER_TTL", .value = null },
        .{ .key = "JULIA_DAEMON_WORKER_ARGS", .value = "-O3 <&>" },
        .{ .key = "JULIA_DAEMON_MAX_TTL", .value = "3600" },
    });
    defer gpa.free(text);
    try std.testing.expectEqualStrings(
        \\<?xml version="1.0" encoding="UTF-8"?>
        \\<plist version="1.0">
        \\<dict>
        \\    <key>Label</key>
        \\    <string>org.julialang.julia-daemon</string>
        \\    <key>EnvironmentVariables</key>
        \\    <dict>
        \\        <key>JULIA_DAEMON_WORKER_ARGS</key>
        \\        <string>-O3 &lt;&amp;&gt;</string>
        \\        <key>JULIA_DAEMON_MAX_TTL</key>
        \\        <string>3600</string>
        \\    </dict>
        \\    <key>RunAtLoad</key>
        \\    <true/>
        \\</dict>
        \\</plist>
        \\
    , text);
    var env = Declared.init(gpa);
    defer env.deinit();
    try parse(gpa, .launchd, text, &env);
    try std.testing.expectEqualStrings("-O3 <&>", env.set.get("JULIA_DAEMON_WORKER_ARGS").?);
    try std.testing.expectError(error.Unrecognised, rewrite(gpa, .launchd, "<plist></plist>", &.{}));
}

const script_text =
    \\$env:JULIA_DAEMON_WORKER_TTL = '7200'
    \\$env:JULIA_DAEMON_WORKER_ARGS = 'it''s'
    \\
    \\[Console]::OutputEncoding = [Text.UTF8Encoding]::new()
    \\& "C:\julia-daemon\julia-conductor.exe" *>> "C:\julia-daemon\conductor.log"
    \\
;

test "a script's $env: lines are set, removed and added" {
    const gpa = std.testing.allocator;
    var env = Declared.init(gpa);
    defer env.deinit();
    try parse(gpa, .powershell, script_text, &env);
    try std.testing.expectEqualStrings("it's", env.set.get("JULIA_DAEMON_WORKER_ARGS").?);
    const text = try rewrite(gpa, .powershell, script_text, &.{
        .{ .key = "JULIA_DAEMON_WORKER_TTL", .value = null },
        .{ .key = "JULIA_DAEMON_WORKER_ARGS", .value = "-O3" },
        .{ .key = "JULIA_DAEMON_MAX_TTL", .value = "a'b" },
    });
    defer gpa.free(text);
    try std.testing.expectEqualStrings(
        \\$env:JULIA_DAEMON_WORKER_ARGS = '-O3'
        \\$env:JULIA_DAEMON_MAX_TTL = 'a''b'
        \\
        \\[Console]::OutputEncoding = [Text.UTF8Encoding]::new()
        \\& "C:\julia-daemon\julia-conductor.exe" *>> "C:\julia-daemon\conductor.log"
        \\
    , text);
    try std.testing.expectError(error.Unrecognised, rewrite(gpa, .powershell, "$env:A = '1'\n", &.{}));
    try std.testing.expectError(error.Unwritable, rewrite(gpa, .powershell, script_text, &.{.{ .key = "A", .value = "a\nb" }}));
}

test "a script keeps its BOM, and its quotes are doubled" {
    const gpa = std.testing.allocator;
    const bom_script = utf8_bom ++ "$env:A = 'x''y'\n\n& \"c:\\conductor.exe\"\n";
    var env = Declared.init(gpa);
    defer env.deinit();
    try parse(gpa, .powershell, bom_script, &env);
    try std.testing.expectEqualStrings("x'y", env.set.get("A").?);
    const text = try rewrite(gpa, .powershell, bom_script, &.{.{ .key = "B", .value = "it's" }});
    defer gpa.free(text);
    try std.testing.expect(std.mem.startsWith(u8, text, utf8_bom ++ "$env:A"));
    try std.testing.expect(std.mem.find(u8, text, "$env:B = 'it''s'\n") != null);
}

test "a script doubles PowerShell's typographic single quotes too, and reads them back" {
    const gpa = std.testing.allocator;
    const value = "C:\\Users\\O\u{2019}Brien \u{2018}a\u{201A}b\u{201B} it's";
    const text = try rewrite(gpa, .powershell, script_text, &.{.{ .key = "B", .value = value }});
    defer gpa.free(text);
    try std.testing.expect(std.mem.find(u8, text, "$env:B = 'C:\\Users\\O\u{2019}\u{2019}Brien \u{2018}\u{2018}a\u{201A}\u{201A}b\u{201B}\u{201B} it''s'\n") != null);
    var env = Declared.init(gpa);
    defer env.deinit();
    try parse(gpa, .powershell, text, &env);
    try std.testing.expectEqualStrings(value, env.set.get("B").?);
}
