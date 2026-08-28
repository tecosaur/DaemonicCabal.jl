const std = @import("std");
const eloop = @import("eloop/windows.zig");

comptime {
    _ = &eloop.run;
}

pub fn main() void {}
