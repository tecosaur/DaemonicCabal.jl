// SPDX-FileCopyrightText: © 2026 TEC <contact@tecosaur.net>
// SPDX-License-Identifier: MPL-2.0
//
// Host memory-pressure monitor. Two-band hysteresis keeps a host hovering at
// the threshold from flapping in and out of eviction episodes.

const std = @import("std");
const platform = @import("platform/main.zig");
const config = @import("config.zig");

pub const Source = enum { psi, memfree, none };

pub const Monitor = struct {
    source: Source,
    under_pressure: bool = false,

    pub fn init(cfg: *const config.Config) Monitor {
        if (!cfg.memory_pressure) return .{ .source = .none };
        const source: Source = if (platform.readPsiSomeAvg10() != null)
            .psi
        else if (platform.readMemInfo() != null)
            .memfree
        else
            .none;
        return .{ .source = source };
    }

    pub fn logResolution(self: *const Monitor, cfg: *const config.Config) void {
        if (!cfg.memory_pressure) {
            std.debug.print(" - Memory pressure: disabled (TTL-only)\n", .{});
            return;
        }
        switch (self.source) {
            .psi => std.debug.print(" - Memory pressure: PSI /proc/pressure/memory, some avg10 >= {d}%\n", .{cfg.psi_threshold}),
            .memfree => std.debug.print(" - Memory pressure: free-memory level (PSI unavailable, normal on stock Linux)\n", .{}),
            .none => std.debug.print(" - Memory pressure: no readable signal on this platform; running TTL-only\n", .{}),
        }
    }

    pub fn active(self: *const Monitor) bool {
        return self.source != .none;
    }

    pub fn poll(self: *Monitor, cfg: *const config.Config) bool {
        switch (self.source) {
            // No hysteresis: the 10s average is already smooth.
            .psi => self.under_pressure = (platform.readPsiSomeAvg10() orelse 0) >= cfg.psi_threshold,
            .memfree => if (platform.readMemInfo()) |m| {
                if (cfg.memfree_low.satisfied(m.available, m.total))
                    self.under_pressure = true
                else if (!cfg.memfree_high.satisfied(m.available, m.total))
                    self.under_pressure = false;
            },
            .none => {},
        }
        return self.under_pressure;
    }
};
