const std = @import("std");
const cli = @import("cli.zig");

pub fn main(init: std.process.Init) !void {
    return cli.main(.from_noise, init);
}
