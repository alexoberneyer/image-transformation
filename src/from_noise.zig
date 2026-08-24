const cli = @import("cli.zig");

pub fn main() !void {
    return cli.main(.from_noise);
}
