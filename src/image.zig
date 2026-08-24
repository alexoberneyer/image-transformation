const std = @import("std");
const Allocator = std.mem.Allocator;
const cipher = @import("cipher.zig");
const png = @import("png.zig");
const ppm = @import("ppm.zig");

pub const Format = enum { png, ppm };

pub const Image = struct {
    allocator: Allocator,
    width: u32,
    height: u32,
    rgb: []u8,

    pub fn init(allocator: Allocator, width: u32, height: u32) !Image {
        const n = try cipher.pixelCount(width, height);
        const rgb = try allocator.alloc(u8, n * 3);
        return .{
            .allocator = allocator,
            .width = width,
            .height = height,
            .rgb = rgb,
        };
    }

    pub fn deinit(self: *Image) void {
        self.allocator.free(self.rgb);
        self.* = undefined;
    }
};

pub fn formatFromPath(path: []const u8) Format {
    if (std.ascii.endsWithIgnoreCase(path, ".ppm") or
        std.ascii.endsWithIgnoreCase(path, ".p6") or
        std.ascii.endsWithIgnoreCase(path, ".pnm"))
    {
        return .ppm;
    }
    return .png;
}

pub fn load(allocator: Allocator, path: []const u8) !Image {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    const data = try file.readToEndAlloc(allocator, 256 * 1024 * 1024);
    defer allocator.free(data);

    if (png.looksLike(data)) {
        const decoded = try png.decode(allocator, data);
        return .{
            .allocator = allocator,
            .width = decoded.width,
            .height = decoded.height,
            .rgb = decoded.rgb,
        };
    }
    if (ppm.looksLike(data)) {
        const decoded = try ppm.decode(allocator, data);
        return .{
            .allocator = allocator,
            .width = decoded.width,
            .height = decoded.height,
            .rgb = decoded.rgb,
        };
    }
    return error.UnsupportedImageFormat;
}

pub fn encode(allocator: Allocator, img: Image, format: Format) ![]u8 {
    return switch (format) {
        .png => png.encode(allocator, img.width, img.height, img.rgb),
        .ppm => ppm.encode(allocator, img.width, img.height, img.rgb),
    };
}

pub fn save(img: Image, path: []const u8) !void {
    const bytes = try encode(img.allocator, img, formatFromPath(path));
    defer img.allocator.free(bytes);
    const file = try std.fs.cwd().createFile(path, .{});
    defer file.close();
    try file.writeAll(bytes);
}

test "image format detection" {
    try std.testing.expectEqual(Format.png, formatFromPath("photo.PNG"));
    try std.testing.expectEqual(Format.ppm, formatFromPath("photo.ppm"));
}
