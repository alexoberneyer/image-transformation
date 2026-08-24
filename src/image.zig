const std = @import("std");
const Allocator = std.mem.Allocator;
const cipher = @import("cipher.zig");
const png = @import("png.zig");
const ppm = @import("ppm.zig");

/// Refuse to read anything larger than this. A `max_pixels` RGBA PNG is well
/// under it even before compression.
pub const max_file_bytes = 256 * 1024 * 1024;

pub const Format = enum { png, ppm };

pub const Image = struct {
    allocator: Allocator,
    width: u32,
    height: u32,
    /// Packed 8-bit RGB, `width * height * 3` bytes, no padding between rows.
    rgb: []u8,

    pub fn init(allocator: Allocator, width: u32, height: u32) !Image {
        const n = try cipher.pixelCount(width, height);
        return .{
            .allocator = allocator,
            .width = width,
            .height = height,
            .rgb = try allocator.alloc(u8, n * 3),
        };
    }

    /// Takes ownership of a decoder's pixel buffer.
    pub fn adopt(allocator: Allocator, decoded: anytype) Image {
        return .{
            .allocator = allocator,
            .width = decoded.width,
            .height = decoded.height,
            .rgb = decoded.rgb,
        };
    }

    pub fn deinit(self: *Image) void {
        self.allocator.free(self.rgb);
        self.* = undefined;
    }
};

/// The one place file extensions are mapped to formats. Anything unrecognised
/// is treated as PNG.
const extensions = [_]struct { text: []const u8, format: Format }{
    .{ .text = ".png", .format = .png },
    .{ .text = ".ppm", .format = .ppm },
    .{ .text = ".pnm", .format = .ppm },
    .{ .text = ".p6", .format = .ppm },
};

pub const PathParts = struct {
    /// `path` with a recognised extension removed.
    stem: []const u8,
    /// A recognised extension, or `.png` when there was none to recognise.
    ext: []const u8,
    format: Format,
};

/// Splits a path into the stem and extension used to name derived outputs.
/// An unrecognised extension is kept as part of the stem, so `photo.jpg`
/// becomes `photo.jpg.noise.png` rather than silently losing the `.jpg`.
pub fn splitPath(path: []const u8) PathParts {
    for (extensions) |e| {
        if (std.ascii.endsWithIgnoreCase(path, e.text)) {
            return .{ .stem = path[0 .. path.len - e.text.len], .ext = e.text, .format = e.format };
        }
    }
    return .{ .stem = path, .ext = extensions[0].text, .format = .png };
}

pub fn formatFromPath(path: []const u8) Format {
    return splitPath(path).format;
}

/// Detects the format from the file's own contents, not its name, so a
/// mislabelled file still loads.
pub fn load(allocator: Allocator, path: []const u8) !Image {
    const data = try std.fs.cwd().readFileAlloc(allocator, path, max_file_bytes);
    defer allocator.free(data);

    if (png.looksLike(data)) return Image.adopt(allocator, try png.decode(allocator, data));
    if (ppm.looksLike(data)) return Image.adopt(allocator, try ppm.decode(allocator, data));
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
    try std.fs.cwd().writeFile(.{ .sub_path = path, .data = bytes });
}

test "image format detection" {
    try std.testing.expectEqual(Format.png, formatFromPath("photo.PNG"));
    try std.testing.expectEqual(Format.ppm, formatFromPath("photo.ppm"));
    try std.testing.expectEqual(Format.ppm, formatFromPath("photo.PnM"));
    try std.testing.expectEqual(Format.ppm, formatFromPath("photo.p6"));
    // Unknown and missing extensions default to PNG.
    try std.testing.expectEqual(Format.png, formatFromPath("photo.jpg"));
    try std.testing.expectEqual(Format.png, formatFromPath("photo"));
}

test "path splitting keeps unrecognised extensions in the stem" {
    const cases = [_]struct { path: []const u8, stem: []const u8, ext: []const u8 }{
        .{ .path = "photo.png", .stem = "photo", .ext = ".png" },
        .{ .path = "photo.PNG", .stem = "photo", .ext = ".png" },
        .{ .path = "a/b/photo.ppm", .stem = "a/b/photo", .ext = ".ppm" },
        .{ .path = "/abs/photo.p6", .stem = "/abs/photo", .ext = ".p6" },
        .{ .path = "photo.jpg", .stem = "photo.jpg", .ext = ".png" },
        .{ .path = "photo", .stem = "photo", .ext = ".png" },
        .{ .path = "archive.png/photo", .stem = "archive.png/photo", .ext = ".png" },
        .{ .path = "", .stem = "", .ext = ".png" },
    };
    for (cases) |case| {
        const parts = splitPath(case.path);
        try std.testing.expectEqualStrings(case.stem, parts.stem);
        try std.testing.expectEqualStrings(case.ext, parts.ext);
    }
}

test "init rejects sizes the cipher cannot handle" {
    try std.testing.expectError(error.InvalidImageSize, Image.init(std.testing.allocator, 0, 8));
    try std.testing.expectError(error.InvalidImageSize, Image.init(std.testing.allocator, 100_000, 100_000));
}
