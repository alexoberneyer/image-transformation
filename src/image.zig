const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const cipher = @import("cipher.zig");
const png = @import("png.zig");
const ppm = @import("ppm.zig");

/// Refuse to read anything larger than this. A `max_pixels` RGBA PNG is well
/// under it even before compression.
pub const max_file_bytes = 256 * 1024 * 1024;

/// The path that stands for stdin or stdout, so the tools can sit in a pipe
/// without an image ever touching the filesystem. That matters here: a temp
/// file would leave the plaintext image on disk.
pub const standard_stream = "-";

/// How much of a standard stream to buffer at a time.
const stream_buffer_bytes = 64 * 1024;

pub fn isStandardStream(path: []const u8) bool {
    return std.mem.eql(u8, path, standard_stream);
}

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
/// mislabelled file - or a nameless stream - still loads.
pub fn load(allocator: Allocator, io: Io, path: []const u8) !Image {
    const data = if (isStandardStream(path))
        try readAll(allocator, io, Io.File.stdin())
    else
        try Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(max_file_bytes));
    defer allocator.free(data);

    if (png.looksLike(data)) return Image.adopt(allocator, try png.decode(allocator, data));
    if (ppm.looksLike(data)) return Image.adopt(allocator, try ppm.decode(allocator, data));
    return error.UnsupportedImageFormat;
}

fn readAll(allocator: Allocator, io: Io, file: Io.File) ![]u8 {
    var buffer: [stream_buffer_bytes]u8 = undefined;
    var reader = file.readerStreaming(io, &buffer);
    return reader.interface.allocRemaining(allocator, .limited(max_file_bytes));
}

pub fn encode(allocator: Allocator, img: Image, format: Format) ![]u8 {
    return switch (format) {
        .png => png.encode(allocator, img.width, img.height, img.rgb),
        .ppm => ppm.encode(allocator, img.width, img.height, img.rgb),
    };
}

/// `format` is passed in rather than derived here because a standard stream
/// has no name to read it from.
pub fn save(img: Image, io: Io, path: []const u8, format: Format) !void {
    const bytes = try encode(img.allocator, img, format);
    defer img.allocator.free(bytes);

    if (isStandardStream(path)) {
        var buffer: [stream_buffer_bytes]u8 = undefined;
        var writer = Io.File.stdout().writerStreaming(io, &buffer);
        try writer.interface.writeAll(bytes);
        try writer.interface.flush();
        return;
    }
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = bytes });
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
