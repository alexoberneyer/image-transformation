const std = @import("std");
const Allocator = std.mem.Allocator;
const cipher = @import("cipher.zig");

pub const RgbImage = struct {
    width: u32,
    height: u32,
    rgb: []u8,
};

pub fn looksLike(data: []const u8) bool {
    return data.len >= 2 and data[0] == 'P' and (data[1] == '5' or data[1] == '6');
}

const Parser = struct {
    data: []const u8,
    index: usize = 0,

    fn skipWhitespaceAndComments(self: *Parser) void {
        while (self.index < self.data.len) {
            const c = self.data[self.index];
            if (c == '#') {
                while (self.index < self.data.len and self.data[self.index] != '\n') self.index += 1;
                continue;
            }
            if (std.ascii.isWhitespace(c)) {
                self.index += 1;
                continue;
            }
            break;
        }
    }

    fn nextToken(self: *Parser) ![]const u8 {
        self.skipWhitespaceAndComments();
        const start = self.index;
        while (self.index < self.data.len) : (self.index += 1) {
            const c = self.data[self.index];
            if (std.ascii.isWhitespace(c) or c == '#') break;
        }
        if (start == self.index) return error.InvalidPpm;
        return self.data[start..self.index];
    }

    fn nextU32(self: *Parser) !u32 {
        return std.fmt.parseInt(u32, try self.nextToken(), 10) catch error.InvalidPpm;
    }
};

pub fn decode(allocator: Allocator, data: []const u8) !RgbImage {
    var parser = Parser{ .data = data };
    const magic = try parser.nextToken();
    const grayscale = std.mem.eql(u8, magic, "P5");
    if (!grayscale and !std.mem.eql(u8, magic, "P6")) return error.InvalidPpm;

    const width = try parser.nextU32();
    const height = try parser.nextU32();
    if (try parser.nextU32() != 255) return error.UnsupportedPpm;

    // Exactly one whitespace byte separates the header from the raster; anything
    // after it is pixel data, including bytes that happen to look like a comment.
    if (parser.index >= data.len or !std.ascii.isWhitespace(data[parser.index])) return error.InvalidPpm;
    parser.index += 1;

    // Validate before sizing anything from the header.
    const n = try cipher.pixelCount(width, height);
    const raster_len = n * @as(usize, if (grayscale) 1 else 3);
    if (data.len - parser.index < raster_len) return error.InvalidPpm;
    const raster = data[parser.index..][0..raster_len];

    const rgb = try allocator.alloc(u8, n * 3);
    errdefer allocator.free(rgb);
    if (grayscale) {
        for (std.mem.bytesAsSlice([3]u8, rgb), raster) |*px, gray| px.* = .{ gray, gray, gray };
    } else {
        @memcpy(rgb, raster);
    }
    return .{ .width = width, .height = height, .rgb = rgb };
}

pub fn encode(allocator: Allocator, width: u32, height: u32, rgb: []const u8) ![]u8 {
    const n = try cipher.pixelCount(width, height);
    if (rgb.len != n * 3) return error.InvalidImageSize;

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    // "P6\n<w> <h>\n255\n" is at most 26 bytes for u32 dimensions.
    try out.ensureTotalCapacityPrecise(allocator, rgb.len + 26);
    try out.print(allocator, "P6\n{d} {d}\n255\n", .{ width, height });
    out.appendSliceAssumeCapacity(rgb);
    return out.toOwnedSlice(allocator);
}

test "ppm encode/decode roundtrip" {
    const allocator = std.testing.allocator;
    var rgb: [3 * 2 * 3]u8 = undefined;
    for (&rgb, 0..) |*byte, i| byte.* = @truncate(i * 40);

    const encoded = try encode(allocator, 3, 2, &rgb);
    defer allocator.free(encoded);

    const decoded = try decode(allocator, encoded);
    defer allocator.free(decoded.rgb);
    try std.testing.expectEqual(@as(u32, 3), decoded.width);
    try std.testing.expectEqual(@as(u32, 2), decoded.height);
    try std.testing.expectEqualSlices(u8, &rgb, decoded.rgb);
}

test "ppm P5 grayscale expands to rgb" {
    const allocator = std.testing.allocator;
    const decoded = try decode(allocator, "P5\n2 1\n255\n\x10\x20");
    defer allocator.free(decoded.rgb);
    try std.testing.expectEqualSlices(u8, &.{ 0x10, 0x10, 0x10, 0x20, 0x20, 0x20 }, decoded.rgb);
}

test "ppm comments and extra header whitespace are ignored" {
    const allocator = std.testing.allocator;
    for ([_][]const u8{
        "P6\n# comment\n1 1\n255\n\x01\x02\x03",
        "P6  1\t1\n\n255\n\x01\x02\x03",
        "P6\n1 1\n# trailing comment\n255\n\x01\x02\x03",
    }) |source| {
        const decoded = try decode(allocator, source);
        defer allocator.free(decoded.rgb);
        try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3 }, decoded.rgb);
    }
}

test "ppm decoder rejects malformed input" {
    const allocator = std.testing.allocator;
    // Not a PPM at all.
    try std.testing.expectError(error.InvalidPpm, decode(allocator, "P4\n1 1\n255\n\x00"));
    // Raster shorter than the header promises.
    try std.testing.expectError(error.InvalidPpm, decode(allocator, "P6\n4 4\n255\n\x01\x02\x03"));
    // Header truncated mid-way.
    try std.testing.expectError(error.InvalidPpm, decode(allocator, "P6\n2 2\n"));
    // 16-bit samples are not supported.
    try std.testing.expectError(error.UnsupportedPpm, decode(allocator, "P6\n1 1\n65535\n\x00" ** 6));
    // Zero and absurd dimensions are rejected before any allocation.
    try std.testing.expectError(error.InvalidImageSize, decode(allocator, "P6\n0 1\n255\n"));
    try std.testing.expectError(error.InvalidImageSize, decode(allocator, "P6\n100000 100000\n255\n"));
}
