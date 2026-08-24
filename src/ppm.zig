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
        if (self.index >= self.data.len) return error.InvalidPpm;
        const start = self.index;
        while (self.index < self.data.len) : (self.index += 1) {
            const c = self.data[self.index];
            if (std.ascii.isWhitespace(c) or c == '#') break;
        }
        if (start == self.index) return error.InvalidPpm;
        return self.data[start..self.index];
    }

    fn nextU32(self: *Parser) !u32 {
        const token = try self.nextToken();
        return std.fmt.parseInt(u32, token, 10) catch error.InvalidPpm;
    }
};

pub fn decode(allocator: Allocator, data: []const u8) !RgbImage {
    if (!looksLike(data)) return error.InvalidPpm;

    var parser = Parser{ .data = data };
    const magic = try parser.nextToken();
    const grayscale = std.mem.eql(u8, magic, "P5");
    if (!grayscale and !std.mem.eql(u8, magic, "P6")) return error.InvalidPpm;

    const width = try parser.nextU32();
    const height = try parser.nextU32();
    const maxval = try parser.nextU32();
    if (maxval != 255) return error.UnsupportedPpm;
    if (parser.index >= data.len) return error.InvalidPpm;
    // Single whitespace separator before the raster.
    const sep = parser.data[parser.index];
    if (!std.ascii.isWhitespace(sep)) return error.InvalidPpm;
    parser.index += 1;

    const pixels = std.math.mul(usize, width, height) catch return error.InvalidImageSize;
    const channels: usize = if (grayscale) 1 else 3;
    const needed = std.math.mul(usize, pixels, channels) catch return error.InvalidPpm;
    if (parser.data.len - parser.index < needed) return error.InvalidPpm;
    const raster = parser.data[parser.index..][0..needed];

    const rgb = try allocator.alloc(u8, std.math.mul(usize, pixels, 3) catch return error.InvalidImageSize);
    errdefer allocator.free(rgb);
    if (grayscale) {
        for (raster, 0..) |g, i| {
            rgb[i * 3] = g;
            rgb[i * 3 + 1] = g;
            rgb[i * 3 + 2] = g;
        }
    } else {
        @memcpy(rgb, raster);
    }
    return .{ .width = width, .height = height, .rgb = rgb };
}

pub fn encode(allocator: Allocator, width: u32, height: u32, rgb: []const u8) ![]u8 {
    const n = try cipher.pixelCount(width, height);
    if (rgb.len != n * 3) return error.InvalidImageSize;
    const header = try std.fmt.allocPrint(allocator, "P6\n{d} {d}\n255\n", .{ width, height });
    defer allocator.free(header);
    const out = try allocator.alloc(u8, header.len + rgb.len);
    @memcpy(out[0..header.len], header);
    @memcpy(out[header.len..], rgb);
    return out;
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
    const data = "P5\n2 1\n255\n\x10\x20";
    const decoded = try decode(allocator, data);
    defer allocator.free(decoded.rgb);
    try std.testing.expectEqualSlices(u8, &.{ 0x10, 0x10, 0x10, 0x20, 0x20, 0x20 }, decoded.rgb);
}

test "ppm comments are ignored" {
    const allocator = std.testing.allocator;
    const data = "P6\n# comment\n1 1\n255\n\x01\x02\x03";
    const decoded = try decode(allocator, data);
    defer allocator.free(decoded.rgb);
    try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3 }, decoded.rgb);
}
