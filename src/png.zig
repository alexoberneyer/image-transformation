const std = @import("std");
const Allocator = std.mem.Allocator;
const cipher = @import("cipher.zig");

pub const RgbImage = struct {
    width: u32,
    height: u32,
    rgb: []u8,
};

const signature = [_]u8{ 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A };

pub fn looksLike(data: []const u8) bool {
    return data.len >= signature.len and std.mem.eql(u8, data[0..signature.len], &signature);
}

pub fn decode(allocator: Allocator, data: []const u8) !RgbImage {
    if (!looksLike(data)) return error.InvalidPng;

    var offset: usize = signature.len;
    var width: u32 = 0;
    var height: u32 = 0;
    var bit_depth: u8 = 0;
    var color_type: u8 = 0;
    var saw_ihdr = false;
    var saw_iend = false;
    var idat = std.ArrayList(u8).init(allocator);
    defer idat.deinit();

    while (offset < data.len) {
        if (data.len - offset < 12) return error.InvalidPng;
        const len = std.mem.readInt(u32, data[offset..][0..4], .big);
        const typ = data[offset + 4 ..][0..4];
        if (len > data.len - (offset + 12)) return error.InvalidPng;
        const chunk = data[offset + 8 ..][0..len];
        const crc_got = std.mem.readInt(u32, data[offset + 8 + len ..][0..4], .big);
        var crc = std.hash.crc.Crc32.init();
        crc.update(typ);
        crc.update(chunk);
        if (crc.final() != crc_got) return error.InvalidPngCrc;
        offset += 12 + @as(usize, len);

        if (!saw_ihdr) {
            if (!std.mem.eql(u8, typ, "IHDR")) return error.InvalidPng;
        }

        if (std.mem.eql(u8, typ, "IHDR")) {
            if (saw_ihdr or chunk.len != 13) return error.InvalidPng;
            width = std.mem.readInt(u32, chunk[0..4], .big);
            height = std.mem.readInt(u32, chunk[4..8], .big);
            bit_depth = chunk[8];
            color_type = chunk[9];
            const compression = chunk[10];
            const filter = chunk[11];
            const interlace = chunk[12];
            if (compression != 0 or filter != 0 or interlace != 0) return error.UnsupportedPng;
            if (bit_depth != 8) return error.UnsupportedPng;
            switch (color_type) {
                0, 2, 4, 6 => {},
                else => return error.UnsupportedPng,
            }
            saw_ihdr = true;
        } else if (std.mem.eql(u8, typ, "IDAT")) {
            try idat.appendSlice(chunk);
        } else if (std.mem.eql(u8, typ, "IEND")) {
            saw_iend = true;
            break;
        } else if (typ[0] & 0x20 == 0) {
            // Unknown critical chunk.
            return error.UnsupportedPng;
        }
    }

    if (!saw_ihdr or !saw_iend) return error.InvalidPng;
    if (idat.items.len == 0) return error.InvalidPng;

    var compressed = std.io.fixedBufferStream(idat.items);
    var inflated = std.ArrayList(u8).init(allocator);
    defer inflated.deinit();
    std.compress.zlib.decompress(compressed.reader(), inflated.writer()) catch return error.InvalidPng;

    const bpp: usize = switch (color_type) {
        0 => 1,
        2 => 3,
        4 => 2,
        6 => 4,
        else => unreachable,
    };
    const stride = std.math.mul(usize, width, bpp) catch return error.InvalidPng;
    const expected = std.math.mul(usize, height, stride + 1) catch return error.InvalidPng;
    if (inflated.items.len < expected) return error.InvalidPng;

    const recon = try allocator.alloc(u8, std.math.mul(usize, height, stride) catch return error.InvalidPng);
    defer allocator.free(recon);
    try unfilter(recon, inflated.items[0..expected], width, height, bpp);

    const n = try cipher.pixelCount(width, height);
    const rgb = try allocator.alloc(u8, n * 3);
    errdefer allocator.free(rgb);
    toRgb(rgb, recon, color_type);
    return .{ .width = width, .height = height, .rgb = rgb };
}

fn unfilter(recon: []u8, inflated: []const u8, width: u32, height: u32, bpp: usize) !void {
    const stride = @as(usize, width) * bpp;
    var y: usize = 0;
    while (y < height) : (y += 1) {
        const row_start = y * (stride + 1);
        const filter = inflated[row_start];
        const src = inflated[row_start + 1 ..][0..stride];
        const dst = recon[y * stride ..][0..stride];
        const prev: []const u8 = if (y == 0) dst[0..0] else recon[(y - 1) * stride ..][0..stride];

        var x: usize = 0;
        while (x < stride) : (x += 1) {
            const a: u8 = if (x >= bpp) dst[x - bpp] else 0;
            const b: u8 = if (prev.len != 0) prev[x] else 0;
            const c: u8 = if (prev.len != 0 and x >= bpp) prev[x - bpp] else 0;
            dst[x] = src[x] +% switch (filter) {
                0 => 0,
                1 => a,
                2 => b,
                3 => @as(u8, @truncate((@as(u16, a) + b) / 2)),
                4 => paeth(a, b, c),
                else => return error.InvalidPng,
            };
        }
    }
}

fn paeth(a: u8, b: u8, c: u8) u8 {
    const ia: i16 = a;
    const ib: i16 = b;
    const ic: i16 = c;
    const p = ia + ib - ic;
    const pa = @abs(p - ia);
    const pb = @abs(p - ib);
    const pc = @abs(p - ic);
    if (pa <= pb and pa <= pc) return a;
    if (pb <= pc) return b;
    return c;
}

fn toRgb(out: []u8, recon: []const u8, color_type: u8) void {
    var i: usize = 0;
    var o: usize = 0;
    switch (color_type) {
        0 => {
            while (o < out.len) : ({
                i += 1;
                o += 3;
            }) {
                const g = recon[i];
                out[o] = g;
                out[o + 1] = g;
                out[o + 2] = g;
            }
        },
        2 => @memcpy(out, recon),
        4 => {
            while (o < out.len) : ({
                i += 2;
                o += 3;
            }) {
                const g = recon[i];
                out[o] = g;
                out[o + 1] = g;
                out[o + 2] = g;
            }
        },
        6 => {
            while (o < out.len) : ({
                i += 4;
                o += 3;
            }) {
                out[o] = recon[i];
                out[o + 1] = recon[i + 1];
                out[o + 2] = recon[i + 2];
            }
        },
        else => unreachable,
    }
}

pub fn encode(allocator: Allocator, width: u32, height: u32, rgb: []const u8) ![]u8 {
    const n = try cipher.pixelCount(width, height);
    if (rgb.len != n * 3) return error.InvalidImageSize;

    const stride = std.math.mul(usize, width, 3) catch return error.InvalidImageSize;
    const filtered_len = std.math.mul(usize, height, stride + 1) catch return error.InvalidImageSize;
    const filtered = try allocator.alloc(u8, filtered_len);
    defer allocator.free(filtered);

    var y: usize = 0;
    while (y < height) : (y += 1) {
        const dst = y * (stride + 1);
        filtered[dst] = 0;
        @memcpy(filtered[dst + 1 ..][0..stride], rgb[y * stride ..][0..stride]);
    }

    var compressed = std.ArrayList(u8).init(allocator);
    defer compressed.deinit();
    var input = std.io.fixedBufferStream(filtered);
    try std.compress.zlib.compress(input.reader(), compressed.writer(), .{ .level = .fast });

    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();
    try out.appendSlice(&signature);

    var ihdr: [13]u8 = undefined;
    std.mem.writeInt(u32, ihdr[0..4], width, .big);
    std.mem.writeInt(u32, ihdr[4..8], height, .big);
    ihdr[8] = 8;
    ihdr[9] = 2;
    ihdr[10] = 0;
    ihdr[11] = 0;
    ihdr[12] = 0;
    try writeChunk(&out, "IHDR", &ihdr);
    try writeChunk(&out, "IDAT", compressed.items);
    try writeChunk(&out, "IEND", &.{});
    return out.toOwnedSlice();
}

fn writeChunk(out: *std.ArrayList(u8), typ: *const [4]u8, data: []const u8) !void {
    var len_buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &len_buf, @intCast(data.len), .big);
    try out.appendSlice(&len_buf);
    try out.appendSlice(typ);
    try out.appendSlice(data);
    var crc = std.hash.crc.Crc32.init();
    crc.update(typ);
    crc.update(data);
    var crc_buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &crc_buf, crc.final(), .big);
    try out.appendSlice(&crc_buf);
}

test "png encode/decode roundtrip" {
    const allocator = std.testing.allocator;
    var rgb: [5 * 4 * 3]u8 = undefined;
    for (&rgb, 0..) |*byte, i| byte.* = @truncate(i * 13);

    const encoded = try encode(allocator, 5, 4, &rgb);
    defer allocator.free(encoded);

    const decoded = try decode(allocator, encoded);
    defer allocator.free(decoded.rgb);
    try std.testing.expectEqual(@as(u32, 5), decoded.width);
    try std.testing.expectEqual(@as(u32, 4), decoded.height);
    try std.testing.expectEqualSlices(u8, &rgb, decoded.rgb);
}

test "png decoder reconstructs Sub-filtered RGB" {
    const allocator = std.testing.allocator;
    // 2x1 RGB, filter type 1 (Sub): raw pixels (255,0,0) (0,255,0)
    // filtered: 1, 255, 0, 0, 0-255, 255-0, 0-0 => 1 ff 00 00 01 ff 00
    const raw = [_]u8{ 1, 255, 0, 0, 1, 255, 0 };
    var compressed = std.ArrayList(u8).init(allocator);
    defer compressed.deinit();
    var input = std.io.fixedBufferStream(&raw);
    try std.compress.zlib.compress(input.reader(), compressed.writer(), .{});

    var png = std.ArrayList(u8).init(allocator);
    defer png.deinit();
    try png.appendSlice(&signature);
    var ihdr = [_]u8{
        0, 0, 0, 2,
        0, 0, 0, 1,
        8, 2, 0, 0,
        0,
    };
    try writeChunk(&png, "IHDR", &ihdr);
    try writeChunk(&png, "IDAT", compressed.items);
    try writeChunk(&png, "IEND", &.{});

    const decoded = try decode(allocator, png.items);
    defer allocator.free(decoded.rgb);
    try std.testing.expectEqual(@as(u32, 2), decoded.width);
    try std.testing.expectEqual(@as(u32, 1), decoded.height);
    try std.testing.expectEqualSlices(u8, &.{ 255, 0, 0, 0, 255, 0 }, decoded.rgb);
}

test "png decoder expands 8-bit grayscale" {
    const allocator = std.testing.allocator;
    const raw = [_]u8{ 0, 0x7f };
    var compressed = std.ArrayList(u8).init(allocator);
    defer compressed.deinit();
    var input = std.io.fixedBufferStream(&raw);
    try std.compress.zlib.compress(input.reader(), compressed.writer(), .{});

    var png = std.ArrayList(u8).init(allocator);
    defer png.deinit();
    try png.appendSlice(&signature);
    var ihdr = [_]u8{
        0, 0, 0, 1,
        0, 0, 0, 1,
        8, 0, 0, 0,
        0,
    };
    try writeChunk(&png, "IHDR", &ihdr);
    try writeChunk(&png, "IDAT", compressed.items);
    try writeChunk(&png, "IEND", &.{});

    const decoded = try decode(allocator, png.items);
    defer allocator.free(decoded.rgb);
    try std.testing.expectEqualSlices(u8, &.{ 0x7f, 0x7f, 0x7f }, decoded.rgb);
}
