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
    return std.mem.startsWith(u8, data, &signature);
}

const Header = struct {
    width: u32,
    height: u32,
    color_type: u8,
    /// Bytes per pixel in the decoded scanline, and the filter's left-neighbour
    /// offset.
    bpp: usize,
    /// Decoded bytes per scanline, excluding the leading filter byte.
    stride: usize,
    /// Total size of the inflated scanline stream, filter bytes included.
    raw_len: usize,
};

fn parseHeader(chunk: []const u8) !Header {
    if (chunk.len != 13) return error.InvalidPng;
    const width = std.mem.readInt(u32, chunk[0..4], .big);
    const height = std.mem.readInt(u32, chunk[4..8], .big);
    const bit_depth = chunk[8];
    const color_type = chunk[9];
    const compression = chunk[10];
    const filter = chunk[11];
    const interlace = chunk[12];

    if (compression != 0 or filter != 0 or interlace != 0) return error.UnsupportedPng;
    if (bit_depth != 8) return error.UnsupportedPng;
    const bpp: usize = switch (color_type) {
        0 => 1, // grayscale
        2 => 3, // RGB
        4 => 2, // grayscale + alpha
        6 => 4, // RGBA
        else => return error.UnsupportedPng,
    };

    // Reject implausible dimensions here, before anything is sized from them.
    // `pixelCount` caps width * height at `max_pixels`, which keeps `stride`
    // (<= max_pixels * 4) and `raw_len` (<= max_pixels * 5) inside a usize.
    _ = try cipher.pixelCount(width, height);
    const stride = @as(usize, width) * bpp;
    return .{
        .width = width,
        .height = height,
        .color_type = color_type,
        .bpp = bpp,
        .stride = stride,
        .raw_len = @as(usize, height) * (stride + 1),
    };
}

pub fn decode(allocator: Allocator, data: []const u8) !RgbImage {
    if (!looksLike(data)) return error.InvalidPng;

    var offset: usize = signature.len;
    var header: ?Header = null;
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

        if (std.mem.eql(u8, typ, "IHDR")) {
            if (header != null) return error.InvalidPng;
            header = try parseHeader(chunk);
        } else if (header == null) {
            return error.InvalidPng; // IHDR must come first.
        } else if (std.mem.eql(u8, typ, "IDAT")) {
            try idat.appendSlice(chunk);
        } else if (std.mem.eql(u8, typ, "IEND")) {
            saw_iend = true;
            break;
        } else if (typ[0] & 0x20 == 0) {
            return error.UnsupportedPng; // Unknown critical chunk.
        }
    }

    const hdr = header orelse return error.InvalidPng;
    if (!saw_iend or idat.items.len == 0) return error.InvalidPng;

    // Deflate tops out near 1030:1, so a header promising far more output than
    // this IDAT could possibly produce is a bomb rather than an image - refuse
    // it before sizing a buffer from it. The margin is generous on purpose;
    // this only has to catch the absurd cases.
    if (hdr.raw_len / 2048 > idat.items.len) return error.InvalidPng;

    // Inflate into an exactly-sized buffer. A valid PNG produces precisely
    // `raw_len` bytes, so refusing to grow past it also caps what a
    // decompression bomb can cost us.
    const raw = try allocator.alloc(u8, hdr.raw_len);
    defer allocator.free(raw);
    var compressed = std.io.fixedBufferStream(idat.items);
    var raw_stream = std.io.fixedBufferStream(raw);
    std.compress.zlib.decompress(compressed.reader(), raw_stream.writer()) catch |err| switch (err) {
        error.NoSpaceLeft => {}, // More data than the header promised; ignore the tail.
        else => return error.InvalidPng,
    };
    if (raw_stream.pos != hdr.raw_len) return error.InvalidPng;

    const rgb = try allocator.alloc(u8, (try cipher.pixelCount(hdr.width, hdr.height)) * 3);
    errdefer allocator.free(rgb);

    if (hdr.color_type == 2) {
        // Truecolour scanlines already have the layout we want, so unfilter
        // straight into the result and skip a full-image buffer and copy.
        try unfilter(rgb, raw, hdr);
    } else {
        const recon = try allocator.alloc(u8, hdr.height * hdr.stride);
        defer allocator.free(recon);
        try unfilter(recon, raw, hdr);
        toRgb(rgb, recon, hdr.color_type);
    }
    return .{ .width = hdr.width, .height = hdr.height, .rgb = rgb };
}

/// Reverses the per-scanline filters described in PNG spec section 9.
///
/// The filter type is fixed for a whole scanline, so it is switched on once per
/// row rather than once per byte, and each row is split at `bpp`: before that
/// offset the left neighbour is defined to be zero, after it the general case
/// applies with no bounds checks.
fn unfilter(recon: []u8, raw: []const u8, hdr: Header) !void {
    const stride = hdr.stride;
    const bpp = hdr.bpp;
    std.debug.assert(recon.len == hdr.height * stride);

    var prev: []const u8 = &.{}; // Empty for the first row: `b` and `c` are zero.
    var y: usize = 0;
    while (y < hdr.height) : (y += 1) {
        const row = y * (stride + 1);
        const filter = raw[row];
        const src = raw[row + 1 ..][0..stride];
        const dst = recon[y * stride ..][0..stride];
        const head = @min(bpp, stride);

        switch (filter) {
            0 => @memcpy(dst, src), // None
            1 => { // Sub
                @memcpy(dst[0..head], src[0..head]);
                for (head..stride) |x| dst[x] = src[x] +% dst[x - bpp];
            },
            2 => { // Up
                if (prev.len == 0) {
                    @memcpy(dst, src);
                } else {
                    for (dst, src, prev) |*d, s, b| d.* = s +% b;
                }
            },
            3 => { // Average
                if (prev.len == 0) {
                    @memcpy(dst[0..head], src[0..head]);
                    for (head..stride) |x| dst[x] = src[x] +% (dst[x - bpp] >> 1);
                } else {
                    for (0..head) |x| dst[x] = src[x] +% (prev[x] >> 1);
                    for (head..stride) |x| {
                        const avg: u8 = @intCast((@as(u16, dst[x - bpp]) + prev[x]) >> 1);
                        dst[x] = src[x] +% avg;
                    }
                }
            },
            4 => { // Paeth
                if (prev.len == 0) {
                    // paeth(a, 0, 0) == a, i.e. the same as Sub.
                    @memcpy(dst[0..head], src[0..head]);
                    for (head..stride) |x| dst[x] = src[x] +% dst[x - bpp];
                } else {
                    // paeth(0, b, 0) == b, i.e. the same as Up.
                    for (0..head) |x| dst[x] = src[x] +% prev[x];
                    for (head..stride) |x| dst[x] = src[x] +% paeth(dst[x - bpp], prev[x], prev[x - bpp]);
                }
            },
            else => return error.InvalidPng,
        }
        prev = dst;
    }
}

fn paeth(a: u8, b: u8, c: u8) u8 {
    const p = @as(i16, a) + @as(i16, b) - @as(i16, c);
    const pa = @abs(p - @as(i16, a));
    const pb = @abs(p - @as(i16, b));
    const pc = @abs(p - @as(i16, c));
    if (pa <= pb and pa <= pc) return a;
    if (pb <= pc) return b;
    return c;
}

/// Widens a non-truecolour scanline buffer to packed RGB. Alpha is dropped.
fn toRgb(out: []u8, recon: []const u8, color_type: u8) void {
    const pixels = std.mem.bytesAsSlice([3]u8, out);
    var i: usize = 0;
    switch (color_type) {
        0, 4 => { // grayscale, optionally with alpha
            const step: usize = if (color_type == 0) 1 else 2;
            for (pixels) |*px| {
                px.* = .{ recon[i], recon[i], recon[i] };
                i += step;
            }
        },
        6 => for (pixels) |*px| { // RGBA
            px.* = recon[i..][0..3].*;
            i += 4;
        },
        else => unreachable, // Truecolour never needs a conversion pass.
    }
}

/// Deflating uniformly random bytes cannot shrink them, yet costs ~25x more
/// than storing them verbatim - and `to-noise` output is exactly that. Probe a
/// slice of the payload and let the result pick the encoding; both produce an
/// ordinary zlib stream that any PNG reader accepts.
fn worthCompressing(data: []const u8) bool {
    const max_probe: usize = 128 << 10;
    const probe_len: usize = @min(data.len, max_probe);
    const probe = data[(data.len - probe_len) / 2 ..][0..probe_len];

    var counter = std.io.countingWriter(std.io.null_writer);
    var reader = std.io.fixedBufferStream(probe);
    // If the probe itself fails, fall back to compressing: never worse than
    // storing by more than the time it takes.
    std.compress.zlib.compress(reader.reader(), counter.writer(), .{ .level = .fast }) catch return true;
    return counter.bytes_written * 100 < @as(u64, probe_len) * 98;
}

pub fn encode(allocator: Allocator, width: u32, height: u32, rgb: []const u8) ![]u8 {
    const n = try cipher.pixelCount(width, height);
    if (rgb.len != n * 3) return error.InvalidImageSize;
    const stride = @as(usize, width) * 3;

    // Every scanline gets filter type 0 (None): the payload is either noise,
    // which no filter helps, or a restored image being written once.
    const filtered = try allocator.alloc(u8, n * 3 + height);
    defer allocator.free(filtered);
    for (0..height) |y| {
        const row = y * (stride + 1);
        filtered[row] = 0;
        @memcpy(filtered[row + 1 ..][0..stride], rgb[y * stride ..][0..stride]);
    }

    const compress = worthCompressing(rgb);
    var compressed = std.ArrayList(u8).init(allocator);
    defer compressed.deinit();
    // Stored blocks add 5 bytes per 64 KiB; a rough guess is enough to keep
    // the common case from repeatedly reallocating a large buffer.
    try compressed.ensureTotalCapacityPrecise(
        if (compress) filtered.len / 4 + 64 else filtered.len + filtered.len / 8192 + 64,
    );
    var input = std.io.fixedBufferStream(filtered);
    if (compress) {
        try std.compress.zlib.compress(input.reader(), compressed.writer(), .{ .level = .fast });
    } else {
        try std.compress.zlib.store.compress(input.reader(), compressed.writer());
    }

    const ihdr_len = 13;
    var out = try std.ArrayList(u8).initCapacity(
        allocator,
        signature.len + (12 + ihdr_len) + (12 + compressed.items.len) + 12,
    );
    errdefer out.deinit();
    out.appendSliceAssumeCapacity(&signature);

    var ihdr: [ihdr_len]u8 = undefined;
    std.mem.writeInt(u32, ihdr[0..4], width, .big);
    std.mem.writeInt(u32, ihdr[4..8], height, .big);
    ihdr[8] = 8; // bit depth
    ihdr[9] = 2; // colour type: truecolour
    ihdr[10] = 0; // compression: deflate
    ihdr[11] = 0; // filter method: adaptive
    ihdr[12] = 0; // interlace: none
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Builds a PNG around an already-filtered scanline stream, so the decoder can
/// be pointed at hand-written filter cases.
fn buildPng(
    allocator: Allocator,
    width: u32,
    height: u32,
    color_type: u8,
    raw: []const u8,
) ![]u8 {
    var compressed = std.ArrayList(u8).init(allocator);
    defer compressed.deinit();
    var input = std.io.fixedBufferStream(raw);
    try std.compress.zlib.compress(input.reader(), compressed.writer(), .{});

    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();
    try out.appendSlice(&signature);
    var ihdr: [13]u8 = .{ 0, 0, 0, 0, 0, 0, 0, 0, 8, color_type, 0, 0, 0 };
    std.mem.writeInt(u32, ihdr[0..4], width, .big);
    std.mem.writeInt(u32, ihdr[4..8], height, .big);
    try writeChunk(&out, "IHDR", &ihdr);
    try writeChunk(&out, "IDAT", compressed.items);
    try writeChunk(&out, "IEND", &.{});
    return out.toOwnedSlice();
}

fn expectDecodes(width: u32, height: u32, color_type: u8, raw: []const u8, want: []const u8) !void {
    const allocator = std.testing.allocator;
    const bytes = try buildPng(allocator, width, height, color_type, raw);
    defer allocator.free(bytes);
    const decoded = try decode(allocator, bytes);
    defer allocator.free(decoded.rgb);
    try std.testing.expectEqual(width, decoded.width);
    try std.testing.expectEqual(height, decoded.height);
    try std.testing.expectEqualSlices(u8, want, decoded.rgb);
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

test "png roundtrip survives both compression strategies" {
    const allocator = std.testing.allocator;
    // Incompressible: takes the stored-block path. Smooth: takes deflate.
    for ([_]bool{ true, false }) |noisy| {
        const rgb = try allocator.alloc(u8, 64 * 40 * 3);
        defer allocator.free(rgb);
        if (noisy) {
            var rng = std.Random.DefaultCsprng.init([_]u8{5} ** 32);
            rng.fill(rgb);
        } else {
            for (rgb, 0..) |*byte, i| byte.* = @truncate(i / 64);
        }

        const encoded = try encode(allocator, 64, 40, rgb);
        defer allocator.free(encoded);
        const decoded = try decode(allocator, encoded);
        defer allocator.free(decoded.rgb);
        try std.testing.expectEqualSlices(u8, rgb, decoded.rgb);
    }
}

/// Applies one filter type to raw scanlines using the spec's formulas verbatim.
/// Deliberately naive and independent of `unfilter`'s row-specialised version,
/// so a roundtrip through the two actually proves something.
fn filterRows(
    allocator: Allocator,
    pixels: []const u8,
    width: u32,
    height: u32,
    bpp: usize,
    filter: u8,
) ![]u8 {
    const stride = @as(usize, width) * bpp;
    const out = try allocator.alloc(u8, height * (stride + 1));
    errdefer allocator.free(out);

    for (0..height) |y| {
        out[y * (stride + 1)] = filter;
        const row = pixels[y * stride ..][0..stride];
        const prev: []const u8 = if (y == 0) &.{} else pixels[(y - 1) * stride ..][0..stride];
        const dst = out[y * (stride + 1) + 1 ..][0..stride];
        for (0..stride) |x| {
            const a: u8 = if (x >= bpp) row[x - bpp] else 0;
            const b: u8 = if (prev.len != 0) prev[x] else 0;
            const c: u8 = if (prev.len != 0 and x >= bpp) prev[x - bpp] else 0;
            dst[x] = row[x] -% switch (filter) {
                0 => 0,
                1 => a,
                2 => b,
                3 => @as(u8, @intCast((@as(u16, a) + b) / 2)),
                4 => paeth(a, b, c),
                else => unreachable,
            };
        }
    }
    return out;
}

test "paeth predictor picks the closest neighbour" {
    try std.testing.expectEqual(@as(u8, 10), paeth(10, 0, 0)); // left
    try std.testing.expectEqual(@as(u8, 20), paeth(0, 20, 0)); // above
    try std.testing.expectEqual(@as(u8, 40), paeth(11, 40, 10)); // above
    try std.testing.expectEqual(@as(u8, 100), paeth(10, 200, 100)); // above-left
}

test "png decoder reconstructs every filter type" {
    const allocator = std.testing.allocator;
    // Random pixels so the Paeth predictor takes all three of its branches, and
    // a width that is not a multiple of anything convenient.
    const width: u32 = 9;
    const height: u32 = 5;

    // One case per colour type, so the non-truecolour widening paths are
    // filtered too rather than only ever seeing filter 0.
    for ([_]struct { color_type: u8, bpp: usize }{
        .{ .color_type = 0, .bpp = 1 },
        .{ .color_type = 2, .bpp = 3 },
        .{ .color_type = 4, .bpp = 2 },
        .{ .color_type = 6, .bpp = 4 },
    }, 0..) |variant, variant_index| {
        const pixels = try allocator.alloc(u8, width * height * variant.bpp);
        defer allocator.free(pixels);
        var rng = std.Random.DefaultCsprng.init([_]u8{@intCast(variant_index + 1)} ** 32);
        rng.fill(pixels);

        // What the decoder should hand back after dropping alpha / widening gray.
        const want = try allocator.alloc(u8, width * height * 3);
        defer allocator.free(want);
        for (std.mem.bytesAsSlice([3]u8, want), 0..) |*px, i| {
            const src = pixels[i * variant.bpp ..];
            px.* = if (variant.color_type == 2 or variant.color_type == 6)
                src[0..3].*
            else
                .{ src[0], src[0], src[0] };
        }

        for (0..5) |filter| {
            const raw = try filterRows(allocator, pixels, width, height, variant.bpp, @intCast(filter));
            defer allocator.free(raw);
            try expectDecodes(width, height, variant.color_type, raw, want);
        }
    }
}

test "png decoder expands 8-bit grayscale" {
    try expectDecodes(1, 1, 0, &.{ 0, 0x7f }, &.{ 0x7f, 0x7f, 0x7f });
    try expectDecodes(2, 1, 0, &.{ 0, 0x10, 0x20 }, &.{ 0x10, 0x10, 0x10, 0x20, 0x20, 0x20 });
}

test "png decoder drops alpha" {
    // Grayscale + alpha.
    try expectDecodes(2, 1, 4, &.{ 0, 0x30, 0xff, 0x40, 0x00 }, &.{ 0x30, 0x30, 0x30, 0x40, 0x40, 0x40 });
    // RGBA.
    try expectDecodes(2, 1, 6, &.{ 0, 1, 2, 3, 0xff, 4, 5, 6, 0x00 }, &.{ 1, 2, 3, 4, 5, 6 });
}

test "png decoder rejects malformed input" {
    const allocator = std.testing.allocator;
    const good = try buildPng(allocator, 2, 1, 2, &.{ 0, 1, 2, 3, 4, 5, 6 });
    defer allocator.free(good);

    try std.testing.expectError(error.InvalidPng, decode(allocator, "not a png at all"));
    try std.testing.expectError(error.InvalidPng, decode(allocator, good[0 .. good.len - 4]));

    // A flipped payload byte has to fail the chunk CRC.
    const corrupt = try allocator.dupe(u8, good);
    defer allocator.free(corrupt);
    corrupt[corrupt.len - 20] ^= 0xff;
    try std.testing.expectError(error.InvalidPngCrc, decode(allocator, corrupt));

    // Truncated scanline data: the header promises more than IDAT delivers.
    const short = try buildPng(allocator, 4, 4, 2, &.{ 0, 1, 2, 3 });
    defer allocator.free(short);
    try std.testing.expectError(error.InvalidPng, decode(allocator, short));

    // Unsupported filter byte.
    const bad_filter = try buildPng(allocator, 1, 1, 2, &.{ 9, 1, 2, 3 });
    defer allocator.free(bad_filter);
    try std.testing.expectError(error.InvalidPng, decode(allocator, bad_filter));
}

test "png decoder rejects unsupported variants" {
    const allocator = std.testing.allocator;
    // Colour type 3 is palletised, which we do not implement.
    const paletted = try buildPng(allocator, 1, 1, 3, &.{ 0, 0 });
    defer allocator.free(paletted);
    try std.testing.expectError(error.UnsupportedPng, decode(allocator, paletted));
}

test "png decoder rejects a decompression bomb" {
    const allocator = std.testing.allocator;
    // A header claiming 4000x4000 RGB (48 MB of scanlines) backed by an IDAT
    // far too small to hold that much even at deflate's best ratio.
    const tiny_payload = [_]u8{0} ** 64;
    const bomb = try buildPng(allocator, 4000, 4000, 2, &tiny_payload);
    defer allocator.free(bomb);
    try std.testing.expectError(error.InvalidPng, decode(allocator, bomb));

    // The bound must not reject a legitimately very compressible image.
    const flat = try allocator.alloc(u8, 400 * 400 * 3 + 400);
    defer allocator.free(flat);
    @memset(flat, 0);
    const legit = try buildPng(allocator, 400, 400, 2, flat);
    defer allocator.free(legit);
    const decoded = try decode(allocator, legit);
    defer allocator.free(decoded.rgb);
    try std.testing.expectEqual(@as(u32, 400), decoded.width);
}

test "png decoder rejects oversized dimensions before allocating" {
    const allocator = std.testing.allocator;
    // 100000 x 100000 is past `cipher.max_pixels`; this must fail on the header
    // rather than trying to allocate 30 GB of scanlines.
    const huge = try buildPng(allocator, 100_000, 100_000, 2, &.{0});
    defer allocator.free(huge);
    try std.testing.expectError(error.InvalidImageSize, decode(allocator, huge));
}
