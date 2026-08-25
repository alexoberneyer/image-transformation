//! The wire format of a v2 noise image.
//!
//! A salt and a MAC have to travel with the noise, and the only place in an
//! image that every carrier preserves is the pixels themselves. A PNG text
//! chunk would be stripped by the first tool that touched the file while
//! leaving the picture perfectly intact - a new way to lose data that looks
//! like nothing went wrong - and PPM has nowhere to put one at all. So the
//! header is pixels: the noise image is a few rows taller than the picture it
//! came from, and those rows carry the header. Anything that preserves the
//! pixels losslessly, which is already the one thing this format demands of a
//! carrier, preserves the header too.
//!
//! Layout, at the very start of the pixel buffer:
//!
//!     0   magic    4    "INZ2"
//!     4   version  1
//!     5   kdf      1    how the supplied key becomes a master key
//!     6   width    4    little endian, the picture's own width
//!     10  height   4    little endian, the picture's own height
//!     14  salt     16   fresh per image
//!     30  mac      32   keyed BLAKE3 over everything else
//!     62  padding  ..   random, out to the end of the header rows
//!
//! The MAC covers every byte of the image except the MAC field itself, which
//! cannot cover itself: the salt, the dimensions, the padding and the whole
//! ciphertext are all under it.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const cipher = @import("cipher.zig");
const image = @import("image.zig");

pub const magic = [4]u8{ 'I', 'N', 'Z', '2' };
pub const version: u8 = 2;

pub const mac_offset = 30;
pub const header_bytes = mac_offset + cipher.mac_length;

comptime {
    std.debug.assert(header_bytes == 62);
}

pub const Header = struct {
    kdf: cipher.KdfId,
    width: u32,
    height: u32,
    salt: cipher.Salt,
    mac: cipher.Mac,
};

/// How many pixel rows the header occupies. A wide image hides it in one row;
/// a one-pixel-wide column needs twenty-one.
pub fn rowsFor(width: u32) error{InvalidImageSize}!u32 {
    const row_bytes = @as(usize, width) * 3;
    if (row_bytes == 0) return error.InvalidImageSize;
    return @intCast((header_bytes + row_bytes - 1) / row_bytes);
}

/// Total height of the noise image carrying a `width` x `height` picture.
pub fn noiseHeight(width: u32, height: u32) error{InvalidImageSize}!u32 {
    const rows = try rowsFor(width);
    return std.math.add(u32, height, rows) catch error.InvalidImageSize;
}

/// Writes everything except the MAC, which is not known until the ciphertext
/// it covers exists.
pub fn writeHeader(buffer: []u8, header: Header) void {
    std.debug.assert(buffer.len >= header_bytes);
    buffer[0..4].* = magic;
    buffer[4] = version;
    buffer[5] = @intFromEnum(header.kdf);
    std.mem.writeInt(u32, buffer[6..10], header.width, .little);
    std.mem.writeInt(u32, buffer[10..14], header.height, .little);
    buffer[14..30].* = header.salt;
}

pub fn writeMac(buffer: []u8, mac: cipher.Mac) void {
    std.debug.assert(buffer.len >= header_bytes);
    buffer[mac_offset..header_bytes].* = mac;
}

/// The byte ranges the MAC is taken over: every byte of the noise image except
/// the MAC field itself, which cannot cover itself. `buffer` is the whole pixel
/// buffer, so the salt, the dimensions, the padding and the ciphertext are all
/// included.
pub fn macParts(buffer: []const u8) [2][]const u8 {
    return .{ buffer[0..mac_offset], buffer[header_bytes..] };
}

/// Reads a header out of a pixel buffer, or reports why it is not one. A buffer
/// that simply does not start with the magic is a v1 image (or not ours at all)
/// rather than a corrupt v2 one, so that case is its own error.
pub fn parseHeader(buffer: []const u8) error{ NotV2, UnsupportedVersion }!Header {
    if (buffer.len < header_bytes) return error.NotV2;
    if (!std.mem.eql(u8, buffer[0..4], &magic)) return error.NotV2;
    if (buffer[4] != version) return error.UnsupportedVersion;
    return .{
        .kdf = @enumFromInt(buffer[5]),
        .width = std.mem.readInt(u32, buffer[6..10], .little),
        .height = std.mem.readInt(u32, buffer[10..14], .little),
        .salt = buffer[14..30].*,
        .mac = buffer[mac_offset..header_bytes].*,
    };
}

/// Builds the noise image: header rows carrying the salt and the tag, then the
/// transformed pixels. The header rows are filled with entropy first, so every
/// byte the header does not claim is padding that looks like the rest of it.
pub fn wrap(
    allocator: Allocator,
    io: Io,
    src: image.Image,
    header: Header,
    keys: cipher.DerivedKeys,
) !image.Image {
    std.debug.assert(header.width == src.width and header.height == src.height);

    const rows = try rowsFor(src.width);
    const total_height = try noiseHeight(src.width, src.height);
    _ = try cipher.pixelCount(src.width, total_height);

    var out = try image.Image.init(allocator, src.width, total_height);
    errdefer out.deinit();

    const header_row_bytes = @as(usize, rows) * src.width * 3;
    try io.randomSecure(out.rgb[0..header_row_bytes]);

    @memcpy(out.rgb[header_row_bytes..], src.rgb);
    try cipher.transform(allocator, out.rgb[header_row_bytes..], src.width, src.height, keys, .to_noise);

    writeHeader(out.rgb, header);
    const parts = macParts(out.rgb);
    writeMac(out.rgb, cipher.computeMac(keys.mac_key, &parts));
    return out;
}

/// Checks the tag over the whole noise image before letting the key near the
/// pixels, then unwraps. A wrong key and an altered file both stop at the same
/// gate, which is the point of the tag existing at all.
pub fn unwrap(
    allocator: Allocator,
    noise: image.Image,
    header: Header,
    keys: cipher.DerivedKeys,
) !image.Image {
    const rows = try rowsFor(noise.width);
    if (header.width != noise.width or
        noise.height <= rows or
        header.height != noise.height - rows) return error.GeometryMismatch;

    const parts = macParts(noise.rgb);
    if (!cipher.macMatches(header.mac, cipher.computeMac(keys.mac_key, &parts))) {
        return error.AuthenticationFailed;
    }

    var out = try image.Image.init(allocator, header.width, header.height);
    errdefer out.deinit();
    @memcpy(out.rgb, noise.rgb[@as(usize, rows) * noise.width * 3 ..]);
    try cipher.transform(allocator, out.rgb, out.width, out.height, keys, .from_noise);
    return out;
}

test "header rows cover the header for any width" {
    for ([_]u32{ 1, 2, 7, 20, 21, 32, 100, 4000 }) |width| {
        const rows = try rowsFor(width);
        try std.testing.expect(@as(usize, rows) * width * 3 >= header_bytes);
        // ...and never a row more than needed.
        try std.testing.expect(@as(usize, rows - 1) * width * 3 < header_bytes);
    }
    try std.testing.expectEqual(@as(u32, 1), try rowsFor(21));
    try std.testing.expectEqual(@as(u32, 2), try rowsFor(20));
    try std.testing.expectEqual(@as(u32, 21), try rowsFor(1));
    try std.testing.expectError(error.InvalidImageSize, rowsFor(0));
}

test "header survives a write and read" {
    var buffer = [_]u8{0} ** header_bytes;
    const want = Header{
        .kdf = .argon2id,
        .width = 320,
        .height = 240,
        .salt = [_]u8{0xab} ** cipher.salt_length,
        .mac = [_]u8{0xcd} ** cipher.mac_length,
    };
    writeHeader(&buffer, want);
    writeMac(&buffer, want.mac);

    const got = try parseHeader(&buffer);
    try std.testing.expectEqual(want.kdf, got.kdf);
    try std.testing.expectEqual(want.width, got.width);
    try std.testing.expectEqual(want.height, got.height);
    try std.testing.expectEqualSlices(u8, &want.salt, &got.salt);
    try std.testing.expectEqualSlices(u8, &want.mac, &got.mac);
}

test "a buffer without the magic is not a v2 image" {
    const noise = [_]u8{0x11} ** header_bytes;
    try std.testing.expectError(error.NotV2, parseHeader(&noise));
    try std.testing.expectError(error.NotV2, parseHeader(&[_]u8{ 'I', 'N' }));

    var future = [_]u8{0} ** header_bytes;
    future[0..4].* = magic;
    future[4] = version + 1;
    try std.testing.expectError(error.UnsupportedVersion, parseHeader(&future));
}
