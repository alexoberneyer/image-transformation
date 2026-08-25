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
//!     5   kdf      1    how the master key is reached
//!     6   width    4    little endian, the picture's own width
//!     10  height   4    little endian, the picture's own height
//!     14  salt     16   fresh per image
//!     30  mac      32   keyed BLAKE3 over everything else
//!     62  ...           recipient stanzas, when kdf is x25519
//!     ..  padding  ..   random, out to the end of the header rows
//!
//! With a passphrase or a raw key the header ends at 62 and the rest of the
//! rows are padding, which is the layout every existing v2 image has. Sealing
//! to X25519 recipients appends a count byte and one 80-byte stanza each. The
//! version does not move for that: a build too old to know the kdf refuses the
//! image on the kdf alone, which is the error it should give anyway, and
//! bumping the version would strand passphrase images that have not changed.
//!
//! The MAC covers every byte from the end of its own field onward plus the
//! bytes before it, so the salt, the dimensions, the stanzas, the padding and
//! the whole ciphertext are under it. Only the MAC field is excluded, because
//! it cannot cover itself.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const cipher = @import("cipher.zig");
const image = @import("image.zig");
const recipient = @import("recipient.zig");

pub const magic = [4]u8{ 'I', 'N', 'Z', '2' };
pub const version: u8 = 2;

pub const mac_offset = 30;
/// Where the MAC starts covering, and the size of a header with no stanzas.
pub const fixed_header_bytes = mac_offset + cipher.mac_length;
pub const recipient_count_offset = fixed_header_bytes;

comptime {
    std.debug.assert(fixed_header_bytes == 62);
}

pub const Header = struct {
    kdf: cipher.KdfId,
    width: u32,
    height: u32,
    salt: cipher.Salt,
    mac: cipher.Mac,
    /// Only meaningful when `kdf` is `.x25519`.
    recipient_count: u8 = 0,

    /// Total size of the header, stanzas included.
    pub fn size(self: Header) usize {
        if (self.kdf != .x25519) return fixed_header_bytes;
        return recipient_count_offset + 1 + @as(usize, self.recipient_count) * recipient.stanza_bytes;
    }
};

/// How many pixel rows a header of `header_size` bytes occupies. A wide image
/// hides it in one row; a one-pixel-wide column needs a great many.
pub fn rowsFor(width: u32, header_size: usize) error{InvalidImageSize}!u32 {
    const row_bytes = @as(usize, width) * 3;
    if (row_bytes == 0) return error.InvalidImageSize;
    const rows = (header_size + row_bytes - 1) / row_bytes;
    if (rows > std.math.maxInt(u32)) return error.InvalidImageSize;
    return @intCast(rows);
}

/// Total height of the noise image carrying a `width` x `height` picture.
pub fn noiseHeight(width: u32, height: u32, header_size: usize) error{InvalidImageSize}!u32 {
    const rows = try rowsFor(width, header_size);
    return std.math.add(u32, height, rows) catch error.InvalidImageSize;
}

/// Writes everything except the MAC, which is not known until the ciphertext it
/// covers exists, and except the stanzas, which the caller supplies separately.
pub fn writeHeader(buffer: []u8, header: Header) void {
    std.debug.assert(buffer.len >= header.size());
    buffer[0..4].* = magic;
    buffer[4] = version;
    buffer[5] = @intFromEnum(header.kdf);
    std.mem.writeInt(u32, buffer[6..10], header.width, .little);
    std.mem.writeInt(u32, buffer[10..14], header.height, .little);
    buffer[14..30].* = header.salt;
    if (header.kdf == .x25519) buffer[recipient_count_offset] = header.recipient_count;
}

pub fn writeStanzas(buffer: []u8, stanzas: []const recipient.Stanza) void {
    var at: usize = recipient_count_offset + 1;
    for (stanzas) |stanza| {
        buffer[at..][0..recipient.stanza_bytes].* = stanza;
        at += recipient.stanza_bytes;
    }
}

/// The `i`th sealed copy of the master key.
pub fn stanzaAt(buffer: []const u8, i: usize) []const u8 {
    const at = recipient_count_offset + 1 + i * recipient.stanza_bytes;
    return buffer[at..][0..recipient.stanza_bytes];
}

/// The byte ranges the MAC is taken over: every byte of the noise image except
/// the MAC field itself, which cannot cover itself.
pub fn macParts(buffer: []const u8) [2][]const u8 {
    return .{ buffer[0..mac_offset], buffer[fixed_header_bytes..] };
}

/// Reads a header out of a pixel buffer, or reports why it is not one. A buffer
/// that simply does not start with the magic is a v1 image (or not ours at all)
/// rather than a corrupt v2 one, so that case is its own error.
pub fn parseHeader(buffer: []const u8) error{ NotV2, UnsupportedVersion, MalformedHeader }!Header {
    if (buffer.len < fixed_header_bytes) return error.NotV2;
    if (!std.mem.eql(u8, buffer[0..4], &magic)) return error.NotV2;
    if (buffer[4] != version) return error.UnsupportedVersion;

    var header = Header{
        .kdf = @enumFromInt(buffer[5]),
        .width = std.mem.readInt(u32, buffer[6..10], .little),
        .height = std.mem.readInt(u32, buffer[10..14], .little),
        .salt = buffer[14..30].*,
        .mac = buffer[mac_offset..fixed_header_bytes].*,
    };
    if (header.kdf == .x25519) {
        if (buffer.len < recipient_count_offset + 1) return error.MalformedHeader;
        header.recipient_count = buffer[recipient_count_offset];
        if (header.recipient_count == 0 or header.recipient_count > recipient.max_recipients) {
            return error.MalformedHeader;
        }
        if (buffer.len < header.size()) return error.MalformedHeader;
    }
    return header;
}

/// Builds the noise image: header rows carrying the salt, any sealed copies of
/// the master key, and the tag, then the transformed pixels. The header rows
/// are filled with entropy first, so every byte the header does not claim is
/// padding that looks like the rest of it.
pub fn wrap(
    allocator: Allocator,
    io: Io,
    src: image.Image,
    header: Header,
    stanzas: []const recipient.Stanza,
    keys: cipher.DerivedKeys,
) !image.Image {
    std.debug.assert(header.width == src.width and header.height == src.height);
    std.debug.assert(header.recipient_count == stanzas.len);

    const header_size = header.size();
    const rows = try rowsFor(src.width, header_size);
    const total_height = try noiseHeight(src.width, src.height, header_size);
    _ = try cipher.pixelCount(src.width, total_height);

    var out = try image.Image.init(allocator, src.width, total_height);
    errdefer out.deinit();

    const header_row_bytes = @as(usize, rows) * src.width * 3;
    try io.randomSecure(out.rgb[0..header_row_bytes]);

    @memcpy(out.rgb[header_row_bytes..], src.rgb);
    try cipher.transform(allocator, out.rgb[header_row_bytes..], src.width, src.height, keys, .to_noise);

    writeHeader(out.rgb, header);
    if (stanzas.len > 0) writeStanzas(out.rgb, stanzas);
    const parts = macParts(out.rgb);
    writeMac(out.rgb, cipher.computeMac(keys.mac_key, &parts));
    return out;
}

pub fn writeMac(buffer: []u8, mac: cipher.Mac) void {
    std.debug.assert(buffer.len >= fixed_header_bytes);
    buffer[mac_offset..fixed_header_bytes].* = mac;
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
    const rows = try rowsFor(noise.width, header.size());
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

const testing = std.testing;

fn plainHeader(width: u32, height: u32) Header {
    return .{
        .kdf = .argon2id,
        .width = width,
        .height = height,
        .salt = [_]u8{0xab} ** cipher.salt_length,
        .mac = [_]u8{0xcd} ** cipher.mac_length,
    };
}

test "header rows cover the header for any width" {
    for ([_]u32{ 1, 2, 7, 20, 21, 32, 100, 4000 }) |width| {
        const rows = try rowsFor(width, fixed_header_bytes);
        try testing.expect(@as(usize, rows) * width * 3 >= fixed_header_bytes);
        // ...and never a row more than needed.
        try testing.expect(@as(usize, rows - 1) * width * 3 < fixed_header_bytes);
    }
    try testing.expectEqual(@as(u32, 1), try rowsFor(21, fixed_header_bytes));
    try testing.expectEqual(@as(u32, 2), try rowsFor(20, fixed_header_bytes));
    try testing.expectEqual(@as(u32, 21), try rowsFor(1, fixed_header_bytes));
    try testing.expectError(error.InvalidImageSize, rowsFor(0, fixed_header_bytes));
}

test "sealed headers are bigger and need more rows" {
    var sealed = plainHeader(48, 32);
    sealed.kdf = .x25519;
    sealed.recipient_count = 1;
    try testing.expectEqual(@as(usize, 62 + 1 + 80), sealed.size());
    try testing.expectEqual(@as(usize, 62), plainHeader(48, 32).size());

    // 47px wide is 141 bytes a row: the 62-byte header fits in one, the
    // 143-byte sealed one does not.
    try testing.expectEqual(@as(u32, 1), try rowsFor(47, plainHeader(47, 32).size()));
    try testing.expectEqual(@as(u32, 2), try rowsFor(47, sealed.size()));
    // A row of 144 bytes swallows a single stanza whole.
    try testing.expectEqual(@as(u32, 1), try rowsFor(48, sealed.size()));

    sealed.recipient_count = 3;
    try testing.expectEqual(@as(usize, 62 + 1 + 240), sealed.size());
}

test "header survives a write and read" {
    var buffer = [_]u8{0} ** fixed_header_bytes;
    const want = plainHeader(320, 240);
    writeHeader(&buffer, want);
    writeMac(&buffer, want.mac);

    const got = try parseHeader(&buffer);
    try testing.expectEqual(want.kdf, got.kdf);
    try testing.expectEqual(want.width, got.width);
    try testing.expectEqual(want.height, got.height);
    try testing.expectEqualSlices(u8, &want.salt, &got.salt);
    try testing.expectEqualSlices(u8, &want.mac, &got.mac);
    try testing.expectEqual(@as(u8, 0), got.recipient_count);
}

test "a sealed header round-trips its stanzas" {
    var want = plainHeader(320, 240);
    want.kdf = .x25519;
    want.recipient_count = 2;

    const buffer = try testing.allocator.alloc(u8, want.size());
    defer testing.allocator.free(buffer);
    @memset(buffer, 0);

    const stanzas = [_]recipient.Stanza{ [_]u8{0x11} ** recipient.stanza_bytes, [_]u8{0x22} ** recipient.stanza_bytes };
    writeHeader(buffer, want);
    writeStanzas(buffer, &stanzas);
    writeMac(buffer, want.mac);

    const got = try parseHeader(buffer);
    try testing.expectEqual(cipher.KdfId.x25519, got.kdf);
    try testing.expectEqual(@as(u8, 2), got.recipient_count);
    try testing.expectEqualSlices(u8, &stanzas[0], stanzaAt(buffer, 0));
    try testing.expectEqualSlices(u8, &stanzas[1], stanzaAt(buffer, 1));
}

test "the mac covers the recipient stanzas" {
    // They sit after the MAC field, so they have to fall inside its second part
    // for free. If that ever stops being true, a stanza could be swapped out.
    var header = plainHeader(320, 240);
    header.kdf = .x25519;
    header.recipient_count = 1;

    const buffer = try testing.allocator.alloc(u8, header.size() + 30);
    defer testing.allocator.free(buffer);
    @memset(buffer, 0);

    const parts = macParts(buffer);
    const covered = parts[1];
    try testing.expect(covered.ptr == buffer.ptr + fixed_header_bytes);
    try testing.expect(covered.len >= 1 + recipient.stanza_bytes);
}

test "a buffer without the magic is not a v2 image" {
    const noise = [_]u8{0x11} ** fixed_header_bytes;
    try testing.expectError(error.NotV2, parseHeader(&noise));
    try testing.expectError(error.NotV2, parseHeader(&[_]u8{ 'I', 'N' }));

    var future = [_]u8{0} ** fixed_header_bytes;
    future[0..4].* = magic;
    future[4] = version + 1;
    try testing.expectError(error.UnsupportedVersion, parseHeader(&future));
}

test "a sealed header that promises stanzas it does not have is refused" {
    var buffer = [_]u8{0} ** (fixed_header_bytes + 1);
    buffer[0..4].* = magic;
    buffer[4] = version;
    buffer[5] = @intFromEnum(cipher.KdfId.x25519);

    buffer[recipient_count_offset] = 0;
    try testing.expectError(error.MalformedHeader, parseHeader(&buffer));

    buffer[recipient_count_offset] = recipient.max_recipients + 1;
    try testing.expectError(error.MalformedHeader, parseHeader(&buffer));

    // Claims one stanza, carries none of it.
    buffer[recipient_count_offset] = 1;
    try testing.expectError(error.MalformedHeader, parseHeader(&buffer));
}
