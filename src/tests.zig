//! Aggregates the per-module unit tests and adds the end-to-end ones that span
//! more than one of them.

test {
    _ = @import("cipher.zig");
    _ = @import("container.zig");
    _ = @import("png.zig");
    _ = @import("ppm.zig");
    _ = @import("image.zig");
    _ = @import("cli.zig");
}

const std = @import("std");
const cipher = @import("cipher.zig");
const container = @import("container.zig");
const image = @import("image.zig");
const png = @import("png.zig");
const ppm = @import("ppm.zig");
const sample = @import("generate_sample.zig");

const testing = std.testing;
const io = testing.io;

/// Encodes an image, decodes it again, and hands back the result. Anything that
/// survives this is safe to write to disk and read back.
fn reencode(allocator: std.mem.Allocator, img: image.Image, format: image.Format) !image.Image {
    const bytes = try image.encode(allocator, img, format);
    defer allocator.free(bytes);
    return switch (format) {
        .png => image.Image.adopt(allocator, try png.decode(allocator, bytes)),
        .ppm => image.Image.adopt(allocator, try ppm.decode(allocator, bytes)),
    };
}

/// The whole `to-noise` side: fresh salt, derived schedule, wrapped container.
fn encrypt(allocator: std.mem.Allocator, src: image.Image, master: cipher.Master) !image.Image {
    var salt: cipher.Salt = undefined;
    try io.randomSecure(&salt);
    const keys = cipher.deriveKeys(master, salt, src.width, src.height);
    return container.wrap(allocator, io, src, .{
        .kdf = .argon2id,
        .width = src.width,
        .height = src.height,
        .salt = salt,
        .mac = undefined,
    }, keys);
}

/// The whole `from-noise` side, tag check included.
fn decrypt(allocator: std.mem.Allocator, noise: image.Image, master: cipher.Master) !image.Image {
    const header = try container.parseHeader(noise.rgb);
    const keys = cipher.deriveKeys(master, header.salt, header.width, header.height);
    return container.unwrap(allocator, noise, header, keys);
}

test "file roundtrip through noise and inverse" {
    const allocator = testing.allocator;
    const master = [_]u8{0x31} ** 32;

    for ([_]image.Format{ .png, .ppm }) |format| {
        var original = try image.Image.init(allocator, 48, 32);
        defer original.deinit();
        sample.drawSample(original);

        // Encode, reload, transform, encode the noise, reload it, invert.
        var loaded = try reencode(allocator, original, format);
        defer loaded.deinit();
        try testing.expectEqualSlices(u8, original.rgb, loaded.rgb);

        var noise = try encrypt(allocator, loaded, master);
        defer noise.deinit();
        // The container is taller than the picture by exactly its header rows.
        try testing.expectEqual(original.width, noise.width);
        try testing.expectEqual(original.height + try container.rowsFor(original.width), noise.height);

        var carried = try reencode(allocator, noise, format);
        defer carried.deinit();

        var restored = try decrypt(allocator, carried, master);
        defer restored.deinit();
        try testing.expectEqual(original.width, restored.width);
        try testing.expectEqual(original.height, restored.height);
        try testing.expectEqualSlices(u8, original.rgb, restored.rgb);
    }
}

test "noise survives a crossing of container formats" {
    // The transform works on pixels, so writing the noise as PPM and reading it
    // back as PNG (or the reverse) has to be lossless too.
    const allocator = testing.allocator;
    const master = [_]u8{0x77} ** 32;

    var original = try image.Image.init(allocator, 33, 17);
    defer original.deinit();
    for (original.rgb, 0..) |*byte, i| byte.* = @truncate(i *% 91 +% 5);

    var work = try reencode(allocator, original, .ppm);
    defer work.deinit();

    var noise = try encrypt(allocator, work, master);
    defer noise.deinit();

    var hop = try reencode(allocator, noise, .png);
    defer hop.deinit();
    var back = try reencode(allocator, hop, .ppm);
    defer back.deinit();

    var restored = try decrypt(allocator, back, master);
    defer restored.deinit();
    try testing.expectEqualSlices(u8, original.rgb, restored.rgb);
}

test "noise output is not compressed away" {
    // A regression guard for the encoder's store-vs-deflate choice: noise must
    // still roundtrip exactly, whichever branch it picks.
    const allocator = testing.allocator;
    const master = [_]u8{0x5f} ** 32;

    var original = try image.Image.init(allocator, 120, 90);
    defer original.deinit();
    sample.drawSample(original);

    var noise = try encrypt(allocator, original, master);
    defer noise.deinit();

    var back = try reencode(allocator, noise, .png);
    defer back.deinit();
    try testing.expectEqualSlices(u8, noise.rgb, back.rgb);

    var restored = try decrypt(allocator, back, master);
    defer restored.deinit();
    try testing.expectEqualSlices(u8, original.rgb, restored.rgb);
}

test "two images of one size under one key do not share a keystream" {
    // The bug the salt exists to kill. Both pictures are a blank page, which is
    // what a scanned document mostly is; under a shared keystream their noise
    // would come out byte-for-byte identical and `C1 xor C2` would hand over the
    // difference between the two documents.
    const allocator = testing.allocator;
    const master = [_]u8{0x0d} ** 32;

    var a = try image.Image.init(allocator, 64, 64);
    defer a.deinit();
    @memset(a.rgb, 0xff);
    var b = try image.Image.init(allocator, 64, 64);
    defer b.deinit();
    @memset(b.rgb, 0xff);

    var na = try encrypt(allocator, a, master);
    defer na.deinit();
    var nb = try encrypt(allocator, b, master);
    defer nb.deinit();

    try testing.expect(!std.mem.eql(u8, na.rgb, nb.rgb));

    // Count the bytes that survive the XOR as zero. Identical keystreams over
    // identical plaintexts would give every one of them; independent ones give
    // about 1 in 256.
    var zeros: usize = 0;
    for (na.rgb, nb.rgb) |x, y| {
        if (x == y) zeros += 1;
    }
    try testing.expect(zeros < na.rgb.len / 32);
}

test "a wrong key is refused rather than restored into noise" {
    const allocator = testing.allocator;

    var original = try image.Image.init(allocator, 40, 24);
    defer original.deinit();
    sample.drawSample(original);

    var noise = try encrypt(allocator, original, [_]u8{0xa1} ** 32);
    defer noise.deinit();

    try testing.expectError(
        error.AuthenticationFailed,
        decrypt(allocator, noise, [_]u8{0xa2} ** 32),
    );
}

test "any altered byte is caught" {
    const allocator = testing.allocator;
    const master = [_]u8{0xbe} ** 32;

    var original = try image.Image.init(allocator, 40, 24);
    defer original.deinit();
    sample.drawSample(original);

    // Every distinct region of the container: the version, the declared
    // dimensions, the salt, the tag, the padding after the header, and the
    // ciphertext itself.
    const spots = [_]usize{ 4, 5, 6, 11, 14, 29, 30, 61, 62, 100, 40 * 24 * 3 };
    for (spots) |spot| {
        var noise = try encrypt(allocator, original, master);
        defer noise.deinit();
        if (spot >= noise.rgb.len) continue;

        noise.rgb[spot] ^= 0x01;
        const result = decrypt(allocator, noise, master);
        if (result) |*ok| {
            var restored = ok.*;
            restored.deinit();
            std.debug.print("byte {d} went unnoticed\n", .{spot});
            return error.TestUnexpectedResult;
        } else |err| switch (err) {
            // The magic and the geometry fields fail earlier than the tag, but
            // nothing gets through.
            error.AuthenticationFailed, error.GeometryMismatch, error.NotV2, error.UnsupportedVersion => {},
            else => return err,
        }
    }
}

test "v1 noise is still readable" {
    // Images made before the format change have no header rows and no tag. They
    // have to keep opening, or the format-stability promise was worth nothing.
    const allocator = testing.allocator;

    var original = try image.Image.init(allocator, 24, 18);
    defer original.deinit();
    sample.drawSample(original);

    var legacy = try image.Image.init(allocator, 24, 18);
    defer legacy.deinit();
    @memcpy(legacy.rgb, original.rgb);

    const master = cipher.deriveMasterV1("old-passphrase");
    const keys = cipher.deriveKeysV1(master, 24, 18);
    try cipher.transform(allocator, legacy.rgb, 24, 18, keys, .to_noise);

    // No magic, so the reader knows to take the old path.
    try testing.expectError(error.NotV2, container.parseHeader(legacy.rgb));

    try cipher.transform(allocator, legacy.rgb, 24, 18, keys, .from_noise);
    try testing.expectEqualSlices(u8, original.rgb, legacy.rgb);
}

test "save and load round-trip through the filesystem" {
    const allocator = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var original = try image.Image.init(allocator, 24, 18);
    defer original.deinit();
    sample.drawSample(original);

    for ([_][]const u8{ "out.png", "out.ppm" }) |name| {
        const path = try tmp.dir.realPathFileAlloc(io, ".", allocator);
        defer allocator.free(path);
        const full = try std.fs.path.join(allocator, &.{ path, name });
        defer allocator.free(full);

        try image.save(original, io, full, image.formatFromPath(full));
        var loaded = try image.load(allocator, io, full);
        defer loaded.deinit();
        try testing.expectEqual(original.width, loaded.width);
        try testing.expectEqualSlices(u8, original.rgb, loaded.rgb);
    }
}
