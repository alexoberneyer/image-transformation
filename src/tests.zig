//! Aggregates the per-module unit tests and adds the end-to-end ones that span
//! more than one of them.

test {
    _ = @import("cipher.zig");
    _ = @import("png.zig");
    _ = @import("ppm.zig");
    _ = @import("image.zig");
    _ = @import("cli.zig");
}

const std = @import("std");
const cipher = @import("cipher.zig");
const image = @import("image.zig");
const png = @import("png.zig");
const ppm = @import("ppm.zig");
const sample = @import("generate_sample.zig");

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

test "file roundtrip through noise and inverse" {
    const allocator = std.testing.allocator;

    for ([_]image.Format{ .png, .ppm }) |format| {
        var original = try image.Image.init(allocator, 48, 32);
        defer original.deinit();
        sample.drawSample(original);

        // Encode, reload, transform, encode the noise, reload it, invert.
        var loaded = try reencode(allocator, original, format);
        defer loaded.deinit();
        try std.testing.expectEqualSlices(u8, original.rgb, loaded.rgb);

        try cipher.toNoise(allocator, loaded.rgb, loaded.width, loaded.height, "demo-passphrase");
        try std.testing.expect(!std.mem.eql(u8, original.rgb, loaded.rgb));

        var noise = try reencode(allocator, loaded, format);
        defer noise.deinit();

        try cipher.fromNoise(allocator, noise.rgb, noise.width, noise.height, "demo-passphrase");
        try std.testing.expectEqualSlices(u8, original.rgb, noise.rgb);
    }
}

test "noise survives a crossing of container formats" {
    // The transform works on pixels, so writing the noise as PPM and reading it
    // back as PNG (or the reverse) has to be lossless too.
    const allocator = std.testing.allocator;
    var original = try image.Image.init(allocator, 33, 17);
    defer original.deinit();
    for (original.rgb, 0..) |*byte, i| byte.* = @truncate(i *% 91 +% 5);

    var work = try reencode(allocator, original, .ppm);
    defer work.deinit();
    try cipher.toNoise(allocator, work.rgb, work.width, work.height, "cross-format");

    var hop = try reencode(allocator, work, .png);
    defer hop.deinit();
    var back = try reencode(allocator, hop, .ppm);
    defer back.deinit();

    try cipher.fromNoise(allocator, back.rgb, back.width, back.height, "cross-format");
    try std.testing.expectEqualSlices(u8, original.rgb, back.rgb);
}

test "noise output is not compressed away" {
    // A regression guard for the encoder's store-vs-deflate choice: noise must
    // still roundtrip exactly, whichever branch it picks.
    const allocator = std.testing.allocator;
    var img = try image.Image.init(allocator, 120, 90);
    defer img.deinit();
    sample.drawSample(img);
    try cipher.toNoise(allocator, img.rgb, img.width, img.height, "incompressible");

    var back = try reencode(allocator, img, .png);
    defer back.deinit();
    try std.testing.expectEqualSlices(u8, img.rgb, back.rgb);

    try cipher.fromNoise(allocator, back.rgb, back.width, back.height, "incompressible");
    var reference = try image.Image.init(allocator, 120, 90);
    defer reference.deinit();
    sample.drawSample(reference);
    try std.testing.expectEqualSlices(u8, reference.rgb, back.rgb);
}

test "save and load round-trip through the filesystem" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var original = try image.Image.init(allocator, 24, 18);
    defer original.deinit();
    sample.drawSample(original);

    for ([_][]const u8{ "out.png", "out.ppm" }) |name| {
        const path = try tmp.dir.realpathAlloc(allocator, ".");
        defer allocator.free(path);
        const full = try std.fs.path.join(allocator, &.{ path, name });
        defer allocator.free(full);

        try image.save(original, full);
        var loaded = try image.load(allocator, full);
        defer loaded.deinit();
        try std.testing.expectEqual(original.width, loaded.width);
        try std.testing.expectEqualSlices(u8, original.rgb, loaded.rgb);
    }
}
