test {
    _ = @import("cipher.zig");
    _ = @import("png.zig");
    _ = @import("ppm.zig");
    _ = @import("image.zig");
}

const std = @import("std");
const cipher = @import("cipher.zig");
const image = @import("image.zig");
const png = @import("png.zig");
const ppm = @import("ppm.zig");
const sample = @import("generate_sample.zig");

test "png file roundtrip through noise and inverse" {
    const allocator = std.testing.allocator;
    var original = try image.Image.init(allocator, 48, 32);
    defer original.deinit();
    sample.drawSample(original);

    const encoded_in = try png.encode(allocator, original.width, original.height, original.rgb);
    defer allocator.free(encoded_in);
    const loaded_raw = try png.decode(allocator, encoded_in);
    var loaded = image.Image{
        .allocator = allocator,
        .width = loaded_raw.width,
        .height = loaded_raw.height,
        .rgb = loaded_raw.rgb,
    };
    defer loaded.deinit();

    try cipher.toNoise(allocator, loaded.rgb, loaded.width, loaded.height, "demo-passphrase");
    const noise_bytes = try png.encode(allocator, loaded.width, loaded.height, loaded.rgb);
    defer allocator.free(noise_bytes);

    const noise_raw = try png.decode(allocator, noise_bytes);
    var noise = image.Image{
        .allocator = allocator,
        .width = noise_raw.width,
        .height = noise_raw.height,
        .rgb = noise_raw.rgb,
    };
    defer noise.deinit();
    try std.testing.expect(!std.mem.eql(u8, original.rgb, noise.rgb));

    try cipher.fromNoise(allocator, noise.rgb, noise.width, noise.height, "demo-passphrase");
    try std.testing.expectEqualSlices(u8, original.rgb, noise.rgb);
}

test "ppm file roundtrip through noise and inverse" {
    const allocator = std.testing.allocator;
    var original = try image.Image.init(allocator, 16, 12);
    defer original.deinit();
    for (original.rgb, 0..) |*byte, i| byte.* = @truncate(255 -% i);

    const encoded_in = try ppm.encode(allocator, original.width, original.height, original.rgb);
    defer allocator.free(encoded_in);
    const loaded_raw = try ppm.decode(allocator, encoded_in);
    var loaded = image.Image{
        .allocator = allocator,
        .width = loaded_raw.width,
        .height = loaded_raw.height,
        .rgb = loaded_raw.rgb,
    };
    defer loaded.deinit();

    try cipher.toNoise(allocator, loaded.rgb, loaded.width, loaded.height, "ppm-key");
    try cipher.fromNoise(allocator, loaded.rgb, loaded.width, loaded.height, "ppm-key");
    try std.testing.expectEqualSlices(u8, original.rgb, loaded.rgb);
}
