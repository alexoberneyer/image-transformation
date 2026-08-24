const std = @import("std");
const Allocator = std.mem.Allocator;
const Blake3 = std.crypto.hash.Blake3;
const ChaCha20 = std.crypto.stream.chacha.ChaCha20IETF;

/// Upper bound on the images we are willing to process. It also guarantees a
/// pixel index fits in a `u32`, which `buildPermutation` relies on.
pub const max_pixels = 64_000_000;
comptime {
    std.debug.assert(max_pixels <= std.math.maxInt(u32));
}

const permute_context = "image-transformation/v1 permute seed";
const diffuse_context = "image-transformation/v1 diffuse key";
const nonce_context = "image-transformation/v1 diffuse nonce";
const master_context = "image-transformation/v1 master key";
const key_id_context = "image-transformation/v1 key id";

pub const DerivedKeys = struct {
    permute_seed: [32]u8,
    diffuse_key: [ChaCha20.key_length]u8,
    diffuse_nonce: [ChaCha20.nonce_length]u8,
};

pub const Direction = enum { to_noise, from_noise };

fn deriveMaster(passphrase: []const u8) [32]u8 {
    var master: [32]u8 = undefined;
    var kdf = Blake3.initKdf(master_context, .{});
    kdf.update(passphrase);
    kdf.final(&master);
    return master;
}

/// Non-secret fingerprint of a key, so a caller can tell two runs used the
/// same key without revealing it.
pub fn keyId(passphrase: []const u8) [8]u8 {
    var master = deriveMaster(passphrase);
    defer std.crypto.secureZero(u8, &master);

    var out: [8]u8 = undefined;
    var kdf = Blake3.initKdf(key_id_context, .{});
    kdf.update(&master);
    kdf.final(&out);
    return out;
}

pub fn fingerprint(bytes: []const u8) [16]u8 {
    var out: [16]u8 = undefined;
    Blake3.hash(bytes, &out, .{});
    return out;
}

fn deriveLabeled(context: []const u8, master: []const u8, dims: []const u8, out: []u8) void {
    var kdf = Blake3.initKdf(context, .{});
    kdf.update(master);
    kdf.update(dims);
    kdf.final(out);
}

/// Binding the derived material to the image dimensions means a key reused
/// across differently-sized images never reuses a keystream.
pub fn deriveKeys(passphrase: []const u8, width: u32, height: u32) DerivedKeys {
    var master = deriveMaster(passphrase);
    defer std.crypto.secureZero(u8, &master);

    var dims: [8]u8 = undefined;
    std.mem.writeInt(u32, dims[0..4], width, .little);
    std.mem.writeInt(u32, dims[4..8], height, .little);

    var keys: DerivedKeys = undefined;
    deriveLabeled(permute_context, &master, &dims, &keys.permute_seed);
    deriveLabeled(diffuse_context, &master, &dims, &keys.diffuse_key);

    var nonce_wide: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &nonce_wide);
    deriveLabeled(nonce_context, &master, &dims, &nonce_wide);
    keys.diffuse_nonce = nonce_wide[0..ChaCha20.nonce_length].*;
    return keys;
}

pub fn pixelCount(width: u32, height: u32) error{InvalidImageSize}!usize {
    if (width == 0 or height == 0) return error.InvalidImageSize;
    const n = std.math.mul(usize, width, height) catch return error.InvalidImageSize;
    if (n > max_pixels) return error.InvalidImageSize;
    return n;
}

/// How many swaps to draw before performing any of them. The draws depend only
/// on the RNG, never on the array, so a batch can be computed up front and every
/// slot it is about to touch prefetched in one go. `perm` is far larger than the
/// cache, so without this each swap stalls on a cold line; 64 was the knee of
/// the curve when measured, and the resulting permutation is bit-for-bit the one
/// a naive Fisher-Yates loop produces.
const prefetch_batch = 64;

fn buildPermutation(allocator: Allocator, n: usize, seed: [32]u8) ![]u32 {
    const perm = try allocator.alloc(u32, n);
    errdefer allocator.free(perm);
    for (perm, 0..) |*slot, i| slot.* = @intCast(i);

    var rng = std.Random.DefaultCsprng.init(seed);
    const random = rng.random();
    var draws: [prefetch_batch]u32 = undefined;

    // Targets run from n-1 down to 1; `hi - 1` is the next one to fill.
    var hi = n;
    while (hi > 1) {
        const batch = draws[0..@min(prefetch_batch, hi - 1)];
        for (batch, 0..) |*slot, k| slot.* = @intCast(random.uintLessThan(usize, hi - k));
        for (batch) |j| @prefetch(&perm[j], .{ .rw = .write, .locality = 0 });
        for (batch, 0..) |j, k| std.mem.swap(u32, &perm[hi - 1 - k], &perm[j]);
        hi -= batch.len;
    }
    return perm;
}

const Pixel = [3]u8;

fn permutePixels(rgb: []u8, scratch: []u8, perm: []const u32, direction: Direction) void {
    std.debug.assert(rgb.len == scratch.len);
    std.debug.assert(rgb.len == perm.len * 3);
    @memcpy(scratch, rgb);

    const src = std.mem.bytesAsSlice(Pixel, scratch);
    const dst = std.mem.bytesAsSlice(Pixel, rgb);
    switch (direction) {
        .to_noise => for (dst, perm) |*out, from| {
            out.* = src[from];
        },
        .from_noise => for (src, perm) |in, to| {
            dst[to] = in;
        },
    }
}

pub fn transform(
    allocator: Allocator,
    rgb: []u8,
    width: u32,
    height: u32,
    passphrase: []const u8,
    direction: Direction,
) !void {
    const n = try pixelCount(width, height);
    if (rgb.len != n * 3) return error.InvalidImageSize;

    var keys = deriveKeys(passphrase, width, height);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&keys));

    const perm = try buildPermutation(allocator, n, keys.permute_seed);
    defer allocator.free(perm);

    const scratch = try allocator.alloc(u8, rgb.len);
    defer allocator.free(scratch);

    // XOR is its own inverse but the permutation is not, so the two stages run
    // in opposite order for the two directions.
    switch (direction) {
        .to_noise => {
            permutePixels(rgb, scratch, perm, direction);
            ChaCha20.xor(rgb, rgb, 0, keys.diffuse_key, keys.diffuse_nonce);
        },
        .from_noise => {
            ChaCha20.xor(rgb, rgb, 0, keys.diffuse_key, keys.diffuse_nonce);
            permutePixels(rgb, scratch, perm, direction);
        },
    }
}

pub fn toNoise(allocator: Allocator, rgb: []u8, width: u32, height: u32, passphrase: []const u8) !void {
    try transform(allocator, rgb, width, height, passphrase, .to_noise);
}

pub fn fromNoise(allocator: Allocator, rgb: []u8, width: u32, height: u32, passphrase: []const u8) !void {
    try transform(allocator, rgb, width, height, passphrase, .from_noise);
}

test "roundtrip restores original pixels" {
    const allocator = std.testing.allocator;
    const width: u32 = 17;
    const height: u32 = 9;
    const n = width * height * 3;
    const original = try allocator.alloc(u8, n);
    defer allocator.free(original);
    const work = try allocator.alloc(u8, n);
    defer allocator.free(work);

    for (original, 0..) |*byte, i| {
        byte.* = @truncate(i *% 37 +% 11);
    }
    @memcpy(work, original);

    try toNoise(allocator, work, width, height, "unit-test-key");
    try std.testing.expect(!std.mem.eql(u8, work, original));

    try fromNoise(allocator, work, width, height, "unit-test-key");
    try std.testing.expectEqualSlices(u8, original, work);
}

test "roundtrip survives a batch-crossing image" {
    // Exercises the permutation loop past a single prefetch batch, including a
    // final short batch.
    const allocator = std.testing.allocator;
    const width: u32 = 97;
    const height: u32 = 3;
    const original = try allocator.alloc(u8, width * height * 3);
    defer allocator.free(original);
    const work = try allocator.alloc(u8, original.len);
    defer allocator.free(work);
    for (original, 0..) |*byte, i| byte.* = @truncate(i *% 251);
    @memcpy(work, original);

    try toNoise(allocator, work, width, height, "batch-boundary");
    try fromNoise(allocator, work, width, height, "batch-boundary");
    try std.testing.expectEqualSlices(u8, original, work);
}

test "roundtrip handles the smallest possible image" {
    const allocator = std.testing.allocator;
    var one = [_]u8{ 9, 8, 7 };
    try toNoise(allocator, &one, 1, 1, "single-pixel");
    try fromNoise(allocator, &one, 1, 1, "single-pixel");
    try std.testing.expectEqualSlices(u8, &.{ 9, 8, 7 }, &one);
}

test "wrong key does not restore the image" {
    const allocator = std.testing.allocator;
    const width: u32 = 8;
    const height: u32 = 8;
    const n = width * height * 3;
    const original = try allocator.alloc(u8, n);
    defer allocator.free(original);
    const work = try allocator.alloc(u8, n);
    defer allocator.free(work);

    for (original, 0..) |*byte, i| byte.* = @truncate(i);
    @memcpy(work, original);

    try toNoise(allocator, work, width, height, "alpha");
    try fromNoise(allocator, work, width, height, "beta");
    try std.testing.expect(!std.mem.eql(u8, work, original));
}

test "same key is deterministic" {
    const allocator = std.testing.allocator;
    var a = [_]u8{ 10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120 };
    var b = a;
    try toNoise(allocator, &a, 2, 2, "repeatable");
    try toNoise(allocator, &b, 2, 2, "repeatable");
    try std.testing.expectEqualSlices(u8, &a, &b);
}

test "different keys produce different noise" {
    const allocator = std.testing.allocator;
    var a = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9 };
    var b = a;
    try toNoise(allocator, &a, 3, 1, "k1");
    try toNoise(allocator, &b, 3, 1, "k2");
    try std.testing.expect(!std.mem.eql(u8, &a, &b));
}

test "the same key on different dimensions produces different noise" {
    const allocator = std.testing.allocator;
    var a = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };
    var b = a;
    try toNoise(allocator, &a, 4, 1, "same-key");
    try toNoise(allocator, &b, 2, 2, "same-key");
    try std.testing.expect(!std.mem.eql(u8, &a, &b));
}

test "key id is stable and key-dependent" {
    const a = keyId("secret");
    const b = keyId("secret");
    const c = keyId("other");
    try std.testing.expectEqualSlices(u8, &a, &b);
    try std.testing.expect(!std.mem.eql(u8, &a, &c));
}

test "rejects images that are too large or degenerate" {
    try std.testing.expectError(error.InvalidImageSize, pixelCount(0, 4));
    try std.testing.expectError(error.InvalidImageSize, pixelCount(4, 0));
    try std.testing.expectError(error.InvalidImageSize, pixelCount(100_000, 100_000));
    try std.testing.expectEqual(@as(usize, 12), try pixelCount(4, 3));
}

test "rejects a buffer that does not match the dimensions" {
    var rgb = [_]u8{0} ** 9;
    try std.testing.expectError(
        error.InvalidImageSize,
        transform(std.testing.allocator, &rgb, 2, 2, "k", .to_noise),
    );
}

test "known answer pins the on-disk format" {
    // The transform is only useful if today's `from-noise` can read an image
    // written by an older build, so the exact byte stream is part of the
    // contract. This vector is the v1 format; any change to the key schedule,
    // the permutation or the keystream must fail here rather than silently
    // stranding existing noise images.
    const allocator = std.testing.allocator;
    var work: [7 * 5 * 3]u8 = undefined;
    for (&work, 0..) |*byte, i| byte.* = @truncate(i *% 101 +% 7);

    try toNoise(allocator, &work, 7, 5, "known-answer-vector");
    try std.testing.expectEqualSlices(u8, &.{
        160, 252, 175, 222, 212, 231, 107, 178, 204, 83,  62,  100,
        5,   95,  111, 83,  71,  244, 20,  145, 61,  49,  140, 174,
        120, 252, 171, 47,  15,  66,  139, 217, 40,  177, 213, 152,
        167, 100, 235, 133, 41,  155, 185, 249, 129, 209, 113, 17,
        199, 37,  185, 26,  52,  231, 177, 100, 180, 73,  66,  126,
        218, 244, 95,  127, 244, 141, 196, 139, 107, 12,  113, 155,
        104, 13,  211, 126, 5,   59,  52,  245, 154, 113, 68,  67,
        190, 106, 170, 100, 67,  109, 26,  23,  200, 54,  173, 34,
        197, 149, 81,  1,   154, 149, 43,  223, 201,
    }, &work);

    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x82, 0xec, 0x10, 0xbf, 0x49, 0x60, 0x71, 0xd1 },
        &keyId("known-answer-vector"),
    );
}

test "the permutation is a permutation" {
    const allocator = std.testing.allocator;
    const n = 5000;
    const perm = try buildPermutation(allocator, n, [_]u8{42} ** 32);
    defer allocator.free(perm);

    const seen = try allocator.alloc(bool, n);
    defer allocator.free(seen);
    @memset(seen, false);

    var moved: usize = 0;
    for (perm, 0..) |v, i| {
        try std.testing.expect(v < n);
        try std.testing.expect(!seen[v]);
        seen[v] = true;
        if (v != i) moved += 1;
    }
    // A random permutation of 5000 elements leaves ~1 element in place.
    try std.testing.expect(moved > n - 20);
}

test "batched permutation matches a naive Fisher-Yates" {
    const allocator = std.testing.allocator;
    const seed = [_]u8{7} ** 32;
    // Sizes either side of a batch boundary, so the short tail is covered too.
    for ([_]usize{ 1, 2, 63, 64, 65, 128, 129, 1000 }) |n| {
        const got = try buildPermutation(allocator, n, seed);
        defer allocator.free(got);

        const want = try allocator.alloc(u32, n);
        defer allocator.free(want);
        for (want, 0..) |*slot, i| slot.* = @intCast(i);
        var rng = std.Random.DefaultCsprng.init(seed);
        const random = rng.random();
        var i: usize = n;
        while (i > 1) {
            i -= 1;
            std.mem.swap(u32, &want[i], &want[random.uintLessThan(usize, i + 1)]);
        }
        try std.testing.expectEqualSlices(u32, want, got);
    }
}
