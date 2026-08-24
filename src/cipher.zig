const std = @import("std");
const Allocator = std.mem.Allocator;
const Blake3 = std.crypto.hash.Blake3;
const ChaCha20 = std.crypto.stream.chacha.ChaCha20IETF;

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

pub fn deriveMaster(passphrase: []const u8) [32]u8 {
    var master: [32]u8 = undefined;
    var kdf = Blake3.initKdf(master_context, .{});
    kdf.update(passphrase);
    kdf.final(&master);
    return master;
}

pub fn keyId(passphrase: []const u8) [8]u8 {
    const master = deriveMaster(passphrase);
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

fn mixDims(width: u32, height: u32) [8]u8 {
    var dims: [8]u8 = undefined;
    std.mem.writeInt(u32, dims[0..4], width, .little);
    std.mem.writeInt(u32, dims[4..8], height, .little);
    return dims;
}

fn deriveLabeled(context: []const u8, master: []const u8, dims: []const u8, out: []u8) void {
    var kdf = Blake3.initKdf(context, .{});
    kdf.update(master);
    kdf.update(dims);
    kdf.final(out);
}

pub fn deriveKeys(passphrase: []const u8, width: u32, height: u32) DerivedKeys {
    const master = deriveMaster(passphrase);
    const dims = mixDims(width, height);

    var keys: DerivedKeys = undefined;
    deriveLabeled(permute_context, &master, &dims, &keys.permute_seed);
    deriveLabeled(diffuse_context, &master, &dims, &keys.diffuse_key);

    var nonce_wide: [32]u8 = undefined;
    deriveLabeled(nonce_context, &master, &dims, &nonce_wide);
    @memcpy(&keys.diffuse_nonce, nonce_wide[0..ChaCha20.nonce_length]);
    return keys;
}

pub fn pixelCount(width: u32, height: u32) error{InvalidImageSize}!usize {
    if (width == 0 or height == 0) return error.InvalidImageSize;
    const n = std.math.mul(usize, width, height) catch return error.InvalidImageSize;
    if (n > 64_000_000) return error.InvalidImageSize;
    return n;
}

fn buildPermutation(allocator: Allocator, n: usize, seed: [32]u8) ![]usize {
    const perm = try allocator.alloc(usize, n);
    errdefer allocator.free(perm);
    for (perm, 0..) |*slot, i| slot.* = i;

    var rng = std.Random.DefaultCsprng.init(seed);
    const random = rng.random();
    var i: usize = n;
    while (i > 1) {
        i -= 1;
        const j = random.uintLessThan(usize, i + 1);
        const tmp = perm[i];
        perm[i] = perm[j];
        perm[j] = tmp;
    }
    return perm;
}

fn permutePixels(rgb: []u8, scratch: []u8, perm: []const usize, inverse: bool) void {
    std.debug.assert(rgb.len == scratch.len);
    std.debug.assert(rgb.len == perm.len * 3);
    @memcpy(scratch, rgb);
    if (!inverse) {
        for (perm, 0..) |src, dst| {
            @memcpy(rgb[dst * 3 ..][0..3], scratch[src * 3 ..][0..3]);
        }
    } else {
        for (perm, 0..) |src, dst| {
            @memcpy(rgb[src * 3 ..][0..3], scratch[dst * 3 ..][0..3]);
        }
    }
}

fn diffuse(rgb: []u8, key: [ChaCha20.key_length]u8, nonce: [ChaCha20.nonce_length]u8) void {
    ChaCha20.xor(rgb, rgb, 0, key, nonce);
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

    const keys = deriveKeys(passphrase, width, height);
    const perm = try buildPermutation(allocator, n, keys.permute_seed);
    defer allocator.free(perm);

    const scratch = try allocator.alloc(u8, rgb.len);
    defer allocator.free(scratch);

    switch (direction) {
        .to_noise => {
            permutePixels(rgb, scratch, perm, false);
            diffuse(rgb, keys.diffuse_key, keys.diffuse_nonce);
        },
        .from_noise => {
            diffuse(rgb, keys.diffuse_key, keys.diffuse_nonce);
            permutePixels(rgb, scratch, perm, true);
        },
    }
}

pub fn toNoise(allocator: Allocator, rgb: []u8, width: u32, height: u32, passphrase: []const u8) !void {
    try transform(allocator, rgb, width, height, passphrase, .to_noise);
}

pub fn fromNoise(allocator: Allocator, rgb: []u8, width: u32, height: u32, passphrase: []const u8) !void {
    try transform(allocator, rgb, width, height, passphrase, .from_noise);
}

fn hexLower(bytes: []const u8, out: []u8) void {
    const digits = "0123456789abcdef";
    std.debug.assert(out.len >= bytes.len * 2);
    for (bytes, 0..) |byte, i| {
        out[i * 2] = digits[byte >> 4];
        out[i * 2 + 1] = digits[byte & 0x0f];
    }
}

pub fn hexEncode(bytes: []const u8, out: []u8) []const u8 {
    hexLower(bytes, out);
    return out[0 .. bytes.len * 2];
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

test "key id is stable and key-dependent" {
    const a = keyId("secret");
    const b = keyId("secret");
    const c = keyId("other");
    try std.testing.expectEqualSlices(u8, &a, &b);
    try std.testing.expect(!std.mem.eql(u8, &a, &c));
}
