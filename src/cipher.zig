const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const Blake3 = std.crypto.hash.Blake3;
const ChaCha20 = std.crypto.stream.chacha.ChaCha20IETF;
const argon2 = std.crypto.pwhash.argon2;

/// Upper bound on the images we are willing to process. It also guarantees a
/// pixel index fits in a `u32`, which `buildPermutation` relies on.
pub const max_pixels = 64_000_000;
comptime {
    std.debug.assert(max_pixels <= std.math.maxInt(u32));
}

pub const salt_length = 16;
pub const mac_length = 32;

pub const Master_length = 32;
pub const Master = [Master_length]u8;
pub const Salt = [salt_length]u8;
pub const Mac = [mac_length]u8;

const v2_permute_context = "image-transformation/v2 permute seed";
const v2_diffuse_context = "image-transformation/v2 diffuse key";
const v2_nonce_context = "image-transformation/v2 diffuse nonce";
const v2_mac_context = "image-transformation/v2 mac key";
const key_id_context = "image-transformation/v1 key id";

const v1_master_context = "image-transformation/v1 master key";
const v1_permute_context = "image-transformation/v1 permute seed";
const v1_diffuse_context = "image-transformation/v1 diffuse key";
const v1_nonce_context = "image-transformation/v1 diffuse nonce";

/// How the bytes the caller supplied become a master key. The choice is written
/// into every noise image, so the inverse knows how to treat the key it is
/// handed rather than having to be told again on the command line.
pub const KdfId = enum(u8) {
    /// 32 bytes of full-entropy key material, used as the master directly.
    /// Stretching it would only cost time - there is nothing to guess.
    raw = 0,
    /// A passphrase. Argon2id makes each guess expensive, which is the only
    /// thing standing between a human-memorable key and a GPU.
    argon2id = 1,
    /// The master is random and travels sealed to one or more X25519 public
    /// keys in the header. Nothing is derived from a supplied key at all - it
    /// is unwrapped with a private key instead.
    x25519 = 2,
    _,
};

/// OWASP's current password-storage recommendation: 19 MiB, two passes. It
/// lands around 30 ms here, which a hotkey can absorb and a cracking rig
/// cannot - a single BLAKE3 pass, which is what v1 did, costs a few hundred
/// nanoseconds and buys a passphrase nothing at all.
pub const argon2_params = argon2.Params.owasp_2id;

/// A fixed salt, which is a deliberate and limited compromise. Argon2id wants a
/// per-target salt so one precomputed table cannot cover everybody; `key-id`
/// wants the master to depend on the passphrase alone, so a key keeps the same
/// public name across every image made with it and the clipboard scripts can
/// find it in the keychain again. Per-image salting happens one level down, in
/// `deriveKeys`, where it is what actually stops keystream reuse. What is left
/// here is the cost of a precomputed Argon2id table, which is 19 MiB and two
/// passes per candidate rather than one hash - expensive, but shared across
/// everyone using this tool. A high-entropy key sidesteps it entirely.
const argon2_salt = "image-transformation/v2 argon2id salt";

pub const DerivedKeys = struct {
    permute_seed: [32]u8,
    diffuse_key: [ChaCha20.key_length]u8,
    diffuse_nonce: [ChaCha20.nonce_length]u8,
    mac_key: [32]u8,
};

pub const Direction = enum { to_noise, from_noise };

pub const MasterError = error{ RawKeyLength, UnsupportedKdf, IdentityRequired } || std.crypto.pwhash.KdfError;

/// Turns whatever the caller supplied into a master key. Everything else in the
/// schedule hangs off this one value.
pub fn deriveMaster(allocator: Allocator, io: Io, key: []const u8, kdf: KdfId) MasterError!Master {
    switch (kdf) {
        .raw => {
            if (key.len != 32) return error.RawKeyLength;
            return key[0..32].*;
        },
        .argon2id => {
            var master: Master = undefined;
            try argon2.kdf(allocator, &master, key, argon2_salt, argon2_params, .argon2id, io);
            return master;
        },
        // Not derived from anything the caller typed: see `recipient.open`.
        .x25519 => return error.IdentityRequired,
        _ => return error.UnsupportedKdf,
    }
}

/// The v1 master: a single unkeyed BLAKE3 pass over the passphrase. Kept so
/// noise images written before the format change can still be opened, and used
/// for nothing else - a passphrase run through this is cheap to guess.
pub fn deriveMasterV1(passphrase: []const u8) Master {
    var master: Master = undefined;
    var kdf = Blake3.initKdf(v1_master_context, .{});
    kdf.update(passphrase);
    kdf.final(&master);
    return master;
}

/// Non-secret fingerprint of a master key, so a caller can tell two runs used
/// the same key without revealing it. Reaching the master from a passphrase now
/// costs an Argon2id derivation, so this is no longer a cheap oracle for
/// testing guesses against.
pub fn keyId(master: Master) [8]u8 {
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

fn deriveLabeled(context: []const u8, master: []const u8, info: []const u8, out: []u8) void {
    var kdf = Blake3.initKdf(context, .{});
    kdf.update(master);
    kdf.update(info);
    kdf.final(out);
}

fn dimensionBytes(width: u32, height: u32) [8]u8 {
    var dims: [8]u8 = undefined;
    std.mem.writeInt(u32, dims[0..4], width, .little);
    std.mem.writeInt(u32, dims[4..8], height, .little);
    return dims;
}

/// The per-image schedule. `salt` is fresh random bytes for every single image,
/// which is what keeps two pictures encrypted under one key from sharing a
/// keystream: without it, `C1 xor C2` cancels the keystream and leaves a
/// permutation of `A xor B`, which for two scans of the same size is close to
/// handing over both.
pub fn deriveKeys(master: Master, salt: Salt, width: u32, height: u32) DerivedKeys {
    var info: [salt_length + 8]u8 = undefined;
    info[0..salt_length].* = salt;
    info[salt_length..][0..8].* = dimensionBytes(width, height);

    var keys: DerivedKeys = undefined;
    deriveLabeled(v2_permute_context, &master, &info, &keys.permute_seed);
    deriveLabeled(v2_diffuse_context, &master, &info, &keys.diffuse_key);
    deriveLabeled(v2_mac_context, &master, &info, &keys.mac_key);

    var nonce_wide: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &nonce_wide);
    deriveLabeled(v2_nonce_context, &master, &info, &nonce_wide);
    keys.diffuse_nonce = nonce_wide[0..ChaCha20.nonce_length].*;
    return keys;
}

/// The v1 schedule, which bound the keystream to the dimensions and nothing
/// else. Read-only: `to-noise` never produces this format any more.
pub fn deriveKeysV1(master: Master, width: u32, height: u32) DerivedKeys {
    const dims = dimensionBytes(width, height);

    var keys: DerivedKeys = undefined;
    deriveLabeled(v1_permute_context, &master, &dims, &keys.permute_seed);
    deriveLabeled(v1_diffuse_context, &master, &dims, &keys.diffuse_key);
    // v1 had no authentication, so there is no MAC key to derive.
    @memset(&keys.mac_key, 0);

    var nonce_wide: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &nonce_wide);
    deriveLabeled(v1_nonce_context, &master, &dims, &nonce_wide);
    keys.diffuse_nonce = nonce_wide[0..ChaCha20.nonce_length].*;
    return keys;
}

/// Keyed BLAKE3 over the pieces of the output that have to be immutable. Taken
/// over the ciphertext rather than the plaintext, so a modified file is
/// rejected before the key ever touches it.
pub fn computeMac(mac_key: [32]u8, parts: []const []const u8) Mac {
    var hasher = Blake3.init(.{ .key = mac_key });
    for (parts) |part| hasher.update(part);
    var out: Mac = undefined;
    hasher.final(&out);
    return out;
}

pub fn macMatches(expected: Mac, actual: Mac) bool {
    return std.crypto.timing_safe.eql([mac_length]u8, expected, actual);
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

/// Shuffle and mask, or unmask and unshuffle. The ChaCha20 layer is what makes
/// this confidential; the permutation is what makes the result look like an
/// image rather than static, and is not load-bearing for secrecy.
pub fn transform(
    allocator: Allocator,
    rgb: []u8,
    width: u32,
    height: u32,
    keys: DerivedKeys,
    direction: Direction,
) !void {
    const n = try pixelCount(width, height);
    if (rgb.len != n * 3) return error.InvalidImageSize;

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

const testing = std.testing;

/// A fixed schedule for tests that care about the transform rather than about
/// how the key was reached.
fn testKeys(width: u32, height: u32) DerivedKeys {
    return deriveKeys([_]u8{7} ** 32, [_]u8{0xa5} ** salt_length, width, height);
}

test "roundtrip restores original pixels" {
    const allocator = testing.allocator;
    const width: u32 = 17;
    const height: u32 = 9;
    const n = width * height * 3;
    const original = try allocator.alloc(u8, n);
    defer allocator.free(original);
    const work = try allocator.alloc(u8, n);
    defer allocator.free(work);

    for (original, 0..) |*byte, i| byte.* = @truncate(i *% 37 +% 11);
    @memcpy(work, original);

    const keys = testKeys(width, height);
    try transform(allocator, work, width, height, keys, .to_noise);
    try testing.expect(!std.mem.eql(u8, work, original));

    try transform(allocator, work, width, height, keys, .from_noise);
    try testing.expectEqualSlices(u8, original, work);
}

test "roundtrip survives a batch-crossing image" {
    // Exercises the permutation loop past a single prefetch batch, including a
    // final short batch.
    const allocator = testing.allocator;
    const width: u32 = 97;
    const height: u32 = 3;
    const original = try allocator.alloc(u8, width * height * 3);
    defer allocator.free(original);
    const work = try allocator.alloc(u8, original.len);
    defer allocator.free(work);
    for (original, 0..) |*byte, i| byte.* = @truncate(i *% 251);
    @memcpy(work, original);

    const keys = testKeys(width, height);
    try transform(allocator, work, width, height, keys, .to_noise);
    try transform(allocator, work, width, height, keys, .from_noise);
    try testing.expectEqualSlices(u8, original, work);
}

test "roundtrip handles the smallest possible image" {
    const allocator = testing.allocator;
    var one = [_]u8{ 9, 8, 7 };
    const keys = testKeys(1, 1);
    try transform(allocator, &one, 1, 1, keys, .to_noise);
    try transform(allocator, &one, 1, 1, keys, .from_noise);
    try testing.expectEqualSlices(u8, &.{ 9, 8, 7 }, &one);
}

test "a different salt gives a different keystream" {
    // The reason the salt exists. Two pictures of the same size under one key
    // used to share a keystream exactly, so `C1 xor C2` cancelled it and left a
    // permutation of `A xor B` - for two scans of the same form, close to
    // handing over both. A fresh salt per image has to break that.
    const allocator = testing.allocator;
    const master = [_]u8{3} ** 32;
    const width: u32 = 16;
    const height: u32 = 16;
    const n = width * height * 3;

    const plain = try allocator.alloc(u8, n);
    defer allocator.free(plain);
    @memset(plain, 0xff); // A blank page: the worst case for keystream reuse.

    const a = try allocator.alloc(u8, n);
    defer allocator.free(a);
    const b = try allocator.alloc(u8, n);
    defer allocator.free(b);
    @memcpy(a, plain);
    @memcpy(b, plain);

    try transform(allocator, a, width, height, deriveKeys(master, [_]u8{1} ** salt_length, width, height), .to_noise);
    try transform(allocator, b, width, height, deriveKeys(master, [_]u8{2} ** salt_length, width, height), .to_noise);

    // With one shared keystream these two would be byte-for-byte equal, since
    // the plaintexts are. Count how far from that they land.
    var equal: usize = 0;
    for (a, b) |x, y| {
        if (x == y) equal += 1;
    }
    try testing.expect(!std.mem.eql(u8, a, b));
    // Two independent streams agree on about 1 byte in 256.
    try testing.expect(equal < n / 32);
}

test "a different master gives a different keystream" {
    const allocator = testing.allocator;
    const salt = [_]u8{9} ** salt_length;
    var a = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9 };
    var b = a;
    try transform(allocator, &a, 3, 1, deriveKeys([_]u8{1} ** 32, salt, 3, 1), .to_noise);
    try transform(allocator, &b, 3, 1, deriveKeys([_]u8{2} ** 32, salt, 3, 1), .to_noise);
    try testing.expect(!std.mem.eql(u8, &a, &b));
}

test "the same key and salt on different dimensions produce different noise" {
    const allocator = testing.allocator;
    const master = [_]u8{4} ** 32;
    const salt = [_]u8{5} ** salt_length;
    var a = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };
    var b = a;
    try transform(allocator, &a, 4, 1, deriveKeys(master, salt, 4, 1), .to_noise);
    try transform(allocator, &b, 2, 2, deriveKeys(master, salt, 2, 2), .to_noise);
    try testing.expect(!std.mem.eql(u8, &a, &b));
}

test "the same key and salt are deterministic" {
    const allocator = testing.allocator;
    var a = [_]u8{ 10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120 };
    var b = a;
    const keys = testKeys(2, 2);
    try transform(allocator, &a, 2, 2, keys, .to_noise);
    try transform(allocator, &b, 2, 2, keys, .to_noise);
    try testing.expectEqualSlices(u8, &a, &b);
}

test "the mac changes with any bit of what it covers" {
    const key = [_]u8{0x11} ** 32;
    const body = [_]u8{0x22} ** 64;
    const base = computeMac(key, &.{&body});

    try testing.expect(macMatches(base, computeMac(key, &.{&body})));

    var flipped = body;
    flipped[7] ^= 0x01;
    try testing.expect(!macMatches(base, computeMac(key, &.{&flipped})));

    // A different key over the same bytes, which is what a wrong passphrase
    // amounts to by the time it reaches here.
    try testing.expect(!macMatches(base, computeMac([_]u8{0x12} ** 32, &.{&body})));

    // The pieces are concatenated, not hashed independently.
    try testing.expect(macMatches(base, computeMac(key, &.{ body[0..10], body[10..] })));
}

test "argon2 masters are deterministic and passphrase-dependent" {
    const allocator = testing.allocator;
    const io = testing.io;
    const a = try deriveMaster(allocator, io, "correct horse battery staple", .argon2id);
    const b = try deriveMaster(allocator, io, "correct horse battery staple", .argon2id);
    const c = try deriveMaster(allocator, io, "correct horse battery stapler", .argon2id);
    try testing.expectEqualSlices(u8, &a, &b);
    try testing.expect(!std.mem.eql(u8, &a, &c));

    // ...and it is not the v1 derivation wearing a new name.
    try testing.expect(!std.mem.eql(u8, &a, &deriveMasterV1("correct horse battery staple")));
}

test "a raw key is used as the master unchanged" {
    const allocator = testing.allocator;
    const io = testing.io;
    const raw = [_]u8{0x5a} ** 32;
    const master = try deriveMaster(allocator, io, &raw, .raw);
    try testing.expectEqualSlices(u8, &raw, &master);

    try testing.expectError(error.RawKeyLength, deriveMaster(allocator, io, "short", .raw));
    try testing.expectError(error.UnsupportedKdf, deriveMaster(allocator, io, "x", @enumFromInt(99)));
}

test "key id is stable and key-dependent" {
    const a = keyId([_]u8{1} ** 32);
    const b = keyId([_]u8{1} ** 32);
    const c = keyId([_]u8{2} ** 32);
    try testing.expectEqualSlices(u8, &a, &b);
    try testing.expect(!std.mem.eql(u8, &a, &c));
}

test "rejects images that are too large or degenerate" {
    try testing.expectError(error.InvalidImageSize, pixelCount(0, 4));
    try testing.expectError(error.InvalidImageSize, pixelCount(4, 0));
    try testing.expectError(error.InvalidImageSize, pixelCount(100_000, 100_000));
    try testing.expectEqual(@as(usize, 12), try pixelCount(4, 3));
}

test "rejects a buffer that does not match the dimensions" {
    var rgb = [_]u8{0} ** 9;
    try testing.expectError(
        error.InvalidImageSize,
        transform(testing.allocator, &rgb, 2, 2, testKeys(2, 2), .to_noise),
    );
}

test "known answer pins the v2 key schedule" {
    // The byte stream is a contract: noise is only useful if a later build can
    // still invert it. Any change to the key schedule, the permutation or the
    // keystream has to fail here rather than quietly stranding existing images.
    const allocator = testing.allocator;
    var work: [7 * 5 * 3]u8 = undefined;
    for (&work, 0..) |*byte, i| byte.* = @truncate(i *% 101 +% 7);

    const keys = deriveKeys([_]u8{0x2a} ** 32, [_]u8{0x5c} ** salt_length, 7, 5);
    try transform(allocator, &work, 7, 5, keys, .to_noise);

    // Regenerate with `zig build test` after any deliberate format change, and
    // treat needing to as the warning it is.
    const digest = fingerprint(&work);
    try testing.expectEqualStrings(
        "bd9f48ba5ab153728edfcc0fd84c73b6",
        &std.fmt.bytesToHex(digest, .lower),
    );
}

test "known answer pins the v1 format that is still readable" {
    // Unchanged from before the format change, so old noise still opens.
    const allocator = testing.allocator;
    var work: [7 * 5 * 3]u8 = undefined;
    for (&work, 0..) |*byte, i| byte.* = @truncate(i *% 101 +% 7);

    const master = deriveMasterV1("known-answer-vector");
    try transform(allocator, &work, 7, 5, deriveKeysV1(master, 7, 5), .to_noise);
    try testing.expectEqualSlices(u8, &.{
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

    try testing.expectEqualSlices(
        u8,
        &.{ 0x82, 0xec, 0x10, 0xbf, 0x49, 0x60, 0x71, 0xd1 },
        &keyId(master),
    );
}

test "the permutation is a permutation" {
    const allocator = testing.allocator;
    const n = 5000;
    const perm = try buildPermutation(allocator, n, [_]u8{42} ** 32);
    defer allocator.free(perm);

    const seen = try allocator.alloc(bool, n);
    defer allocator.free(seen);
    @memset(seen, false);

    var moved: usize = 0;
    for (perm, 0..) |v, i| {
        try testing.expect(v < n);
        try testing.expect(!seen[v]);
        seen[v] = true;
        if (v != i) moved += 1;
    }
    // A random permutation of 5000 elements leaves ~1 element in place.
    try testing.expect(moved > n - 20);
}

test "batched permutation matches a naive Fisher-Yates" {
    const allocator = testing.allocator;
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
        try testing.expectEqualSlices(u32, want, got);
    }
}
