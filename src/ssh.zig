//! Just enough of the two OpenSSH key formats to use an `ssh-ed25519` keypair
//! for encryption.
//!
//! Only ed25519 is supported. RSA would need OAEP, which Zig's std keeps inside
//! the certificate machinery for verification rather than exposing for
//! encryption, and ECDSA keys cannot do this at all - the same two exclusions
//! age settles on.
//!
//! Ed25519 signing keys live on the Edwards curve and encryption wants
//! Montgomery, so both sides are converted with the birational map that std
//! already implements. Using one key to both log in and decrypt is a mild abuse
//! of key separation; it is what makes "send me your public key" cost your
//! friends nothing, and it is what age does too.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const Ed25519 = std.crypto.sign.Ed25519;
const X25519 = std.crypto.dh.X25519;
const Aes256 = std.crypto.core.aes.Aes256;
const modes = std.crypto.core.modes;
const bcrypt = std.crypto.pwhash.bcrypt;

pub const key_type = "ssh-ed25519";

const pem_begin = "-----BEGIN OPENSSH PRIVATE KEY-----";
const pem_end = "-----END OPENSSH PRIVATE KEY-----";
const auth_magic = "openssh-key-v1\x00";

/// Nobody's key file is this big; the bound keeps a malformed one from being
/// read into memory forever.
pub const max_key_file_bytes = 64 * 1024;

pub const Error = error{
    UnsupportedKeyType,
    MalformedKey,
    NoKeyFound,
    PassphraseRequired,
    WrongPassphrase,
    UnsupportedCipher,
};

pub const PublicKey = [X25519.public_length]u8;
pub const Identity = X25519.KeyPair;

/// The SSH wire format is a run of length-prefixed byte strings. Everything
/// below is reading them in order.
const Reader = struct {
    bytes: []const u8,
    pos: usize = 0,

    fn take(self: *Reader, n: usize) Error![]const u8 {
        if (self.pos + n > self.bytes.len) return error.MalformedKey;
        defer self.pos += n;
        return self.bytes[self.pos..][0..n];
    }

    fn u32be(self: *Reader) Error!u32 {
        const raw = try self.take(4);
        return std.mem.readInt(u32, raw[0..4], .big);
    }

    fn string(self: *Reader) Error![]const u8 {
        const len = try self.u32be();
        return self.take(len);
    }

    fn expectString(self: *Reader, want: []const u8) Error!void {
        const got = try self.string();
        if (!std.mem.eql(u8, got, want)) return error.UnsupportedKeyType;
    }
};

fn ed25519ToX25519Public(raw: []const u8) Error!PublicKey {
    if (raw.len != Ed25519.PublicKey.encoded_length) return error.MalformedKey;
    const ed = Ed25519.PublicKey.fromBytes(raw[0..Ed25519.PublicKey.encoded_length].*) catch
        return error.MalformedKey;
    return X25519.publicKeyFromEd25519(ed) catch error.MalformedKey;
}

/// Reads one `ssh-ed25519 AAAAC3Nz... comment` line - the contents of an
/// `id_ed25519.pub`, or a line of an `authorized_keys`.
pub fn parsePublicKey(allocator: Allocator, line: []const u8) !PublicKey {
    var fields = std.mem.tokenizeAny(u8, line, " \t\r\n");
    const kind = fields.next() orelse return error.MalformedKey;
    if (!std.mem.eql(u8, kind, key_type)) return error.UnsupportedKeyType;
    const body = fields.next() orelse return error.MalformedKey;

    const decoder = std.base64.standard.Decoder;
    const size = decoder.calcSizeForSlice(body) catch return error.MalformedKey;
    const blob = try allocator.alloc(u8, size);
    defer allocator.free(blob);
    decoder.decode(blob, body) catch return error.MalformedKey;

    // The blob repeats the key type, and it is the one that counts.
    var reader = Reader{ .bytes = blob };
    try reader.expectString(key_type);
    return ed25519ToX25519Public(try reader.string());
}

/// Collects every `ssh-ed25519` line in a file. Other key types are skipped
/// rather than refused, so pointing this at an `authorized_keys` works.
pub fn parsePublicKeyFile(allocator: Allocator, contents: []const u8, out: *std.ArrayList(PublicKey)) !void {
    var lines = std.mem.splitScalar(u8, contents, '\n');
    var found = false;
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;
        const key = parsePublicKey(allocator, line) catch |err| switch (err) {
            error.UnsupportedKeyType => continue,
            else => return err,
        };
        try out.append(allocator, key);
        found = true;
    }
    if (!found) return error.NoKeyFound;
}

/// Strips the PEM armour and returns the raw `openssh-key-v1` blob.
fn decodeArmour(allocator: Allocator, pem: []const u8) ![]u8 {
    const start = std.mem.indexOf(u8, pem, pem_begin) orelse return error.NoKeyFound;
    const body_start = start + pem_begin.len;
    const end = std.mem.indexOfPos(u8, pem, body_start, pem_end) orelse return error.MalformedKey;

    const decoder = std.base64.standard.decoderWithIgnore(" \t\r\n");
    const body = pem[body_start..end];
    const buffer = try allocator.alloc(u8, body.len);
    errdefer allocator.free(buffer);
    const written = decoder.decode(buffer, body) catch return error.MalformedKey;
    return allocator.realloc(buffer, written);
}

/// bcrypt-pbkdf over the passphrase gives 32 bytes of AES key and a 16-byte IV,
/// which is the only cipher `ssh-keygen` writes today.
fn decryptPrivateBlob(
    allocator: Allocator,
    cipher_name: []const u8,
    kdf_name: []const u8,
    kdf_options: []const u8,
    blob: []const u8,
    passphrase: ?[]const u8,
) ![]u8 {
    if (!std.mem.eql(u8, cipher_name, "aes256-ctr")) return error.UnsupportedCipher;
    if (!std.mem.eql(u8, kdf_name, "bcrypt")) return error.UnsupportedCipher;

    const pass = passphrase orelse return error.PassphraseRequired;
    if (pass.len == 0) return error.PassphraseRequired;

    var options = Reader{ .bytes = kdf_options };
    const salt = try options.string();
    const rounds = try options.u32be();

    var material: [Aes256.key_bits / 8 + 16]u8 = undefined;
    defer std.crypto.secureZero(u8, &material);
    bcrypt.opensshKdf(pass, salt, &material, rounds) catch return error.MalformedKey;

    const out = try allocator.alloc(u8, blob.len);
    errdefer allocator.free(out);
    const ctx = Aes256.initEnc(material[0 .. Aes256.key_bits / 8].*);
    modes.ctr(@TypeOf(ctx), ctx, out, blob, material[Aes256.key_bits / 8 ..][0..16].*, .big);
    return out;
}

/// Reads an `id_ed25519` and hands back the keypair to decrypt with.
///
/// `passphrase` is only consulted when the file is actually encrypted; an
/// unprotected key opens without one.
pub fn parseIdentity(allocator: Allocator, pem: []const u8, passphrase: ?[]const u8) !Identity {
    const blob = try decodeArmour(allocator, pem);
    defer allocator.free(blob);

    var reader = Reader{ .bytes = blob };
    if (!std.mem.eql(u8, try reader.take(auth_magic.len), auth_magic)) return error.MalformedKey;

    const cipher_name = try reader.string();
    const kdf_name = try reader.string();
    const kdf_options = try reader.string();
    const key_count = try reader.u32be();
    if (key_count != 1) return error.MalformedKey;
    _ = try reader.string(); // The public key, which the private half repeats.
    const encrypted = try reader.string();

    const encrypted_key = !std.mem.eql(u8, cipher_name, "none");
    const plain = if (encrypted_key)
        try decryptPrivateBlob(allocator, cipher_name, kdf_name, kdf_options, encrypted, passphrase)
    else
        try allocator.dupe(u8, encrypted);
    defer {
        std.crypto.secureZero(u8, plain);
        allocator.free(plain);
    }

    var inner = Reader{ .bytes = plain };
    // Two copies of the same random number, which is how OpenSSH itself decides
    // a passphrase was right before trusting anything that follows.
    const check1 = try inner.u32be();
    const check2 = try inner.u32be();
    if (check1 != check2) return if (encrypted_key) error.WrongPassphrase else error.MalformedKey;

    inner.expectString(key_type) catch |err| switch (err) {
        error.UnsupportedKeyType => return error.UnsupportedKeyType,
        else => return err,
    };
    _ = try inner.string(); // public half
    const secret = try inner.string();
    // OpenSSH stores the 32-byte seed followed by the public key.
    if (secret.len != Ed25519.SecretKey.encoded_length) return error.MalformedKey;

    var seed: [Ed25519.KeyPair.seed_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &seed);
    seed = secret[0..Ed25519.KeyPair.seed_length].*;

    const ed = Ed25519.KeyPair.generateDeterministic(seed) catch return error.MalformedKey;
    return X25519.KeyPair.fromEd25519(ed) catch error.MalformedKey;
}

/// True when a private key file will need a passphrase, so a caller can ask for
/// one before it has anything else to go on.
pub fn identityIsEncrypted(allocator: Allocator, pem: []const u8) !bool {
    const blob = try decodeArmour(allocator, pem);
    defer allocator.free(blob);

    var reader = Reader{ .bytes = blob };
    if (!std.mem.eql(u8, try reader.take(auth_magic.len), auth_magic)) return error.MalformedKey;
    return !std.mem.eql(u8, try reader.string(), "none");
}

const testing = std.testing;

test "public keys that are not ed25519 are refused, not misread" {
    const allocator = testing.allocator;
    try testing.expectError(error.UnsupportedKeyType, parsePublicKey(allocator, "ssh-rsa AAAAB3NzaC1yc2E= a@b"));
    try testing.expectError(error.UnsupportedKeyType, parsePublicKey(allocator, "ecdsa-sha2-nistp256 AAAA= a@b"));
    try testing.expectError(error.MalformedKey, parsePublicKey(allocator, "ssh-ed25519"));
    try testing.expectError(error.MalformedKey, parsePublicKey(allocator, "ssh-ed25519 not-base64!!"));
}

test "a truncated wire string is caught rather than read past" {
    var reader = Reader{ .bytes = &[_]u8{ 0, 0, 0, 8, 1, 2 } };
    try testing.expectError(error.MalformedKey, reader.string());
}

test "armour that is not a private key is reported as such" {
    const allocator = testing.allocator;
    try testing.expectError(error.NoKeyFound, parseIdentity(allocator, "not a key at all", null));
    try testing.expectError(error.MalformedKey, parseIdentity(allocator, pem_begin ++ "\nAAAA\n", null));
}

// Real `ssh-keygen -t ed25519` output, generated for this test suite and used
// nowhere else. The parser's whole job is reading what OpenSSH actually writes,
// so the fixtures have to be the real thing rather than something hand-rolled
// to match the parser's own idea of the format.
const fixture = struct {
    const public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBksK2DK22magHxPDTSkajjjjDUCP9VHE99Ms5HggIpe fixture-only-do-not-use";

    const unprotected =
        \\-----BEGIN OPENSSH PRIVATE KEY-----
        \\b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
        \\QyNTUxOQAAACAZLCtgyttpmoB8Tw00pGo444w1Aj/VRxPfTLOR4ICKXgAAAKDgF3qr4Bd6
        \\qwAAAAtzc2gtZWQyNTUxOQAAACAZLCtgyttpmoB8Tw00pGo444w1Aj/VRxPfTLOR4ICKXg
        \\AAAEBBijyxB9axYguctB/FdH8gFa22SUy7kb+0orSK0CeXpBksK2DK22magHxPDTSkajjj
        \\jDUCP9VHE99Ms5HggIpeAAAAF2ZpeHR1cmUtb25seS1kby1ub3QtdXNlAQIDBAUG
        \\-----END OPENSSH PRIVATE KEY-----
    ;

    /// A different key, protected with `passphrase` below.
    const protected =
        \\-----BEGIN OPENSSH PRIVATE KEY-----
        \\b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABC8gNVkZs
        \\KI+763KzFm9J3cAAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIG/gm89ZyO25S1X5
        \\OK4Mbfd2Q/arPytLsBhjDK+6wo/TAAAAoEBqwN8mKMvYFIsT0MSM1ji9+X0Uj94VknWDck
        \\SeMrbebju4fdJY236p0Fu2crn3u6gnzrHa1GyaT3B1cXp/eF28fhzL+n5JbSEvXwrl1pF3
        \\hHiUHWhLejdMswFcMZlkvOHvZeQJMl3hCYvb+FsobY4dW2ojTrZpKAD5N1p7gzgXbA9dbn
        \\p8R6W1ajgNfGiRhKLaec4mrIi4S+vD8MmnP2Y=
        \\-----END OPENSSH PRIVATE KEY-----
    ;

    const passphrase = "test-passphrase";
};

test "the public and private halves of a real key agree" {
    const allocator = testing.allocator;
    const from_pub = try parsePublicKey(allocator, fixture.public_key);
    const identity = try parseIdentity(allocator, fixture.unprotected, null);
    // Reading `id_ed25519.pub` and reading `id_ed25519` have to land on the
    // same encryption key, or sealing and opening would never meet.
    try testing.expectEqualSlices(u8, &from_pub, &identity.public_key);
}

test "a passphrase-protected key opens with its passphrase" {
    const allocator = testing.allocator;
    try testing.expect(try identityIsEncrypted(allocator, fixture.protected));
    try testing.expect(!try identityIsEncrypted(allocator, fixture.unprotected));

    const identity = try parseIdentity(allocator, fixture.protected, fixture.passphrase);
    // bcrypt-pbkdf and AES-CTR both have to be right for the two check words
    // inside to match, so getting this far is the real assertion.
    try testing.expect(!std.mem.allEqual(u8, &identity.public_key, 0));

    try testing.expectError(error.WrongPassphrase, parseIdentity(allocator, fixture.protected, "wrong"));
    try testing.expectError(error.PassphraseRequired, parseIdentity(allocator, fixture.protected, null));
    try testing.expectError(error.PassphraseRequired, parseIdentity(allocator, fixture.protected, ""));
}

test "the two fixtures are different keys" {
    const allocator = testing.allocator;
    const a = try parseIdentity(allocator, fixture.unprotected, null);
    const b = try parseIdentity(allocator, fixture.protected, fixture.passphrase);
    try testing.expect(!std.mem.eql(u8, &a.public_key, &b.public_key));
}

test "public keys are collected from an authorized_keys-style file" {
    const allocator = testing.allocator;
    var keys: std.ArrayList(PublicKey) = .empty;
    defer keys.deinit(allocator);

    const file = "# a comment\n" ++
        "ssh-rsa AAAAB3NzaC1yc2E= someone@host\n" ++
        "\n" ++
        fixture.public_key ++ "\n" ++
        "ecdsa-sha2-nistp256 AAAA= someone@host\n";
    try parsePublicKeyFile(allocator, file, &keys);

    // The other two types are skipped rather than refused, so pointing this at
    // a real authorized_keys works.
    try testing.expectEqual(@as(usize, 1), keys.items.len);
    try testing.expectEqualSlices(u8, &try parsePublicKey(allocator, fixture.public_key), &keys.items[0]);

    var none: std.ArrayList(PublicKey) = .empty;
    defer none.deinit(allocator);
    try testing.expectError(error.NoKeyFound, parsePublicKeyFile(allocator, "ssh-rsa AAAA= a@b\n", &none));
}
