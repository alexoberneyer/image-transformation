//! Wrapping the master key to an X25519 public key, so an image can be sent to
//! someone without first agreeing on a shared secret.
//!
//! The scheme is the ordinary one. `to-noise` already draws a random 32-byte
//! master key when nobody supplies a passphrase; here that key stays random and
//! is sealed to each recipient with an ephemeral Diffie-Hellman, so the only
//! thing that travels with the image is something only their private key opens.
//! Nothing below this layer changes: the salt, the permutation, the keystream
//! and the tag are all derived from that master exactly as before.
//!
//! There is no recipient identifier in a stanza. Opening one is a trial
//! decryption, and the Poly1305 tag is what says "this one was for you", so an
//! image does not carry a list of who can read it.

const std = @import("std");
const Io = std.Io;
const Blake3 = std.crypto.hash.Blake3;
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
const X25519 = std.crypto.dh.X25519;
const cipher = @import("cipher.zig");

pub const public_length = X25519.public_length;
pub const PublicKey = [public_length]u8;
pub const Identity = X25519.KeyPair;

pub const stanza_bytes = public_length + cipher.Master_length + ChaCha20Poly1305.tag_length;

comptime {
    std.debug.assert(stanza_bytes == 80);
}

/// Nothing about the count needs to be large; it is a byte in the header and a
/// sane bound on how many people one image is addressed to.
pub const max_recipients = 32;

const wrap_context = "image-transformation/v2 x25519 wrap";

pub const Stanza = [stanza_bytes]u8;

/// Binding the derived key to both public keys is what stops a stanza from
/// being lifted out of one image and replayed into another addressed elsewhere.
fn wrapKey(shared: [X25519.shared_length]u8, ephemeral: PublicKey, recipient: PublicKey) [32]u8 {
    var out: [32]u8 = undefined;
    var kdf = Blake3.initKdf(wrap_context, .{});
    kdf.update(&shared);
    kdf.update(&ephemeral);
    kdf.update(&recipient);
    kdf.final(&out);
    return out;
}

/// Seals `master` to one recipient. The nonce is fixed because the wrapping key
/// is derived fresh from an ephemeral keypair every time, so it is never reused.
pub fn seal(io: Io, master: cipher.Master, recipient: PublicKey) !Stanza {
    const ephemeral = X25519.KeyPair.generate(io);
    var shared = X25519.scalarmult(ephemeral.secret_key, recipient) catch
        return error.InvalidRecipientKey;
    defer std.crypto.secureZero(u8, &shared);

    var key = wrapKey(shared, ephemeral.public_key, recipient);
    defer std.crypto.secureZero(u8, &key);

    var stanza: Stanza = undefined;
    stanza[0..public_length].* = ephemeral.public_key;
    ChaCha20Poly1305.encrypt(
        stanza[public_length..][0..cipher.Master_length],
        stanza[public_length + cipher.Master_length ..][0..ChaCha20Poly1305.tag_length],
        &master,
        "",
        [_]u8{0} ** ChaCha20Poly1305.nonce_length,
        key,
    );
    return stanza;
}

/// Tries one identity against one stanza. `error.NotForThisIdentity` simply
/// means this was somebody else's copy of the key, which is the normal outcome
/// for every stanza but one.
pub fn open(stanza: []const u8, identity: Identity) !cipher.Master {
    if (stanza.len != stanza_bytes) return error.MalformedStanza;
    const ephemeral: PublicKey = stanza[0..public_length].*;

    var shared = X25519.scalarmult(identity.secret_key, ephemeral) catch
        return error.NotForThisIdentity;
    defer std.crypto.secureZero(u8, &shared);

    var key = wrapKey(shared, ephemeral, identity.public_key);
    defer std.crypto.secureZero(u8, &key);

    var master: cipher.Master = undefined;
    ChaCha20Poly1305.decrypt(
        &master,
        stanza[public_length..][0..cipher.Master_length],
        stanza[public_length + cipher.Master_length ..][0..ChaCha20Poly1305.tag_length].*,
        "",
        [_]u8{0} ** ChaCha20Poly1305.nonce_length,
        key,
    ) catch return error.NotForThisIdentity;
    return master;
}

const testing = std.testing;

test "a sealed master opens with the matching identity" {
    const io = testing.io;
    const identity = X25519.KeyPair.generate(io);
    const master: cipher.Master = [_]u8{0x3c} ** 32;

    const stanza = try seal(io, master, identity.public_key);
    try testing.expectEqualSlices(u8, &master, &try open(&stanza, identity));
}

test "a stanza is opaque to anybody else" {
    const io = testing.io;
    const mine = X25519.KeyPair.generate(io);
    const theirs = X25519.KeyPair.generate(io);
    const master: cipher.Master = [_]u8{0x91} ** 32;

    const stanza = try seal(io, master, mine.public_key);
    try testing.expectError(error.NotForThisIdentity, open(&stanza, theirs));
}

test "sealing twice to one recipient gives different stanzas" {
    // The ephemeral keypair is what makes this true, and it is what lets the
    // nonce be a constant.
    const io = testing.io;
    const identity = X25519.KeyPair.generate(io);
    const master: cipher.Master = [_]u8{0x44} ** 32;

    const a = try seal(io, master, identity.public_key);
    const b = try seal(io, master, identity.public_key);
    try testing.expect(!std.mem.eql(u8, &a, &b));
    try testing.expectEqualSlices(u8, &try open(&a, identity), &try open(&b, identity));
}

test "a tampered stanza does not open" {
    const io = testing.io;
    const identity = X25519.KeyPair.generate(io);
    const master: cipher.Master = [_]u8{0x08} ** 32;
    const good = try seal(io, master, identity.public_key);

    for ([_]usize{ 0, 31, 32, 63, 64, 79 }) |spot| {
        var bad = good;
        bad[spot] ^= 0x01;
        try testing.expectError(error.NotForThisIdentity, open(&bad, identity));
    }
    try testing.expectError(error.MalformedStanza, open(good[0 .. stanza_bytes - 1], identity));
}
