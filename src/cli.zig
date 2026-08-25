const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const cipher = @import("cipher.zig");
const container = @import("container.zig");
const image = @import("image.zig");
const recipient = @import("recipient.zig");
const ssh = @import("ssh.zig");

pub const Direction = cipher.Direction;

const max_key_file_bytes = 1024 * 1024;

/// Everything the tools need from the process, gathered in one place so `parse`
/// and `run` stay testable without touching globals.
pub const Context = struct {
    allocator: Allocator,
    io: Io,
    argv: []const [:0]const u8,
    environ: *const std.process.Environ.Map,
};

pub const Args = struct {
    allocator: Allocator,
    /// Absent in recipient mode, where the master key is random and sealed into
    /// the image rather than derived from anything the caller typed.
    key: ?[]u8,
    /// How the supplied bytes become a master key. `--key-hex` hands over full
    /// entropy and is used as-is; everything else is a passphrase and gets
    /// stretched.
    kdf: cipher.KdfId,
    /// `--recipient` values, each an `ssh-ed25519 ...` line or a path to a file
    /// of them. `to-noise` only.
    recipients: [][]u8,
    /// `--identity` paths, tried in order. `from-noise` only.
    identities: [][]u8,
    identity_passphrase_env: ?[]u8,
    input: []const u8,
    output: []const u8,
    format: image.Format,

    pub fn deinit(self: *Args) void {
        if (self.key) |key| {
            std.crypto.secureZero(u8, key);
            self.allocator.free(key);
        }
        for (self.recipients) |value| self.allocator.free(value);
        self.allocator.free(self.recipients);
        for (self.identities) |value| self.allocator.free(value);
        self.allocator.free(self.identities);
        if (self.identity_passphrase_env) |value| self.allocator.free(value);
        self.allocator.free(self.input);
        self.allocator.free(self.output);
        self.* = undefined;
    }
};

pub fn fatal(comptime fmt: []const u8, args: anytype) noreturn {
    std.process.fatal(fmt, args);
}

/// Both tools take the same options and differ only in wording, so the help is
/// one template filled in per direction.
fn usage(direction: Direction) []const u8 {
    const template =
        \\Usage: {[command]s} [options] <{[input]s}>
        \\
        \\{[summary]s}
        \\
        \\Options:
        \\  -k, --key <text>       Passphrase used as the transformation key
        \\      --key-file <path>  Read the key from a file (the exact bytes, so a
        \\                         trailing newline is part of the key)
        \\      --key-hex <hex>    64 hex digits used as a 32-byte master key
        \\      --key-env <name>   Read the key from an environment variable, which
        \\                         keeps it out of both argv and the filesystem
        \\{[keying]s}
        \\  -o, --output <path>    Output image (default: <stem>.{[tag]s}.png)
        \\      --format <fmt>     Output format, png or ppm (default: from --output)
        \\  -h, --help             Show this help
        \\
        \\A path of `-` reads stdin or writes stdout, so the tools compose in a
        \\pipe and no image has to touch the filesystem. Progress and fingerprints
        \\are always written to stderr.
        \\
        \\{[footer]s}
        \\
    ;
    return switch (direction) {
        .to_noise => std.fmt.comptimePrint(template, .{
            .command = "to-noise",
            .input = "input-image",
            .summary =
            \\Transform an image into authenticated keyed noise. The inverse
            \\(`from-noise` with the same key) restores the original pixels.
            ,
            .tag = "noise",
            .keying =
            \\  -r, --recipient <k>    Seal to an ssh-ed25519 public key instead of a
            \\                         shared secret. Takes the key itself or a path to
            \\                         a file of them, and may be repeated.
            ,
            .footer =
            \\Supported formats: PNG (8-bit gray/RGB/RGBA) and binary PPM (P5/P6).
            \\Keep the noise image lossless; JPEG will destroy the hidden data.
            \\The noise is a few rows taller than the input: those rows carry the
            \\per-image salt, the authentication tag, and any sealed keys.
            ,
        }),
        .from_noise => std.fmt.comptimePrint(template, .{
            .command = "from-noise",
            .input = "noise-image",
            .summary =
            \\Verify a noise image and reconstruct the original, given the key it
            \\was made with or an identity it was sealed to.
            ,
            .tag = "restored",
            .keying =
            \\  -i, --identity <path>  Private key to open a sealed image with, e.g.
            \\                         ~/.ssh/id_ed25519. May be repeated.
            \\      --identity-passphrase-env <name>
            \\                         Environment variable holding the passphrase for
            \\                         an encrypted private key
            ,
            .footer =
            \\A wrong key, or a file altered anywhere along the way, is rejected
            \\outright rather than restored into something that looks like noise.
            ,
        }),
    };
}

/// What each direction calls the pixels going in and coming out. `to-noise`
/// and `from-noise` deliberately share the `noise` label: that is the pair a
/// caller compares to prove the noise survived the trip between them.
fn labels(direction: Direction) struct { input: []const u8, output: []const u8, wrote: []const u8 } {
    return switch (direction) {
        .to_noise => .{ .input = "source", .output = "noise", .wrote = "noise" },
        .from_noise => .{ .input = "noise", .output = "restored", .wrote = "restored image" },
    };
}

fn defaultOutput(allocator: Allocator, input: []const u8, direction: Direction) ![]const u8 {
    // A stream has no name to build one from, so it stays a stream.
    if (image.isStandardStream(input)) return allocator.dupe(u8, image.standard_stream);

    const parts = image.splitPath(input);
    var stem = parts.stem;
    const tag = switch (direction) {
        .to_noise => ".noise",
        .from_noise => tag: {
            // `photo.noise.png` restores to `photo.restored.png` rather than
            // accumulating both tags.
            if (std.ascii.endsWithIgnoreCase(stem, ".noise")) stem = stem[0 .. stem.len - ".noise".len];
            break :tag ".restored";
        },
    };
    return std.fmt.allocPrint(allocator, "{s}{s}{s}", .{ stem, tag, parts.ext });
}

fn parseHexKey(allocator: Allocator, hex: []const u8) ![]u8 {
    var trimmed = hex;
    if (std.ascii.startsWithIgnoreCase(trimmed, "0x")) trimmed = trimmed[2..];
    if (trimmed.len != 64) return error.InvalidHexKey;

    var raw: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &raw);
    _ = std.fmt.hexToBytes(&raw, trimmed) catch return error.InvalidHexKey;
    return allocator.dupe(u8, &raw);
}

pub fn parse(ctx: Context, direction: Direction) !Args {
    const allocator = ctx.allocator;

    var key_text: ?[]const u8 = null;
    var key_file: ?[]const u8 = null;
    var key_hex: ?[]const u8 = null;
    var key_env: ?[]const u8 = null;
    var output: ?[]const u8 = null;
    var format_text: ?[]const u8 = null;
    var input: ?[]const u8 = null;
    var passphrase_env: ?[]const u8 = null;

    var recipients: std.ArrayList([]u8) = .empty;
    errdefer {
        for (recipients.items) |value| allocator.free(value);
        recipients.deinit(allocator);
    }
    var identities: std.ArrayList([]u8) = .empty;
    errdefer {
        for (identities.items) |value| allocator.free(value);
        identities.deinit(allocator);
    }

    var i: usize = 1;
    while (i < ctx.argv.len) : (i += 1) {
        const arg = ctx.argv[i];
        // Every option below takes exactly one value, so grab it in one place.
        // A bare `-` is a stream, not an option.
        const value: ?[]const u8 = blk: {
            if (arg.len < 2 or arg[0] != '-') break :blk null;
            if (i + 1 >= ctx.argv.len) break :blk null;
            break :blk ctx.argv[i + 1];
        };

        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            try writeOut(ctx.io, "{s}", .{usage(direction)});
            std.process.exit(0);
        } else if (std.mem.eql(u8, arg, "-k") or std.mem.eql(u8, arg, "--key")) {
            key_text = value orelse fatal("missing value for {s}", .{arg});
            i += 1;
        } else if (std.mem.eql(u8, arg, "--key-file")) {
            key_file = value orelse fatal("missing value for {s}", .{arg});
            i += 1;
        } else if (std.mem.eql(u8, arg, "--key-hex")) {
            key_hex = value orelse fatal("missing value for {s}", .{arg});
            i += 1;
        } else if (std.mem.eql(u8, arg, "--key-env")) {
            key_env = value orelse fatal("missing value for {s}", .{arg});
            i += 1;
        } else if (std.mem.eql(u8, arg, "-r") or std.mem.eql(u8, arg, "--recipient")) {
            if (direction != .to_noise) fatal("{s} is only meaningful for to-noise", .{arg});
            const text = value orelse fatal("missing value for {s}", .{arg});
            try recipients.append(allocator, try allocator.dupe(u8, text));
            i += 1;
        } else if (std.mem.eql(u8, arg, "-i") or std.mem.eql(u8, arg, "--identity")) {
            if (direction != .from_noise) fatal("{s} is only meaningful for from-noise", .{arg});
            const text = value orelse fatal("missing value for {s}", .{arg});
            try identities.append(allocator, try allocator.dupe(u8, text));
            i += 1;
        } else if (std.mem.eql(u8, arg, "--identity-passphrase-env")) {
            if (direction != .from_noise) fatal("{s} is only meaningful for from-noise", .{arg});
            passphrase_env = value orelse fatal("missing value for {s}", .{arg});
            i += 1;
        } else if (std.mem.eql(u8, arg, "-o") or std.mem.eql(u8, arg, "--output")) {
            output = value orelse fatal("missing value for {s}", .{arg});
            i += 1;
        } else if (std.mem.eql(u8, arg, "--format")) {
            format_text = value orelse fatal("missing value for {s}", .{arg});
            i += 1;
        } else if (arg.len > 1 and arg[0] == '-') {
            fatal("unknown option {s}", .{arg});
        } else if (input == null) {
            input = arg;
        } else {
            fatal("unexpected argument {s}", .{arg});
        }
    }

    const in_path = input orelse fatal("missing input image\n\n{s}", .{usage(direction)});

    var key_sources: usize = 0;
    for ([_]?[]const u8{ key_text, key_file, key_hex, key_env }) |source| {
        if (source != null) key_sources += 1;
    }
    const public_keying = recipients.items.len > 0 or identities.items.len > 0;
    if (key_sources > 1) {
        fatal("provide exactly one of --key, --key-file, --key-hex, or --key-env", .{});
    }
    if (key_sources > 0 and public_keying) {
        fatal("a key and {s} are two different ways to open the same image; pick one", .{
            if (direction == .to_noise) "--recipient" else "--identity",
        });
    }
    if (key_sources == 0 and !public_keying) {
        fatal("provide a key (--key, --key-file, --key-hex, --key-env) or {s}", .{
            if (direction == .to_noise) "--recipient" else "--identity",
        });
    }

    const key: ?[]u8 = if (public_keying) null else if (key_text) |text| key: {
        if (text.len == 0) fatal("key must not be empty", .{});
        break :key try allocator.dupe(u8, text);
    } else if (key_env) |name| key: {
        // Reading through the environment keeps the key out of argv, where any
        // other process on the machine could read it out of `ps`.
        const text = ctx.environ.get(name) orelse fatal("environment variable {s} is not set", .{name});
        if (text.len == 0) fatal("environment variable {s} is empty", .{name});
        break :key try allocator.dupe(u8, text);
    } else if (key_file) |path| key: {
        const bytes = Io.Dir.cwd().readFileAlloc(ctx.io, path, allocator, .limited(max_key_file_bytes)) catch |err| {
            fatal("cannot read key file {s}: {t}", .{ path, err });
        };
        if (bytes.len == 0) {
            allocator.free(bytes);
            fatal("key file {s} is empty", .{path});
        }
        break :key bytes;
    } else parseHexKey(allocator, key_hex.?) catch fatal("key-hex must be 64 hexadecimal digits", .{});
    errdefer if (key) |bytes| {
        std.crypto.secureZero(u8, bytes);
        allocator.free(bytes);
    };

    const in_owned = try allocator.dupe(u8, in_path);
    errdefer allocator.free(in_owned);

    const out_owned = if (output) |path|
        try allocator.dupe(u8, path)
    else
        try defaultOutput(allocator, in_path, direction);
    errdefer allocator.free(out_owned);

    return .{
        .allocator = allocator,
        .key = key,
        .kdf = if (public_keying) .x25519 else if (key_hex != null) .raw else .argon2id,
        .recipients = try recipients.toOwnedSlice(allocator),
        .identities = try identities.toOwnedSlice(allocator),
        .identity_passphrase_env = if (passphrase_env) |name| try allocator.dupe(u8, name) else null,
        .input = in_owned,
        .output = out_owned,
        .format = try resolveFormat(format_text, out_owned),
    };
}

/// A named output picks its own format from the extension; a stream has no
/// name, so it defaults to PNG unless `--format` says otherwise.
fn resolveFormat(format_text: ?[]const u8, output: []const u8) !image.Format {
    if (format_text) |text| {
        return std.meta.stringToEnum(image.Format, text) orelse
            fatal("unknown format {s} (use png or ppm)", .{text});
    }
    if (image.isStandardStream(output)) return .png;
    return image.formatFromPath(output);
}

fn writeOut(io: Io, comptime fmt: []const u8, args: anytype) !void {
    var buffer: [4096]u8 = undefined;
    var out = Io.File.stdout().writerStreaming(io, &buffer);
    try out.interface.print(fmt, args);
    try out.interface.flush();
}

/// Diagnostics go to stderr unconditionally, so `-o -` stays a clean pipe.
fn report(io: Io, comptime fmt: []const u8, args: anytype) !void {
    var buffer: [4096]u8 = undefined;
    var err = Io.File.stderr().writerStreaming(io, &buffer);
    try err.interface.print(fmt, args);
    try err.interface.flush();
}

fn masterOrFatal(ctx: Context, args: Args, kdf: cipher.KdfId) cipher.Master {
    const key = args.key orelse fatal("this image needs a key, but none was given", .{});
    return cipher.deriveMaster(ctx.allocator, ctx.io, key, kdf) catch |err| switch (err) {
        error.RawKeyLength => fatal(
            "this noise image was made with a 32-byte raw key; supply it with --key-hex",
            .{},
        ),
        error.IdentityRequired => fatal(
            "this noise image is sealed to a public key; open it with --identity <private key>",
            .{},
        ),
        error.UnsupportedKdf => fatal(
            "this noise image uses a key derivation this build does not know; upgrade the tools",
            .{},
        ),
        else => fatal("cannot derive the key: {t}", .{err}),
    };
}

fn readKeyFile(ctx: Context, path: []const u8) []u8 {
    return Io.Dir.cwd().readFileAlloc(ctx.io, path, ctx.allocator, .limited(ssh.max_key_file_bytes)) catch |err| switch (err) {
        error.FileNotFound => fatal("no such key file: {s}", .{path}),
        else => fatal("cannot read {s}: {t}", .{ path, err }),
    };
}

/// A `--recipient` value is either the key itself or a path to a file of them,
/// which is the difference between pasting what a friend sent and pointing at
/// where you saved it. Both are common enough that guessing beats a second flag.
fn loadRecipients(ctx: Context, values: []const []u8) []recipient.PublicKey {
    var keys: std.ArrayList(recipient.PublicKey) = .empty;
    for (values) |value| {
        const trimmed = std.mem.trim(u8, value, " \t\r\n");
        if (std.mem.startsWith(u8, trimmed, "ssh-")) {
            const key = ssh.parsePublicKey(ctx.allocator, trimmed) catch |err| switch (err) {
                error.UnsupportedKeyType => fatal(
                    "only ssh-ed25519 recipients are supported; ask for one with `ssh-keygen -t ed25519`",
                    .{},
                ),
                else => fatal("cannot read that recipient key: {t}", .{err}),
            };
            keys.append(ctx.allocator, key) catch fatal("out of memory", .{});
            continue;
        }
        const contents = readKeyFile(ctx, trimmed);
        defer ctx.allocator.free(contents);
        ssh.parsePublicKeyFile(ctx.allocator, contents, &keys) catch |err| switch (err) {
            error.NoKeyFound => fatal("no ssh-ed25519 public key in {s}", .{trimmed}),
            else => fatal("cannot read {s}: {t}", .{ trimmed, err }),
        };
    }
    if (keys.items.len == 0) fatal("no recipients to seal to", .{});
    if (keys.items.len > recipient.max_recipients) {
        fatal("at most {d} recipients per image", .{recipient.max_recipients});
    }
    return keys.toOwnedSlice(ctx.allocator) catch fatal("out of memory", .{});
}

fn loadIdentities(ctx: Context, args: Args) []ssh.Identity {
    const passphrase: ?[]const u8 = if (args.identity_passphrase_env) |name|
        ctx.environ.get(name) orelse fatal("environment variable {s} is not set", .{name})
    else
        null;

    var out: std.ArrayList(ssh.Identity) = .empty;
    for (args.identities) |path| {
        const contents = readKeyFile(ctx, path);
        defer {
            std.crypto.secureZero(u8, contents);
            ctx.allocator.free(contents);
        }
        const identity = ssh.parseIdentity(ctx.allocator, contents, passphrase) catch |err| switch (err) {
            error.PassphraseRequired => fatal(
                \\{s} is passphrase-protected, and there is no terminal here to ask on.
                \\Put the passphrase in the environment and name it:
                \\  IDENTITY_PASSPHRASE=... from-noise --identity-passphrase-env IDENTITY_PASSPHRASE ...
                \\Or keep an unprotected copy: ssh-keygen -p -N "" -f <copy of the key>
            ,
                .{path},
            ),
            error.WrongPassphrase => fatal("wrong passphrase for {s}", .{path}),
            error.UnsupportedKeyType => fatal(
                "{s} is not an ed25519 key; only ssh-ed25519 can be used here",
                .{path},
            ),
            error.UnsupportedCipher => fatal(
                "{s} uses a cipher this build cannot read (expected the usual aes256-ctr)",
                .{path},
            ),
            error.NoKeyFound => fatal("{s} does not look like an OpenSSH private key", .{path}),
            else => fatal("cannot read {s}: {t}", .{ path, err }),
        };
        out.append(ctx.allocator, identity) catch fatal("out of memory", .{});
    }
    if (out.items.len == 0) fatal("no identities to try", .{});
    return out.toOwnedSlice(ctx.allocator) catch fatal("out of memory", .{});
}

/// Trial decryption: every stanza is tried against every identity, and the
/// Poly1305 tag on one of them is what says it was addressed to you.
fn openSealed(ctx: Context, args: Args, noise: image.Image, header: container.Header) cipher.Master {
    const identities = loadIdentities(ctx, args);
    defer {
        std.crypto.secureZero(u8, std.mem.sliceAsBytes(identities));
        ctx.allocator.free(identities);
    }

    for (identities) |identity| {
        var i: usize = 0;
        while (i < header.recipient_count) : (i += 1) {
            if (recipient.open(container.stanzaAt(noise.rgb, i), identity)) |master| {
                return master;
            } else |_| {}
        }
    }
    fatal(
        "none of the identities given can open this image: it was sealed to a different key, " ++
            "or the sealed keys in the header have been altered",
        .{},
    );
}

/// What a run produced, so the two directions can share one report.
const Outcome = struct {
    width: u32,
    height: u32,
    key_id: [8]u8,
    in_fp: [16]u8,
    out_fp: [16]u8,
};

/// Wraps the picture in a v2 container: header rows carrying a fresh salt, any
/// sealed copies of the master key, and a tag, then the transformed pixels.
fn toNoise(ctx: Context, args: Args, src: image.Image) !Outcome {
    var master: cipher.Master = undefined;
    defer std.crypto.secureZero(u8, &master);
    var stanzas: []recipient.Stanza = &.{};
    defer ctx.allocator.free(stanzas);

    if (args.kdf == .x25519) {
        const keys = loadRecipients(ctx, args.recipients);
        defer ctx.allocator.free(keys);

        // Nobody types this one: it is random, and each recipient gets their own
        // sealed copy of it.
        ctx.io.randomSecure(&master) catch fatal("no source of secure randomness is available", .{});

        stanzas = try ctx.allocator.alloc(recipient.Stanza, keys.len);
        for (stanzas, keys) |*stanza, key| {
            stanza.* = recipient.seal(ctx.io, master, key) catch
                fatal("one of the recipient keys is not usable", .{});
        }
    } else {
        master = masterOrFatal(ctx, args, args.kdf);
    }

    var salt: cipher.Salt = undefined;
    ctx.io.randomSecure(&salt) catch fatal("no source of secure randomness is available", .{});

    var keys = cipher.deriveKeys(master, salt, src.width, src.height);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&keys));

    var out = container.wrap(ctx.allocator, ctx.io, src, .{
        .kdf = args.kdf,
        .width = src.width,
        .height = src.height,
        .salt = salt,
        .mac = undefined,
        .recipient_count = @intCast(stanzas.len),
    }, stanzas, keys) catch |err| switch (err) {
        error.InvalidImageSize => fatal(
            "image is too large: the header rows push it past the {d} pixel limit",
            .{cipher.max_pixels},
        ),
        error.EntropyUnavailable => fatal("no source of secure randomness is available", .{}),
        else => return err,
    };
    defer out.deinit();

    try save(ctx, args, out);
    return .{
        .width = out.width,
        .height = out.height,
        .key_id = cipher.keyId(master),
        .in_fp = cipher.fingerprint(src.rgb),
        .out_fp = cipher.fingerprint(out.rgb),
    };
}

/// Verifies a v2 container and unwraps it, or falls back to the unauthenticated
/// v1 layout for noise written before the format change.
fn fromNoise(ctx: Context, args: Args, noise: image.Image) !Outcome {
    const header = container.parseHeader(noise.rgb) catch |err| switch (err) {
        error.NotV2 => return fromNoiseV1(ctx, args, noise),
        error.UnsupportedVersion => fatal(
            "this noise image was written by a newer build of the tools; upgrade to open it",
            .{},
        ),
        error.MalformedHeader => fatal("this noise image has a corrupt header", .{}),
    };

    if (header.kdf == .x25519 and args.identities.len == 0) {
        fatal("this image is sealed to a public key; open it with --identity <private key>", .{});
    }
    if (header.kdf != .x25519 and args.identities.len > 0) {
        fatal("this image was made with a shared key, not sealed to anyone; use --key", .{});
    }

    var master = if (header.kdf == .x25519)
        openSealed(ctx, args, noise, header)
    else
        masterOrFatal(ctx, args, header.kdf);
    defer std.crypto.secureZero(u8, &master);

    var keys = cipher.deriveKeys(master, header.salt, header.width, header.height);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&keys));

    var out = container.unwrap(ctx.allocator, noise, header, keys) catch |err| switch (err) {
        error.AuthenticationFailed => fatal(
            "authentication failed: the key is wrong, or this file is not the one that was written\n" ++
                "(key-id {s} for the key given)",
            .{std.fmt.bytesToHex(cipher.keyId(master), .lower)},
        ),
        error.GeometryMismatch => fatal(
            "this noise image has been cropped or resized; the header no longer matches it",
            .{},
        ),
        error.InvalidImageSize => fatal("image dimensions are out of range", .{}),
        else => return err,
    };
    defer out.deinit();

    try save(ctx, args, out);
    return .{
        .width = out.width,
        .height = out.height,
        .key_id = cipher.keyId(master),
        .in_fp = cipher.fingerprint(noise.rgb),
        .out_fp = cipher.fingerprint(out.rgb),
    };
}

/// The pre-salt, pre-MAC layout, kept readable so noise made by an older build
/// is not stranded. There is nothing to verify here, which is the whole reason
/// the format changed.
fn fromNoiseV1(ctx: Context, args: Args, noise: image.Image) !Outcome {
    const key = args.key orelse fatal("a v1 noise image needs a key, not an identity", .{});
    try report(ctx.io,
        \\warning: this is a v1 noise image - no salt, no authentication.
        \\         A wrong key will produce a plausible-looking wrong image, and
        \\         any change to the file will go unnoticed. Re-encrypt it with
        \\         this build to fix both.
        \\
    , .{});

    var master = cipher.deriveMasterV1(key);
    defer std.crypto.secureZero(u8, &master);
    var keys = cipher.deriveKeysV1(master, noise.width, noise.height);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&keys));

    const in_fp = cipher.fingerprint(noise.rgb);
    try cipher.transform(ctx.allocator, noise.rgb, noise.width, noise.height, keys, .from_noise);

    try save(ctx, args, noise);
    return .{
        .width = noise.width,
        .height = noise.height,
        .key_id = cipher.keyId(master),
        .in_fp = in_fp,
        .out_fp = cipher.fingerprint(noise.rgb),
    };
}

fn save(ctx: Context, args: Args, img: image.Image) !void {
    if (!image.isStandardStream(args.output)) {
        if (std.fs.path.dirname(args.output)) |dir| {
            // A missing parent directory surfaces as a clearer error from `save`.
            if (dir.len > 0) Io.Dir.cwd().createDirPath(ctx.io, dir) catch {};
        }
    }
    image.save(img, ctx.io, args.output, args.format) catch |err| {
        fatal("cannot write {s}: {t}", .{ args.output, err });
    };
}

pub fn run(ctx: Context, direction: Direction) !void {
    var args = try parse(ctx, direction);
    defer args.deinit();

    var img = image.load(ctx.allocator, ctx.io, args.input) catch |err| switch (err) {
        error.FileNotFound => fatal("input not found: {s}", .{args.input}),
        error.UnsupportedImageFormat => fatal("unsupported image format (use PNG or PPM)", .{}),
        error.UnsupportedPng, error.UnsupportedPpm => fatal("unsupported image variant (need 8-bit, non-interlaced PNG or maxval-255 PPM)", .{}),
        error.InvalidPng, error.InvalidPngCrc, error.InvalidPpm => fatal("image file is corrupt", .{}),
        error.InvalidImageSize => fatal("image dimensions are out of range (limit is {d} pixels)", .{cipher.max_pixels}),
        error.StreamTooLong => fatal("input is larger than the {d} byte limit", .{image.max_file_bytes}),
        else => return err,
    };
    defer img.deinit();

    const outcome = switch (direction) {
        .to_noise => try toNoise(ctx, args, img),
        .from_noise => try fromNoise(ctx, args, img),
    };

    // Fingerprinting both sides still makes a round trip checkable by eye. The
    // authentication tag is what actually decides whether the noise arrived
    // intact and the key was right; these are for reading, not for trusting.
    const names = labels(direction);
    try report(ctx.io,
        \\wrote {s} ({d}x{d} {s})
        \\key-id {s}
        \\{s} fingerprint {s}
        \\{s} fingerprint {s}
        \\
    , .{
        args.output,
        outcome.width,
        outcome.height,
        names.wrote,
        std.fmt.bytesToHex(outcome.key_id, .lower),
        names.input,
        std.fmt.bytesToHex(outcome.in_fp, .lower),
        names.output,
        std.fmt.bytesToHex(outcome.out_fp, .lower),
    });
}

/// Shared entry point for both binaries. `std.process.Init` hands over the
/// allocator, the `Io` implementation, argv and the environment in one go.
pub fn main(direction: Direction, init: std.process.Init) !void {
    const argv = try init.minimal.args.toSlice(init.arena.allocator());
    run(.{
        .allocator = init.gpa,
        .io = init.io,
        .argv = argv,
        .environ = init.environ_map,
    }, direction) catch |err| fatal("{t}", .{err});
}

test "default output names" {
    const allocator = std.testing.allocator;
    const cases = [_]struct { in: []const u8, direction: Direction, want: []const u8 }{
        .{ .in = "photo.png", .direction = .to_noise, .want = "photo.noise.png" },
        .{ .in = "photo.ppm", .direction = .to_noise, .want = "photo.noise.ppm" },
        .{ .in = "a/b/photo.png", .direction = .to_noise, .want = "a/b/photo.noise.png" },
        // An unrecognised extension is preserved rather than replaced.
        .{ .in = "photo.jpg", .direction = .to_noise, .want = "photo.jpg.noise.png" },
        .{ .in = "photo", .direction = .to_noise, .want = "photo.noise.png" },
        // The `.noise` tag is consumed on the way back, not stacked.
        .{ .in = "photo.noise.png", .direction = .from_noise, .want = "photo.restored.png" },
        .{ .in = "photo.png", .direction = .from_noise, .want = "photo.restored.png" },
        .{ .in = "a/b/photo.noise.ppm", .direction = .from_noise, .want = "a/b/photo.restored.ppm" },
        // A stream in stays a stream out; there is no name to derive.
        .{ .in = "-", .direction = .to_noise, .want = "-" },
        .{ .in = "-", .direction = .from_noise, .want = "-" },
    };
    for (cases) |case| {
        const got = try defaultOutput(allocator, case.in, case.direction);
        defer allocator.free(got);
        try std.testing.expectEqualStrings(case.want, got);
    }
}

test "output format resolution" {
    // An explicit --format always wins.
    try std.testing.expectEqual(image.Format.ppm, try resolveFormat("ppm", "out.png"));
    try std.testing.expectEqual(image.Format.png, try resolveFormat("png", "-"));
    // Otherwise the extension decides, and a stream defaults to PNG.
    try std.testing.expectEqual(image.Format.ppm, try resolveFormat(null, "out.ppm"));
    try std.testing.expectEqual(image.Format.png, try resolveFormat(null, "out.png"));
    try std.testing.expectEqual(image.Format.png, try resolveFormat(null, "-"));
}

test "hex keys" {
    const allocator = std.testing.allocator;
    const key = try parseHexKey(allocator, "00112233445566778899aabbccddeeff" ** 2);
    defer allocator.free(key);
    try std.testing.expectEqual(@as(usize, 32), key.len);
    try std.testing.expectEqual(@as(u8, 0xff), key[31]);

    const prefixed = try parseHexKey(allocator, "0X" ++ "00112233445566778899aabbccddeeff" ** 2);
    defer allocator.free(prefixed);
    try std.testing.expectEqualSlices(u8, key, prefixed);

    try std.testing.expectError(error.InvalidHexKey, parseHexKey(allocator, "abcd"));
    try std.testing.expectError(error.InvalidHexKey, parseHexKey(allocator, "zz" ** 32));
}

test "usage text is complete for both directions" {
    for ([_]Direction{ .to_noise, .from_noise }) |direction| {
        const text = usage(direction);
        try std.testing.expect(std.mem.indexOf(u8, text, "--key-file") != null);
        try std.testing.expect(std.mem.indexOf(u8, text, "--key-env") != null);
        try std.testing.expect(std.mem.indexOf(u8, text, "--output") != null);
        try std.testing.expect(std.mem.indexOf(u8, text, "--format") != null);
    }
    try std.testing.expect(std.mem.indexOf(u8, usage(.to_noise), "<stem>.noise.png") != null);
    try std.testing.expect(std.mem.indexOf(u8, usage(.from_noise), "<stem>.restored.png") != null);
    // The inverse must not still promise the old wrong-key behaviour.
    try std.testing.expect(std.mem.indexOf(u8, usage(.from_noise), "rejected") != null);
}

test "the two directions agree on the shared noise label" {
    // The whole verification story rests on these matching.
    try std.testing.expectEqualStrings("noise", labels(.to_noise).output);
    try std.testing.expectEqualStrings("noise", labels(.from_noise).input);
}
