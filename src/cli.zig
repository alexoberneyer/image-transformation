const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const cipher = @import("cipher.zig");
const image = @import("image.zig");

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
    key: []u8,
    input: []const u8,
    output: []const u8,
    format: image.Format,

    pub fn deinit(self: *Args) void {
        std.crypto.secureZero(u8, self.key);
        self.allocator.free(self.key);
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
            \\Transform an image into deterministic keyed noise. The inverse
            \\(`from-noise` with the same key) restores the original pixels.
            ,
            .tag = "noise",
            .footer =
            \\Supported formats: PNG (8-bit gray/RGB/RGBA) and binary PPM (P5/P6).
            \\Keep the noise image lossless; JPEG will destroy the hidden data.
            ,
        }),
        .from_noise => std.fmt.comptimePrint(template, .{
            .command = "from-noise",
            .input = "noise-image",
            .summary =
            \\Apply the inverse transformation and reconstruct the original image.
            \\The key must match the one used with `to-noise`.
            ,
            .tag = "restored",
            .footer = "A wrong key still produces an image, but it will look like noise.",
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
    if (key_sources != 1) {
        fatal("provide exactly one of --key, --key-file, --key-hex, or --key-env", .{});
    }

    const key = if (key_text) |text| key: {
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
    errdefer {
        std.crypto.secureZero(u8, key);
        allocator.free(key);
    }

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

    // Fingerprinting both sides is what makes a round trip checkable. The
    // `noise` fingerprints of the two tools must agree, which proves the noise
    // reached `from-noise` intact; `source` and `restored` agreeing proves the
    // key was right. Neither is detectable from the image alone.
    const in_fp = cipher.fingerprint(img.rgb);
    try cipher.transform(ctx.allocator, img.rgb, img.width, img.height, args.key, direction);
    const out_fp = cipher.fingerprint(img.rgb);

    if (!image.isStandardStream(args.output)) {
        if (std.fs.path.dirname(args.output)) |dir| {
            // A missing parent directory surfaces as a clearer error from `save`.
            if (dir.len > 0) Io.Dir.cwd().createDirPath(ctx.io, dir) catch {};
        }
    }
    image.save(img, ctx.io, args.output, args.format) catch |err| {
        fatal("cannot write {s}: {t}", .{ args.output, err });
    };

    const names = labels(direction);
    try report(ctx.io,
        \\wrote {s} ({d}x{d} {s})
        \\key-id {s}
        \\{s} fingerprint {s}
        \\{s} fingerprint {s}
        \\
    , .{
        args.output,
        img.width,
        img.height,
        names.wrote,
        std.fmt.bytesToHex(cipher.keyId(args.key), .lower),
        names.input,
        std.fmt.bytesToHex(in_fp, .lower),
        names.output,
        std.fmt.bytesToHex(out_fp, .lower),
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
}

test "the two directions agree on the shared noise label" {
    // The whole verification story rests on these matching.
    try std.testing.expectEqualStrings("noise", labels(.to_noise).output);
    try std.testing.expectEqualStrings("noise", labels(.from_noise).input);
}
