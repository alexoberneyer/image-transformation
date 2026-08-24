const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const cipher = @import("cipher.zig");
const image = @import("image.zig");

pub const Direction = cipher.Direction;

const max_key_file_bytes = 1024 * 1024;

pub const Args = struct {
    allocator: Allocator,
    key: []u8,
    input: []const u8,
    output: []const u8,

    pub fn deinit(self: *Args) void {
        std.crypto.secureZero(u8, self.key);
        self.allocator.free(self.key);
        self.allocator.free(self.input);
        self.allocator.free(self.output);
        self.* = undefined;
    }
};

pub fn fatal(comptime fmt: []const u8, args: anytype) noreturn {
    std.io.getStdErr().writer().print("error: " ++ fmt ++ "\n", args) catch {};
    std.process.exit(1);
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
        \\  -o, --output <path>    Output image (default: <stem>.{[tag]s}.png)
        \\  -h, --help             Show this help
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

fn defaultOutput(allocator: Allocator, input: []const u8, direction: Direction) ![]const u8 {
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

pub fn parse(allocator: Allocator, direction: Direction) !Args {
    const argv = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, argv);

    var key_text: ?[]const u8 = null;
    var key_file: ?[]const u8 = null;
    var key_hex: ?[]const u8 = null;
    var output: ?[]const u8 = null;
    var input: ?[]const u8 = null;

    var i: usize = 1;
    while (i < argv.len) : (i += 1) {
        const arg = argv[i];
        // Every option below takes exactly one value, so grab it in one place.
        const value: ?[]const u8 = blk: {
            if (arg.len < 2 or arg[0] != '-') break :blk null;
            if (i + 1 >= argv.len) break :blk null;
            break :blk argv[i + 1];
        };

        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            try std.io.getStdOut().writeAll(usage(direction));
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
        } else if (std.mem.eql(u8, arg, "-o") or std.mem.eql(u8, arg, "--output")) {
            output = value orelse fatal("missing value for {s}", .{arg});
            i += 1;
        } else if (std.mem.startsWith(u8, arg, "-")) {
            fatal("unknown option {s}", .{arg});
        } else if (input == null) {
            input = arg;
        } else {
            fatal("unexpected argument {s}", .{arg});
        }
    }

    const in_path = input orelse fatal("missing input image\n\n{s}", .{usage(direction)});

    var key_sources: usize = 0;
    for ([_]?[]const u8{ key_text, key_file, key_hex }) |source| {
        if (source != null) key_sources += 1;
    }
    if (key_sources != 1) fatal("provide exactly one of --key, --key-file, or --key-hex", .{});

    const key = if (key_text) |text| key: {
        if (text.len == 0) fatal("key must not be empty", .{});
        break :key try allocator.dupe(u8, text);
    } else if (key_file) |path| key: {
        const bytes = std.fs.cwd().readFileAlloc(allocator, path, max_key_file_bytes) catch |err| {
            fatal("cannot read key file {s}: {s}", .{ path, @errorName(err) });
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

    return .{
        .allocator = allocator,
        .key = key,
        .input = in_owned,
        .output = if (output) |path|
            try allocator.dupe(u8, path)
        else
            try defaultOutput(allocator, in_path, direction),
    };
}

pub fn run(allocator: Allocator, direction: Direction) !void {
    var args = try parse(allocator, direction);
    defer args.deinit();

    var img = image.load(allocator, args.input) catch |err| switch (err) {
        error.FileNotFound => fatal("input not found: {s}", .{args.input}),
        error.UnsupportedImageFormat => fatal("unsupported image format (use PNG or PPM)", .{}),
        error.UnsupportedPng, error.UnsupportedPpm => fatal("unsupported image variant (need 8-bit, non-interlaced PNG or maxval-255 PPM)", .{}),
        error.InvalidPng, error.InvalidPngCrc, error.InvalidPpm => fatal("image file is corrupt", .{}),
        error.InvalidImageSize => fatal("image dimensions are out of range (limit is {d} pixels)", .{cipher.max_pixels}),
        else => return err,
    };
    defer img.deinit();

    try cipher.transform(allocator, img.rgb, img.width, img.height, args.key, direction);

    if (std.fs.path.dirname(args.output)) |dir| {
        // A missing parent directory surfaces as a clearer error from `save`.
        if (dir.len > 0) std.fs.cwd().makePath(dir) catch {};
    }
    image.save(img, args.output) catch |err| {
        fatal("cannot write {s}: {s}", .{ args.output, @errorName(err) });
    };

    // Matching fingerprints across a round trip are what tell the caller the
    // reconstruction actually succeeded, since a wrong key is not detectable.
    const id = cipher.keyId(args.key);
    const fp = cipher.fingerprint(img.rgb);

    var stdout = std.io.bufferedWriter(std.io.getStdOut().writer());
    try stdout.writer().print(
        "wrote {s} ({d}x{d} {s})\nkey-id {s}\npixel fingerprint {s}\n",
        .{
            args.output,
            img.width,
            img.height,
            switch (direction) {
                .to_noise => "noise",
                .from_noise => "restored image",
            },
            std.fmt.bytesToHex(id, .lower),
            std.fmt.bytesToHex(fp, .lower),
        },
    );
    try stdout.flush();
}

/// Shared entry point for both binaries.
pub fn main(direction: Direction) !void {
    // The debug allocator's bookkeeping is pure overhead for a handful of very
    // large, short-lived buffers, so only pay for it where it earns its keep.
    var debug_allocator = std.heap.GeneralPurposeAllocator(.{}){};
    const use_debug_allocator = builtin.mode == .Debug or builtin.mode == .ReleaseSafe;
    defer if (use_debug_allocator) {
        _ = debug_allocator.deinit();
    };
    const allocator = if (use_debug_allocator) debug_allocator.allocator() else std.heap.smp_allocator;

    run(allocator, direction) catch |err| fatal("{s}", .{@errorName(err)});
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
    };
    for (cases) |case| {
        const got = try defaultOutput(allocator, case.in, case.direction);
        defer allocator.free(got);
        try std.testing.expectEqualStrings(case.want, got);
    }
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
        try std.testing.expect(std.mem.indexOf(u8, text, "--output") != null);
    }
    try std.testing.expect(std.mem.indexOf(u8, usage(.to_noise), "<stem>.noise.png") != null);
    try std.testing.expect(std.mem.indexOf(u8, usage(.from_noise), "<stem>.restored.png") != null);
}
