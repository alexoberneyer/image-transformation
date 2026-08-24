const std = @import("std");
const Allocator = std.mem.Allocator;
const cipher = @import("cipher.zig");
const image = @import("image.zig");

pub const Direction = cipher.Direction;

pub const Args = struct {
    allocator: Allocator,
    key: []u8,
    input: []const u8,
    output: []const u8,

    pub fn deinit(self: *Args) void {
        self.allocator.free(self.key);
        self.allocator.free(self.input);
        self.allocator.free(self.output);
        self.* = undefined;
    }
};

pub fn fatal(comptime fmt: []const u8, args: anytype) noreturn {
    const stderr = std.io.getStdErr().writer();
    stderr.print("error: " ++ fmt ++ "\n", args) catch {};
    std.process.exit(1);
}

fn usage(direction: Direction) []const u8 {
    return switch (direction) {
        .to_noise =>
        \\Usage: to-noise [options] <input-image>
        \\
        \\Transform an image into deterministic keyed noise. The inverse
        \\(`from-noise` with the same key) restores the original pixels.
        \\
        \\Options:
        \\  -k, --key <text>       Passphrase used as the transformation key
        \\      --key-file <path>  Read the key from a file (raw bytes)
        \\      --key-hex <hex>    64 hex digits used as a 32-byte master key
        \\  -o, --output <path>    Output image (default: <stem>.noise.png)
        \\  -h, --help             Show this help
        \\
        \\Supported formats: PNG (8-bit gray/RGB/RGBA) and binary PPM (P5/P6).
        \\Keep the noise image lossless; JPEG will destroy the hidden data.
        \\
        ,
        .from_noise =>
        \\Usage: from-noise [options] <noise-image>
        \\
        \\Apply the inverse transformation and reconstruct the original image.
        \\The key must match the one used with `to-noise`.
        \\
        \\Options:
        \\  -k, --key <text>       Passphrase used as the transformation key
        \\      --key-file <path>  Read the key from a file (raw bytes)
        \\      --key-hex <hex>    64 hex digits used as a 32-byte master key
        \\  -o, --output <path>    Output image (default: <stem>.restored.png)
        \\  -h, --help             Show this help
        \\
        \\A wrong key still produces an image, but it will look like noise.
        \\
        ,
    };
}

fn defaultOutput(allocator: Allocator, input: []const u8, direction: Direction) ![]const u8 {
    const ext = imageExt(input);
    const stem = stemWithoutExt(input);
    return switch (direction) {
        .to_noise => try std.fmt.allocPrint(allocator, "{s}.noise{s}", .{ stem, ext }),
        .from_noise => blk: {
            if (std.ascii.endsWithIgnoreCase(stem, ".noise")) {
                break :blk try std.fmt.allocPrint(allocator, "{s}.restored{s}", .{ stem[0 .. stem.len - 6], ext });
            }
            break :blk try std.fmt.allocPrint(allocator, "{s}.restored{s}", .{ stem, ext });
        },
    };
}

fn imageExt(path: []const u8) []const u8 {
    if (std.ascii.endsWithIgnoreCase(path, ".ppm")) return ".ppm";
    if (std.ascii.endsWithIgnoreCase(path, ".pnm")) return ".pnm";
    if (std.ascii.endsWithIgnoreCase(path, ".p6")) return ".p6";
    if (std.ascii.endsWithIgnoreCase(path, ".png")) return ".png";
    return ".png";
}

fn stemWithoutExt(path: []const u8) []const u8 {
    const slash = std.mem.lastIndexOfAny(u8, path, "/\\") orelse 0;
    const start = if (slash == 0 and (path.len == 0 or (path[0] != '/' and path[0] != '\\'))) 0 else slash + 1;
    const base = path[start..];
    if (std.ascii.endsWithIgnoreCase(base, ".ppm") or
        std.ascii.endsWithIgnoreCase(base, ".pnm") or
        std.ascii.endsWithIgnoreCase(base, ".p6") or
        std.ascii.endsWithIgnoreCase(base, ".png"))
    {
        const dot = std.mem.lastIndexOfScalar(u8, base, '.') orelse return path[0 .. start + base.len];
        return path[0 .. start + dot];
    }
    return path[0 .. start + base.len];
}

fn parseHexKey(allocator: Allocator, hex: []const u8) ![]u8 {
    var trimmed = hex;
    if (std.mem.startsWith(u8, trimmed, "0x") or std.mem.startsWith(u8, trimmed, "0X")) {
        trimmed = trimmed[2..];
    }
    if (trimmed.len != 64) return error.InvalidHexKey;
    var raw: [32]u8 = undefined;
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
    var show_help = false;

    var i: usize = 1;
    while (i < argv.len) : (i += 1) {
        const arg = argv[i];
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            show_help = true;
        } else if (std.mem.eql(u8, arg, "-k") or std.mem.eql(u8, arg, "--key")) {
            i += 1;
            if (i >= argv.len) fatal("missing value for {s}", .{arg});
            key_text = argv[i];
        } else if (std.mem.eql(u8, arg, "--key-file")) {
            i += 1;
            if (i >= argv.len) fatal("missing value for {s}", .{arg});
            key_file = argv[i];
        } else if (std.mem.eql(u8, arg, "--key-hex")) {
            i += 1;
            if (i >= argv.len) fatal("missing value for {s}", .{arg});
            key_hex = argv[i];
        } else if (std.mem.eql(u8, arg, "-o") or std.mem.eql(u8, arg, "--output")) {
            i += 1;
            if (i >= argv.len) fatal("missing value for {s}", .{arg});
            output = argv[i];
        } else if (std.mem.startsWith(u8, arg, "-")) {
            fatal("unknown option {s}", .{arg});
        } else if (input == null) {
            input = arg;
        } else {
            fatal("unexpected argument {s}", .{arg});
        }
    }

    if (show_help) {
        const stdout = std.io.getStdOut().writer();
        try stdout.writeAll(usage(direction));
        std.process.exit(0);
    }

    const in_path = input orelse fatal("missing input image\n\n{s}", .{usage(direction)});

    var key_sources: usize = 0;
    if (key_text != null) key_sources += 1;
    if (key_file != null) key_sources += 1;
    if (key_hex != null) key_sources += 1;
    if (key_sources != 1) {
        fatal("provide exactly one of --key, --key-file, or --key-hex", .{});
    }

    const key = if (key_text) |text| blk: {
        if (text.len == 0) fatal("key must not be empty", .{});
        break :blk try allocator.dupe(u8, text);
    } else if (key_file) |path| blk: {
        const bytes = std.fs.cwd().readFileAlloc(allocator, path, 1024 * 1024) catch |err| {
            fatal("cannot read key file {s}: {s}", .{ path, @errorName(err) });
        };
        if (bytes.len == 0) {
            allocator.free(bytes);
            fatal("key file {s} is empty", .{path});
        }
        break :blk bytes;
    } else blk: {
        break :blk parseHexKey(allocator, key_hex.?) catch fatal("key-hex must be 64 hexadecimal digits", .{});
    };

    const out_path = if (output) |path|
        try allocator.dupe(u8, path)
    else
        try defaultOutput(allocator, in_path, direction);

    return .{
        .allocator = allocator,
        .key = key,
        .input = try allocator.dupe(u8, in_path),
        .output = out_path,
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
        else => return err,
    };
    defer img.deinit();

    try cipher.transform(allocator, img.rgb, img.width, img.height, args.key, direction);

    if (std.fs.path.dirname(args.output)) |dir| {
        if (dir.len > 0) {
            std.fs.cwd().makePath(dir) catch {};
        }
    }
    image.save(img, args.output) catch |err| {
        fatal("cannot write {s}: {s}", .{ args.output, @errorName(err) });
    };

    const id = cipher.keyId(args.key);
    const fp = cipher.fingerprint(img.rgb);
    var id_hex: [16]u8 = undefined;
    var fp_hex: [32]u8 = undefined;
    const verb: []const u8 = switch (direction) {
        .to_noise => "noise",
        .from_noise => "restored image",
    };

    const stdout = std.io.getStdOut().writer();
    try stdout.print(
        "wrote {s} ({d}x{d} {s})\nkey-id {s}\npixel fingerprint {s}\n",
        .{
            args.output,
            img.width,
            img.height,
            verb,
            cipher.hexEncode(&id, &id_hex),
            cipher.hexEncode(&fp, &fp_hex),
        },
    );
}
