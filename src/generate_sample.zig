const std = @import("std");
const image = @import("image.zig");

fn putPixel(img: image.Image, x: i32, y: i32, r: u8, g: u8, b: u8) void {
    if (x < 0 or y < 0) return;
    const ux: u32 = @intCast(x);
    const uy: u32 = @intCast(y);
    if (ux >= img.width or uy >= img.height) return;
    const i = (@as(usize, uy) * img.width + ux) * 3;
    img.rgb[i] = r;
    img.rgb[i + 1] = g;
    img.rgb[i + 2] = b;
}

fn fillRect(img: image.Image, x0: i32, y0: i32, x1: i32, y1: i32, r: u8, g: u8, b: u8) void {
    var y = y0;
    while (y <= y1) : (y += 1) {
        var x = x0;
        while (x <= x1) : (x += 1) {
            putPixel(img, x, y, r, g, b);
        }
    }
}

fn fillCircle(img: image.Image, cx: i32, cy: i32, radius: i32, r: u8, g: u8, b: u8) void {
    var y: i32 = -radius;
    while (y <= radius) : (y += 1) {
        var x: i32 = -radius;
        while (x <= radius) : (x += 1) {
            if (x * x + y * y <= radius * radius) {
                putPixel(img, cx + x, cy + y, r, g, b);
            }
        }
    }
}

fn hsv(h: f32, s: f32, v: f32) struct { r: u8, g: u8, b: u8 } {
    const c = v * s;
    const hp = @mod(h, 360.0) / 60.0;
    const x = c * (1.0 - @abs(@mod(hp, 2.0) - 1.0));
    var r: f32 = 0;
    var g: f32 = 0;
    var b: f32 = 0;
    if (hp < 1) {
        r = c;
        g = x;
    } else if (hp < 2) {
        r = x;
        g = c;
    } else if (hp < 3) {
        g = c;
        b = x;
    } else if (hp < 4) {
        g = x;
        b = c;
    } else if (hp < 5) {
        r = x;
        b = c;
    } else {
        r = c;
        b = x;
    }
    const m = v - c;
    return .{
        .r = @intFromFloat(std.math.clamp((r + m) * 255.0, 0.0, 255.0)),
        .g = @intFromFloat(std.math.clamp((g + m) * 255.0, 0.0, 255.0)),
        .b = @intFromFloat(std.math.clamp((b + m) * 255.0, 0.0, 255.0)),
    };
}

pub fn drawSample(img: image.Image) void {
    const w: i32 = @intCast(img.width);
    const h: i32 = @intCast(img.height);

    var y: i32 = 0;
    while (y < h) : (y += 1) {
        var x: i32 = 0;
        while (x < w) : (x += 1) {
            if (y < @divTrunc(h * 5, 8)) {
                const t = @as(f32, @floatFromInt(y)) / @as(f32, @floatFromInt(@divTrunc(h * 5, 8)));
                const r: u8 = @intFromFloat(40.0 + 80.0 * (1.0 - t));
                const g: u8 = @intFromFloat(90.0 + 70.0 * (1.0 - t));
                const b: u8 = @intFromFloat(170.0 + 70.0 * (1.0 - t));
                putPixel(img, x, y, r, g, b);
            } else {
                const stripe = @mod(@divTrunc(x, 8) + @divTrunc(y, 8), 2);
                if (stripe == 0) {
                    putPixel(img, x, y, 46, 140, 58);
                } else {
                    putPixel(img, x, y, 34, 110, 46);
                }
            }
        }
    }

    fillCircle(img, @divTrunc(w * 4, 5), @divTrunc(h, 5), @divTrunc(h, 9), 255, 210, 64);
    fillRect(img, @divTrunc(w, 3), @divTrunc(h * 7, 16), @divTrunc(w * 2, 3), @divTrunc(h * 13, 16), 188, 62, 52);
    fillRect(img, @divTrunc(w, 3) - 4, @divTrunc(h * 7, 16) - 28, @divTrunc(w * 2, 3) + 4, @divTrunc(h * 7, 16), 92, 48, 32);

    // Roof triangle.
    {
        const top_x = @divTrunc(w, 2);
        const top_y = @divTrunc(h * 7, 16) - 70;
        const left = @divTrunc(w, 3) - 12;
        const right = @divTrunc(w * 2, 3) + 12;
        const base = @divTrunc(h * 7, 16);
        var yy = top_y;
        while (yy <= base) : (yy += 1) {
            const t = @as(f32, @floatFromInt(yy - top_y)) / @as(f32, @floatFromInt(base - top_y));
            const x0 = top_x + @as(i32, @intFromFloat(@as(f32, @floatFromInt(left - top_x)) * t));
            const x1 = top_x + @as(i32, @intFromFloat(@as(f32, @floatFromInt(right - top_x)) * t));
            var xx = x0;
            while (xx <= x1) : (xx += 1) {
                putPixel(img, xx, yy, 120, 42, 36);
            }
        }
    }

    fillRect(img, @divTrunc(w, 2) - 14, @divTrunc(h * 10, 16), @divTrunc(w, 2) + 14, @divTrunc(h * 13, 16), 92, 50, 28);
    fillRect(img, @divTrunc(w, 3) + 18, @divTrunc(h * 8, 16), @divTrunc(w, 3) + 48, @divTrunc(h * 8, 16) + 28, 210, 230, 255);
    fillRect(img, @divTrunc(w * 2, 3) - 48, @divTrunc(h * 8, 16), @divTrunc(w * 2, 3) - 18, @divTrunc(h * 8, 16) + 28, 210, 230, 255);

    var bar: i32 = 0;
    while (bar < 8) : (bar += 1) {
        const color = hsv(@as(f32, @floatFromInt(bar)) * 45.0, 0.85, 0.95);
        const x0 = 12 + bar * 18;
        fillRect(img, x0, h - 36, x0 + 16, h - 12, color.r, color.g, color.b);
    }
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const argv = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, argv);

    const path: []const u8 = if (argv.len >= 2) argv[1] else "examples/original.png";
    if (std.fs.path.dirname(path)) |dir| {
        if (dir.len > 0) try std.fs.cwd().makePath(dir);
    }

    var img = try image.Image.init(allocator, 320, 240);
    defer img.deinit();
    drawSample(img);
    try image.save(img, path);

    const stdout = std.io.getStdOut().writer();
    try stdout.print("wrote {s} ({d}x{d})\n", .{ path, img.width, img.height });
}
