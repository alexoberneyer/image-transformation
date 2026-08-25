const std = @import("std");

const Tool = struct {
    name: []const u8,
    source: []const u8,
    /// Name and description of the `zig build <step>` shortcut that runs it.
    step: []const u8,
    description: []const u8,
};

const tools = [_]Tool{
    .{
        .name = "to-noise",
        .source = "src/to_noise.zig",
        .step = "to-noise",
        .description = "Transform an image into keyed noise",
    },
    .{
        .name = "from-noise",
        .source = "src/from_noise.zig",
        .step = "from-noise",
        .description = "Reconstruct an image from keyed noise",
    },
    .{
        .name = "generate-sample",
        .source = "src/generate_sample.zig",
        .step = "sample",
        .description = "Write a colorful sample image",
    },
};

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    for (tools) |tool| {
        const exe = b.addExecutable(.{
            .name = tool.name,
            .root_module = b.createModule(.{
                .root_source_file = b.path(tool.source),
                .target = target,
                .optimize = optimize,
            }),
        });
        b.installArtifact(exe);

        const run = b.addRunArtifact(exe);
        run.step.dependOn(b.getInstallStep());
        if (b.args) |args| run.addArgs(args);
        b.step(tool.step, tool.description).dependOn(&run.step);
    }

    // The unit tests cover optimizer-sensitive code (prefetching, unchecked
    // scanline loops), so run them in the selected mode rather than only in
    // Debug: `zig build test -Doptimize=ReleaseFast` is a meaningful check.
    const unit_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/tests.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    b.step("test", "Run unit tests").dependOn(&b.addRunArtifact(unit_tests).step);
}
