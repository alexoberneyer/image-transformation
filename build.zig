const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const to_noise = b.addExecutable(.{
        .name = "to-noise",
        .root_source_file = b.path("src/to_noise.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.installArtifact(to_noise);

    const from_noise = b.addExecutable(.{
        .name = "from-noise",
        .root_source_file = b.path("src/from_noise.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.installArtifact(from_noise);

    const generate_sample = b.addExecutable(.{
        .name = "generate-sample",
        .root_source_file = b.path("src/generate_sample.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.installArtifact(generate_sample);

    const run_to_noise = b.addRunArtifact(to_noise);
    run_to_noise.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_to_noise.addArgs(args);
    b.step("to-noise", "Transform an image into keyed noise").dependOn(&run_to_noise.step);

    const run_from_noise = b.addRunArtifact(from_noise);
    run_from_noise.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_from_noise.addArgs(args);
    b.step("from-noise", "Reconstruct an image from keyed noise").dependOn(&run_from_noise.step);

    const run_sample = b.addRunArtifact(generate_sample);
    run_sample.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_sample.addArgs(args);
    b.step("sample", "Write a colorful sample image").dependOn(&run_sample.step);

    const unit_tests = b.addTest(.{
        .root_source_file = b.path("src/tests.zig"),
        .target = target,
        .optimize = optimize,
    });
    const run_tests = b.addRunArtifact(unit_tests);
    b.step("test", "Run unit tests").dependOn(&run_tests.step);
}
