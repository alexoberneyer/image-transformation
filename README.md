# image-transformation

Keyed, lossless **image → noise → image** transforms in Zig.

`to-noise` turns any PNG or PPM into a noise image using a secret key.
`from-noise` applies the matching inverse transform and reconstructs the original pixels, byte for byte, when given that same key.

A wrong key still produces an image, but it looks like noise.

## Requirements

- [Zig 0.14.x](https://ziglang.org/download/)

## Build

```bash
zig build
```

Binaries land in `zig-out/bin/`:

- `to-noise`
- `from-noise`
- `generate-sample`

Release mode is faster for large pictures:

```bash
zig build -Doptimize=ReleaseFast
```

## Usage

```bash
# 1. Create a sample picture (optional)
zig build sample -- examples/original.png

# 2. Turn it into keyed noise
zig-out/bin/to-noise --key "correct horse battery staple" examples/original.png -o examples/noise.png

# 3. Reconstruct the original with the same key
zig-out/bin/from-noise --key "correct horse battery staple" examples/noise.png -o examples/restored.png
```

You can also run the scripts directly:

```bash
zig run src/to_noise.zig -- --key "my-secret" photo.png -o noise.png
zig run src/from_noise.zig -- --key "my-secret" noise.png -o restored.png
```

### Keys

Provide **exactly one** of:

| Option | Meaning |
| --- | --- |
| `-k`, `--key <text>` | Passphrase. Any length. Fed through BLAKE3-KDF. |
| `--key-file <path>` | Raw key bytes from a file. |
| `--key-hex <hex>` | 64 hex digits (32-byte master key). |

Each run prints a `key-id` (a non-secret fingerprint of the key) and a `pixel fingerprint` of the output. Matching fingerprints after a round-trip means reconstruction succeeded.

### Formats

- **PNG** 8-bit grayscale, gray+alpha, RGB, or RGBA, non-interlaced
- **PPM** binary `P6` (RGB) and `P5` (grayscale), maxval 255

Alpha is dropped on load. Output is always opaque RGB.

Keep the noise file lossless. JPEG (or any other lossy export) will make reconstruction impossible.

## How the transform works

The key never travels with the image. Both directions re-derive the same material from the passphrase plus the image width and height.

```
passphrase
    │
    ▼
BLAKE3-KDF  ──► master key
    │
    ├── permute seed  ──► ChaCha8 CSPRNG  ──► Fisher–Yates pixel permutation
    └── diffuse key + nonce  ──► ChaCha20  ──► XOR of every RGB byte
```

**Forward (`to-noise`)**

1. Shuffle pixels with a keyed permutation.
2. XOR the packed RGB buffer with a ChaCha20 keystream.

**Inverse (`from-noise`)**

1. XOR with the same keystream (XOR is its own inverse).
2. Apply the inverse permutation.

Without the key, both the pixel order and the color values are computationally infeasible to recover. This is a reversible visual cipher, not authenticated encryption: it does not detect a wrong key or a tampered file, it just fails to look like the original.

## Tests

```bash
zig build test
```
