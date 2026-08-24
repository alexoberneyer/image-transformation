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
| `--key-file <path>` | Raw key bytes from a file — the *exact* bytes, so a trailing newline is part of the key. |
| `--key-hex <hex>` | 64 hex digits (32-byte master key), with or without a `0x` prefix. |

Each run prints a `key-id` (a non-secret fingerprint of the key) and a `pixel fingerprint` of the output. Matching fingerprints after a round-trip means reconstruction succeeded.

### Formats

- **PNG** 8-bit grayscale, gray+alpha, RGB, or RGBA, non-interlaced
- **PPM** binary `P6` (RGB) and `P5` (grayscale), maxval 255

Alpha is dropped on load. Output is always opaque RGB. Images are capped at 64 megapixels.

Keep the noise file lossless. JPEG (or any other lossy export) will make reconstruction impossible.

The PNG writer probes the payload and picks between deflate and stored blocks. Noise does not compress, so `to-noise` skips a pointless deflate pass; `from-noise` output is a real image again and gets compressed normally. Either way the result is an ordinary PNG.

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

### Format stability

The byte stream is a contract: a noise image is only useful if a later build can still invert it. `cipher.zig` carries a known-answer test that pins the key schedule, the pixel permutation and the keystream, so any change to them fails the test suite instead of quietly stranding existing noise images.

## Performance

Building the keyed permutation is the bulk of the work, and it is bound by cache misses rather than arithmetic: the index array is much larger than the cache and Fisher-Yates touches it at random. Because the random draws depend only on the RNG and never on the array, a batch of them is taken up front and the slots they will touch are prefetched together. The permutation that comes out is bit-for-bit the one a naive loop produces.

The PNG writer probes the payload rather than always deflating, which matters because noise is exactly the input deflate cannot help with.

A 3000x2000 image, `-Doptimize=ReleaseFast`, best of three:

| | before | after | peak RSS |
| --- | --- | --- | --- |
| `to-noise` PPM to PPM | 1208 ms | **292 ms** | 80 -> 57 MB |
| `to-noise` PPM to PNG | 1773 ms | **385 ms** | 80 -> 69 MB |
| `from-noise` PNG to PNG | 1142 ms | **466 ms** | 86 -> 69 MB |
| `from-noise` PNG to PPM | 1126 ms | **399 ms** | 86 -> 69 MB |

## Tests

```bash
zig build test
```

The suite also runs under an optimizing build, which is worth doing since the hot paths use prefetching and unchecked scanline loops:

```bash
zig build test -Doptimize=ReleaseFast
```
