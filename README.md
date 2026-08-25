# image-transformation

Keyed, lossless **image → noise → image** transforms in Zig.

`to-noise` turns any PNG or PPM into a noise image using a secret key.
`from-noise` applies the matching inverse transform and reconstructs the original pixels, byte for byte, when given that same key.

A wrong key still produces an image, but it looks like noise.

## Requirements

- [Zig 0.16.x](https://ziglang.org/download/)

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

### Pipes

A path of `-` reads stdin or writes stdout, so a whole round trip can happen
without an image ever reaching the filesystem - which matters for a tool whose
input is the secret:

```bash
cat photo.png | to-noise --key "s3cret" - -o - | from-noise --key "s3cret" - -o - > restored.png
```

`--format png|ppm` picks the container when the output is a stream and has no
extension to read it from. Progress and fingerprints always go to stderr, so
the pipe stays clean.

### Keys

Provide **exactly one** of:

| Option | Meaning |
| --- | --- |
| `-k`, `--key <text>` | Passphrase. Any length. Fed through BLAKE3-KDF. |
| `--key-file <path>` | Raw key bytes from a file — the *exact* bytes, so a trailing newline is part of the key. |
| `--key-hex <hex>` | 64 hex digits (32-byte master key), with or without a `0x` prefix. |
| `--key-env <name>` | Read the passphrase from an environment variable. |

Prefer `--key-env` for anything scripted. A key passed as `--key` sits in the
process's argv, where any other process on the machine can read it out of `ps`,
and a `--key-file` leaves the key on disk. The environment is the one channel
that avoids both:

```bash
export IMAGE_NOISE_KEY=$(security find-generic-password -w -s image-noise)
to-noise --key-env IMAGE_NOISE_KEY photo.png
```

### Verifying a round trip

The transform is not authenticated: a wrong key produces an image rather than
an error, and a mangled noise file is indistinguishable from a wrong key. The
fingerprints are what tell the two apart. Each run reports a non-secret
`key-id` plus a fingerprint of the pixels going in and coming out:

```
$ to-noise --key "s3cret" photo.png -o noise.png
wrote noise.png (320x240 noise)
key-id 56b5b2bbfdf8a28c
source fingerprint f32c46cd062680ceafd1d5ee95d86181
noise fingerprint 1cbcf26c5e4304a9415cf706a650fd96

$ from-noise --key "s3cret" noise.png -o restored.png
wrote restored.png (320x240 restored image)
key-id 56b5b2bbfdf8a28c
noise fingerprint 1cbcf26c5e4304a9415cf706a650fd96
restored fingerprint f32c46cd062680ceafd1d5ee95d86181
```

Two independent checks fall out of that:

- The **`noise` fingerprints agree**, so the noise reached `from-noise` byte for
  byte. If they differ, whatever carried the file re-encoded it.
- **`restored` matches the original `source`**, so the key was right. If the
  `noise` lines agree but this one does not, the file is fine and the key is
  wrong.

### Formats

- **PNG** 8-bit grayscale, gray+alpha, RGB, or RGBA, non-interlaced
- **PPM** binary `P6` (RGB) and `P5` (grayscale), maxval 255

Alpha is dropped on load. Output is always opaque RGB. Images are capped at 64 megapixels.

Keep the noise file lossless. JPEG (or any other lossy export) will make reconstruction impossible.

The PNG writer probes the payload and picks between deflate and stored blocks. Noise does not compress, so `to-noise` skips a pointless deflate pass; `from-noise` output is a real image again and gets compressed normally. Either way the result is an ordinary PNG.

## Clipboard (macOS)

`scripts/clip-to-noise` and `scripts/clip-from-noise` wrap the tools around the
pasteboard, so a screenshot can become noise and come back without a filename
in sight. They build what they need on first run.

```bash
# copy an image, then:
scripts/clip-to-noise           # clipboard now holds the noise
scripts/clip-from-noise         # ...and now the original again
```

The key comes from `$IMAGE_NOISE_KEY`, or the login keychain, or - with neither
configured - a random one minted for that image alone. To use one passphrase
across everything instead, set it up once:

```bash
security add-generic-password -s image-noise -a "$USER" -w
```

Two details in there are not incidental:

**`clip-to-noise` leaves a file *reference* on the clipboard, not a bitmap.**
Pasting a reference into a chat or a document attaches the PNG untouched;
pasting a bitmap lets the receiving app re-encode it, and a re-encoded noise
image cannot be inverted. `--bitmap` opts into the inline paste when that is
genuinely what you want, and skips the disk entirely.

**Only the `to-noise` side normalizes.** Clipboard images arrive as 16-bit, or
with an alpha channel, or with a colour profile attached - shapes the transform
rejects. Forcing them to 8-bit RGB is harmless going in, because whatever pixels
come out of it are simply what gets encrypted. Doing the same on the way back
would colour-manage the noise and destroy the exact bytes the inverse depends
on, so `clip-from-noise` passes them through untouched.

The pasteboard itself is lossless as long as a lossless flavour is pinned, which
the helper does. It advertises several at once - a single copy can offer PNG,
TIFF, JPEG, GIF and AVIF - and asking for the wrong one silently destroys the
payload.

### Random keys

With nothing configured, `clip-to-noise` does not ask for a passphrase. It draws
32 bytes from the system CSPRNG, uses them for that one image, and hands the key
back afterwards:

```
$ scripts/clip-to-noise
wrote /tmp/image-noise/noise-20260825-095938-b36bda7681dcf4ca.png (320x240 noise)
key-id b36bda7681dcf4ca
source fingerprint f32c46cd062680ceafd1d5ee95d86181
noise fingerprint f4fa663906bbec051cd179d720f27cb2
clipboard now holds a reference to /tmp/image-noise/noise-20260825-095938-b36bda7681dcf4ca.png

no key was configured, so this image got a random one:

  84481026f385a9d16bb59ca330f3370ef28bbba5b40bbc170d8d5312fd086854

Saved to the keychain, and the noise filename carries the key-id, so
clip-from-noise will find it again on its own. Copy the key above to
send this image to anyone else - they cannot read your keychain.
```

That is a strictly stronger secret than a passphrase - a full 256 bits, never
reused across images - at the cost of having to keep it. Two things make that
survivable.

**The key-id names the key.** `to-noise` already prints a `key-id`, a public
digest of the key that identifies it without revealing it. The minted key goes
into the keychain filed under that id, and the id goes into the noise filename.
`clip-from-noise` reads it back off the file reference on the clipboard and
finds the right key on its own, however many images have their own key:

```bash
scripts/clip-to-noise      # mints a key, prints it, files it under its key-id
scripts/clip-from-noise    # reads the id off the filename, restores
```

**The printed key is the copy you can send.** Nobody else can read your
keychain, so a recipient needs the hex:

```bash
IMAGE_NOISE_KEY=84481026... scripts/clip-from-noise
```

The lookup needs a filename to read the id from, so it does not apply to
`--bitmap`, to a path you chose yourself with `-o`, or to a file that has been
renamed. Those still work - they just need the key handed back explicitly. The
key is printed to stderr either way, so it lands in terminal scrollback; treat
that the way you would treat any other secret on screen.

## Raycast (macOS)

`scripts/raycast/` holds two Raycast script commands wrapping the clipboard
scripts, so the round trip runs from a hotkey instead of a terminal:

| Command | Wraps |
| --- | --- |
| **Image to Noise** | `clip-to-noise` |
| **Image from Noise** | `clip-from-noise` |

Build once first, so the first press of the hotkey is not a compile:

```bash
zig build -Doptimize=ReleaseFast
```

Then point Raycast at the folder: **Settings → Extensions → Script Commands →
Add Script Directory**, and pick `scripts/raycast`. Both commands appear under
the *Image Noise* package, searchable by title, and a hotkey can be bound to
each from the same screen.

Nothing else needs configuring. The keychain entry these scripts write is
created by `/usr/bin/security` and read back by that same binary, which macOS
trusts automatically, so a key resolves inside a Raycast-launched script without
an authorization dialog in the way.

Three things about the wrappers are deliberate.

**They run in `fullOutput` mode.** The interesting output is never the last
line. Going out, a minted key is printed once and is the only copy a recipient
can be handed; coming back, the fingerprints are the only thing separating a
wrong key from a file that was re-encoded in transit. `compact` shows one line
and would hide both.

**They fold stderr into stdout.** The clipboard scripts report on stderr to keep
their pipes clean, and Raycast displays stdout.

**They put Homebrew back on `$PATH`.** Raycast runs script commands in a
non-interactive shell that reads no profile, so the PATH is bare and `zig` -
which `require_tools` falls back to - is not on it. `swiftc` already lives in
`/usr/bin` and needs no help.

`--bitmap` is deliberately not reachable from here. Inlining a bitmap lets the
next app re-encode the noise, and a single keystroke is too short a path to an
image nobody can invert.

One consequence of the hotkey worth knowing: what lands on the clipboard is a
reference to a file under `$TMPDIR`, which macOS reaps on its own schedule.
Pasting shortly afterwards is fine and uploads the bytes; coming back to
re-paste that same reference next week is not.

### Handing an image to someone else

**Image from Noise** takes an optional key, masked as it is typed. Left empty it
behaves as it always did and resolves the key from the keychain. Filled in, it is
the only way anyone who did not make the image can restore it: their keychain
holds nothing under its key-id, and there is no tty here for `prompt_key` to fall
back to. It covers a file that arrived renamed, too, with the key-id no longer in
the name to read.

Send the noise file and the hex key `clip-to-noise` printed, by different routes
if the image is worth that much. Two things the recipient needs to know.

**Copy the file, not the picture.** Select it in Finder and press ⌘C. Opening the
PNG and copying the image puts a bitmap on the pasteboard instead, which the next
app is free to re-encode, and re-encoded noise cannot be inverted. No key fixes
that afterwards.

**The key-id is their version of the fingerprint check.** They never saw the
original, so a `restored` fingerprint tells them nothing. The `key-id` line does:
it is a public digest of the key they just typed, and while the file still
carries its own id in the name, the two match only when the key is the one the
image was made with.

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

| | time | peak RSS |
| --- | --- | --- |
| `to-noise` PPM to PPM | 80 ms | 59 MB |
| `to-noise` PPM to PNG | 110 ms | 77 MB |
| `from-noise` PNG to PNG | 150 ms | 80 MB |
| `from-noise` PNG to PPM | 110 ms | 76 MB |

## Tests

```bash
zig build test
```

The suite also runs under an optimizing build, which is worth doing since the hot paths use prefetching and unchecked scanline loops:

```bash
zig build test -Doptimize=ReleaseFast
```
