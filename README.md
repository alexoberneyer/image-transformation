# image-transformation

Keyed, lossless **image → noise → image** transforms in Zig.

`to-noise` turns any PNG or PPM into a noise image using a secret key.
`from-noise` applies the matching inverse transform and reconstructs the original pixels, byte for byte, when given that same key.

Every noise image carries its own random salt and an authentication tag, so a
wrong key - or a file altered anywhere along the way - is refused outright
rather than restored into something that merely looks wrong.

Images can be sealed to an `ssh-ed25519` public key instead of a shared
passphrase, so sending one to somebody costs them nothing to set up.

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
| `-k`, `--key <text>` | Passphrase. Any length. Stretched with Argon2id. |
| `--key-file <path>` | Raw key bytes from a file — the *exact* bytes, so a trailing newline is part of the key. |
| `--key-hex <hex>` | 64 hex digits used as the 32-byte master key directly, with or without a `0x` prefix. |
| `--key-env <name>` | Read the passphrase from an environment variable. |

Or none of them - see [Sending to someone else's key](#sending-to-someone-elses-key).

Prefer `--key-env` for anything scripted. A key passed as `--key` sits in the
process's argv, where any other process on the machine can read it out of `ps`,
and a `--key-file` leaves the key on disk. The environment is the one channel
that avoids both:

```bash
export IMAGE_NOISE_KEY=$(security find-generic-password -w -s image-noise)
to-noise --key-env IMAGE_NOISE_KEY photo.png
```

Everything except `--key-hex` is treated as a passphrase and stretched with
Argon2id (19 MiB, two passes) before it becomes a master key. That costs about
20 ms per run and is the only thing standing between a memorable passphrase and
a GPU that would otherwise test billions of guesses a second. `--key-hex` skips
the stretching, because 32 random bytes have nothing left to guess. Which one an
image was made with is recorded in the image, so the inverse does not have to be
told again.

### Sending to someone else's key

A shared passphrase has to reach the other person somehow, and that is the part
with no good answer. The alternative is to seal the image to a public key, which
they can hand out in the clear:

```bash
# they send you this once - it is already on their machine
cat ~/.ssh/id_ed25519.pub

# you seal to it
to-noise --recipient friend.pub scan.png -o noise.png

# they open it
from-noise --identity ~/.ssh/id_ed25519 noise.png -o scan.png
```

`--recipient` takes either the key itself or a path to a file of them, because
both are what actually happens - one gets pasted, the other gets saved. An
`authorized_keys` works: lines that are not `ssh-ed25519` are skipped rather than
refused. Repeat the flag to seal to several people, up to 32:

```bash
to-noise -r alice.pub -r bob.pub -r ~/team-keys.txt scan.png
```

Each recipient gets their own sealed copy of the key, and no stanza says who it
belongs to - opening one is a trial decryption, so the image does not carry a
list of who can read it. `--identity` can be repeated too, and each is tried in
turn.

**Only `ssh-ed25519`.** RSA would need OAEP, which Zig's standard library keeps
inside its certificate machinery rather than exposing for encryption, and ECDSA
keys cannot do this at all - the same two exclusions age settles on. If a friend
sends anything else, ask for `ssh-keygen -t ed25519`.

**A passphrase-protected private key needs its passphrase in the environment.**
There is no prompt here, deliberately: the clipboard scripts already own that
job, and Raycast has no terminal to ask on.

```bash
IDENTITY_PASSPHRASE=... from-noise -i ~/.ssh/id_ed25519 \
    --identity-passphrase-env IDENTITY_PASSPHRASE noise.png
```

Ed25519 signing keys live on the Edwards curve and encryption wants Montgomery,
so both halves are converted with the standard birational map. Using one key to
both log in and decrypt is a mild abuse of key separation; it is also what makes
this cost your friends nothing, and it is what age does too.

### Verifying a round trip

The authentication tag does this for you: `from-noise` verifies it over the
whole file before the key touches a single pixel, so a wrong key and a modified
file both stop at the same gate and neither produces an image. The fingerprints
are still printed, now as something to read rather than something to rely on -
a non-secret `key-id` plus a fingerprint of the pixels going in and coming out:

```
$ to-noise --key "s3cret" photo.png -o noise.png
wrote noise.png (320x241 noise)
key-id 56b5b2bbfdf8a28c
source fingerprint f32c46cd062680ceafd1d5ee95d86181
noise fingerprint 1cbcf26c5e4304a9415cf706a650fd96

$ from-noise --key "s3cret" noise.png -o restored.png
wrote restored.png (320x240 restored image)
key-id 56b5b2bbfdf8a28c
noise fingerprint 1cbcf26c5e4304a9415cf706a650fd96
restored fingerprint f32c46cd062680ceafd1d5ee95d86181
```

The noise is one row taller than the picture: that row carries the salt and the
tag. `from-noise` strips it again, so what comes back has the original
dimensions.

If verification fails there is nothing to compare, because nothing is written:

```
$ from-noise --key "wrong" noise.png -o restored.png
error: authentication failed: the key is wrong, or this file is not the one that was written
(key-id f40ada885a612076 for the key given)
```

That one message covers both failures on purpose - the tag cannot tell a wrong
key from a wrong file, and neither can you. What separates them in practice is
whether the recipient's `key-id` matches the one in the sender's output.

### Formats

- **PNG** 8-bit grayscale, gray+alpha, RGB, or RGBA, non-interlaced
- **PPM** binary `P6` (RGB) and `P5` (grayscale), maxval 255

Alpha is dropped on load. Output is always opaque RGB. Images are capped at 64 megapixels.

A noise image is a few rows taller than the picture it came from - one row for
anything at least 21 pixels wide, more for a narrow column. Those rows hold the
salt and the tag. They live in the pixels rather than in a PNG metadata chunk
because pixels are the one thing every carrier of a lossless image preserves; a
text chunk would be stripped by the first tool that touched the file while
leaving the picture intact, which is a new way to lose data that looks like
nothing went wrong. PPM has nowhere to put one at all.

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

`clip-from-noise -i <path>` reads the noise from a file instead of the
clipboard, for when the clipboard is needed for something else. Same bytes off
the same disk; only the route differs.

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
wrote /tmp/image-noise/noise-20260825-095938-b36bda7681dcf4ca.png (320x241 noise)
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
wrong key from a file that could not be opened at all. `compact` shows one line
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
back to.

A key worth having is too long to type, so it arrives by being pasted - and that
replaces whatever was on the clipboard, which cannot then also hold the noise.
So the recipient does not put the image on the clipboard at all:

1. Save the noise file and **select it in Finder**. No need to copy it.
2. Copy the key.
3. Run **Image from Noise** and paste the key into the argument.

The first run asks macOS for permission to read the Finder selection, once. If
it is declined, the command says so and falls back to reading the clipboard,
which still works for anyone who copied the file and has the key somewhere it
need not be pasted. To restore a declined prompt: System Settings > Privacy &
Security > Automation > Raycast > Finder.

Taking the file this way also retires the sharpest edge in the whole workflow.
A file that is never copied cannot arrive as a bitmap, and a bitmap is what the
next app is free to re-encode - which no key can undo afterwards. On the
clipboard fallback the old rule still holds: copy the file in Finder with ⌘C,
never the picture out of an opened PNG.

**A wrong key fails loudly.** They never saw the original, so a `restored`
fingerprint would tell them nothing - but the tag does not need them to know
anything. A key that is not the one the image was made with produces an error and
no file, so there is no wrong image to mistake for a right one.

## How the transform works

The key never travels with the image. The salt does, in the header rows, and both directions re-derive the same material from the key plus that salt plus the picture's dimensions.

```
passphrase           32 random bytes        sealed to a public key
    │                  (--key-hex)            (--recipient)
    ▼                       │                       │
Argon2id                    │            random master, X25519-wrapped
(19 MiB, t=2)               │              into the header, one copy
    │                       │                   per recipient
    └───────────────► master key ◄──────────────────┘
                          │
              + per-image salt + dimensions
                          │
                     BLAKE3-KDF
                          │
    ├── permute seed  ──► ChaCha8 CSPRNG ──► Fisher–Yates pixel permutation
    ├── diffuse key + nonce  ──► ChaCha20 ──► XOR of every RGB byte
    └── mac key  ──► keyed BLAKE3 ──► tag over the whole noise image
```

**Forward (`to-noise`)**

0. In recipient mode, draw a random master key and seal a copy of it to each
   recipient with an ephemeral Diffie-Hellman. Everything below is unchanged by
   that: the master is a master however it was reached.
1. Draw a fresh 16-byte salt and derive the schedule from it.
2. Shuffle pixels with a keyed permutation.
3. XOR the packed RGB buffer with a ChaCha20 keystream.
4. Tag the result - header, salt, dimensions, padding and ciphertext - with keyed BLAKE3.

**Inverse (`from-noise`)**

1. Read the salt out of the header and derive the same schedule.
2. Recompute the tag and compare in constant time. Stop here if it does not match.
3. XOR with the same keystream (XOR is its own inverse).
4. Apply the inverse permutation.

The salt is what makes this safe to use more than once with one key. Without it the schedule depended on the passphrase and the dimensions alone, so two pictures of the same size under the same key shared a keystream exactly: `C1 xor C2` cancelled it and left a permutation of `A xor B`, which for two scans of the same form is close to handing over both. Encrypt-then-MAC is what makes a wrong key an error instead of a plausible-looking wrong image, and what stops a ChaCha20 keystream - malleable by construction - from letting someone flip chosen bits in the picture that comes back.

The permutation is not what provides secrecy; ChaCha20 is. It is what makes the output look like an image rather than static, and it stays because that is the point of the tool.

### Format stability

The byte stream is a contract: a noise image is only useful if a later build can still invert it. `cipher.zig` carries known-answer tests that pin the key schedule, the pixel permutation and the keystream, so any change to them fails the test suite instead of quietly stranding existing noise images.

There are two formats. **v2** is what `to-noise` writes: header rows, a salt and a tag. **v1** is everything written before those existed - no header, no salt, no authentication.

Sealing to recipients did not move the version. It adds a key-derivation id and a count byte followed by one 80-byte stanza each, all of it after the tag field and so covered by the tag. A build too old to know that id refuses the image on the id alone, which is the error it should give anyway, and bumping the version would have stranded passphrase images that did not change at all. `from-noise` recognises a v1 image by the absence of the magic at the start of the pixels, opens it with the old unstretched key schedule, and says so:

```
warning: this is a v1 noise image - no salt, no authentication.
```

Nothing writes v1 any more. Re-encrypting an old image with this build is the fix, and worth doing for anything that matters.

## What this protects, and what it does not

Closed by the current format:

- **A key used on more than one image.** Every image draws its own 16-byte salt,
  so no two share a keystream. Before, the schedule came from the passphrase and
  the dimensions alone, and two scans of one form under one key leaked the
  difference between them.
- **Cheap guessing of a passphrase.** Argon2id costs 19 MiB and two passes per
  candidate. The old single BLAKE3 pass cost a few hundred nanoseconds, and the
  `key-id` printed in every filename was a free offline oracle for testing
  guesses against.
- **Silent modification.** ChaCha20 is malleable by construction: a flipped bit
  in the noise used to become a flipped bit in the restored picture, with
  nothing to notice it. The tag is checked before the key touches the pixels.

Still true, and worth knowing before trusting it with anything that matters:

- **The Argon2id salt is fixed, not per-image.** It has to be, for `key-id` to
  stay a stable name for a key across every image made with it - which is what
  the clipboard scripts use to find it in the keychain again. The cost is that
  one precomputed Argon2id table works against every user of this tool. That
  table is expensive to build and nobody has built it, but a high-entropy key
  (`--key-hex`, or the random key the clipboard scripts mint) sidesteps the
  question entirely.
- **Nothing about the sender is authenticated.** The tag proves the file was not
  altered after it was made. It says nothing about who made it: anyone holding
  the key - or, in recipient mode, anyone at all, since the public key is
  public - can produce a valid image addressed to you. Public-key encryption
  changes who can read something, not who can write it.
- **A sealed image is only as private as the private key.** `--identity` reads
  the key file directly and never consults `ssh-agent`, so an already-unlocked
  agent does not help and the passphrase has to be supplied each time.
- **The metadata is in the clear.** Dimensions, file size, and - if you keep the
  clipboard scripts' naming - a `key-id` in the filename that links every image
  made with the same key.
- **A lossy carrier still destroys the image.** JPEG, a re-encode, a pasted
  bitmap: any of them and the file will not open. That failure is at least loud
  now.

And the honest framing: if the goal is to get a document to someone privately,
[`age`](https://age-encryption.org) is the better tool and one command. This one
earns its place only when the channel takes images and nothing else.

## Performance

Building the keyed permutation is the bulk of the work, and it is bound by cache misses rather than arithmetic: the index array is much larger than the cache and Fisher-Yates touches it at random. Because the random draws depend only on the RNG and never on the array, a batch of them is taken up front and the slots they will touch are prefetched together. The permutation that comes out is bit-for-bit the one a naive loop produces.

The PNG writer probes the payload rather than always deflating, which matters because noise is exactly the input deflate cannot help with.

A 3000x2000 image, `-Doptimize=ReleaseFast`, best of three:

| | time | peak RSS |
| --- | --- | --- |
| `to-noise` PPM to PPM | 130 ms | 78 MB |
| `to-noise` PPM to PNG | 170 ms | 113 MB |
| `from-noise` PNG to PNG | 195 ms | 94 MB |
| `from-noise` PNG to PPM | 155 ms | 76 MB |

About 20 ms of each of those is Argon2id, which is a fixed cost per run rather than per pixel: on a small image it is most of the wall clock, and `--key-hex` skips it.

## Tests

```bash
zig build test
```

The suite also runs under an optimizing build, which is worth doing since the hot paths use prefetching and unchecked scanline loops:

```bash
zig build test -Doptimize=ReleaseFast
```
