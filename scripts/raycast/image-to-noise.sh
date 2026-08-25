#!/usr/bin/env bash

# Required parameters:
# @raycast.schemaVersion 1
# @raycast.title Image to Noise
# @raycast.mode fullOutput

# Optional parameters:
# @raycast.icon 🌀
# @raycast.packageName Image Noise
# @raycast.argument1 { "type": "text", "placeholder": "recipient (optional)", "optional": true }

# Documentation:
# @raycast.description Turn the image on the clipboard into keyed noise, ready to paste
# @raycast.author alexoberneyer
# @raycast.authorURL https://github.com/alexoberneyer

# Wraps scripts/clip-to-noise so it can run from a hotkey.
#
# fullOutput rather than compact, because the interesting output is not the
# last line. With no key configured the script mints one and prints it, and
# that print is the only copy anyone else can be handed - a one-line summary
# would hide exactly the thing that cannot be recovered later.
#
# The recipient argument is what makes the hotkey usable for sending something.
# Left empty it behaves as it always did: a shared key, minted if there is none,
# and a hex string to hand over somehow. Filled in, the image is sealed to that
# person's ssh-ed25519 public key and there is nothing to hand over at all -
# which also means this machine can no longer open the result.
#
# A short name is the point. `resolve_recipient` looks under
# $IMAGE_NOISE_RECIPIENTS_DIR (default ~/.config/image-noise/recipients), so
# typing "alex" beats pasting eighty characters of base64 into a hotkey.
# $IMAGE_NOISE_RECIPIENTS sets a standing default for when even that is too much.
#
# The default file-reference mode is the one that survives being pasted into a
# chat, so --bitmap is deliberately not reachable from here: a hotkey that
# inlines a bitmap is a fast way to make noise no one can invert.
#
# Raycast runs this in a non-interactive shell that never reads a profile, so
# the PATH is bare. Homebrew goes back on it for the `zig build` fallback in
# require_tools; swiftc is already in /usr/bin. Everything the script prints
# goes to stderr to keep its pipes clean, and Raycast shows stdout, so the two
# are folded together here.

export PATH="/opt/homebrew/bin:$PATH"

scripts_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
noise_args=()

# A name typed into a hotkey field picks up whatever whitespace came with it.
who=${1:-}
who="${who#"${who%%[![:space:]]*}"}"
who="${who%"${who##*[![:space:]]}"}"
[ -n "$who" ] && noise_args=(-r "$who")

exec "$scripts_dir/clip-to-noise" "${noise_args[@]}" 2>&1
