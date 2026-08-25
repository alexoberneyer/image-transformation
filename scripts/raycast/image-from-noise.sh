#!/usr/bin/env bash

# Required parameters:
# @raycast.schemaVersion 1
# @raycast.title Image from Noise
# @raycast.mode fullOutput

# Optional parameters:
# @raycast.icon 🧩
# @raycast.packageName Image Noise
# @raycast.argument1 { "type": "password", "placeholder": "key hex (optional)", "optional": true }

# Documentation:
# @raycast.description Restore the original image from the noise on the clipboard
# @raycast.author alexoberneyer
# @raycast.authorURL https://github.com/alexoberneyer

# Wraps scripts/clip-from-noise so it can run from a hotkey.
#
# fullOutput rather than compact, because the fingerprints are the whole point
# of reading the output at all: matching 'noise' lines say the file arrived
# intact, and 'restored' matching the original 'source' says the key was right.
# Nothing else tells a wrong key from a re-encoded file, and compact mode shows
# neither.
#
# The key argument is what makes this usable by anyone who did not make the
# image. Their keychain holds nothing filed under its key-id, and there is no
# tty here for prompt_key to fall back to, so without it the command can only
# ever run on the machine that minted the key. Left empty it changes nothing:
# load_key_for_id returns early on an environment variable that is already set,
# and otherwise resolves the key exactly as before. It also covers a file that
# arrived renamed, with the key-id no longer in the name to read.
#
# `password` masks the input. It is still a command-line argument, which is the
# one place these scripts otherwise take care to keep a key out of; a recipient
# trades that for the command working at all. It goes no further than this
# process - clip-from-noise reads it from the environment, never from argv.
#
# PATH and the stderr fold are there for the same reasons as in the forward
# script - see image-to-noise.sh.

export PATH="/opt/homebrew/bin:$PATH"

if [ -n "${1:-}" ]; then
    export IMAGE_NOISE_KEY="$1"
fi

scripts_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
exec "$scripts_dir/clip-from-noise" 2>&1
