#!/usr/bin/env bash

# Required parameters:
# @raycast.schemaVersion 1
# @raycast.title Image from Noise
# @raycast.mode fullOutput

# Optional parameters:
# @raycast.icon 🧩
# @raycast.packageName Image Noise

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
# There is no tty here, so the prompt in prompt_key cannot fire. It notices and
# exits with the instructions instead, which is the right failure: a hotkey
# that appears to hang while waiting for input nobody can type would be worse.
#
# PATH and the stderr fold are there for the same reasons as in the forward
# script - see image-to-noise.sh.

export PATH="/opt/homebrew/bin:$PATH"

scripts_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
exec "$scripts_dir/clip-from-noise" 2>&1
