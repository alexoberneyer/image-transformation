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
# load_key_for_id returns early on an environment variable that is already set.
#
# `password` masks the input. It is still a command-line argument, which is the
# one place these scripts otherwise take care to keep a key out of; a recipient
# trades that for the command working at all. It goes no further than this
# process - clip-from-noise reads it from the environment, never from argv.
#
# PATH and the stderr fold are there for the same reasons as in the forward
# script - see image-to-noise.sh.

export PATH="/opt/homebrew/bin:$PATH"

scripts_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
noise_args=()

# A pasted key picks up whatever whitespace came with the selection, and every
# key option is raw bytes through the same KDF, so one trailing space is simply
# a different key - and an unauthenticated transform cannot say so. It restores
# noise, with only the key-id to hint at why. Trimming here is the difference
# between that and it just working.
key=${1:-}
key="${key#"${key%%[![:space:]]*}"}"
key="${key%"${key##*[![:space:]]}"}"

if [ -n "$key" ]; then
    export IMAGE_NOISE_KEY="$key"

    # A key long enough to be worth having is too long to type, so it arrives by
    # being pasted - which replaces whatever was on the clipboard, and the noise
    # cannot be there too. The file selected in Finder is the one way in that
    # does not compete for the clipboard.
    #
    # It is a fallback, not a redirect: nothing selected, or Finder not
    # authorized, and this says so and lets clip-from-noise read the clipboard
    # as it always has. That still works for a recipient who copied the file and
    # keeps the key somewhere it need not be pasted.
    selected=$(osascript \
        -e 'tell application "Finder" to set sel to selection as alias list' \
        -e 'if sel is {} then return ""' \
        -e 'return POSIX path of (item 1 of sel)' 2>/dev/null) || selected=""

    if [ -n "$selected" ]; then
        noise_args=(-i "$selected")
        echo "reading the noise from the Finder selection:"
        echo "  $selected"
        echo
    else
        echo "Nothing usable is selected in Finder, so the clipboard is being"
        echo "read instead. If pasting the key replaced the image there, select"
        echo "the noise file in Finder and run this again."
        echo
        echo "The first attempt asks macOS for permission to read the Finder"
        echo "selection. If that was declined, turn it back on under System"
        echo "Settings > Privacy & Security > Automation > Raycast > Finder."
        echo
    fi
fi

exec "$scripts_dir/clip-from-noise" "${noise_args[@]}" 2>&1
