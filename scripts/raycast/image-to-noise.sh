#!/usr/bin/env bash

# Required parameters:
# @raycast.schemaVersion 1
# @raycast.title Image to Noise
# @raycast.mode fullOutput

# Optional parameters:
# @raycast.icon 🌀
# @raycast.packageName Image Noise

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
# This is the shared-key command, and it takes no argument on purpose: one
# keystroke, no prompt. Sending an image to somebody else is a different intent
# with a different consequence - a sealed image cannot be opened by the machine
# that made it - so it lives in its own command, `Seal Image to Noise`, where it
# gets its own hotkey and cannot happen by leaving a field blank or filling one
# by accident.
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
exec "$scripts_dir/clip-to-noise" 2>&1
