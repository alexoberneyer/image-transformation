# Shared setup for the clip-* scripts. macOS only: the pasteboard is the whole
# point, and NSPasteboard has no portable equivalent.
set -euo pipefail

if [ "$(uname -s)" != "Darwin" ]; then
    echo "${0##*/}: macOS only (the clipboard helper uses NSPasteboard)" >&2
    exit 1
fi

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
bin_dir="$repo_root/zig-out/bin"

# The key travels in the environment rather than argv, so it never shows up in
# another process's view of `ps`, and never lands on disk.
key_var=IMAGE_NOISE_KEY
keychain_service=${IMAGE_NOISE_KEYCHAIN:-image-noise}

# A minted key is filed under its own key-id rather than under the shared
# service, so any number of them can coexist. The key-id is not a secret -
# `to-noise` prints it, and `clip-to-noise` puts it in the noise filename - it
# only says which key made a given image.
key_service_for_id() { printf '%s-key-%s' "$keychain_service" "$1"; }

require_tools() {
    if [ ! -x "$bin_dir/to-noise" ] || [ ! -x "$bin_dir/from-noise" ]; then
        echo "building the transform..." >&2
        (cd "$repo_root" && zig build -Doptimize=ReleaseFast)
    fi
    # Rebuild the pasteboard helper whenever its source is newer than the binary.
    if [ ! -x "$bin_dir/clipimg" ] || [ "$repo_root/tools/clipimg.swift" -nt "$bin_dir/clipimg" ]; then
        echo "building the clipboard helper..." >&2
        mkdir -p "$bin_dir"
        swiftc -O "$repo_root/tools/clipimg.swift" -o "$bin_dir/clipimg"
    fi
}

# 32 bytes from the system CSPRNG. Every key option the tool takes is funnelled
# through the same BLAKE3-KDF, so hex text is as good a master secret as raw
# bytes - and unlike raw bytes it survives being read aloud or pasted into a
# chat window.
mint_key() {
    export "$key_var=$(od -An -tx1 -N32 /dev/urandom | tr -d ' \n')"
}

# Files the current key under a key-id. The value goes in on stdin - twice,
# because `security` wants a confirmation it would otherwise read off the tty -
# rather than as `-w <value>`, which would put the key in argv for anyone
# running `ps` to see.
remember_key() {
    printf '%s\n%s\n' "${!key_var}" "${!key_var}" \
        | security add-generic-password -U -s "$(key_service_for_id "$1")" -a "$USER" -w >/dev/null 2>&1
}

# Last resort on the inverse side: a key that arrived out of band, typed rather
# than stored. A key-id says which one to reach for, and is worth naming - a
# lookup that came up empty is otherwise indistinguishable from never having
# looked.
prompt_key() {
    local id=${1:-}
    local missing="no key"
    [ -n "$id" ] && missing="no stored key for key-id $id"
    if [ ! -t 0 ] && [ ! -t 2 ]; then
        echo "${0##*/}: $missing. Set \$$key_var, or store one with:" >&2
        echo "  security add-generic-password -s $keychain_service -a \"\$USER\" -w" >&2
        exit 1
    fi
    [ -n "$id" ] && echo "${0##*/}: $missing" >&2
    local typed
    printf 'key: ' >&2
    IFS= read -rs typed < /dev/tty
    printf '\n' >&2
    [ -n "$typed" ] || { echo "${0##*/}: empty key" >&2; exit 1; }
    export "$key_var=$typed"
}

# Resolves the key for the forward transform without ever putting it on a
# command line: an already-set environment variable wins, then the Keychain,
# and with neither configured a random key is minted for this one image. Sets
# `minted`, which tells the caller the key still has to be handed back.
load_or_mint_key() {
    minted=0
    if [ -n "${!key_var:-}" ]; then
        return
    fi
    local from_keychain
    if from_keychain=$(security find-generic-password -w -s "$keychain_service" 2>/dev/null); then
        export "$key_var=$from_keychain"
        return
    fi
    mint_key
    minted=1
}

# Resolves the key for the inverse transform. A key-id read off the noise
# filename names a minted key directly; failing that it is the same environment
# variable and Keychain entry the forward direction uses, and then a prompt.
load_key_for_id() {
    local id=${1:-}
    if [ -n "${!key_var:-}" ]; then
        return
    fi
    local found
    if [ -n "$id" ] && found=$(security find-generic-password -w -s "$(key_service_for_id "$id")" 2>/dev/null); then
        export "$key_var=$found"
        echo "using the stored key for key-id $id" >&2
        return
    fi
    if found=$(security find-generic-password -w -s "$keychain_service" 2>/dev/null); then
        export "$key_var=$found"
        return
    fi
    prompt_key "$id"
}
