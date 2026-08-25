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

# Resolves the key without ever putting it on a command line: an already-set
# environment variable wins, then the Keychain, then an interactive prompt.
load_key() {
    if [ -n "${!key_var:-}" ]; then
        return
    fi
    local from_keychain
    if from_keychain=$(security find-generic-password -w -s "$keychain_service" 2>/dev/null); then
        export "$key_var=$from_keychain"
        return
    fi
    if [ ! -t 0 ] && [ ! -t 2 ]; then
        echo "${0##*/}: no key. Set \$$key_var, or store one with:" >&2
        echo "  security add-generic-password -s $keychain_service -a \"\$USER\" -w" >&2
        exit 1
    fi
    local typed
    printf 'passphrase: ' >&2
    IFS= read -rs typed < /dev/tty
    printf '\n' >&2
    [ -n "$typed" ] || { echo "${0##*/}: empty key" >&2; exit 1; }
    export "$key_var=$typed"
}
