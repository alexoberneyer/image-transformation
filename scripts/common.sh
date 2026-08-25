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
    # A fresh clone has the template but not the command Raycast loads, since
    # the rendered one is not tracked. Build it the same way the binaries get
    # built: on first use, without being asked.
    if [ ! -f "$sealed_command" ]; then
        echo "rendering the sealed Raycast command..." >&2
        render_sealed_command
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

# --- Public-key mode -----------------------------------------------------
#
# The other way to key an image: seal it to somebody's ssh-ed25519 public key
# and there is no shared secret to hand over at all. Nothing here is stored in
# the keychain, because there is nothing to store - the only thing that opens
# a sealed image is a private key that never leaves its owner's machine.

# Where `to-noise -r <name>` looks when the name is not a path or a key.
recipients_dir=${IMAGE_NOISE_RECIPIENTS_DIR:-$HOME/.config/image-noise/recipients}

# The passphrase for an encrypted private key travels the same way a key does:
# in the environment, never in argv.
identity_var=IMAGE_NOISE_IDENTITY_PASSPHRASE

# Asks the noise itself how it expects to be opened. Reads only the header, so
# it needs no key and cannot fail for the wrong reason - which is what lets the
# inverse decide between an identity and a keychain lookup before prompting
# anyone for anything.
# Fails, loudly and in from-noise's own words, when the input is not a noise
# image at all - which would otherwise surface much later as a puzzling "no key".
noise_keying() {
    local info
    info=$("$bin_dir/from-noise" --inspect "$1") || return 1
    printf '%s\n' "$info" | awk '$1 == "keying" { print $2; exit }'
}

# A recipient is whatever is quickest to say: the key itself, a path to it, or
# a short name filed under $recipients_dir. The last is the one worth having on
# a hotkey - "alex" beats pasting 80 characters of base64.
resolve_recipient() {
    local value=$1
    case "$value" in
        ssh-*) printf '%s' "$value"; return ;;
    esac
    local candidate
    for candidate in "$value" "$recipients_dir/$value.pub" "$recipients_dir/$value"; do
        if [ -f "$candidate" ]; then printf '%s' "$candidate"; return; fi
    done
    echo "${0##*/}: no recipient '$value': not a key, not a file, and nothing in" >&2
    echo "  $recipients_dir" >&2
    echo "Save one there to name it on a hotkey:" >&2
    echo "  mkdir -p $recipients_dir && cp their_key.pub $recipients_dir/$value.pub" >&2
    exit 1
}

# The private key to open a sealed image with. $IMAGE_NOISE_IDENTITY wins, then
# the usual ed25519 key - the one a friend would have sent the public half of.
resolve_identity() {
    local candidate=${IMAGE_NOISE_IDENTITY:-}
    if [ -n "$candidate" ]; then
        [ -f "$candidate" ] || { echo "${0##*/}: no such identity: $candidate" >&2; exit 1; }
        printf '%s' "$candidate"
        return
    fi
    if [ -f "$HOME/.ssh/id_ed25519" ]; then printf '%s' "$HOME/.ssh/id_ed25519"; return; fi
    echo "${0##*/}: this image is sealed to a public key, and there is no private" >&2
    echo "key to open it with. Point at one with \$IMAGE_NOISE_IDENTITY, or put it" >&2
    echo "at ~/.ssh/id_ed25519." >&2
    exit 1
}

# `ssh-keygen -y` reads the key and fails on an empty passphrase when it needs
# one, which is the cheapest honest answer available.
identity_is_encrypted() {
    ! ssh-keygen -y -P "" -f "$1" >/dev/null 2>&1
}

# Same shape as prompt_key, for the other kind of secret.
prompt_identity_passphrase() {
    local path=$1
    [ -n "${!identity_var:-}" ] && return
    if [ ! -t 0 ] && [ ! -t 2 ]; then
        echo "${0##*/}: $path is passphrase-protected and there is no terminal to ask on." >&2
        echo "Set \$$identity_var, or keep an unprotected copy:" >&2
        echo "  ssh-keygen -p -N \"\" -f <a copy of the key>" >&2
        exit 1
    fi
    local typed
    printf 'passphrase for %s: ' "$path" >&2
    IFS= read -rs typed < /dev/tty
    printf '\n' >&2
    [ -n "$typed" ] || { echo "${0##*/}: empty passphrase" >&2; exit 1; }
    export "$identity_var=$typed"
}

# The flags `from-noise` needs to open a sealed image, prompting for the
# private key's passphrase only if it turns out to need one.
identity_args() {
    local path
    path=$(resolve_identity)
    identity_flags=(--identity "$path")
    if identity_is_encrypted "$path"; then
        prompt_identity_passphrase "$path"
        identity_flags+=(--identity-passphrase-env "$identity_var")
    fi
    echo "opening with $path" >&2
}

# --- The generated Raycast command ---------------------------------------
#
# A Raycast dropdown is static metadata: Raycast parses it out of the comment
# block before the script ever runs, so there is no way to fill one in at run
# time. The recipient list therefore has to be baked into the file - and a file
# listing who you send things to has no business being tracked, so git holds the
# template and ignores what comes out of it.

sealed_template="$repo_root/scripts/templates/image-to-noise-sealed.sh.in"
sealed_command="$repo_root/scripts/raycast/image-to-noise-sealed.sh"

json_string() {
    local value=$1
    value=${value//\\/\\\\}
    value=${value//\"/\\\"}
    printf '%s' "$value"
}

# Fills `recipient_names` with every ssh-ed25519 key saved in the recipients
# directory, and `recipient_skipped` with the ones that cannot be sealed to. A
# dropdown entry that could never work is worse than no entry at all.
scan_recipients() {
    recipient_names=()
    recipient_skipped=()
    [ -d "$recipients_dir" ] || return 0

    local key name kind _rest
    shopt -s nullglob
    for key in "$recipients_dir"/*.pub; do
        name=${key##*/}
        name=${name%.pub}
        # The first field of a public key file is its type, and only one type
        # can be sealed to.
        if ! read -r kind _rest < "$key" 2>/dev/null || [ "$kind" != "ssh-ed25519" ]; then
            recipient_skipped+=("$name")
            continue
        fi
        recipient_names+=("$name")
    done
    shopt -u nullglob
}

# Renders the template into the command Raycast loads, with the dropdown filled
# in. Nothing else in the template is touched.
render_sealed_command() {
    if [ ! -f "$sealed_template" ]; then
        echo "${0##*/}: missing template $sealed_template" >&2
        return 1
    fi
    scan_recipients

    local data="" name escaped
    if [ ${#recipient_names[@]} -gt 0 ]; then
        for name in "${recipient_names[@]}"; do
            escaped=$(json_string "$name")
            [ -n "$data" ] && data="$data, "
            data="$data{\"title\": \"$escaped\", \"value\": \"$escaped\"}"
        done
    else
        # Raycast wants a non-empty list, and the placeholder keeps the shape
        # stable so there is always an argument1 line to rewrite.
        data='{"title": "(none saved yet)", "value": ""}'
    fi

    local line="# @raycast.argument1 {\"type\": \"dropdown\", \"placeholder\": \"recipient\", \"optional\": true, \"data\": [$data]}"
    local tmp
    tmp=$(mktemp "${TMPDIR:-/tmp}/image-noise-render.XXXXXX")

    # Passed through the environment rather than -v, which would process
    # backslash escapes in a value that is already JSON.
    if ! REFRESH_LINE="$line" awk '
        /^# @raycast\.argument1 / { print ENVIRON["REFRESH_LINE"]; replaced = 1; next }
        { print }
        END { if (!replaced) exit 3 }
    ' "$sealed_template" > "$tmp"; then
        rm -f "$tmp"
        echo "${0##*/}: no @raycast.argument1 line in $sealed_template to fill in" >&2
        return 1
    fi

    # Never install something that is not a script any more.
    if ! bash -n "$tmp"; then
        rm -f "$tmp"
        echo "${0##*/}: the rendered command does not parse; leaving the old one alone" >&2
        return 1
    fi

    mkdir -p "$(dirname "$sealed_command")"
    # `cat >` rather than `mv`, so an existing file keeps its inode and Raycast
    # keeps its registration.
    cat "$tmp" > "$sealed_command"
    chmod +x "$sealed_command"
    rm -f "$tmp"
}
