#!/usr/bin/env bash
set -euo pipefail

BIN="${1:-./target/release/runprint}"
BIN="$(realpath "$BIN")"

ROOT="$(mktemp -d)"

cleanup() {
    rm -rf "$ROOT"
}

trap cleanup EXIT

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

expect_scope_rejected() {
    local label="$1"
    shift

    local log="$ROOT/${label// /_}.log"

    set +e
    "$@" >"$log" 2>&1
    local rc=$?
    set -e

    if [ "$rc" -eq 0 ]; then
        cat "$log" >&2
        fail "$label unexpectedly succeeded"
    fi

    if ! grep -q "scoped enforcement path escapes" "$log"; then
        cat "$log" >&2
        fail "$label failed for an unexpected reason"
    fi

    echo "PASS: $label"
}

mkdir -p \
    "$ROOT/project" \
    "$ROOT/home" \
    "$ROOT/tmp" \
    "$ROOT/outside" \
    "$ROOT/project/inside"

ln -s "$ROOT/outside" "$ROOT/project/project-escape"
ln -s "$ROOT/outside" "$ROOT/home/home-escape"
ln -s "$ROOT/outside" "$ROOT/tmp/tmp-escape"
ln -s "$ROOT/project/inside" "$ROOT/project/inside-alias"

cd "$ROOT/project"

echo
echo "Runprint symbolic path scope matrix"
echo

# ============================================================
# PROJECT escape
# ============================================================

cat > .runprint.toml <<'CFG'
version = 1

[enforce]
write = ["$PROJECT/project-escape/**"]
CFG

expect_scope_rejected \
    "PROJECT symlink escape rejected" \
    "$BIN" enforce -- /bin/true

# ============================================================
# Relative path escape
# ============================================================

cat > .runprint.toml <<'CFG'
version = 1

[enforce]
write = ["project-escape/**"]
CFG

expect_scope_rejected \
    "relative symlink escape rejected" \
    "$BIN" enforce -- /bin/true

# ============================================================
# HOME escape
# ============================================================

cat > .runprint.toml <<'CFG'
version = 1

[enforce]
write = ["$HOME/home-escape/**"]
CFG

expect_scope_rejected \
    "HOME symlink escape rejected" \
    env HOME="$ROOT/home" \
    "$BIN" enforce -- /bin/true

# ============================================================
# TMP escape
# ============================================================

cat > .runprint.toml <<'CFG'
version = 1

[enforce]
write = ["$TMP/tmp-escape/**"]
CFG

expect_scope_rejected \
    "TMP symlink escape rejected" \
    env TMPDIR="$ROOT/tmp" \
    "$BIN" enforce -- /bin/true

# ============================================================
# Symlink that remains inside project is valid
# ============================================================

cat > .runprint.toml <<'CFG'
version = 1

[enforce]
write = ["$PROJECT/inside-alias/**"]
CFG

"$BIN" enforce -- \
    /bin/sh -c 'printf allowed > inside-alias/data.txt'

grep -qx 'allowed' inside/data.txt ||
    fail "inside-project symlink grant failed"

echo "PASS: project-internal symlink allowed"

# ============================================================
# Absolute paths remain explicit
# ============================================================

cat > .runprint.toml <<EOF_CONFIG
version = 1

[enforce]
write = ["$ROOT/outside/**"]
EOF_CONFIG

"$BIN" enforce -- \
    /bin/sh -c "printf allowed > '$ROOT/outside/absolute.txt'"

grep -qx 'allowed' "$ROOT/outside/absolute.txt" ||
    fail "explicit absolute path grant failed"

echo "PASS: explicit absolute scope allowed"

echo
echo "PASS: symbolic path scope matrix"
