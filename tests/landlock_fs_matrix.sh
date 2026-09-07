#!/usr/bin/env bash
set -euo pipefail

BIN="${1:-./target/release/runprint}"
BIN="$(realpath "$BIN")"

ROOT="$(mktemp -d)"
CASE_ID=0

cleanup() {
    rm -rf "$ROOT"
}

trap cleanup EXIT

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

expect_ok() {
    local label="$1"
    shift

    CASE_ID=$((CASE_ID + 1))
    local log="$ROOT/case-${CASE_ID}.log"

    if "$@" >"$log" 2>&1; then
        echo "PASS: $label"
        return 0
    fi

    cat "$log" >&2
    fail "$label"
}

expect_denied() {
    local label="$1"
    shift

    CASE_ID=$((CASE_ID + 1))
    local log="$ROOT/case-${CASE_ID}.log"

    set +e
    "$@" >"$log" 2>&1
    local rc=$?
    set -e

    if [ "$rc" -eq 0 ]; then
        cat "$log" >&2
        fail "$label unexpectedly succeeded"
    fi

    if ! grep -Eqi \
        'Permission denied|Operation not permitted' \
        "$log"
    then
        cat "$log" >&2
        fail "$label failed for an unexpected reason"
    fi

    echo "PASS: $label (blocked, exit=$rc)"
}

mkdir -p \
    "$ROOT/modify" \
    "$ROOT/create" \
    "$ROOT/remove" \
    "$ROOT/write/src" \
    "$ROOT/write/dst"

cd "$ROOT"

echo
echo "Runprint Landlock filesystem capability matrix"
echo

# ============================================================
# MODIFY
# ============================================================

printf 'original\n' > modify/existing.txt
printf 'truncate-me\n' > modify/truncate.txt

cat > .runprint.toml <<'CFG'
version = 1

[enforce]
modify = ["$PROJECT/modify/**"]
CFG

expect_ok \
    "modify: write existing file" \
    "$BIN" enforce -- \
    /bin/sh -c 'printf changed > modify/existing.txt'

[ "$(cat modify/existing.txt)" = "changed" ] ||
    fail "modify did not update existing file"

expect_ok \
    "modify: truncate existing file" \
    "$BIN" enforce -- \
    /usr/bin/python3 -c \
    "import os; os.truncate('modify/truncate.txt', 0)"

[ ! -s modify/truncate.txt ] ||
    fail "modify did not truncate existing file"

expect_denied \
    "modify: mkdir denied" \
    "$BIN" enforce -- \
    /bin/mkdir modify/newdir

expect_denied \
    "modify: create empty regular file denied" \
    "$BIN" enforce -- \
    /usr/bin/python3 -c \
    "import os,stat; os.mknod('modify/new-empty', stat.S_IFREG | 0o600)"

expect_denied \
    "modify: unlink denied" \
    "$BIN" enforce -- \
    /bin/rm modify/existing.txt

expect_denied \
    "modify: rename denied" \
    "$BIN" enforce -- \
    /bin/mv modify/existing.txt modify/renamed.txt

[ -f modify/existing.txt ] ||
    fail "modify scope removed or renamed existing file"

# ============================================================
# CREATE
# ============================================================

cat > .runprint.toml <<'CFG'
version = 1

[enforce]
create = ["$PROJECT/create/**"]
CFG

expect_ok \
    "create: mkdir" \
    "$BIN" enforce -- \
    /bin/mkdir create/newdir

expect_ok \
    "create: empty regular entry" \
    "$BIN" enforce -- \
    /usr/bin/python3 -c \
    "import os,stat; os.mknod('create/empty', stat.S_IFREG | 0o600)"

[ -f create/empty ] ||
    fail "create did not create empty regular entry"

expect_denied \
    "create: create-and-write regular file denied" \
    "$BIN" enforce -- \
    /bin/sh -c 'printf payload > create/data.txt'

# A failed create-and-write may still have entry-level effects
# depending on the syscall path.  The contract tested here is
# that the requested write operation itself does not succeed.
rm -f create/data.txt

expect_denied \
    "create: unlink denied" \
    "$BIN" enforce -- \
    /bin/rm create/empty

expect_denied \
    "create: rmdir denied" \
    "$BIN" enforce -- \
    /bin/rmdir create/newdir

[ -f create/empty ] ||
    fail "create scope unexpectedly removed regular entry"

[ -d create/newdir ] ||
    fail "create scope unexpectedly removed directory"

# ============================================================
# REMOVE
# ============================================================

printf 'protected\n' > remove/existing.txt
printf 'delete-me\n' > remove/file.txt
mkdir remove/dir

cat > .runprint.toml <<'CFG'
version = 1

[enforce]
remove = ["$PROJECT/remove/**"]
CFG

expect_ok \
    "remove: unlink file" \
    "$BIN" enforce -- \
    /bin/rm remove/file.txt

[ ! -e remove/file.txt ] ||
    fail "remove did not unlink file"

expect_ok \
    "remove: rmdir" \
    "$BIN" enforce -- \
    /bin/rmdir remove/dir

[ ! -e remove/dir ] ||
    fail "remove did not remove directory"

expect_denied \
    "remove: modify existing file denied" \
    "$BIN" enforce -- \
    /bin/sh -c 'printf changed > remove/existing.txt'

grep -qx 'protected' remove/existing.txt ||
    fail "remove scope modified existing file"

expect_denied \
    "remove: mkdir denied" \
    "$BIN" enforce -- \
    /bin/mkdir remove/newdir

expect_denied \
    "remove: create regular entry denied" \
    "$BIN" enforce -- \
    /usr/bin/python3 -c \
    "import os,stat; os.mknod('remove/new-empty', stat.S_IFREG | 0o600)"

# ============================================================
# WRITE — broad compatibility mode
# ============================================================

printf 'original\n' > write/existing.txt
printf 'truncate-me\n' > write/truncate.txt
printf 'delete-me\n' > write/remove-file.txt
mkdir write/remove-dir
printf 'move-me\n' > write/src/item.txt

cat > .runprint.toml <<'CFG'
version = 1

[enforce]
write = ["$PROJECT/write/**"]
CFG

expect_ok \
    "write: modify existing file" \
    "$BIN" enforce -- \
    /bin/sh -c 'printf changed > write/existing.txt'

expect_ok \
    "write: truncate existing file" \
    "$BIN" enforce -- \
    /usr/bin/python3 -c \
    "import os; os.truncate('write/truncate.txt', 0)"

expect_ok \
    "write: mkdir" \
    "$BIN" enforce -- \
    /bin/mkdir write/newdir

expect_ok \
    "write: create and populate regular file" \
    "$BIN" enforce -- \
    /bin/sh -c 'printf payload > write/new-file.txt'

grep -qx 'payload' write/new-file.txt ||
    fail "write scope did not populate new file"

expect_ok \
    "write: unlink" \
    "$BIN" enforce -- \
    /bin/rm write/remove-file.txt

expect_ok \
    "write: rmdir" \
    "$BIN" enforce -- \
    /bin/rmdir write/remove-dir

expect_ok \
    "write: rename/reparent" \
    "$BIN" enforce -- \
    /bin/mv write/src/item.txt write/dst/item.txt

[ -f write/dst/item.txt ] ||
    fail "write scope did not reparent file"

[ ! -e write/src/item.txt ] ||
    fail "write scope left source after rename"

echo
echo "PASS: Landlock filesystem capability matrix"
