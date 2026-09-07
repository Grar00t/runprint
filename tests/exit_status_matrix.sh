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

cd "$ROOT"

echo
echo "Runprint exit verdict matrix"
echo

# CHECK: child exit 10, runtime unchanged.

set +e

"$BIN" record \
    --output check.lock \
    -- /bin/sh -c 'exit 10' \
    >/dev/null 2>&1

RECORD10=$?

set -e

[ "$RECORD10" -eq 10 ] || \
    fail "check baseline command should exit 10"

set +e

"$BIN" check \
    --baseline check.lock \
    --status-file check-child.json \
    -- /bin/sh -c 'exit 10' \
    >/dev/null 2>&1

CHECK_CHILD_EXIT=$?

set -e

[ "$CHECK_CHILD_EXIT" -eq 10 ] || \
    fail "unchanged check should preserve child exit 10"

# CHECK: real runtime drift, same process exit 10.

set +e

"$BIN" check \
    --baseline check.lock \
    --status-file check-drift.json \
    -- /bin/sh -c 'printf x > drift.txt; exit 0' \
    >/dev/null 2>&1

CHECK_DRIFT_EXIT=$?

set -e

[ "$CHECK_DRIFT_EXIT" -eq 10 ] || \
    fail "runtime drift should exit 10"

# GATE: child exit 20 while gate allows.

set +e

"$BIN" record \
    --output gate.lock \
    -- /bin/sh -c 'exit 20' \
    >/dev/null 2>&1

RECORD20=$?

set -e

[ "$RECORD20" -eq 20 ] || \
    fail "gate baseline command should exit 20"

set +e

"$BIN" gate \
    --baseline gate.lock \
    --status-file gate-child.json \
    -- /bin/sh -c 'exit 20' \
    >/dev/null 2>&1

GATE_CHILD_EXIT=$?

set -e

[ "$GATE_CHILD_EXIT" -eq 20 ] || \
    fail "allowed gate should preserve child exit 20"

# GATE: real deny, same process exit 20.

set +e

"$BIN" gate \
    --baseline gate.lock \
    --status-file gate-deny.json \
    -- /bin/sh -c 'printf x > denied.txt; exit 0' \
    >/dev/null 2>&1

GATE_DENY_EXIT=$?

set -e

[ "$GATE_DENY_EXIT" -eq 20 ] || \
    fail "gate denial should exit 20"

/usr/bin/python3 - <<'PY_VERIFY'
import json
from pathlib import Path

def load(name):
    return json.loads(Path(name).read_text())

check_child = load("check-child.json")
check_drift = load("check-drift.json")
gate_child = load("gate-child.json")
gate_deny = load("gate-deny.json")

assert check_child == {
    "version": 1,
    "operation": "check",
    "verdict": "unchanged",
    "command_exit": 10,
    "added": 0,
    "removed": 0,
}, check_child

assert check_drift["version"] == 1
assert check_drift["operation"] == "check"
assert check_drift["verdict"] == "changed"
assert check_drift["command_exit"] == 0
assert check_drift["added"] >= 1
assert check_drift["removed"] == 0

assert gate_child == {
    "version": 1,
    "operation": "gate",
    "verdict": "allow",
    "command_exit": 20,
    "violations": 0,
}, gate_child

assert gate_deny["version"] == 1
assert gate_deny["operation"] == "gate"
assert gate_deny["verdict"] == "deny"
assert gate_deny["command_exit"] == 0
assert gate_deny["violations"] >= 1

print("PASS: check exit 10 distinguished from runtime drift")
print("PASS: gate child exit 20 distinguished from gate denial")
print("PASS: machine-readable status channel")
PY_VERIFY

echo
echo "PASS: Runprint exit verdict matrix"
