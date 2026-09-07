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

mkdir -p "$ROOT/demo/src"
cd "$ROOT/demo"

cat > Cargo.toml <<'CARGO_EOF'
[package]
name = "runprint-cargo-determinism"
version = "0.1.0"
edition = "2021"

[dependencies]
CARGO_EOF

cat > src/lib.rs <<'RUST_EOF'
pub fn add(a: u64, b: u64) -> u64 {
    a + b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn works() {
        assert_eq!(add(2, 3), 5);
    }
}
RUST_EOF

echo
echo "Runprint Cargo determinism matrix"
echo

# Warm the build so compilation artifacts are stable before observation.
cargo test --offline --quiet >/dev/null

"$BIN" record \
    --output first.lock \
    -- cargo test --offline --quiet \
    >/dev/null

"$BIN" record \
    --output second.lock \
    -- cargo test --offline --quiet \
    >/dev/null

if ! cmp -s first.lock second.lock; then
    echo "Recorded locks differ:"
    "$BIN" diff first.lock second.lock || true
    fail "identical warm Cargo workloads produced different behavior locks"
fi

/usr/bin/python3 - <<'PY_VERIFY'
import json
from pathlib import Path

first = json.loads(Path("first.lock").read_text())
second = json.loads(Path("second.lock").read_text())

assert first["version"] == 4
assert second["version"] == 4
assert first == second

print("behaviors:", len(first["behaviors"]))
print("PASS: identical warm Cargo workloads produce identical locks")
PY_VERIFY

echo
echo "PASS: Cargo determinism matrix"
