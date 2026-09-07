#!/usr/bin/env bash
set -euo pipefail

BIN="${1:-./target/release/runprint}"
BIN="$(realpath "$BIN")"

ROOT="$(mktemp -d)"
SERVER_PID=""

cleanup() {
    if [ -n "${SERVER_PID:-}" ]; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi

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

    local log="$ROOT/ok.log"

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

    local log="$ROOT/denied.log"

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

pick_two_free_ports() {
    /usr/bin/python3 - <<'PY'
import socket

sockets = []

for _ in range(2):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    sockets.append(s)

ports = [s.getsockname()[1] for s in sockets]

if ports[0] == ports[1]:
    raise SystemExit("failed to allocate distinct TCP ports")

print(ports[0], ports[1])

for s in sockets:
    s.close()
PY
}

pick_free_port() {
    /usr/bin/python3 - <<'PY'
import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("127.0.0.1", 0))

print(s.getsockname()[1])

s.close()
PY
}

cd "$ROOT"

echo
echo "Runprint Landlock TCP capability matrix"
echo

# ============================================================
# Start two real listeners.
#
# Having a listener on both ports is important: a denied connect
# must fail with EACCES, not ECONNREFUSED.
# ============================================================

rm -f ports.txt server.log

/usr/bin/python3 - <<'PY' >server.log 2>&1 &
import socket
import time

listeners = []

for _ in range(2):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    s.listen(8)
    listeners.append(s)

with open("ports.txt", "w") as f:
    f.write(
        f"{listeners[0].getsockname()[1]} "
        f"{listeners[1].getsockname()[1]}\n"
    )
    f.flush()

while True:
    time.sleep(60)
PY

SERVER_PID=$!

for _ in $(seq 1 100); do
    [ -s ports.txt ] && break

    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        cat server.log >&2
        fail "TCP listener process exited"
    fi

    sleep 0.05
done

[ -s ports.txt ] || {
    cat server.log >&2
    fail "TCP listeners did not become ready"
}

read CONNECT_ALLOWED CONNECT_BLOCKED < ports.txt

echo "connect allowed port: $CONNECT_ALLOWED"
echo "connect blocked port: $CONNECT_BLOCKED"

# ============================================================
# CONNECT_TCP
# ============================================================

cat > .runprint.toml <<EOF_CONFIG
version = 1

[enforce]
connect_tcp = [$CONNECT_ALLOWED]
EOF_CONFIG

expect_ok \
    "connect_tcp: allowed destination port" \
    "$BIN" enforce -- \
    /usr/bin/python3 -c \
    "import socket; s=socket.create_connection(('127.0.0.1',$CONNECT_ALLOWED),2); s.close()"

expect_denied \
    "connect_tcp: other destination port denied" \
    "$BIN" enforce -- \
    /usr/bin/python3 -c \
    "import socket; s=socket.create_connection(('127.0.0.1',$CONNECT_BLOCKED),2); s.close()"

# connect_tcp must not implicitly restrict bind_tcp.

UNRESTRICTED_BIND="$(pick_free_port)"

expect_ok \
    "connect_tcp: bind remains unrestricted" \
    "$BIN" enforce -- \
    /usr/bin/python3 -c \
    "import socket; s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.bind(('127.0.0.1',$UNRESTRICTED_BIND)); s.listen(1); s.close()"

# connect_tcp must not implicitly restrict filesystem mutation.

rm -f connect-fs.txt

expect_ok \
    "connect_tcp: filesystem remains unrestricted" \
    "$BIN" enforce -- \
    /bin/sh -c 'printf "connect-fs\n" > connect-fs.txt'

[ "$(cat connect-fs.txt)" = "connect-fs" ] || \
    fail "connect_tcp filesystem write did not persist"

# ============================================================
# BIND_TCP
# ============================================================

read BIND_ALLOWED BIND_BLOCKED < <(
    pick_two_free_ports
)

echo "bind allowed port: $BIND_ALLOWED"
echo "bind blocked port: $BIND_BLOCKED"

cat > .runprint.toml <<EOF_CONFIG
version = 1

[enforce]
bind_tcp = [$BIND_ALLOWED]
EOF_CONFIG

expect_ok \
    "bind_tcp: allowed local port" \
    "$BIN" enforce -- \
    /usr/bin/python3 -c \
    "import socket; s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.bind(('127.0.0.1',$BIND_ALLOWED)); s.listen(1); s.close()"

expect_denied \
    "bind_tcp: other local port denied" \
    "$BIN" enforce -- \
    /usr/bin/python3 -c \
    "import socket; s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.bind(('127.0.0.1',$BIND_BLOCKED)); s.listen(1); s.close()"

# bind_tcp must not implicitly restrict connect_tcp.

expect_ok \
    "bind_tcp: connect remains unrestricted" \
    "$BIN" enforce -- \
    /usr/bin/python3 -c \
    "import socket; s=socket.create_connection(('127.0.0.1',$CONNECT_BLOCKED),2); s.close()"

# bind_tcp must not implicitly restrict filesystem mutation.

rm -f bind-fs.txt

expect_ok \
    "bind_tcp: filesystem remains unrestricted" \
    "$BIN" enforce -- \
    /bin/sh -c 'printf "bind-fs\n" > bind-fs.txt'

[ "$(cat bind-fs.txt)" = "bind-fs" ] || \
    fail "bind_tcp filesystem write did not persist"

echo
echo "PASS: Landlock TCP capability matrix"
