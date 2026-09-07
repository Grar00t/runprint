#!/usr/bin/env bash
# Run a command, print its output, and on failure republish that output as
# GitHub Actions error annotations.
#
# Step output is kept only in the raw job log, which is an authenticated
# archive download. A failing step therefore reports nothing more than
# "Process completed with exit code 1" through the API. Annotations are part
# of the check run, so mirroring the output there keeps a failure readable
# without fetching the log archive.
#
# Usage: ci-annotate.sh <label> <command> [args...]

set -uo pipefail

if [ "$#" -lt 2 ]; then
  echo "usage: ci-annotate.sh <label> <command> [args...]" >&2
  exit 2
fi

label="$1"
shift

log="$(mktemp)"
trap 'rm -f "$log"' EXIT

"$@" >"$log" 2>&1
status=$?

cat "$log"

if [ "$status" -ne 0 ]; then
  awk -v label="$label" '
    function flush() {
      if (n > 0) {
        part += 1
        if (part <= 10) {
          printf("::error title=%s (part %d)::%s\n", label, part, body)
        }
        body = ""
        n = 0
      }
    }
    {
      gsub(/%/, "%25")
      gsub(/\r/, "%0D")
      body = body $0 "%0A"
      n += 1
      if (n >= 30) {
        flush()
      }
    }
    END {
      flush()
    }
  ' "$log"
fi

exit "$status"
