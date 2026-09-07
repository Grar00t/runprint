# Runprint

**A lockfile for runtime behavior.**

Your dependencies have lockfiles. Your runtime behavior should too.

```bash
runprint record -- npm test
runprint check -- npm test
runprint diff old.lock new.lock
```

Runprint executes a command under a local runtime observer and produces a deterministic `behavior.lock`.

```text
$ runprint record -- ./app

Runprint

exec       1
file read  3
file write 1
network    2
unix       0
-----------
total      7

saved      behavior.lock
```

Commit the lockfile to Git.

When runtime behavior changes:

```text
$ runprint check -- ./app

RUNTIME BEHAVIOR CHANGED

+ exec     /usr/bin/curl
+ connect  203.0.113.20:443
+ write    /home/user/.config/example/device-id
```

## What Runprint observes

- program execution
- file reads
- file writes
- network connections
- local Unix socket connections

System-loader and locale noise is hidden by default.

Use `--include-system` when the raw system dependencies matter.

## Why

Dependency lockfiles tell you **what software you installed**.

Runprint tells you **what that software actually did when you ran it**.

## Status

Early development.

Linux only. The current observer backend uses `strace`; a kernel event backend is planned after the lockfile format and normalization semantics stabilize.
