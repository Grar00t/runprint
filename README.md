# Runprint

**A lockfile for runtime behavior.**

Your dependencies have lockfiles. Your runtime behavior should too.

```bash
runprint record -- npm test
runprint check --baseline behavior.lock -- npm test
runprint diff old.lock new.lock
runprint gate --baseline behavior.lock -- npm test
```

Runprint observes a command on Linux, canonicalizes the runtime behavior, and writes a Git-friendly `behavior.lock`.

## Record

```bash
runprint record -- npm test
```

The default output is `behavior.lock`. Use `--output PATH` to write another file.

Runprint currently records:

- program execution
- file reads and writes
- file and directory deletion
- rename and `RENAME_EXCHANGE`
- directory creation
- symbolic and hard link creation
- successful IPv4/IPv6 `connect()` destinations
- pathname and abstract Unix socket connections

Runprint does not currently model `bind()`, `listen()`, or `accept()` as lockfile behaviors. Server-side socket activity is therefore outside the current behavior vocabulary.

System-loader and locale noise is hidden by default. Use `--include-system` when those dependencies matter.

## Check

```bash
runprint check --baseline behavior.lock -- npm test
```

If behavior is unchanged, Runprint preserves the observed command exit status.

If runtime behavior changed, `check` prints the added and removed behavior and exits `10`.

For automation, use the independent status channel:

```bash
runprint check \
  --baseline behavior.lock \
  --status-file runprint-status.json \
  -- npm test
```

Example:

```json
{
  "version": 1,
  "operation": "check",
  "verdict": "unchanged",
  "command_exit": 0,
  "added": 0,
  "removed": 0
}
```

The status file separates the Runprint verdict from the child process exit code. For example, a child that exits `10` with unchanged runtime behavior still reports `"verdict": "unchanged"` and `"command_exit": 10`.

## Diff

```bash
runprint diff old.lock new.lock
```

`diff` compares two existing lockfiles without running a command.

## Gate

```bash
runprint gate --baseline behavior.lock -- npm test
```

`gate` is **post-execution validation**. It runs the command, observes its behavior, and then evaluates the result against the baseline and gate policy.

Existing baseline behavior is allowed unless explicitly denied. By default, new reads are allowed; other new behavior categories are denied unless allowed by policy.

A denied gate exits `20`.

`gate` also supports `--status-file`:

```json
{
  "version": 1,
  "operation": "gate",
  "verdict": "deny",
  "command_exit": 0,
  "violations": 1
}
```

## Configuration

Runprint reads `.runprint.toml` from the current directory unless `--config PATH` is supplied.

Current config version:

```toml
version = 1
```

Example gate policy:

```toml
version = 1

[gate]
allow_new_reads = true
allow_exec = ["/usr/bin/git"]
allow_write = ["$PROJECT/target/**"]
allow_network = ["suffix::443"]
deny_write = ["$HOME/.ssh/**"]
deny_network = ["prefix:169.254.169.254:"]
```

Gate policy matching is intentionally small and explicit:

```text
literal value        exact match
exact:<value>        exact match
prefix:<value>       string prefix match
suffix:<value>       string suffix match
/path/**             path itself and descendants only
```

Bare `*` is not a wildcard. Patterns such as `$PROJECT/dist*`, `127.0.0.1:*`, and `@name-*` do not match. Use `$PROJECT/dist/**`, `prefix:127.0.0.1:`, or `prefix:@name-` instead.

For network destinations, `suffix::443` means any recorded IPv4/IPv6 destination ending in port `443`.

Gate policy supports broad allow switches, scoped allowlists, and explicit denylists for reads, exec, writes, deletes, renames, directories, links, network, and Unix sockets.

Explicit deny rules override baseline behavior.

## Enforce

`enforce` applies supported restrictions **before** the command runs using Linux Landlock.

Example `.runprint.toml`:

```toml
version = 1

[enforce]
write = ["$PROJECT/target/**"]
connect_tcp = [443]
```

Then run:

```bash
runprint enforce -- npm test
```

Supported enforcement fields:

```toml
[enforce]
write = []
modify = []
create = []
remove = []
connect_tcp = []
bind_tcp = []
```

Unconfigured capability domains remain unrestricted. An empty enforcement policy is a no-op.

Filesystem scopes support project-relative paths, `$PROJECT`, `$HOME`, `$TMP`, and explicit absolute paths. Recursive directory scopes use `/path/**`.

Runprint requires Landlock enforcement to become fully active; it does not silently downgrade to unenforced execution.

`gate` and `enforce` remain separate commands in the current release. `gate` observes and validates after execution; `enforce` prevents configured classes of behavior before execution.

## Normalization and determinism

Machine-specific paths are normalized:

```text
/home/alice/project/src/main.rs -> $PROJECT/src/main.rs
/home/alice/.config/app.json    -> $HOME/.config/app.json
/tmp/example.txt                -> $TMP/example.txt
```

Proven volatile identifiers are normalized narrowly. For example, Rust documentation-test directories such as:

```text
$TMP/rustdoctestRuFt9q
$TMP/rustdoctestaPg4Uu
```

are represented as:

```text
$TMP/rustdoctest@volatile
```

The underlying read, write, create, delete, and directory behavior remains in the lock.

The CI suite includes a warm `cargo test` regression that records the same workload twice and requires byte-identical lockfiles.

The `digest` printed by `record` is a BLAKE3 digest of Runprint's compact serialized lock model. It is not a hash of the pretty-printed `behavior.lock` bytes and it is not a content hash of files touched by the observed command.

## Lockfile compatibility

Current lockfile schema: `version 4`.

The current reader accepts versions `1` through `4` and rejects unsupported future versions.

Version `4` is the compatibility target. Additive optional fields should remain backward-compatible where possible instead of forcing a schema bump.

## Exit behavior

```text
record   child result              -> child exit status
check    unchanged                 -> child exit status
check    runtime drift             -> 10
gate     allow                     -> child exit status
gate     deny                      -> 20
enforce  child result              -> child exit status
```

Signals are mapped to shell-style `128 + signal`.

Use `--status-file` with `check` or `gate` when automation must distinguish the child result from the Runprint verdict.

## Platform

Linux only.

Current observation backend: `strace`.

Observation requires `strace`/ptrace access. Hardened containers, CI sandboxes, seccomp profiles, Yama settings, or other ptrace restrictions can prevent recording.

Current enforcement backend: Landlock.

Configured Landlock domains are fail-closed: Runprint requires the ruleset to report fully enforced state and does not silently continue when the requested restriction cannot be activated. Capability domains not configured in `[enforce]` remain unrestricted.

An eBPF observation backend is deferred until the behavior model and normalization semantics are stable.

## Status

Early development.
