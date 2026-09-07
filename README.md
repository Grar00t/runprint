# Runprint

A lockfile for runtime behavior.

Runprint runs a command under `strace`, turns the syscalls it observes into a
normalized set of behaviors, and writes that set to a deterministic
Git-friendly lockfile. A later run can be compared against the lockfile to see
whether a command started doing something new.

```
runprint record -- cargo build
runprint check --baseline behavior.lock -- cargo build
```

On Linux it can also apply a Landlock ruleset before executing a command, which
is a real restriction rather than an observation.

## What this is not

Being precise about this matters more than the feature list.

A behavior lock is **not**:

- a file-content integrity database — no file contents are hashed or compared;
- a cryptographic provenance proof — nothing is signed;
- a malware detector;
- a sandbox for the behavior categories it only observes;
- proof that an observed command is safe.

`gate` **is not a sandbox**. It runs the command to completion and then
compares what happened against a baseline and a policy. Anything the command
did, it has already done by the time a verdict exists. Only `enforce` restricts
a command, and only within the Landlock capabilities it configures.

The BLAKE3 digest printed by `record` is computed over the **compact JSON
serialization of the behavior set**. It is not a hash of the lockfile bytes and
not a hash of any observed file's contents. It identifies a behavior set, and
nothing more.

## Capability status

### IMPLEMENTED

| Area | State |
| --- | --- |
| `record` / `check` / `diff` / `gate` | Working |
| `enforce` | Working on kernels with Landlock |
| Observation backend | `strace` (ptrace), Linux only |
| Enforcement backend | Linux Landlock ABI 1-4 via `landlock` 0.4 |
| Lockfile schema | Version 4; reader accepts 1-4 |
| Path normalization | `$PROJECT`, `$HOME`, `$TMP` |

### ENFORCED (`enforce` only, pre-execution)

| Capability | Config key |
| --- | --- |
| Filesystem write | `enforce.write` |
| Filesystem modify | `enforce.modify` |
| Filesystem create | `enforce.create` |
| Filesystem remove | `enforce.remove` |
| TCP connect ports | `enforce.connect_tcp` |
| TCP bind ports | `enforce.bind_tcp` |

### OBSERVED (recorded and gated, never restricted)

| Behavior | Lockfile `kind` |
| --- | --- |
| Process execution | `exec` |
| File read | `file_read` |
| File write | `file_write` |
| File deletion | `file_delete` |
| Rename | `file_rename` |
| Atomic exchange (`RENAME_EXCHANGE`) | `rename_exchange` |
| Directory create | `directory_create` |
| Directory remove | `directory_delete` |
| Symlink create | `symlink_create` |
| Hardlink create | `hardlink_create` |
| TCP connect destination | `network_connect` |
| Unix pathname socket connect | `unix_connect` |
| Unix abstract socket connect | `unix_abstract_connect` |

### NOT MODELED

These are outside the behavior vocabulary. Runprint says nothing about them,
and a lock that does not mention them is not evidence they did not happen.

- Server-side networking: `bind`, `listen`, `accept`. A recorded lock never
  describes what a command listened on.
- UDP, raw sockets, and any protocol other than a TCP `connect` destination.
- File contents, sizes, modes, ownership, or timestamps.
- Syscall counts, ordering, timing, or duration.
- Environment variables, argv of the traced command, and working directory as
  behavior.
- Signals, `ptrace`, `ioctl`, `mmap`, and memory behavior.
- Attaching to an already-running process.

### PLANNED

- eBPF observation. **Not implemented.** There is no eBPF code in the tree.
  `strace` is the only backend, and it is sufficient while the behavior model
  is still being stabilized.

## Commands

```
runprint record  [-o behavior.lock] [--include-system] -- <command>
runprint check   [-b behavior.lock] [--include-system] [--status-file P] -- <command>
runprint diff    <old.lock> <new.lock>
runprint gate    [-b behavior.lock] [--config P] [--include-system] [--status-file P] -- <command>
runprint enforce [--config P] -- <command>
```

`--` is required before the command, and the command must be non-empty.

By default, reads of shared libraries and other system runtime noise are
dropped. `--include-system` keeps them, which makes a lock much larger and much
more sensitive to the host.

## Exit codes

The command's result and Runprint's verdict are deliberately separate.

| Situation | Exit code |
| --- | --- |
| `record` | The command's exit code |
| `check`, behavior unchanged | The command's exit code |
| `check`, behavior changed | `10` |
| `gate`, allowed | The command's exit code |
| `gate`, denied | `20` |
| `enforce` | The command's exit code |
| Command killed by signal `N` | `128 + N` |

A command that exits `10` or `20` on its own is indistinguishable from a
Runprint verdict **by exit code alone**. Use `--status-file` when a caller
needs to tell them apart; `command_exit` there is always the command's own
result.

## Status files

`check` and `gate` accept `--status-file`. `record` does not write one.

```json
{
  "version": 1,
  "operation": "gate",
  "verdict": "deny",
  "command_exit": 0,
  "violations": 2
}
```

- `operation` is `check` or `gate`.
- `verdict` is `unchanged` or `changed` for `check`, `allow` or `deny` for
  `gate`.
- `command_exit` is the observed command's own exit code, independent of the
  verdict.
- `check` reports `added` and `removed`; `gate` reports `violations`.

Guarantees:

- The file is written to a temporary file in the same directory, flushed, and
  renamed into place, so a reader never sees a partial document.
- Any existing report is removed **before** the command runs. If Runprint
  itself fails, no stale verdict from an earlier run is left behind.
- A status path whose directory does not exist is rejected before the command
  runs.

## Lockfile format

```json
{
  "version": 4,
  "behaviors": [
    { "kind": "exec", "path": "/usr/bin/cc" },
    { "kind": "file_write", "path": "$PROJECT/target/debug/app" }
  ]
}
```

- Behaviors are stored in a `BTreeSet`, so ordering is total and duplicates
  collapse. Two runs that observe the same set produce byte-identical files.
- Serialization is pretty-printed JSON, which keeps diffs readable.
- The reader checks `version` **before** decoding behaviors, so a future lock
  fails with `unsupported behavior lock version N` instead of a confusing
  decode error. Versions 1-4 are accepted.
- `hardlink_create` carries `follow_symlink` and `empty_path` only when true,
  which is why v3 locks still read correctly.

Do not bump the version for changes that do not need it.

## Path normalization

Observed paths are rewritten so a lock is portable between machines:

| Prefix | Symbol |
| --- | --- |
| Project root (working directory) | `$PROJECT` |
| Home directory | `$HOME` |
| Temporary directory | `$TMP` |

Normalization is **lexical**. `.`, `..`, and repeated separators are resolved
textually, and relative paths are resolved against the traced process's
recorded working directory or the referenced directory file descriptor.
**Symlinks are not resolved at record time**, so a lock records the path the
command used, not the path the kernel ultimately reached.

Prefix replacement is component-wise. `/home/a/project-other` does not
normalize under a `/home/a/project` root. `$PROJECT` is applied before `$HOME`,
so a project inside the home directory normalizes to `$PROJECT`.

Temporary paths that are volatile but semantically irrelevant are canonicalized
rather than dropped — a `rustdoctest` instance directory becomes
`rustdoctest@volatile`. Nothing else is normalized to make output stable.

## Observation semantics

These details determine what a lock means, so they are stated exactly.

- **A syscall that failed records nothing.** The result is read from the return
  value after the closing parenthesis, so a path containing something that
  looks like a result cannot suppress a real syscall, and a restarted call
  (`ERESTARTSYS`) is not treated as success.
- **Interrupted calls.** `<unfinished ...>` and `<... name resumed>` lines are
  spliced back together. An entry is recorded only once a resumed line confirms
  its result. An unresumed entry records nothing.
- **Non-blocking `connect`.** A `connect` reporting `EINPROGRESS` or `EALREADY`
  **is** recorded, because the connection was genuinely initiated. `connect`
  failing with `ECONNREFUSED` or `EACCES` records nothing.
- **Open access mode.** A file is recorded as read unless `O_WRONLY` is set,
  and as written when any of `O_WRONLY`, `O_RDWR`, `O_CREAT`, or `O_TRUNC` is
  set. So `O_RDONLY|O_CREAT` records **both** a read and a write. `O_PATH`
  records neither, because it only resolves a path. `creat()` records a write
  only.
- **Process tree.** `strace -ff` follows `fork`, `vfork`, and `clone`, so
  children and grandchildren are traced. Each traced process inherits its
  parent's working directory for path resolution. If the trace does not contain
  exactly one process without a recorded parent, Runprint fails rather than
  attributing behavior to the wrong working directory.

## Gate policy

`gate` compares observed behavior against a baseline and a policy from
`.runprint.toml` (or `--config`).

```toml
version = 1

[gate]
allow_new_reads = true
allow_write = ["$PROJECT/target/**", "$TMP/**"]
allow_network = ["prefix:127.0.0.1:"]
deny_read = ["$HOME/.ssh/id_ed25519"]
deny_network = ["prefix:169.254.169.254:"]
```

Precedence, in order:

1. A behavior matching a `deny_*` pattern is a violation, **even if it is in
   the baseline**.
2. A behavior present in the baseline is allowed.
3. A new behavior is allowed only if its `allow_new_*` flag is set or it
   matches an `allow_*` pattern.

Only `allow_new_reads` defaults to true. Every other category denies new
behavior by default.

### Pattern forms

| Form | Meaning |
| --- | --- |
| `$PROJECT/build/out.js` | Exact literal comparison |
| `exact:<value>` | Exact literal comparison, explicitly |
| `prefix:<value>` | Value starts with `<value>` |
| `suffix:<value>` | Value ends with `<value>` |
| `$PROJECT/build/**` | That directory and everything under it |

`*` is **literal**, not a wildcard. `$PROJECT/dist*` matches only a value that
contains a literal asterisk, and it is rejected as a bare pattern precisely so
it cannot be mistaken for a glob. Use `prefix:` or `/**` instead. Inside
`exact:`, `prefix:`, and `suffix:` an asterisk is accepted, because there it is
a working literal match.

`/**` is matched component-wise, so `$HOME/project/**` does not match
`$HOME/project-other/x`.

Patterns are checked when the config is loaded, and a pattern that cannot do
what it appears to do is rejected against its field and file:

- an empty pattern, or an empty `exact:`, `prefix:`, or `suffix:` body — an
  empty `prefix:` would otherwise match every value, silently turning a scoped
  allow list into "allow everything";
- a bare `/**`, which would otherwise match every absolute path;
- `**` anywhere other than a trailing `/**` segment;
- a bare pattern containing `*`, which could never match.

### Matching values

Patterns are matched against the same normalized strings stored in the lock:

- TCP: `127.0.0.1:8080`, and `[2001:db8::10]:443` for IPv6. IPv6 addresses are
  bracketed, so `suffix::443` matches the port and not part of an address.
- Unix pathname sockets: the normalized socket path.
- Unix abstract sockets: `@name`. The `@` is always present, so a pathname rule
  can never be satisfied by an abstract socket of the same name.

Two-path behaviors are asymmetric on purpose: an `allow_*` rule must cover
**both** paths of a rename, exchange, or hardlink, while a `deny_*` rule only
has to match **one**.

## Enforcement

```toml
version = 1

[enforce]
write = ["$PROJECT/target/**", "$TMP/**"]
connect_tcp = [443]
```

`enforce` applies a Landlock ruleset to itself and then executes the command,
so the command starts already restricted and cannot remove the restriction.

It is **fail-closed**. The ruleset is built with `CompatLevel::HardRequirement`
and execution proceeds only when the kernel reports the ruleset as fully
enforced and `no_new_privs` is set. A kernel without the required Landlock ABI
causes an error; a configured restriction never degrades into an unrestricted
run.

### Domain independence — read this carefully

The filesystem and network restrictions are independent of each other.
Configuring only `connect_tcp` leaves filesystem access unrestricted, and
configuring only `write` leaves the network unrestricted.

**Within the filesystem, `write`, `modify`, `create`, and `remove` are not
independent domains.** They are narrowing grants inside one restriction. As
soon as any one of them is configured, filesystem restriction is active for the
whole filesystem, and each key grants only its own operations on its own roots:

- `modify = [...]` grants content modification there, and therefore denies
  `mkdir`, file creation, `unlink`, and `rename` everywhere;
- `create = [...]` grants creation there, and therefore denies `unlink` and
  `rmdir` everywhere;
- `remove = [...]` grants removal there, and therefore denies modification,
  `mkdir`, and creation everywhere.

So a filesystem policy is a complete statement about filesystem access, not an
additive list of separate permissions. This is asserted by
`tests/landlock_fs_matrix.sh`.

An enforcement policy with no configured keys applies no restriction at all.

### Path rules

- Roots are expanded from `$PROJECT`, `$HOME`, and `$TMP`.
- A root must resolve inside the scope root it claims; an escaping path is
  rejected rather than silently widened.
- `create` and `remove` roots must be directories written as `<dir>/**`,
  because those operations act on a directory rather than a file.
- `write` and `modify` accept both files and directories.
- Paths are canonicalized, so a root that does not exist is an error rather
  than an ineffective rule.

## Requirements

- Linux.
- `strace` on `PATH` for `record`, `check`, and `gate`.
- A kernel with Landlock for `enforce`.
- Rust 1.75 or later.

`ptrace` may be restricted by `kernel.yama.ptrace_scope` or by a container
security profile; Landlock may be unavailable in a container. Both surface as
errors, not as silently reduced coverage.

## Tests

```
cargo test --workspace
```

The shell matrices under `tests/` need a release binary, `strace`, and a
Landlock-capable kernel:

```
cargo build --release
bash tests/exit_status_matrix.sh        ./target/release/runprint
bash tests/path_scope_matrix.sh        ./target/release/runprint
bash tests/cargo_determinism_matrix.sh ./target/release/runprint
bash tests/landlock_fs_matrix.sh       ./target/release/runprint
bash tests/landlock_net_matrix.sh      ./target/release/runprint
```

`cargo_determinism_matrix.sh` records the same workload twice and requires the
two lockfiles to be byte-identical.

## License

See `LICENSE`.
