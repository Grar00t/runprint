# Security Policy

## Scope

Runprint records and compares runtime behavior and can optionally apply selected Linux Landlock restrictions before a child process starts.

`record`, `check`, and `gate` are observation/verification tools. They are not sandboxes. Only `enforce` applies preventive restrictions, and only for capability domains explicitly configured in `[enforce]`.

## Trust boundary

- Observation currently depends on `strace`/ptrace access.
- Enforcement currently depends on Linux Landlock.
- Configured Landlock domains fail closed if Runprint cannot activate the requested restrictions fully.
- Capability domains omitted from `[enforce]` remain unrestricted.
- A lockfile describes observed behavior; it is not a cryptographic attestation that the child process or host is trustworthy.

## Sensitive data

Runtime traces and lockfiles can expose filesystem paths, network destinations, Unix-socket names, process arguments, and other behavioral metadata. Review artifacts before publishing them.

## Reporting

Report reproducible security defects through a GitHub issue when public disclosure is appropriate. Do not attach credentials, secrets, private traces, production lockfiles, or confidential filesystem paths.

Include the Runprint version, kernel version, Landlock ABI if relevant, exact command, policy snippet, observed exit status, and the smallest reproducible fixture.
