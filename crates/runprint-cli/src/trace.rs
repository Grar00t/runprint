mod strace;

#[cfg(test)]
mod tests;

use crate::status::shell_exit_code;
use anyhow::{bail, Context, Result};
use runprint_core::{Behavior, BehaviorLock, NormalizeContext};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use self::strace::{
    angle_path, extract_between, extract_strace_abstract_unix_address, extract_strace_quoted_field,
    file_open_flags, first_quoted_string, flags_have_token, nth_quoted_string, observable_syscall,
    quoted_end, reassemble_trace_lines, syscall_result, syscall_succeeded,
};

pub struct RecordedRun {
    pub lock: BehaviorLock,
    pub exit_code: i32,
}

pub fn record(command: &[String], include_system: bool) -> Result<RecordedRun> {
    if command.is_empty() {
        bail!("missing command");
    }

    let project_root = std::env::current_dir().context("failed to determine current directory")?;

    let normalize_context = NormalizeContext::new(
        project_root.clone(),
        std::env::var_os("HOME").map(PathBuf::from),
        std::env::temp_dir(),
    );

    let dir = tempfile::tempdir()?;
    let prefix = dir.path().join("trace");

    let status = Command::new("strace")
        .arg("-ff")
        .arg("-qq")
        .arg("-yy")
        .arg("-s")
        .arg("4096")
        .arg("-e")
        .arg("trace=process,file,network")
        .arg("-o")
        .arg(&prefix)
        .arg("--")
        .arg(&command[0])
        .args(&command[1..])
        .status()
        .context("failed to execute strace; is strace installed?")?;

    let exit_code = shell_exit_code(&status);

    let lock = parse_trace_dir(
        dir.path(),
        include_system,
        &normalize_context,
        &project_root,
    )?;

    Ok(RecordedRun { lock, exit_code })
}

fn parse_trace_dir(
    dir: &Path,
    include_system: bool,
    context: &NormalizeContext,
    root_cwd: &Path,
) -> Result<BehaviorLock> {
    let traces = load_traces(dir)?;

    if traces.is_empty() {
        bail!("strace produced no trace files");
    }

    let mut children = BTreeSet::new();

    for lines in traces.values() {
        for line in lines {
            if let Some(pid) = child_pid(line) {
                children.insert(pid);
            }
        }
    }

    let roots: Vec<u32> = traces
        .keys()
        .copied()
        .filter(|pid| !children.contains(pid))
        .collect();

    if roots.len() != 1 {
        bail!(
            "expected exactly one traced process without a recorded parent, found {}; \
             the trace is incomplete and behavior cannot be attributed reliably",
            roots.len()
        );
    }

    let root = roots[0];

    let mut lock = BehaviorLock::new();
    let mut initial_cwds = BTreeMap::<u32, PathBuf>::new();
    let mut processed = BTreeSet::<u32>::new();
    let mut queue = VecDeque::<u32>::new();

    initial_cwds.insert(root, root_cwd.to_path_buf());
    queue.push_back(root);

    while let Some(pid) = queue.pop_front() {
        if !processed.insert(pid) {
            continue;
        }

        let mut cwd = initial_cwds
            .get(&pid)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("missing cwd for pid {pid}"))?;

        let lines = traces
            .get(&pid)
            .ok_or_else(|| anyhow::anyhow!("missing trace for pid {pid}"))?;

        for line in lines {
            // Never infer an operation from syscall arguments when the
            // reported result means it did not occur.
            if !observable_syscall(line) {
                continue;
            }

            if line.starts_with("chdir(") {
                if let Some(raw) = first_quoted_string(line) {
                    cwd = resolve_path(&cwd, &raw);
                }
                continue;
            }

            if line.starts_with("fchdir(") {
                if let Some(path) = first_fd_path(line) {
                    cwd = PathBuf::from(path);
                }
                continue;
            }

            if let Some(child) = child_pid(line) {
                initial_cwds.entry(child).or_insert_with(|| cwd.clone());

                if traces.contains_key(&child) {
                    queue.push_back(child);
                }

                continue;
            }

            parse_behavior_line(line, &cwd, &mut lock, include_system, context)?;
        }
    }

    for pid in traces.keys() {
        if !processed.contains(pid) {
            bail!("unable to determine inherited cwd for traced pid {pid}");
        }
    }

    Ok(lock)
}

fn load_traces(dir: &Path) -> Result<BTreeMap<u32, Vec<String>>> {
    let mut traces = BTreeMap::new();

    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();

        let Some(pid) = trace_pid(&path) else {
            continue;
        };

        let text = fs::read_to_string(&path)?;
        traces.insert(pid, reassemble_trace_lines(&text));
    }

    Ok(traces)
}

fn trace_pid(path: &Path) -> Option<u32> {
    let name = path.file_name()?.to_str()?;
    name.strip_prefix("trace.")?.parse().ok()
}

fn parse_behavior_line(
    line: &str,
    cwd: &Path,
    lock: &mut BehaviorLock,
    include_system: bool,
    context: &NormalizeContext,
) -> Result<()> {
    if line.starts_with("execve(") {
        if let Some(raw) = first_quoted_string(line) {
            let path = resolve_path(cwd, &raw).to_string_lossy().into_owned();

            lock.insert_normalized(Behavior::Exec { path }, include_system, context);
        }

        return Ok(());
    }

    if line.starts_with("execveat(") {
        if let Some(raw) = first_quoted_string(line) {
            let path = resolve_openat(line, cwd, &raw)?
                .to_string_lossy()
                .into_owned();

            lock.insert_normalized(Behavior::Exec { path }, include_system, context);
        }

        return Ok(());
    }

    if line.starts_with("open(") || line.starts_with("creat(") {
        if let Some(raw) = first_quoted_string(line) {
            insert_file_behavior(line, resolve_path(cwd, &raw), lock, include_system, context);
        }

        return Ok(());
    }

    if line.starts_with("openat(") || line.starts_with("openat2(") {
        if let Some(raw) = first_quoted_string(line) {
            let path = resolve_openat(line, cwd, &raw)?;
            insert_file_behavior(line, path, lock, include_system, context);
        }

        return Ok(());
    }

    if line.starts_with("unlink(") {
        if let Some(raw) = first_quoted_string(line) {
            let path = resolve_path(cwd, &raw).to_string_lossy().into_owned();

            lock.insert_normalized(Behavior::FileDelete { path }, include_system, context);
        }

        return Ok(());
    }

    if line.starts_with("rmdir(") {
        if let Some(raw) = first_quoted_string(line) {
            let path = resolve_path(cwd, &raw).to_string_lossy().into_owned();

            lock.insert_normalized(Behavior::DirectoryDelete { path }, include_system, context);
        }

        return Ok(());
    }

    if line.starts_with("mkdir(") {
        if let Some(raw) = first_quoted_string(line) {
            let path = resolve_path(cwd, &raw).to_string_lossy().into_owned();

            lock.insert_normalized(Behavior::DirectoryCreate { path }, include_system, context);
        }

        return Ok(());
    }

    if line.starts_with("mkdirat(") {
        if let Some(raw) = first_quoted_string(line) {
            let path = resolve_openat(line, cwd, &raw)?
                .to_string_lossy()
                .into_owned();

            lock.insert_normalized(Behavior::DirectoryCreate { path }, include_system, context);
        }

        return Ok(());
    }

    if line.starts_with("unlinkat(") {
        if let Some(raw) = first_quoted_string(line) {
            let path = resolve_openat(line, cwd, &raw)?
                .to_string_lossy()
                .into_owned();

            let behavior = if line.contains("AT_REMOVEDIR") {
                Behavior::DirectoryDelete { path }
            } else {
                Behavior::FileDelete { path }
            };

            lock.insert_normalized(behavior, include_system, context);
        }

        return Ok(());
    }

    if line.starts_with("rename(") {
        let from = nth_quoted_string(line, 0);
        let to = nth_quoted_string(line, 1);

        if let (Some(from), Some(to)) = (from, to) {
            let from = resolve_path(cwd, &from).to_string_lossy().into_owned();
            let to = resolve_path(cwd, &to).to_string_lossy().into_owned();

            lock.insert_normalized(Behavior::FileRename { from, to }, include_system, context);
        }

        return Ok(());
    }

    if line.starts_with("renameat(") || line.starts_with("renameat2(") {
        let from = nth_quoted_string(line, 0);
        let to = nth_quoted_string(line, 1);

        if let (Some(from), Some(to)) = (from, to) {
            let from = resolve_openat(line, cwd, &from)?;

            let first_end =
                quoted_end(line, 0).ok_or_else(|| anyhow::anyhow!("malformed renameat source"))?;

            let after = &line[first_end + 1..];
            let after = after
                .trim_start()
                .strip_prefix(',')
                .ok_or_else(|| anyhow::anyhow!("malformed renameat arguments"))?
                .trim_start();

            let comma = after
                .find(',')
                .ok_or_else(|| anyhow::anyhow!("missing renameat destination dirfd"))?;

            let dirfd = after[..comma].trim();
            let to = resolve_dirfd(dirfd, cwd, &to)?;

            let from = from.to_string_lossy().into_owned();
            let to = to.to_string_lossy().into_owned();

            let behavior = if renameat2_has_flag(line, "RENAME_EXCHANGE") {
                Behavior::RenameExchange {
                    left: from,
                    right: to,
                }
            } else {
                Behavior::FileRename { from, to }
            };

            lock.insert_normalized(behavior, include_system, context);
        }

        return Ok(());
    }

    if line.starts_with("symlink(") {
        if let (Some(target), Some(link)) = (nth_quoted_string(line, 0), nth_quoted_string(line, 1))
        {
            let link = resolve_path(cwd, &link).to_string_lossy().into_owned();

            lock.insert_normalized(
                Behavior::SymlinkCreate { target, link },
                include_system,
                context,
            );
        }

        return Ok(());
    }

    if line.starts_with("symlinkat(") {
        if let (Some(target), Some(link)) = (nth_quoted_string(line, 0), nth_quoted_string(line, 1))
        {
            let first_end =
                quoted_end(line, 0).ok_or_else(|| anyhow::anyhow!("malformed symlinkat target"))?;

            let after = &line[first_end + 1..];
            let after = after
                .trim_start()
                .strip_prefix(',')
                .ok_or_else(|| anyhow::anyhow!("malformed symlinkat arguments"))?
                .trim_start();

            let comma = after
                .find(',')
                .ok_or_else(|| anyhow::anyhow!("missing symlinkat dirfd"))?;

            let dirfd = after[..comma].trim();

            let link = resolve_dirfd(dirfd, cwd, &link)?
                .to_string_lossy()
                .into_owned();

            lock.insert_normalized(
                Behavior::SymlinkCreate { target, link },
                include_system,
                context,
            );
        }

        return Ok(());
    }

    if line.starts_with("link(") {
        if let (Some(from), Some(to)) = (nth_quoted_string(line, 0), nth_quoted_string(line, 1)) {
            let from = resolve_path(cwd, &from).to_string_lossy().into_owned();
            let to = resolve_path(cwd, &to).to_string_lossy().into_owned();

            lock.insert_normalized(
                Behavior::HardlinkCreate {
                    from,
                    to,
                    follow_symlink: false,
                    empty_path: false,
                },
                include_system,
                context,
            );
        }

        return Ok(());
    }

    if line.starts_with("linkat(") {
        let from = nth_quoted_string(line, 0);
        let to = nth_quoted_string(line, 1);

        if let (Some(from), Some(to)) = (from, to) {
            let from = resolve_openat(line, cwd, &from)?;

            let first_end =
                quoted_end(line, 0).ok_or_else(|| anyhow::anyhow!("malformed linkat source"))?;

            let after = &line[first_end + 1..];
            let after = after
                .trim_start()
                .strip_prefix(',')
                .ok_or_else(|| anyhow::anyhow!("malformed linkat arguments"))?
                .trim_start();

            let comma = after
                .find(',')
                .ok_or_else(|| anyhow::anyhow!("missing linkat destination dirfd"))?;

            let dirfd = after[..comma].trim();

            let to = resolve_dirfd(dirfd, cwd, &to)?;

            lock.insert_normalized(
                Behavior::HardlinkCreate {
                    from: from.to_string_lossy().into_owned(),
                    to: to.to_string_lossy().into_owned(),
                    follow_symlink: linkat_has_flag(line, "AT_SYMLINK_FOLLOW"),
                    empty_path: linkat_has_flag(line, "AT_EMPTY_PATH"),
                },
                include_system,
                context,
            );
        }

        return Ok(());
    }

    if line.starts_with("connect(") {
        if let Some(behavior) = parse_connect(line) {
            lock.insert_normalized(behavior, include_system, context);
        }
    }

    Ok(())
}

fn insert_file_behavior(
    line: &str,
    path: PathBuf,
    lock: &mut BehaviorLock,
    include_system: bool,
    context: &NormalizeContext,
) {
    let path = path.to_string_lossy().into_owned();

    // creat() is equivalent to opening with O_WRONLY|O_CREAT|O_TRUNC,
    // but strace prints no access flags for the creat syscall itself.
    if line.starts_with("creat(") {
        lock.insert_normalized(Behavior::FileWrite { path }, include_system, context);
        return;
    }

    // Only inspect the syscall argument region after the quoted path.
    // This prevents path names or returned -yy fd annotations containing
    // strings such as O_RDWR from impersonating access flags.
    let flags = file_open_flags(line);

    // O_PATH yields a reference used only for name resolution. It grants
    // neither read nor write access to the file contents, so recording a read
    // would overstate what the command did.
    if flags_have_token(flags, "O_PATH") {
        return;
    }

    // The access mode is a two-bit field that strace prints as exactly one of
    // O_RDONLY, O_WRONLY or O_RDWR, so a descriptor is readable unless it was
    // opened write-only.
    let write_only = flags_have_token(flags, "O_WRONLY");

    // O_CREAT and O_TRUNC mutate the file even when the access mode itself is
    // read-only, so they are write behavior in their own right. O_APPEND adds
    // no mutation beyond the write access mode that must accompany it.
    let writable = write_only
        || flags_have_token(flags, "O_RDWR")
        || flags_have_token(flags, "O_CREAT")
        || flags_have_token(flags, "O_TRUNC");

    if !write_only {
        lock.insert_normalized(
            Behavior::FileRead { path: path.clone() },
            include_system,
            context,
        );
    }

    if writable {
        lock.insert_normalized(Behavior::FileWrite { path }, include_system, context);
    }
}

fn renameat2_has_flag(line: &str, wanted: &str) -> bool {
    if !line.starts_with("renameat2(") {
        return false;
    }

    let Some(second_end) = quoted_end(line, 1) else {
        return false;
    };

    let after = line[second_end + 1..].trim_start();

    let Some(after) = after.strip_prefix(',') else {
        return false;
    };

    let flags = after
        .split_once(')')
        .map(|(flags, _)| flags.trim())
        .unwrap_or_else(|| after.trim());

    flags.split('|').map(str::trim).any(|flag| flag == wanted)
}

fn linkat_has_flag(line: &str, wanted: &str) -> bool {
    if !line.starts_with("linkat(") {
        return false;
    }

    let Some(second_end) = quoted_end(line, 1) else {
        return false;
    };

    let after = line[second_end + 1..].trim_start();

    let Some(after) = after.strip_prefix(',') else {
        return false;
    };

    let flags = after
        .split_once(')')
        .map(|(flags, _)| flags.trim())
        .unwrap_or_else(|| after.trim());

    flags.split('|').map(str::trim).any(|flag| flag == wanted)
}

fn resolve_openat(line: &str, cwd: &Path, raw: &str) -> Result<PathBuf> {
    let raw_path = PathBuf::from(raw);

    if raw_path.is_absolute() {
        return Ok(raw_path);
    }

    let open = line
        .find('(')
        .ok_or_else(|| anyhow::anyhow!("malformed openat syscall"))?
        + 1;

    let rest = &line[open..];

    let comma = rest
        .find(',')
        .ok_or_else(|| anyhow::anyhow!("malformed openat dirfd"))?;

    let dirfd = rest[..comma].trim();

    resolve_dirfd(dirfd, cwd, raw)
}

fn resolve_dirfd(dirfd: &str, cwd: &Path, raw: &str) -> Result<PathBuf> {
    let raw_path = PathBuf::from(raw);

    if raw_path.is_absolute() {
        return Ok(raw_path);
    }

    if dirfd.starts_with("AT_FDCWD") {
        return Ok(cwd.join(raw));
    }

    if let Some(base) = angle_path(dirfd) {
        return Ok(PathBuf::from(base).join(raw));
    }

    bail!("unable to resolve dirfd: {dirfd}")
}

fn resolve_path(cwd: &Path, raw: &str) -> PathBuf {
    let path = PathBuf::from(raw);

    if path.is_absolute() {
        path
    } else {
        cwd.join(path)
    }
}

fn child_pid(line: &str) -> Option<u32> {
    let child_call = line.starts_with("fork(")
        || line.starts_with("vfork(")
        || line.starts_with("clone(")
        || line.starts_with("clone3(");

    if !child_call || !syscall_succeeded(line) {
        return None;
    }

    let result = syscall_result(line)?;

    result.split_whitespace().next()?.parse::<u32>().ok()
}

fn first_fd_path(line: &str) -> Option<String> {
    angle_path(line)
}

fn parse_connect(line: &str) -> Option<Behavior> {
    if let Some(address) = extract_strace_abstract_unix_address(line) {
        return Some(Behavior::UnixAbstractConnect { address });
    }

    if let Some(path) = extract_strace_quoted_field(line, "sun_path=") {
        return Some(Behavior::UnixConnect { path });
    }

    if let Some(port) = extract_between(line, "sin_port=htons(", ")") {
        if let Some(ip) = extract_between(line, "inet_addr(\"", "\"") {
            return Some(Behavior::NetworkConnect {
                address: format!("{ip}:{port}"),
            });
        }
    }

    if let Some(port) = extract_between(line, "sin6_port=htons(", ")") {
        if let Some(ip) = extract_between(line, "inet_pton(AF_INET6, \"", "\"") {
            return Some(Behavior::NetworkConnect {
                address: format!("[{ip}]:{port}"),
            });
        }
    }

    None
}
