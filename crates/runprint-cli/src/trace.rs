use anyhow::{bail, Context, Result};
use runprint_core::{Behavior, BehaviorLock, NormalizeContext};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fs,
    path::{Path, PathBuf},
    process::Command,
};

pub fn record(command: &[String], include_system: bool) -> Result<BehaviorLock> {
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

    if !status.success() {
        eprintln!("command exited with {status}");
    }

    parse_trace_dir(
        dir.path(),
        include_system,
        &normalize_context,
        &project_root,
    )
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
        bail!("expected one root trace process, found {}", roots.len());
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
            if syscall_failed(line) {
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
        traces.insert(pid, text.lines().map(str::to_owned).collect());
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

    let write = line.contains("O_WRONLY")
        || line.contains("O_RDWR")
        || line.contains("O_CREAT")
        || line.contains("O_TRUNC");

    let behavior = if write {
        Behavior::FileWrite { path }
    } else {
        Behavior::FileRead { path }
    };

    lock.insert_normalized(behavior, include_system, context);
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

    if dirfd.starts_with("AT_FDCWD") {
        return Ok(cwd.join(raw));
    }

    if let Some(base) = angle_path(dirfd) {
        return Ok(PathBuf::from(base).join(raw));
    }

    bail!("unable to resolve openat dirfd: {dirfd}")
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

    if !child_call || syscall_failed(line) {
        return None;
    }

    let (_, result) = line.rsplit_once(" = ")?;

    result.split_whitespace().next()?.parse::<u32>().ok()
}

fn first_fd_path(line: &str) -> Option<String> {
    angle_path(line)
}

fn angle_path(value: &str) -> Option<String> {
    let start = value.find('<')? + 1;
    let rest = &value[start..];
    let end = rest.find('>')?;
    Some(rest[..end].to_string())
}

fn syscall_failed(line: &str) -> bool {
    line.contains(" = -1 ")
}

fn first_quoted_string(line: &str) -> Option<String> {
    let start = line.find('"')? + 1;
    let rest = &line[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn parse_connect(line: &str) -> Option<Behavior> {
    if let Some(path) = extract_between(line, "sun_path=\"", "\"") {
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

fn extract_between(line: &str, start: &str, end: &str) -> Option<String> {
    let start_pos = line.find(start)? + start.len();
    let rest = &line[start_pos..];
    let end_pos = rest.find(end)?;
    Some(rest[..end_pos].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_relative_path_from_cwd() {
        assert_eq!(
            resolve_path(Path::new("/project/subdir"), "output.txt"),
            PathBuf::from("/project/subdir/output.txt")
        );
    }

    #[test]
    fn resolves_openat_fdcwd() {
        let line = r#"openat(AT_FDCWD, "output.txt", O_WRONLY|O_CREAT, 0666) = 3"#;

        assert_eq!(
            resolve_openat(line, Path::new("/project/subdir"), "output.txt").unwrap(),
            PathBuf::from("/project/subdir/output.txt")
        );
    }

    #[test]
    fn resolves_openat_directory_fd() {
        let line = r#"openat(3</project/assets>, "config.json", O_RDONLY) = 4"#;

        assert_eq!(
            resolve_openat(line, Path::new("/ignored"), "config.json").unwrap(),
            PathBuf::from("/project/assets/config.json")
        );
    }
}
