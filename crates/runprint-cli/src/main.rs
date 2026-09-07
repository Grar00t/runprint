use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use runprint_core::{diff, Behavior, BehaviorLock, NormalizeContext};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

#[derive(Parser)]
#[command(name = "runprint", version, about = "A lockfile for runtime behavior")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Record a command's observable runtime behavior.
    Record {
        #[arg(short, long, default_value = "behavior.lock")]
        output: PathBuf,

        /// Include dynamic-loader, procfs and other runtime noise.
        #[arg(long)]
        include_system: bool,

        #[arg(required = true, trailing_var_arg = true)]
        command: Vec<String>,
    },

    /// Compare two behavior lockfiles.
    Diff { old: PathBuf, new: PathBuf },

    /// Run a command and compare its behavior with a baseline.
    Check {
        #[arg(short, long, default_value = "behavior.lock")]
        baseline: PathBuf,

        #[arg(long)]
        include_system: bool,

        #[arg(required = true, trailing_var_arg = true)]
        command: Vec<String>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Record {
            output,
            include_system,
            command,
        } => {
            let lock = record(&command, include_system)?;
            save(&output, &lock)?;

            let counts = lock.counts();

            println!();
            println!("Runprint");
            println!();
            println!("exec       {}", counts.exec);
            println!("file read  {}", counts.file_read);
            println!("file write {}", counts.file_write);
            println!("network    {}", counts.network);
            println!("unix       {}", counts.unix);
            println!("-----------");
            println!("total      {}", counts.total());
            println!();
            println!("digest     {}", lock.digest()?);
            println!("saved      {}", output.display());
        }

        Commands::Diff { old, new } => {
            let old = load(&old)?;
            let new = load(&new)?;

            let changed = print_diff(&old, &new);

            if !changed {
                println!("runtime behavior unchanged");
            }
        }

        Commands::Check {
            baseline,
            include_system,
            command,
        } => {
            let expected = load(&baseline)?;
            let observed = record(&command, include_system)?;
            let d = diff(&expected, &observed);

            if d.added.is_empty() && d.removed.is_empty() {
                println!();
                println!("runtime behavior unchanged");
                return Ok(());
            }

            println!();
            println!("RUNTIME BEHAVIOR CHANGED");
            println!();

            for item in &d.added {
                println!("+ {}", render(item));
            }

            for item in &d.removed {
                println!("- {}", render(item));
            }

            std::process::exit(10);
        }
    }

    Ok(())
}

fn record(command: &[String], include_system: bool) -> Result<BehaviorLock> {
    if command.is_empty() {
        bail!("missing command");
    }

    let project_root = std::env::current_dir().context("failed to determine current directory")?;

    let home = std::env::var_os("HOME").map(PathBuf::from);

    let normalize_context = NormalizeContext::new(project_root, home, std::env::temp_dir());

    let dir = tempfile::tempdir()?;
    let prefix = dir.path().join("trace");

    let status = Command::new("strace")
        .arg("-ff")
        .arg("-qq")
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

    parse_trace_dir(dir.path(), include_system, &normalize_context)
}

fn parse_trace_dir(
    dir: &Path,
    include_system: bool,
    normalize_context: &NormalizeContext,
) -> Result<BehaviorLock> {
    let mut lock = BehaviorLock::new();

    let mut entries = fs::read_dir(dir)?.collect::<std::io::Result<Vec<_>>>()?;

    entries.sort_by_key(|entry| entry.path());

    for entry in entries {
        let text = fs::read_to_string(entry.path())?;

        for line in text.lines() {
            parse_line(line, &mut lock, include_system, normalize_context);
        }
    }

    Ok(lock)
}

fn parse_line(
    line: &str,
    lock: &mut BehaviorLock,
    include_system: bool,
    normalize_context: &NormalizeContext,
) {
    if line.starts_with("execve(") {
        if syscall_failed(line) {
            return;
        }

        if let Some(path) = first_quoted_string(line) {
            lock.insert_normalized(Behavior::Exec { path }, include_system, normalize_context);
        }

        return;
    }

    if line.starts_with("open(") || line.starts_with("openat(") || line.starts_with("creat(") {
        if syscall_failed(line) {
            return;
        }

        if let Some(path) = first_quoted_string(line) {
            let write = line.contains("O_WRONLY")
                || line.contains("O_RDWR")
                || line.contains("O_CREAT")
                || line.contains("O_TRUNC");

            let behavior = if write {
                Behavior::FileWrite { path }
            } else {
                Behavior::FileRead { path }
            };

            lock.insert_normalized(behavior, include_system, normalize_context);
        }

        return;
    }

    if line.starts_with("connect(") {
        if let Some(behavior) = parse_connect(line) {
            lock.insert_normalized(behavior, include_system, normalize_context);
        }
    }
}

fn syscall_failed(line: &str) -> bool {
    line.contains(" = -1 ")
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

fn first_quoted_string(line: &str) -> Option<String> {
    let start = line.find('"')? + 1;
    let rest = &line[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn save(path: &Path, lock: &BehaviorLock) -> Result<()> {
    fs::write(path, lock.canonical_json()?)?;
    Ok(())
}

fn load(path: &Path) -> Result<BehaviorLock> {
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

fn print_diff(old: &BehaviorLock, new: &BehaviorLock) -> bool {
    let d = diff(old, new);

    for item in &d.added {
        println!("+ {}", render(item));
    }

    for item in &d.removed {
        println!("- {}", render(item));
    }

    !d.added.is_empty() || !d.removed.is_empty()
}

fn render(item: &Behavior) -> String {
    match item {
        Behavior::Exec { path } => format!("exec     {path}"),
        Behavior::FileRead { path } => format!("read     {path}"),
        Behavior::FileWrite { path } => format!("write    {path}"),
        Behavior::NetworkConnect { address } => {
            format!("connect  {address}")
        }
        Behavior::UnixConnect { path } => {
            format!("ipc      {path}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_connect() {
        let line = r#"connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("203.0.113.5")}, 16) = 0"#;

        assert_eq!(
            parse_connect(line),
            Some(Behavior::NetworkConnect {
                address: "203.0.113.5:443".into()
            })
        );
    }

    #[test]
    fn parses_unix_connect() {
        let line = r#"connect(3, {sa_family=AF_UNIX, sun_path="/run/example.sock"}, 110) = 0"#;

        assert_eq!(
            parse_connect(line),
            Some(Behavior::UnixConnect {
                path: "/run/example.sock".into()
            })
        );
    }

    #[test]
    fn detects_failed_syscall() {
        assert!(syscall_failed(
            r#"openat(AT_FDCWD, "/missing", O_RDONLY) = -1 ENOENT (No such file or directory)"#
        ));
    }
}
