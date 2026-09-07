mod enforce;
mod status;
mod trace;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use runprint_core::{
    diff,
    gate::{evaluate_gate, GatePolicy},
    Behavior, BehaviorLock,
};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::Write,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

#[derive(Parser)]
#[command(name = "runprint", version, about = "A lockfile for runtime behavior")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Record {
        #[arg(short, long, default_value = "behavior.lock")]
        output: PathBuf,

        #[arg(long)]
        include_system: bool,

        #[arg(required = true, trailing_var_arg = true)]
        command: Vec<String>,
    },

    Diff {
        old: PathBuf,
        new: PathBuf,
    },

    Check {
        #[arg(short, long, default_value = "behavior.lock")]
        baseline: PathBuf,

        #[arg(long)]
        include_system: bool,

        #[arg(long)]
        status_file: Option<PathBuf>,

        #[arg(required = true, trailing_var_arg = true)]
        command: Vec<String>,
    },

    Enforce {
        #[arg(long)]
        config: Option<PathBuf>,

        #[arg(required = true, trailing_var_arg = true)]
        command: Vec<String>,
    },

    Gate {
        #[arg(short, long, default_value = "behavior.lock")]
        baseline: PathBuf,

        #[arg(long)]
        config: Option<PathBuf>,

        #[arg(long)]
        include_system: bool,

        #[arg(long)]
        status_file: Option<PathBuf>,

        #[arg(required = true, trailing_var_arg = true)]
        command: Vec<String>,
    },
}

#[derive(Debug, Serialize)]
struct StatusReport {
    version: u32,
    operation: &'static str,
    verdict: &'static str,
    command_exit: i32,

    #[serde(skip_serializing_if = "Option::is_none")]
    added: Option<usize>,

    #[serde(skip_serializing_if = "Option::is_none")]
    removed: Option<usize>,

    #[serde(skip_serializing_if = "Option::is_none")]
    violations: Option<usize>,
}

/// The directory a status file will be created in.
fn status_directory(path: &Path) -> PathBuf {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

/// Prepares the status-file destination before the observed command runs.
///
/// Two problems are addressed here rather than at write time. An unusable
/// destination is reported before anything is executed, and any report from a
/// previous run is removed, so if Runprint fails after the command runs a
/// consumer cannot read a stale verdict and believe it describes this run.
fn prepare_status(path: Option<&Path>) -> Result<()> {
    let Some(path) = path else {
        return Ok(());
    };

    let directory = status_directory(path);

    if !directory.is_dir() {
        anyhow::bail!(
            "status file directory does not exist: {}",
            directory.display()
        );
    }

    if let Err(error) = fs::remove_file(path) {
        if error.kind() != std::io::ErrorKind::NotFound {
            return Err(error).context(format!("stale status file {}", path.display()));
        }
    }

    Ok(())
}

fn write_status(path: Option<&Path>, report: &StatusReport) -> Result<()> {
    let Some(path) = path else {
        return Ok(());
    };

    let mut json = serde_json::to_string_pretty(report)?;
    json.push('\n');

    replace_atomically(path, json.as_bytes())
        .context(format!("failed to write status file {}", path.display()))
}

/// Replaces `path` so a concurrent reader never observes a partial document.
///
/// Writing in place would leave the file truncated for the duration of the
/// write. A rename within the same directory is atomic, so a reader sees
/// either the previous report or the complete new one.
fn replace_atomically(path: &Path, bytes: &[u8]) -> Result<()> {
    let directory = status_directory(path);

    let mut file = tempfile::Builder::new()
        .prefix(".runprint-status")
        .tempfile_in(directory)?;

    file.write_all(bytes)?;

    // Rename only guarantees the name change, not that the contents reached
    // the disk, so the data is flushed before it becomes visible.
    file.as_file().sync_all()?;

    // Temporary files are created 0600, but a status file is a build artifact
    // that consumers are expected to read, as with the previous fs::write.
    file.as_file()
        .set_permissions(fs::Permissions::from_mode(0o644))?;

    file.persist(path).map_err(|error| error.error)?;

    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Record {
            output,
            include_system,
            command,
        } => {
            let run = trace::record(&command, include_system)?;
            save(&output, &run.lock)?;

            let counts = run.lock.counts();

            println!();
            println!("Runprint");
            println!();
            println!("exec       {}", counts.exec);
            println!("file read  {}", counts.file_read);
            println!("file write {}", counts.file_write);
            println!("delete     {}", counts.file_delete);
            println!("rename     {}", counts.file_rename);
            println!("exchange   {}", counts.rename_exchange);
            println!("mkdir      {}", counts.directory_create);
            println!("rmdir      {}", counts.directory_delete);
            println!("symlink    {}", counts.symlink_create);
            println!("hardlink   {}", counts.hardlink_create);
            println!("network    {}", counts.network);
            println!("unix       {}", counts.unix);
            println!("-----------");
            println!("total      {}", counts.total());
            println!();
            println!("digest     {}", run.lock.digest()?);
            println!("exit       {}", run.exit_code);
            println!("saved      {}", output.display());

            if run.exit_code != 0 {
                std::process::exit(run.exit_code);
            }
        }

        Commands::Diff { old, new } => {
            let old = load(&old)?;
            let new = load(&new)?;
            let d = diff(&old, &new);

            if d.added.is_empty() && d.removed.is_empty() {
                println!("runtime behavior unchanged");
                return Ok(());
            }

            for item in &d.added {
                println!("+ {}", render(item));
            }

            for item in &d.removed {
                println!("- {}", render(item));
            }
        }

        Commands::Enforce { config, command } => {
            let config = load_config(config.as_deref())?;

            println!();
            println!("Runprint Enforce");
            println!();
            println!("backend      landlock");
            println!("write roots  {}", config.enforce.write.len());
            println!("modify roots {}", config.enforce.modify.len());
            println!("create roots {}", config.enforce.create.len());
            println!("remove roots {}", config.enforce.remove.len());
            println!("connect tcp  {}", config.enforce.connect_tcp.len());
            println!("bind tcp     {}", config.enforce.bind_tcp.len());

            let exit_code = enforce::run(&command, &config.enforce)?;

            println!("exit       {exit_code}");

            if exit_code != 0 {
                std::process::exit(exit_code);
            }
        }

        Commands::Gate {
            baseline,
            config,
            include_system,
            status_file,
            command,
        } => {
            let baseline = load(&baseline)?;
            let policy = load_gate_policy(config.as_deref())?;

            prepare_status(status_file.as_deref())?;

            let run = trace::record(&command, include_system)?;
            let result = evaluate_gate(&baseline, &run.lock, &policy);

            write_status(
                status_file.as_deref(),
                &StatusReport {
                    version: 1,
                    operation: "gate",
                    verdict: if result.allowed { "allow" } else { "deny" },
                    command_exit: run.exit_code,
                    added: None,
                    removed: None,
                    violations: Some(result.violations.len()),
                },
            )?;

            println!();
            println!("Runprint Gate");
            println!();

            if result.allowed {
                println!("ALLOW");
                println!("no restricted runtime drift");

                if run.exit_code != 0 {
                    eprintln!("command exited with {}", run.exit_code);
                    std::process::exit(run.exit_code);
                }

                return Ok(());
            }

            println!("DENY");
            println!();

            for violation in &result.violations {
                println!("! {}", render(violation));
            }

            println!();
            println!("violations {}", result.violations.len());

            std::process::exit(20);
        }

        Commands::Check {
            baseline,
            include_system,
            status_file,
            command,
        } => {
            let expected = load(&baseline)?;

            prepare_status(status_file.as_deref())?;

            let run = trace::record(&command, include_system)?;
            let d = diff(&expected, &run.lock);
            let changed = !d.added.is_empty() || !d.removed.is_empty();

            write_status(
                status_file.as_deref(),
                &StatusReport {
                    version: 1,
                    operation: "check",
                    verdict: if changed { "changed" } else { "unchanged" },
                    command_exit: run.exit_code,
                    added: Some(d.added.len()),
                    removed: Some(d.removed.len()),
                    violations: None,
                },
            )?;

            if !changed {
                println!();
                println!("runtime behavior unchanged");

                if run.exit_code != 0 {
                    eprintln!("command exited with {}", run.exit_code);
                    std::process::exit(run.exit_code);
                }

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

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RunprintConfig {
    version: u32,

    #[serde(default)]
    gate: GatePolicy,

    #[serde(default)]
    enforce: enforce::EnforcePolicy,
}

impl Default for RunprintConfig {
    fn default() -> Self {
        Self {
            version: 1,
            gate: GatePolicy::default(),
            enforce: enforce::EnforcePolicy::default(),
        }
    }
}

fn load_gate_policy(explicit: Option<&Path>) -> Result<GatePolicy> {
    Ok(load_config(explicit)?.gate)
}

fn load_config(explicit: Option<&Path>) -> Result<RunprintConfig> {
    let default_path = Path::new(".runprint.toml");
    let path = explicit.unwrap_or(default_path);

    if !path.exists() {
        if explicit.is_some() {
            anyhow::bail!("config not found: {}", path.display());
        }

        return Ok(RunprintConfig::default());
    }

    let raw = fs::read_to_string(path).context(format!("failed to read {}", path.display()))?;

    let config: RunprintConfig =
        toml::from_str(&raw).context(format!("invalid config {}", path.display()))?;

    if config.version != 1 {
        anyhow::bail!(
            "unsupported config version {} in {}",
            config.version,
            path.display()
        );
    }

    // A pattern that can never match, or one that would match everything, is
    // an authoring error. Reporting it here names the config file instead of
    // letting it quietly change a gate verdict.
    config
        .gate
        .validate()
        .context(format!("invalid gate policy in {}", path.display()))?;

    Ok(config)
}

fn save(path: &Path, lock: &BehaviorLock) -> Result<()> {
    let json = lock.canonical_json()?;

    fs::write(path, json).context(format!("failed to write {}", path.display()))?;

    Ok(())
}

#[derive(Debug, Deserialize)]
struct BehaviorLockHeader {
    version: u32,
}

fn parse_lock(raw: &[u8]) -> Result<BehaviorLock> {
    let header: BehaviorLockHeader = serde_json::from_slice(raw)?;

    if !BehaviorLock::is_supported_version(header.version) {
        anyhow::bail!("unsupported behavior lock version {}", header.version);
    }

    Ok(serde_json::from_slice(raw)?)
}

fn load(path: &Path) -> Result<BehaviorLock> {
    let raw = fs::read(path).context(format!("failed to read {}", path.display()))?;

    parse_lock(&raw).context(format!("invalid lock {}", path.display()))
}

fn render(item: &Behavior) -> String {
    match item {
        Behavior::Exec { path } => format!("exec     {path}"),
        Behavior::FileRead { path } => format!("read     {path}"),
        Behavior::FileWrite { path } => format!("write    {path}"),
        Behavior::FileDelete { path } => format!("delete   {path}"),
        Behavior::FileRename { from, to } => format!("rename   {from} -> {to}"),
        Behavior::RenameExchange { left, right } => {
            format!("exchange {left} <-> {right}")
        }
        Behavior::DirectoryCreate { path } => format!("mkdir    {path}"),
        Behavior::DirectoryDelete { path } => format!("rmdir    {path}"),
        Behavior::SymlinkCreate { target, link } => {
            format!("symlink  {link} -> {target}")
        }
        Behavior::HardlinkCreate {
            from,
            to,
            follow_symlink,
            empty_path,
        } => {
            let mut flags = Vec::new();

            if *follow_symlink {
                flags.push("AT_SYMLINK_FOLLOW");
            }

            if *empty_path {
                flags.push("AT_EMPTY_PATH");
            }

            if flags.is_empty() {
                format!("hardlink {from} -> {to}")
            } else {
                format!("hardlink {from} -> {to} [{}]", flags.join("|"))
            }
        }
        Behavior::NetworkConnect { address } => format!("connect  {address}"),
        Behavior::UnixConnect { path } => format!("ipc      {path}"),
        Behavior::UnixAbstractConnect { address } => {
            format!("ipc      {address}")
        }
    }
}

#[cfg(test)]
mod config_tests {
    use super::*;

    #[test]
    fn lock_loader_accepts_legacy_v1() {
        let raw = br#"{
            "version": 1,
            "behaviors": []
        }"#;

        let lock = parse_lock(raw).unwrap();

        assert_eq!(lock.version, 1);
        assert!(lock.behaviors.is_empty());
    }

    #[test]
    fn lock_loader_accepts_legacy_v2() {
        let raw = br#"{
            "version": 2,
            "behaviors": []
        }"#;

        let lock = parse_lock(raw).unwrap();

        assert_eq!(lock.version, 2);
        assert!(lock.behaviors.is_empty());
    }

    #[test]
    fn lock_loader_accepts_legacy_v3() {
        let raw = br#"{
            "version": 3,
            "behaviors": [
                {
                    "kind": "unix_abstract_connect",
                    "address": "@runprint-abstract"
                }
            ]
        }"#;

        let lock = parse_lock(raw).unwrap();

        assert_eq!(lock.version, 3);
        assert!(lock.behaviors.contains(&Behavior::UnixAbstractConnect {
            address: "@runprint-abstract".into(),
        }));
    }

    #[test]
    fn lock_loader_accepts_current_v4() {
        let raw = br#"{
            "version": 4,
            "behaviors": [
                {
                    "kind": "hardlink_create",
                    "from": "$PROJECT/source-link",
                    "to": "$PROJECT/out",
                    "follow_symlink": true
                }
            ]
        }"#;

        let lock = parse_lock(raw).unwrap();

        assert_eq!(lock.version, 4);
        assert!(lock.behaviors.contains(&Behavior::HardlinkCreate {
            from: "$PROJECT/source-link".into(),
            to: "$PROJECT/out".into(),
            follow_symlink: true,
            empty_path: false,
        }));
    }

    #[test]
    fn lock_loader_rejects_future_version_before_behavior_decode() {
        let raw = br#"{
            "version": 5,
            "behaviors": [
                {
                    "kind": "future_behavior_that_this_binary_does_not_know",
                    "value": "x"
                }
            ]
        }"#;

        let error = parse_lock(raw).unwrap_err();

        assert_eq!(error.to_string(), "unsupported behavior lock version 5");
    }

    #[test]
    fn config_rejects_unknown_gate_key() {
        let raw = r#"
version = 1

[gate]
allow_new_reads = true
deny_wirte = ["$PROJECT/**"]
"#;

        let result = toml::from_str::<RunprintConfig>(raw);

        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_unknown_top_level_key() {
        let raw = r#"
version = 1
mystery = true

[gate]
allow_new_reads = true
"#;

        let result = toml::from_str::<RunprintConfig>(raw);

        assert!(result.is_err());
    }

    #[test]
    fn config_defaults_to_version_one() {
        let raw = r#"
[gate]
allow_new_reads = false
"#;

        let config = toml::from_str::<RunprintConfig>(raw).unwrap();

        assert_eq!(config.version, 1);
        assert!(!config.gate.allow_new_reads);
    }

    /// A degenerate pattern must be refused where it can be attributed to a
    /// file and a field, not silently applied.
    #[test]
    fn config_rejects_a_degenerate_gate_pattern() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("runprint.toml");

        let raw = r#"
version = 1

[gate]
allow_write = ["prefix:"]
"#;

        fs::write(&path, raw).unwrap();

        let error = load_config(Some(path.as_path())).unwrap_err();
        let message = format!("{error:#}");

        assert!(message.contains("invalid gate policy"));
        assert!(message.contains("allow_write"));
    }

    #[test]
    fn config_accepts_a_scoped_gate_policy() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("runprint.toml");

        let raw = r#"
version = 1

[gate]
allow_write = ["$PROJECT/dist/**"]
"#;

        fs::write(&path, raw).unwrap();

        let config = load_config(Some(path.as_path())).unwrap();

        assert_eq!(config.gate.allow_write.len(), 1);
    }

    #[test]
    fn missing_config_names_the_path() {
        let error = load_config(Some(Path::new("no-such-config.toml")));
        let error = error.unwrap_err();

        assert!(error.to_string().contains("no-such-config.toml"));
    }

    #[test]
    fn missing_lock_names_the_path() {
        let error = load(Path::new("no-such-behavior.lock")).unwrap_err();
        let message = format!("{error:#}");

        assert!(message.contains("no-such-behavior.lock"));
    }

    /// A consumer reads a status file to decide what happens next, so it must
    /// never see a partial document, and never a previous run's verdict.
    #[test]
    fn status_report_is_complete_and_replaces_prior_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("status.json");

        fs::write(&path, "{ truncated").unwrap();

        let report = StatusReport {
            version: 1,
            operation: "gate",
            verdict: "deny",
            command_exit: 0,
            added: None,
            removed: None,
            violations: Some(2),
        };

        write_status(Some(path.as_path()), &report).unwrap();

        let raw = fs::read_to_string(&path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&raw).unwrap();

        assert_eq!(parsed["operation"], "gate");
        assert_eq!(parsed["verdict"], "deny");
        assert_eq!(parsed["violations"], 2);
        assert!(parsed.get("added").is_none());
        assert!(raw.ends_with('\n'));
    }

    /// The child result and the Runprint verdict are independent fields, so a
    /// failing command under an allowed gate stays distinguishable.
    #[test]
    fn status_report_keeps_child_exit_independent_of_verdict() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("status.json");

        let report = StatusReport {
            version: 1,
            operation: "gate",
            verdict: "allow",
            command_exit: 20,
            added: None,
            removed: None,
            violations: Some(0),
        };

        write_status(Some(path.as_path()), &report).unwrap();

        let raw = fs::read_to_string(&path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&raw).unwrap();

        assert_eq!(parsed["verdict"], "allow");
        assert_eq!(parsed["command_exit"], 20);
    }

    #[test]
    fn prepare_status_removes_a_stale_report() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("status.json");

        fs::write(&path, "{\"verdict\":\"allow\"}").unwrap();

        prepare_status(Some(path.as_path())).unwrap();

        assert!(!path.exists());
    }

    #[test]
    fn prepare_status_rejects_a_missing_directory() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("missing").join("status.json");

        let error = prepare_status(Some(path.as_path())).unwrap_err();

        assert!(error.to_string().contains("does not exist"));
    }

    #[test]
    fn prepare_status_accepts_a_missing_report() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("status.json");

        assert!(prepare_status(Some(path.as_path())).is_ok());
    }

    #[test]
    fn no_status_file_is_not_an_error() {
        assert!(prepare_status(None).is_ok());

        let report = StatusReport {
            version: 1,
            operation: "check",
            verdict: "unchanged",
            command_exit: 0,
            added: Some(0),
            removed: Some(0),
            violations: None,
        };

        assert!(write_status(None, &report).is_ok());
    }

    #[test]
    fn status_directory_defaults_to_the_current_directory() {
        let directory = status_directory(Path::new("status.json"));

        assert_eq!(directory, PathBuf::from("."));
    }
}
