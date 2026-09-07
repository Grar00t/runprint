use anyhow::{bail, Context, Result};
use landlock::{
    make_bitflags, AccessFs, AccessNet, BitFlags, CompatLevel, Compatible, NetPort, PathBeneath,
    PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus,
};
use serde::Deserialize;
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct EnforcePolicy {
    /// Broad filesystem mutation permission.
    /// Includes modify, create, remove, link, rename/refer, and truncate.
    pub write: Vec<String>,

    /// Narrow permission for modifying existing regular files only.
    /// Does not allow creating or deleting filesystem entries.
    pub modify: Vec<String>,

    /// Permission to create filesystem entries beneath a directory.
    /// This grants Landlock MAKE_* rights only.
    pub create: Vec<String>,

    /// Permission to remove filesystem entries beneath a directory.
    pub remove: Vec<String>,

    /// Allowed TCP destination ports.
    /// Empty means TCP connect is not restricted by Runprint.
    pub connect_tcp: Vec<u16>,

    /// Allowed local TCP bind ports.
    /// Empty means TCP bind is not restricted by Runprint.
    pub bind_tcp: Vec<u16>,
}

pub fn run(command: &[String], policy: &EnforcePolicy) -> Result<i32> {
    if command.is_empty() {
        bail!("missing command");
    }

    let project_root = env::current_dir().context("failed to determine current directory")?;

    apply_policy(policy, &project_root)?;

    let status = Command::new(&command[0])
        .args(&command[1..])
        .status()
        .with_context(|| format!("failed to execute {}", command[0]))?;

    Ok(status.code().unwrap_or(128))
}

fn apply_policy(policy: &EnforcePolicy, project_root: &Path) -> Result<()> {
    let mut builder = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(write_access())?;

    if !policy.connect_tcp.is_empty() {
        builder = builder.handle_access(AccessNet::ConnectTcp)?;
    }

    if !policy.bind_tcp.is_empty() {
        builder = builder.handle_access(AccessNet::BindTcp)?;
    }

    let mut ruleset = builder.create()?;

    // Backward-compatible broad mutation roots.
    for pattern in &policy.write {
        let (path, recursive) = resolve_write_rule(pattern, project_root)?;

        let access = if recursive {
            write_access()
        } else {
            file_write_access()
        };

        ruleset = add_path_rule(ruleset, &path, access)?;
    }

    // Existing-file modification roots.
    for pattern in &policy.modify {
        let (path, _) = resolve_write_rule(pattern, project_root)?;

        ruleset = add_path_rule(ruleset, &path, file_write_access())?;
    }

    // Filesystem entry creation roots.
    for pattern in &policy.create {
        let (path, recursive) = resolve_write_rule(pattern, project_root)?;

        if !recursive {
            bail!("create enforcement roots must be directories ending with /**: {pattern}");
        }

        ruleset = add_path_rule(ruleset, &path, create_access())?;
    }

    // Filesystem entry removal roots.
    for pattern in &policy.remove {
        let (path, recursive) = resolve_write_rule(pattern, project_root)?;

        if !recursive {
            bail!("remove enforcement roots must be directories ending with /**: {pattern}");
        }

        ruleset = add_path_rule(ruleset, &path, remove_access())?;
    }

    // TCP destination-port allowlist.
    for port in &policy.connect_tcp {
        ruleset = ruleset.add_rule(NetPort::new(*port, AccessNet::ConnectTcp))?;
    }

    // Local TCP bind-port allowlist.
    for port in &policy.bind_tcp {
        ruleset = ruleset.add_rule(NetPort::new(*port, AccessNet::BindTcp))?;
    }

    let status = ruleset.restrict_self()?;

    if status.ruleset != RulesetStatus::FullyEnforced || !status.no_new_privs {
        bail!(
            "Landlock enforcement is not fully active: ruleset={:?}, no_new_privs={}",
            status.ruleset,
            status.no_new_privs
        );
    }

    Ok(())
}

fn add_path_rule(
    ruleset: landlock::RulesetCreated,
    path: &Path,
    access: BitFlags<AccessFs>,
) -> Result<landlock::RulesetCreated> {
    let fd = PathFd::new(path).map_err(|error| {
        anyhow::anyhow!(
            "failed to open enforcement path {}: {error}",
            path.display()
        )
    })?;

    Ok(ruleset.add_rule(PathBeneath::new(fd, access))?)
}

fn write_access() -> BitFlags<AccessFs> {
    make_bitflags!(AccessFs::{
        WriteFile
        | RemoveDir
        | RemoveFile
        | MakeChar
        | MakeDir
        | MakeReg
        | MakeSock
        | MakeFifo
        | MakeBlock
        | MakeSym
        | Refer
        | Truncate
    })
}

fn file_write_access() -> BitFlags<AccessFs> {
    make_bitflags!(AccessFs::{
        WriteFile
        | Truncate
    })
}

fn create_access() -> BitFlags<AccessFs> {
    make_bitflags!(AccessFs::{
        MakeChar
        | MakeDir
        | MakeReg
        | MakeSock
        | MakeFifo
        | MakeBlock
        | MakeSym
    })
}

fn remove_access() -> BitFlags<AccessFs> {
    make_bitflags!(AccessFs::{
        RemoveDir
        | RemoveFile
    })
}

fn resolve_write_rule(pattern: &str, project_root: &Path) -> Result<(PathBuf, bool)> {
    let (raw, recursive) = match pattern.strip_suffix("/**") {
        Some("") => ("/", true),
        Some(base) => (base, true),
        None => (pattern, false),
    };

    if raw.contains('*') {
        bail!("unsupported enforcement wildcard in {pattern}; only /** is supported");
    }

    let expanded = expand_path(raw, project_root)?;

    let canonical = fs::canonicalize(&expanded)
        .with_context(|| format!("enforcement path does not exist: {}", expanded.display()))?;

    if is_project_scoped(raw) {
        let canonical_project_root =
            fs::canonicalize(project_root).context("failed to canonicalize project root")?;

        if !canonical.starts_with(&canonical_project_root) {
            bail!(
                "project-scoped enforcement path escapes project root: {} -> {}",
                expanded.display(),
                canonical.display()
            );
        }
    }

    let metadata = fs::metadata(&canonical)?;

    if recursive {
        if !metadata.is_dir() {
            bail!(
                "recursive enforcement path is not a directory: {}",
                canonical.display()
            );
        }
    } else if metadata.is_dir() {
        bail!("directory enforcement paths must end with /**: {}", pattern);
    }

    Ok((canonical, recursive))
}

fn is_project_scoped(raw: &str) -> bool {
    raw == "$PROJECT"
        || raw.starts_with("$PROJECT/")
        || (!raw.starts_with('$') && !Path::new(raw).is_absolute())
}

fn expand_path(raw: &str, project_root: &Path) -> Result<PathBuf> {
    if let Some(path) = expand_prefix(raw, "$PROJECT", project_root) {
        return Ok(path);
    }

    if raw == "$HOME" || raw.starts_with("$HOME/") {
        let home = env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or_else(|| anyhow::anyhow!("HOME is not set"))?;

        return expand_prefix(raw, "$HOME", &home)
            .ok_or_else(|| anyhow::anyhow!("invalid $HOME path: {raw}"));
    }

    if raw == "$TMP" || raw.starts_with("$TMP/") {
        let temp = env::temp_dir();

        return expand_prefix(raw, "$TMP", &temp)
            .ok_or_else(|| anyhow::anyhow!("invalid $TMP path: {raw}"));
    }

    if raw.starts_with('$') {
        bail!("unsupported enforcement path variable: {raw}");
    }

    let path = PathBuf::from(raw);

    if path.is_absolute() {
        Ok(path)
    } else {
        Ok(project_root.join(path))
    }
}

fn expand_prefix(raw: &str, token: &str, base: &Path) -> Option<PathBuf> {
    if raw == token {
        return Some(base.to_path_buf());
    }

    let rest = raw.strip_prefix(token)?.strip_prefix('/')?;

    Some(base.join(rest))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn project_prefix_expands() {
        assert_eq!(
            expand_path("$PROJECT/dist", Path::new("/home/test/project"),).unwrap(),
            PathBuf::from("/home/test/project/dist")
        );
    }

    #[test]
    fn unknown_variable_is_rejected() {
        assert!(expand_path("$UNKNOWN/file", Path::new("/project")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn project_symlink_escape_is_rejected() {
        use std::os::unix::fs::symlink;

        let project = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();

        symlink(outside.path(), project.path().join("escape")).unwrap();

        let result = resolve_write_rule("$PROJECT/escape/**", project.path());

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("escapes project root"));
    }

    #[cfg(unix)]
    #[test]
    fn project_symlink_to_inside_is_allowed() {
        use std::os::unix::fs::symlink;

        let project = tempfile::tempdir().unwrap();
        let inside = project.path().join("inside");

        fs::create_dir(&inside).unwrap();
        symlink(&inside, project.path().join("alias")).unwrap();

        let (resolved, recursive) =
            resolve_write_rule("$PROJECT/alias/**", project.path()).unwrap();

        assert!(recursive);
        assert_eq!(resolved, fs::canonicalize(&inside).unwrap());
    }

    #[test]
    fn network_ports_parse_from_policy() {
        let policy: EnforcePolicy = toml::from_str(
            r#"
connect_tcp = [443, 5432]
bind_tcp = [3000]
"#,
        )
        .unwrap();

        assert_eq!(policy.connect_tcp, vec![443, 5432]);

        assert_eq!(policy.bind_tcp, vec![3000]);
    }
}
