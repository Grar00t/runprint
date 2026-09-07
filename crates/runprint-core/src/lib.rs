use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Ord, PartialOrd)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Behavior {
    Exec { path: String },
    FileRead { path: String },
    FileWrite { path: String },
    FileDelete { path: String },
    FileRename { from: String, to: String },
    DirectoryCreate { path: String },
    DirectoryDelete { path: String },
    SymlinkCreate { target: String, link: String },
    HardlinkCreate { from: String, to: String },
    NetworkConnect { address: String },
    UnixConnect { path: String },
}

#[derive(Debug, Clone)]
pub struct NormalizeContext {
    pub project_root: PathBuf,
    pub home: Option<PathBuf>,
    pub temp: PathBuf,
}

impl NormalizeContext {
    pub fn new(project_root: PathBuf, home: Option<PathBuf>, temp: PathBuf) -> Self {
        Self {
            project_root,
            home,
            temp,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BehaviorLock {
    pub version: u32,
    pub behaviors: BTreeSet<Behavior>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct BehaviorCounts {
    pub exec: usize,
    pub file_read: usize,
    pub file_write: usize,
    pub file_delete: usize,
    pub file_rename: usize,
    pub directory_create: usize,
    pub directory_delete: usize,
    pub symlink_create: usize,
    pub hardlink_create: usize,
    pub network: usize,
    pub unix: usize,
}

impl BehaviorCounts {
    pub fn total(&self) -> usize {
        self.exec
            + self.file_read
            + self.file_write
            + self.file_delete
            + self.file_rename
            + self.directory_create
            + self.directory_delete
            + self.symlink_create
            + self.hardlink_create
            + self.network
            + self.unix
    }
}

impl BehaviorLock {
    pub fn new() -> Self {
        Self {
            version: 1,
            behaviors: BTreeSet::new(),
        }
    }

    pub fn insert(&mut self, behavior: Behavior) {
        self.behaviors.insert(behavior);
    }

    pub fn insert_normalized(
        &mut self,
        behavior: Behavior,
        include_system: bool,
        context: &NormalizeContext,
    ) {
        if let Some(behavior) = normalize_behavior(behavior, include_system, context) {
            self.insert(behavior);
        }
    }

    pub fn counts(&self) -> BehaviorCounts {
        let mut counts = BehaviorCounts::default();

        for behavior in &self.behaviors {
            match behavior {
                Behavior::Exec { .. } => counts.exec += 1,
                Behavior::FileRead { .. } => counts.file_read += 1,
                Behavior::FileWrite { .. } => counts.file_write += 1,
                Behavior::FileDelete { .. } => counts.file_delete += 1,
                Behavior::FileRename { .. } => counts.file_rename += 1,
                Behavior::DirectoryCreate { .. } => counts.directory_create += 1,
                Behavior::DirectoryDelete { .. } => counts.directory_delete += 1,
                Behavior::SymlinkCreate { .. } => counts.symlink_create += 1,
                Behavior::HardlinkCreate { .. } => counts.hardlink_create += 1,
                Behavior::NetworkConnect { .. } => counts.network += 1,
                Behavior::UnixConnect { .. } => counts.unix += 1,
            }
        }

        counts
    }

    pub fn canonical_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    pub fn digest(&self) -> Result<String, serde_json::Error> {
        let bytes = serde_json::to_vec(self)?;
        Ok(blake3::hash(&bytes).to_hex().to_string())
    }
}

impl Default for BehaviorLock {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct BehaviorDiff {
    pub added: Vec<Behavior>,
    pub removed: Vec<Behavior>,
}

pub fn diff(old: &BehaviorLock, new: &BehaviorLock) -> BehaviorDiff {
    BehaviorDiff {
        added: new.behaviors.difference(&old.behaviors).cloned().collect(),
        removed: old.behaviors.difference(&new.behaviors).cloned().collect(),
    }
}

pub fn normalize_behavior(
    behavior: Behavior,
    include_system: bool,
    context: &NormalizeContext,
) -> Option<Behavior> {
    match behavior {
        Behavior::FileRead { path } => {
            let path = normalize_runtime_path(&path, context);

            if !include_system && is_runtime_noise(&path) {
                return None;
            }

            Some(Behavior::FileRead { path })
        }

        Behavior::FileWrite { path } => Some(Behavior::FileWrite {
            path: normalize_runtime_path(&path, context),
        }),

        Behavior::FileDelete { path } => Some(Behavior::FileDelete {
            path: normalize_runtime_path(&path, context),
        }),

        Behavior::FileRename { from, to } => Some(Behavior::FileRename {
            from: normalize_runtime_path(&from, context),
            to: normalize_runtime_path(&to, context),
        }),

        Behavior::DirectoryCreate { path } => Some(Behavior::DirectoryCreate {
            path: normalize_runtime_path(&path, context),
        }),

        Behavior::DirectoryDelete { path } => Some(Behavior::DirectoryDelete {
            path: normalize_runtime_path(&path, context),
        }),

        Behavior::SymlinkCreate { target, link } => Some(Behavior::SymlinkCreate {
            target,
            link: normalize_runtime_path(&link, context),
        }),

        Behavior::HardlinkCreate { from, to } => Some(Behavior::HardlinkCreate {
            from: normalize_runtime_path(&from, context),
            to: normalize_runtime_path(&to, context),
        }),

        Behavior::Exec { path } => Some(Behavior::Exec {
            path: normalize_runtime_path(&path, context),
        }),

        Behavior::UnixConnect { path } => {
            let path = normalize_runtime_path(&path, context);

            if !include_system && is_runtime_socket_noise(&path) {
                return None;
            }

            Some(Behavior::UnixConnect { path })
        }

        Behavior::NetworkConnect { address } => Some(Behavior::NetworkConnect { address }),
    }
}

fn normalize_runtime_path(raw: &str, context: &NormalizeContext) -> String {
    let raw = lexical_clean(raw);

    if raw == "." {
        return "$PROJECT".into();
    }

    let path = PathBuf::from(&raw);

    let absolute = if path.is_absolute() {
        path
    } else {
        context.project_root.join(path)
    };

    let absolute = PathBuf::from(lexical_clean(&absolute.to_string_lossy()));

    if let Some(rel) = strip_prefix(&absolute, &context.project_root) {
        return symbolic("$PROJECT", rel);
    }

    if let Some(home) = &context.home {
        if let Some(rel) = strip_prefix(&absolute, home) {
            return symbolic("$HOME", rel);
        }
    }

    if let Some(rel) = strip_prefix(&absolute, &context.temp) {
        return symbolic("$TMP", rel);
    }

    absolute.to_string_lossy().into_owned()
}

fn strip_prefix<'a>(path: &'a Path, base: &Path) -> Option<&'a Path> {
    path.strip_prefix(base).ok()
}

fn symbolic(prefix: &str, rel: &Path) -> String {
    if rel.as_os_str().is_empty() {
        prefix.to_string()
    } else {
        format!("{prefix}/{}", rel.to_string_lossy())
    }
}

fn lexical_clean(path: &str) -> String {
    let absolute = path.starts_with('/');
    let mut parts: Vec<&str> = Vec::new();

    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if parts.last().copied() != Some("..") && !parts.is_empty() {
                    parts.pop();
                } else if !absolute {
                    parts.push("..");
                }
            }
            _ => parts.push(part),
        }
    }

    let joined = parts.join("/");

    if absolute {
        if joined.is_empty() {
            "/".into()
        } else {
            format!("/{joined}")
        }
    } else if joined.is_empty() {
        ".".into()
    } else {
        joined
    }
}

fn is_runtime_noise(path: &str) -> bool {
    matches!(
        path,
        "/etc/ld.so.cache"
            | "/etc/localtime"
            | "/proc/filesystems"
            | "/proc/mounts"
            | "/proc/self/maps"
            | "/proc/self/mountinfo"
    ) || path.starts_with("/proc/self/")
        || path.starts_with("/usr/share/locale/")
        || path.starts_with("/usr/share/coreutils/locales/")
        || path.starts_with("/usr/share/zoneinfo/")
        || path.starts_with("/usr/lib/locale/")
        || path.contains("/gconv/gconv-modules.cache")
        || is_shared_library(path)
}

fn is_shared_library(path: &str) -> bool {
    let system_lib = path.starts_with("/lib/")
        || path.starts_with("/lib64/")
        || path.starts_with("/usr/lib/")
        || path.starts_with("/usr/lib64/");

    system_lib && path.contains(".so")
}

fn is_runtime_socket_noise(path: &str) -> bool {
    matches!(path, "/var/run/nscd/socket" | "/run/nscd/socket")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> NormalizeContext {
        NormalizeContext::new(
            PathBuf::from("/home/test/project"),
            Some(PathBuf::from("/home/test")),
            PathBuf::from("/tmp"),
        )
    }

    #[test]
    fn behavior_is_deduplicated() {
        let mut lock = BehaviorLock::new();

        lock.insert(Behavior::Exec {
            path: "/bin/echo".into(),
        });

        lock.insert(Behavior::Exec {
            path: "/bin/echo".into(),
        });

        assert_eq!(lock.behaviors.len(), 1);
    }

    #[test]
    fn diff_detects_new_behavior() {
        let old = BehaviorLock::new();

        let mut new = BehaviorLock::new();

        new.insert(Behavior::NetworkConnect {
            address: "203.0.113.10:443".into(),
        });

        let d = diff(&old, &new);

        assert_eq!(d.added.len(), 1);
        assert!(d.removed.is_empty());
    }

    #[test]
    fn hides_dynamic_loader_noise() {
        let behavior = Behavior::FileRead {
            path: "/usr/lib/x86_64-linux-gnu/libc.so.6".into(),
        };

        assert_eq!(normalize_behavior(behavior, false, &context()), None);
    }

    #[test]
    fn system_noise_can_be_requested() {
        let behavior = Behavior::FileRead {
            path: "/etc/ld.so.cache".into(),
        };

        assert!(normalize_behavior(behavior, true, &context()).is_some());
    }

    #[test]
    fn writes_are_never_hidden_as_runtime_noise() {
        let behavior = Behavior::FileWrite {
            path: "/usr/lib/example.so".into(),
        };

        assert!(normalize_behavior(behavior, false, &context()).is_some());
    }

    #[test]
    fn project_path_is_portable() {
        let behavior = Behavior::FileRead {
            path: "/home/test/project/src/main.rs".into(),
        };

        assert_eq!(
            normalize_behavior(behavior, false, &context()),
            Some(Behavior::FileRead {
                path: "$PROJECT/src/main.rs".into(),
            })
        );
    }

    #[test]
    fn home_path_is_portable() {
        let behavior = Behavior::FileWrite {
            path: "/home/test/.config/example/id".into(),
        };

        assert_eq!(
            normalize_behavior(behavior, false, &context()),
            Some(Behavior::FileWrite {
                path: "$HOME/.config/example/id".into(),
            })
        );
    }

    #[test]
    fn temp_path_is_portable() {
        let behavior = Behavior::FileWrite {
            path: "/tmp/example.txt".into(),
        };

        assert_eq!(
            normalize_behavior(behavior, false, &context()),
            Some(Behavior::FileWrite {
                path: "$TMP/example.txt".into(),
            })
        );
    }

    #[test]
    fn relative_path_becomes_project_path() {
        let behavior = Behavior::FileRead {
            path: "src/lib.rs".into(),
        };

        assert_eq!(
            normalize_behavior(behavior, false, &context()),
            Some(Behavior::FileRead {
                path: "$PROJECT/src/lib.rs".into(),
            })
        );
    }
}
