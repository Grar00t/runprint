use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Ord, PartialOrd)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Behavior {
    Exec { path: String },
    FileRead { path: String },
    FileWrite { path: String },
    NetworkConnect { address: String },
    UnixConnect { path: String },
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
    pub network: usize,
    pub unix: usize,
}

impl BehaviorCounts {
    pub fn total(&self) -> usize {
        self.exec + self.file_read + self.file_write + self.network + self.unix
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

    pub fn insert_normalized(&mut self, behavior: Behavior, include_system: bool) {
        if let Some(behavior) = normalize_behavior(behavior, include_system) {
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

pub fn normalize_behavior(behavior: Behavior, include_system: bool) -> Option<Behavior> {
    match behavior {
        Behavior::FileRead { path } => {
            let path = normalize_path(&path);

            if !include_system && is_runtime_noise(&path) {
                return None;
            }

            Some(Behavior::FileRead { path })
        }

        Behavior::FileWrite { path } => Some(Behavior::FileWrite {
            path: normalize_path(&path),
        }),

        Behavior::Exec { path } => Some(Behavior::Exec {
            path: normalize_path(&path),
        }),

        Behavior::UnixConnect { path } => {
            let path = normalize_path(&path);

            if !include_system && is_runtime_socket_noise(&path) {
                return None;
            }

            Some(Behavior::UnixConnect { path })
        }

        Behavior::NetworkConnect { address } => Some(Behavior::NetworkConnect { address }),
    }
}

fn normalize_path(path: &str) -> String {
    let mut value = path.replace("//", "/");

    while value.contains("/./") {
        value = value.replace("/./", "/");
    }

    if value.ends_with("/.") && value.len() > 2 {
        value.truncate(value.len() - 2);
    }

    value
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

        assert_eq!(normalize_behavior(behavior, false), None);
    }

    #[test]
    fn system_noise_can_be_requested() {
        let behavior = Behavior::FileRead {
            path: "/etc/ld.so.cache".into(),
        };

        assert!(normalize_behavior(behavior, true).is_some());
    }

    #[test]
    fn writes_are_never_hidden_as_runtime_noise() {
        let behavior = Behavior::FileWrite {
            path: "/usr/lib/example.so".into(),
        };

        assert!(normalize_behavior(behavior, false).is_some());
    }
}
