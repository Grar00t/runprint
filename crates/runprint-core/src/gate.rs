use crate::{Behavior, BehaviorLock};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct GatePolicy {
    pub allow_new_reads: bool,
    pub allow_new_exec: bool,
    pub allow_new_writes: bool,
    pub allow_new_deletes: bool,
    pub allow_new_renames: bool,
    pub allow_new_directories: bool,
    pub allow_new_links: bool,
    pub allow_new_network: bool,
    pub allow_new_unix: bool,

    pub allow_read: Vec<String>,
    pub allow_exec: Vec<String>,
    pub allow_write: Vec<String>,
    pub allow_delete: Vec<String>,
    pub allow_rename: Vec<String>,
    pub allow_directory: Vec<String>,
    pub allow_link: Vec<String>,
    pub allow_network: Vec<String>,
    pub allow_unix: Vec<String>,

    pub deny_read: Vec<String>,
    pub deny_exec: Vec<String>,
    pub deny_write: Vec<String>,
    pub deny_delete: Vec<String>,
    pub deny_rename: Vec<String>,
    pub deny_directory: Vec<String>,
    pub deny_link: Vec<String>,
    pub deny_network: Vec<String>,
    pub deny_unix: Vec<String>,
}

impl Default for GatePolicy {
    fn default() -> Self {
        Self {
            allow_new_reads: true,
            allow_new_exec: false,
            allow_new_writes: false,
            allow_new_deletes: false,
            allow_new_renames: false,
            allow_new_directories: false,
            allow_new_links: false,
            allow_new_network: false,
            allow_new_unix: false,

            allow_read: Vec::new(),
            allow_exec: Vec::new(),
            allow_write: Vec::new(),
            allow_delete: Vec::new(),
            allow_rename: Vec::new(),
            allow_directory: Vec::new(),
            allow_link: Vec::new(),
            allow_network: Vec::new(),
            allow_unix: Vec::new(),

            deny_read: Vec::new(),
            deny_exec: Vec::new(),
            deny_write: Vec::new(),
            deny_delete: Vec::new(),
            deny_rename: Vec::new(),
            deny_directory: Vec::new(),
            deny_link: Vec::new(),
            deny_network: Vec::new(),
            deny_unix: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateResult {
    pub allowed: bool,
    pub violations: Vec<Behavior>,
}

pub fn evaluate_gate(
    baseline: &BehaviorLock,
    observed: &BehaviorLock,
    policy: &GatePolicy,
) -> GateResult {
    let violations = observed
        .behaviors
        .iter()
        .filter(|behavior| {
            if explicitly_denied(policy, behavior) {
                return true;
            }

            if baseline.behaviors.contains(*behavior) {
                return false;
            }

            !allows_new_behavior(policy, behavior)
        })
        .cloned()
        .collect::<Vec<_>>();

    GateResult {
        allowed: violations.is_empty(),
        violations,
    }
}

fn explicitly_denied(policy: &GatePolicy, behavior: &Behavior) -> bool {
    match behavior {
        Behavior::Exec { path } => matches_any(path, &policy.deny_exec),

        Behavior::FileRead { path } => matches_any(path, &policy.deny_read),

        Behavior::FileWrite { path } => matches_any(path, &policy.deny_write),

        Behavior::FileDelete { path } => matches_any(path, &policy.deny_delete),

        Behavior::FileRename { from, to } => {
            matches_any(from, &policy.deny_rename) || matches_any(to, &policy.deny_rename)
        }

        Behavior::DirectoryCreate { path } | Behavior::DirectoryDelete { path } => {
            matches_any(path, &policy.deny_directory)
        }

        Behavior::SymlinkCreate { link, .. } => matches_any(link, &policy.deny_link),

        Behavior::HardlinkCreate { from, to } => {
            matches_any(from, &policy.deny_link) || matches_any(to, &policy.deny_link)
        }

        Behavior::NetworkConnect { address } => matches_any(address, &policy.deny_network),

        Behavior::UnixConnect { path } => matches_any(path, &policy.deny_unix),
    }
}

fn allows_new_behavior(policy: &GatePolicy, behavior: &Behavior) -> bool {
    match behavior {
        Behavior::Exec { path } => policy.allow_new_exec || matches_any(path, &policy.allow_exec),

        Behavior::FileRead { path } => {
            policy.allow_new_reads || matches_any(path, &policy.allow_read)
        }

        Behavior::FileWrite { path } => {
            policy.allow_new_writes || matches_any(path, &policy.allow_write)
        }

        Behavior::FileDelete { path } => {
            policy.allow_new_deletes || matches_any(path, &policy.allow_delete)
        }

        Behavior::FileRename { from, to } => {
            policy.allow_new_renames
                || (matches_any(from, &policy.allow_rename)
                    && matches_any(to, &policy.allow_rename))
        }

        Behavior::DirectoryCreate { path } | Behavior::DirectoryDelete { path } => {
            policy.allow_new_directories || matches_any(path, &policy.allow_directory)
        }

        Behavior::SymlinkCreate { link, .. } => {
            policy.allow_new_links || matches_any(link, &policy.allow_link)
        }

        Behavior::HardlinkCreate { from, to } => {
            policy.allow_new_links
                || (matches_any(from, &policy.allow_link) && matches_any(to, &policy.allow_link))
        }

        Behavior::NetworkConnect { address } => {
            policy.allow_new_network || matches_any(address, &policy.allow_network)
        }

        Behavior::UnixConnect { path } => {
            policy.allow_new_unix || matches_any(path, &policy.allow_unix)
        }
    }
}

fn matches_any(value: &str, patterns: &[String]) -> bool {
    patterns
        .iter()
        .any(|pattern| pattern_matches(value, pattern))
}

fn pattern_matches(value: &str, pattern: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix("/**") {
        return value == prefix
            || value
                .strip_prefix(prefix)
                .is_some_and(|rest| rest.starts_with('/'));
    }

    if let Some(prefix) = pattern.strip_suffix('*') {
        return value.starts_with(prefix);
    }

    value == pattern
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recursive_path_pattern_matches_children() {
        assert!(pattern_matches("$PROJECT/dist/app.js", "$PROJECT/dist/**"));

        assert!(pattern_matches("$PROJECT/dist", "$PROJECT/dist/**"));

        assert!(!pattern_matches("$PROJECT/src/app.js", "$PROJECT/dist/**"));
    }

    #[test]
    fn prefix_pattern_matches_network_port() {
        assert!(pattern_matches("127.0.0.1:8080", "127.0.0.1:*"));

        assert!(!pattern_matches("203.0.113.10:8080", "127.0.0.1:*"));
    }

    #[test]
    fn scoped_write_is_allowed() {
        let policy = GatePolicy {
            allow_write: vec!["$PROJECT/dist/**".into()],
            ..GatePolicy::default()
        };

        let baseline = BehaviorLock::new();

        let mut observed = BehaviorLock::new();
        observed.insert(Behavior::FileWrite {
            path: "$PROJECT/dist/app.js".into(),
        });

        let result = evaluate_gate(&baseline, &observed, &policy);

        assert!(result.allowed);
    }

    #[test]
    fn write_outside_scope_is_denied() {
        let policy = GatePolicy {
            allow_write: vec!["$PROJECT/dist/**".into()],
            ..GatePolicy::default()
        };

        let baseline = BehaviorLock::new();

        let mut observed = BehaviorLock::new();
        observed.insert(Behavior::FileWrite {
            path: "$PROJECT/secret.txt".into(),
        });

        let result = evaluate_gate(&baseline, &observed, &policy);

        assert!(!result.allowed);
        assert_eq!(result.violations.len(), 1);
    }

    #[test]
    fn scoped_exec_is_allowed() {
        let policy = GatePolicy {
            allow_exec: vec!["/usr/bin/git".into()],
            ..GatePolicy::default()
        };

        let baseline = BehaviorLock::new();

        let mut observed = BehaviorLock::new();
        observed.insert(Behavior::Exec {
            path: "/usr/bin/git".into(),
        });

        let result = evaluate_gate(&baseline, &observed, &policy);

        assert!(result.allowed);
    }

    #[test]
    fn scoped_network_is_allowed() {
        let policy = GatePolicy {
            allow_network: vec!["127.0.0.1:*".into()],
            ..GatePolicy::default()
        };

        let baseline = BehaviorLock::new();

        let mut observed = BehaviorLock::new();
        observed.insert(Behavior::NetworkConnect {
            address: "127.0.0.1:3000".into(),
        });

        let result = evaluate_gate(&baseline, &observed, &policy);

        assert!(result.allowed);
    }

    #[test]
    fn explicit_deny_overrides_baseline() {
        let mut baseline = BehaviorLock::new();

        baseline.insert(Behavior::FileRead {
            path: "$PROJECT/secret.txt".into(),
        });

        let observed = baseline.clone();

        let policy = GatePolicy {
            deny_read: vec!["$PROJECT/secret.txt".into()],
            ..GatePolicy::default()
        };

        let result = evaluate_gate(&baseline, &observed, &policy);

        assert!(!result.allowed);
        assert_eq!(result.violations.len(), 1);
    }

    #[test]
    fn explicit_network_deny_overrides_global_allow() {
        let baseline = BehaviorLock::new();

        let mut observed = BehaviorLock::new();
        observed.insert(Behavior::NetworkConnect {
            address: "169.254.169.254:80".into(),
        });

        let policy = GatePolicy {
            allow_new_network: true,
            deny_network: vec!["169.254.169.254:*".into()],
            ..GatePolicy::default()
        };

        let result = evaluate_gate(&baseline, &observed, &policy);

        assert!(!result.allowed);
        assert_eq!(result.violations.len(), 1);
    }

    #[test]
    fn baseline_behavior_is_always_allowed() {
        let mut baseline = BehaviorLock::new();

        baseline.insert(Behavior::FileWrite {
            path: "$PROJECT/output.txt".into(),
        });

        let observed = baseline.clone();

        let result = evaluate_gate(&baseline, &observed, &GatePolicy::default());

        assert!(result.allowed);
    }
}
