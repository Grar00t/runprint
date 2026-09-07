use crate::{Behavior, BehaviorLock};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
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
        .difference(&baseline.behaviors)
        .filter(|behavior| !allows_new_behavior(policy, behavior))
        .cloned()
        .collect::<Vec<_>>();

    GateResult {
        allowed: violations.is_empty(),
        violations,
    }
}

fn allows_new_behavior(policy: &GatePolicy, behavior: &Behavior) -> bool {
    match behavior {
        Behavior::Exec { .. } => policy.allow_new_exec,
        Behavior::FileRead { .. } => policy.allow_new_reads,
        Behavior::FileWrite { .. } => policy.allow_new_writes,
        Behavior::FileDelete { .. } => policy.allow_new_deletes,
        Behavior::FileRename { .. } => policy.allow_new_renames,

        Behavior::DirectoryCreate { .. } | Behavior::DirectoryDelete { .. } => {
            policy.allow_new_directories
        }

        Behavior::SymlinkCreate { .. } | Behavior::HardlinkCreate { .. } => policy.allow_new_links,

        Behavior::NetworkConnect { .. } => policy.allow_new_network,
        Behavior::UnixConnect { .. } => policy.allow_new_unix,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_allows_new_read() {
        let baseline = BehaviorLock::new();

        let mut observed = BehaviorLock::new();
        observed.insert(Behavior::FileRead {
            path: "$PROJECT/input.txt".into(),
        });

        let result = evaluate_gate(&baseline, &observed, &GatePolicy::default());

        assert!(result.allowed);
    }

    #[test]
    fn default_policy_denies_new_write() {
        let baseline = BehaviorLock::new();

        let mut observed = BehaviorLock::new();
        observed.insert(Behavior::FileWrite {
            path: "$PROJECT/output.txt".into(),
        });

        let result = evaluate_gate(&baseline, &observed, &GatePolicy::default());

        assert!(!result.allowed);
        assert_eq!(result.violations.len(), 1);
    }

    #[test]
    fn policy_can_deny_new_reads() {
        let policy = GatePolicy {
            allow_new_reads: false,
            ..GatePolicy::default()
        };

        let baseline = BehaviorLock::new();

        let mut observed = BehaviorLock::new();
        observed.insert(Behavior::FileRead {
            path: "$PROJECT/secret.txt".into(),
        });

        let result = evaluate_gate(&baseline, &observed, &policy);

        assert!(!result.allowed);
    }

    #[test]
    fn policy_can_allow_new_network() {
        let policy = GatePolicy {
            allow_new_network: true,
            ..GatePolicy::default()
        };

        let baseline = BehaviorLock::new();

        let mut observed = BehaviorLock::new();
        observed.insert(Behavior::NetworkConnect {
            address: "203.0.113.10:443".into(),
        });

        let result = evaluate_gate(&baseline, &observed, &policy);

        assert!(result.allowed);
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
        assert!(result.violations.is_empty());
    }
}
