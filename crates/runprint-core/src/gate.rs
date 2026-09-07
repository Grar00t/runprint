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

/// A gate pattern that cannot express what its author intended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyPatternError {
    pub field: &'static str,
    pub pattern: String,
    pub reason: &'static str,
}

impl std::fmt::Display for PolicyPatternError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{} pattern {:?}: {}",
            self.field, self.pattern, self.reason
        )
    }
}

impl std::error::Error for PolicyPatternError {}

impl GatePolicy {
    /// Rejects patterns that cannot do what they appear to do.
    ///
    /// A degenerate pattern is dangerous in both directions. An empty
    /// `prefix:` would match every value, so an allow list silently becomes
    /// "allow everything". A bare `*` never matches anything, so a deny list
    /// silently becomes "deny nothing". `pattern_matches` refuses to match on
    /// either form, which is fail-closed for allow lists only, so unusable
    /// patterns are rejected here before any policy is applied.
    pub fn validate(&self) -> Result<(), PolicyPatternError> {
        for (field, patterns) in self.pattern_fields() {
            for pattern in patterns {
                validate_pattern(field, pattern)?;
            }
        }

        Ok(())
    }

    fn pattern_fields(&self) -> Vec<(&'static str, &[String])> {
        vec![
            ("allow_read", self.allow_read.as_slice()),
            ("allow_exec", self.allow_exec.as_slice()),
            ("allow_write", self.allow_write.as_slice()),
            ("allow_delete", self.allow_delete.as_slice()),
            ("allow_rename", self.allow_rename.as_slice()),
            ("allow_directory", self.allow_directory.as_slice()),
            ("allow_link", self.allow_link.as_slice()),
            ("allow_network", self.allow_network.as_slice()),
            ("allow_unix", self.allow_unix.as_slice()),
            ("deny_read", self.deny_read.as_slice()),
            ("deny_exec", self.deny_exec.as_slice()),
            ("deny_write", self.deny_write.as_slice()),
            ("deny_delete", self.deny_delete.as_slice()),
            ("deny_rename", self.deny_rename.as_slice()),
            ("deny_directory", self.deny_directory.as_slice()),
            ("deny_link", self.deny_link.as_slice()),
            ("deny_network", self.deny_network.as_slice()),
            ("deny_unix", self.deny_unix.as_slice()),
        ]
    }
}

fn pattern_error(
    field: &'static str,
    pattern: &str,
    reason: &'static str,
) -> Result<(), PolicyPatternError> {
    Err(PolicyPatternError {
        field,
        pattern: pattern.to_string(),
        reason,
    })
}

fn validate_pattern(field: &'static str, pattern: &str) -> Result<(), PolicyPatternError> {
    if pattern.is_empty() {
        return pattern_error(field, pattern, "the pattern is empty");
    }

    // Inside an explicit matcher a `*` is a working literal match, so only an
    // empty body is rejected for these three forms.
    if let Some(rest) = pattern.strip_prefix("exact:") {
        if rest.is_empty() {
            return pattern_error(field, pattern, "`exact:` needs a value to compare");
        }

        return Ok(());
    }

    if let Some(rest) = pattern.strip_prefix("prefix:") {
        if rest.is_empty() {
            return pattern_error(field, pattern, "an empty `prefix:` matches everything");
        }

        return Ok(());
    }

    if let Some(rest) = pattern.strip_prefix("suffix:") {
        if rest.is_empty() {
            return pattern_error(field, pattern, "an empty `suffix:` matches everything");
        }

        return Ok(());
    }

    if let Some(base) = pattern.strip_suffix("/**") {
        if base.is_empty() {
            return pattern_error(field, pattern, "`/**` needs a directory to scope it");
        }

        if base.contains('*') {
            return pattern_error(field, pattern, "`**` must be a trailing `/**` segment");
        }

        return Ok(());
    }

    // A bare pattern is compared literally, and `pattern_matches` deliberately
    // refuses to match one containing `*` rather than guessing at a glob. Such
    // a pattern can never match, so it is an authoring error, not a policy.
    if pattern.contains('*') {
        return pattern_error(field, pattern, "`*` is literal, not a wildcard");
    }

    Ok(())
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

        Behavior::RenameExchange { left, right } => {
            matches_any(left, &policy.deny_rename) || matches_any(right, &policy.deny_rename)
        }

        Behavior::DirectoryCreate { path } | Behavior::DirectoryDelete { path } => {
            matches_any(path, &policy.deny_directory)
        }

        Behavior::SymlinkCreate { link, .. } => matches_any(link, &policy.deny_link),

        Behavior::HardlinkCreate { from, to, .. } => {
            matches_any(from, &policy.deny_link) || matches_any(to, &policy.deny_link)
        }

        Behavior::NetworkConnect { address } => matches_any(address, &policy.deny_network),

        Behavior::UnixConnect { path } => matches_any(path, &policy.deny_unix),

        Behavior::UnixAbstractConnect { address } => matches_any(address, &policy.deny_unix),
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

        Behavior::RenameExchange { left, right } => {
            policy.allow_new_renames
                || (matches_any(left, &policy.allow_rename)
                    && matches_any(right, &policy.allow_rename))
        }

        Behavior::DirectoryCreate { path } | Behavior::DirectoryDelete { path } => {
            policy.allow_new_directories || matches_any(path, &policy.allow_directory)
        }

        Behavior::SymlinkCreate { link, .. } => {
            policy.allow_new_links || matches_any(link, &policy.allow_link)
        }

        Behavior::HardlinkCreate { from, to, .. } => {
            policy.allow_new_links
                || (matches_any(from, &policy.allow_link) && matches_any(to, &policy.allow_link))
        }

        Behavior::NetworkConnect { address } => {
            policy.allow_new_network || matches_any(address, &policy.allow_network)
        }

        Behavior::UnixConnect { path } => {
            policy.allow_new_unix || matches_any(path, &policy.allow_unix)
        }

        Behavior::UnixAbstractConnect { address } => {
            policy.allow_new_unix || matches_any(address, &policy.allow_unix)
        }
    }
}

fn matches_any(value: &str, patterns: &[String]) -> bool {
    patterns
        .iter()
        .any(|pattern| pattern_matches(value, pattern))
}

fn pattern_matches(value: &str, pattern: &str) -> bool {
    // Every branch below refuses to match a degenerate pattern rather than
    // matching every value. GatePolicy::validate rejects these patterns at
    // load time; this is the second line of defence for policies built in
    // code, where no validation step is guaranteed to have run.
    if let Some(exact) = pattern.strip_prefix("exact:") {
        return !exact.is_empty() && value == exact;
    }

    if let Some(prefix) = pattern.strip_prefix("prefix:") {
        return !prefix.is_empty() && value.starts_with(prefix);
    }

    if let Some(suffix) = pattern.strip_prefix("suffix:") {
        return !suffix.is_empty() && value.ends_with(suffix);
    }

    if let Some(prefix) = pattern.strip_suffix("/**") {
        if prefix.is_empty() || prefix.contains('*') {
            return false;
        }

        return value == prefix
            || value
                .strip_prefix(prefix)
                .is_some_and(|rest| rest.starts_with('/'));
    }

    if pattern.contains('*') {
        return false;
    }

    !pattern.is_empty() && value == pattern
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recursive_path_pattern_matches_children() {
        assert!(pattern_matches("$PROJECT/dist/app.js", "$PROJECT/dist/**"));
        assert!(pattern_matches("$PROJECT/dist", "$PROJECT/dist/**"));
        assert!(!pattern_matches("$PROJECT/src/app.js", "$PROJECT/dist/**"));
        assert!(!pattern_matches(
            "$PROJECT/disturbed/app.js",
            "$PROJECT/dist/**"
        ));
    }

    #[test]
    fn sibling_directory_cannot_escape_recursive_scope() {
        assert!(!pattern_matches(
            "$HOME/project-other/x",
            "$HOME/project/**"
        ));
        assert!(pattern_matches("$HOME/project/x", "$HOME/project/**"));
        assert!(!pattern_matches("$TMP/build-other", "$TMP/build/**"));
        assert!(pattern_matches("$TMP/build/out", "$TMP/build/**"));
    }

    #[test]
    fn explicit_prefix_pattern_matches_network_host() {
        assert!(pattern_matches("127.0.0.1:8080", "prefix:127.0.0.1:"));
        assert!(!pattern_matches("203.0.113.10:8080", "prefix:127.0.0.1:"));
    }

    #[test]
    fn explicit_suffix_pattern_matches_network_port() {
        assert!(pattern_matches("127.0.0.1:443", "suffix::443"));
        assert!(pattern_matches("[::1]:443", "suffix::443"));
        assert!(!pattern_matches("127.0.0.1:8443", "suffix::443"));
    }

    #[test]
    fn ambiguous_star_pattern_is_not_supported() {
        assert!(!pattern_matches("$PROJECT/disturbed", "$PROJECT/dist*"));
        assert!(!pattern_matches("127.0.0.1:443", "127.0.0.1:*"));
        assert!(!pattern_matches("@runprint-test", "@runprint-*"));
    }

    #[test]
    fn literal_star_still_matches_through_explicit_matchers() {
        assert!(pattern_matches("$PROJECT/a*b", "exact:$PROJECT/a*b"));
        assert!(pattern_matches("$PROJECT/a*b", "prefix:$PROJECT/a*"));
        assert!(pattern_matches("$PROJECT/a*b", "suffix:a*b"));
    }

    #[test]
    fn empty_matcher_body_does_not_match_everything() {
        assert!(!pattern_matches("$PROJECT/secret.txt", "prefix:"));
        assert!(!pattern_matches("$PROJECT/secret.txt", "suffix:"));
        assert!(!pattern_matches("$PROJECT/secret.txt", "exact:"));
        assert!(!pattern_matches("$PROJECT/secret.txt", ""));
        assert!(!pattern_matches("", ""));
    }

    #[test]
    fn bare_recursive_pattern_does_not_match_everything() {
        assert!(!pattern_matches("/etc/shadow", "/**"));
        assert!(!pattern_matches("$PROJECT/secret.txt", "/**"));
        assert!(!pattern_matches("$PROJECT/a/b", "$PROJECT/*/**"));
    }

    /// The whole point of a scoped allow list is that it is narrower than
    /// "allow anything", so a degenerate pattern must not silently open it.
    #[test]
    fn degenerate_allow_pattern_does_not_bypass_the_gate() {
        let policy = GatePolicy {
            allow_write: vec!["prefix:".into()],
            ..GatePolicy::default()
        };

        let baseline = BehaviorLock::new();

        let mut observed = BehaviorLock::new();
        observed.insert(Behavior::FileWrite {
            path: "$HOME/.ssh/authorized_keys".into(),
        });

        let result = evaluate_gate(&baseline, &observed, &policy);

        assert!(!result.allowed);
        assert_eq!(result.violations.len(), 1);
    }

    #[test]
    fn validate_accepts_the_default_policy() {
        assert!(GatePolicy::default().validate().is_ok());
    }

    #[test]
    fn validate_accepts_working_patterns() {
        let policy = GatePolicy {
            allow_write: vec!["$PROJECT/dist/**".into()],
            allow_network: vec!["prefix:127.0.0.1:".into(), "suffix::443".into()],
            allow_exec: vec!["/usr/bin/git".into(), "exact:/usr/bin/a*b".into()],
            deny_read: vec!["$HOME/.ssh/id_ed25519".into()],
            ..GatePolicy::default()
        };

        assert!(policy.validate().is_ok());
    }

    #[test]
    fn validate_rejects_an_empty_prefix_pattern() {
        let policy = GatePolicy {
            allow_write: vec!["prefix:".into()],
            ..GatePolicy::default()
        };

        let error = policy.validate().unwrap_err();

        assert_eq!(error.field, "allow_write");
        assert_eq!(error.pattern, "prefix:");
    }

    #[test]
    fn validate_rejects_an_empty_pattern() {
        let policy = GatePolicy {
            deny_network: vec![String::new()],
            ..GatePolicy::default()
        };

        let error = policy.validate().unwrap_err();

        assert_eq!(error.field, "deny_network");
    }

    #[test]
    fn validate_rejects_a_bare_recursive_pattern() {
        let policy = GatePolicy {
            allow_read: vec!["/**".into()],
            ..GatePolicy::default()
        };

        assert!(policy.validate().is_err());
    }

    #[test]
    fn validate_rejects_a_non_trailing_double_star() {
        let policy = GatePolicy {
            allow_write: vec!["$PROJECT/**/dist/**".into()],
            ..GatePolicy::default()
        };

        assert!(policy.validate().is_err());
    }

    /// A deny rule that can never match is worse than no rule at all, because
    /// it reads like protection that does not exist.
    #[test]
    fn validate_rejects_a_deny_pattern_that_can_never_match() {
        let policy = GatePolicy {
            deny_write: vec!["$PROJECT/secrets*".into()],
            ..GatePolicy::default()
        };

        let error = policy.validate().unwrap_err();

        assert_eq!(error.field, "deny_write");
        assert_eq!(error.reason, "`*` is literal, not a wildcard");
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
    fn exchange_requires_both_paths_in_rename_scope() {
        let policy = GatePolicy {
            allow_rename: vec!["$PROJECT/safe/**".into()],
            ..GatePolicy::default()
        };

        let baseline = BehaviorLock::new();

        let mut allowed = BehaviorLock::new();
        allowed.insert(Behavior::RenameExchange {
            left: "$PROJECT/safe/a.txt".into(),
            right: "$PROJECT/safe/b.txt".into(),
        });

        assert!(evaluate_gate(&baseline, &allowed, &policy).allowed);

        let mut denied = BehaviorLock::new();
        denied.insert(Behavior::RenameExchange {
            left: "$PROJECT/safe/a.txt".into(),
            right: "$PROJECT/outside.txt".into(),
        });

        assert!(!evaluate_gate(&baseline, &denied, &policy).allowed);
    }

    /// Deny is broader than allow on purpose: an allow rule must cover every
    /// path in a two-path behavior, while a deny rule only has to cover one.
    #[test]
    fn deny_rename_matches_either_side() {
        let policy = GatePolicy {
            allow_new_renames: true,
            deny_rename: vec!["$PROJECT/protected.txt".into()],
            ..GatePolicy::default()
        };

        let baseline = BehaviorLock::new();

        let mut source = BehaviorLock::new();
        source.insert(Behavior::FileRename {
            from: "$PROJECT/protected.txt".into(),
            to: "$PROJECT/moved.txt".into(),
        });

        assert!(!evaluate_gate(&baseline, &source, &policy).allowed);

        let mut destination = BehaviorLock::new();
        destination.insert(Behavior::FileRename {
            from: "$PROJECT/moved.txt".into(),
            to: "$PROJECT/protected.txt".into(),
        });

        assert!(!evaluate_gate(&baseline, &destination, &policy).allowed);
    }

    #[test]
    fn deny_rename_matches_either_side_of_an_exchange() {
        let policy = GatePolicy {
            allow_new_renames: true,
            deny_rename: vec!["$PROJECT/protected.txt".into()],
            ..GatePolicy::default()
        };

        let baseline = BehaviorLock::new();

        let mut left = BehaviorLock::new();
        left.insert(Behavior::RenameExchange {
            left: "$PROJECT/protected.txt".into(),
            right: "$PROJECT/other.txt".into(),
        });

        assert!(!evaluate_gate(&baseline, &left, &policy).allowed);

        let mut right = BehaviorLock::new();
        right.insert(Behavior::RenameExchange {
            left: "$PROJECT/other.txt".into(),
            right: "$PROJECT/protected.txt".into(),
        });

        assert!(!evaluate_gate(&baseline, &right, &policy).allowed);
    }

    #[test]
    fn deny_link_matches_either_side() {
        let policy = GatePolicy {
            allow_new_links: true,
            deny_link: vec!["$HOME/.ssh/id_ed25519".into()],
            ..GatePolicy::default()
        };

        let baseline = BehaviorLock::new();

        let mut source = BehaviorLock::new();
        source.insert(Behavior::HardlinkCreate {
            from: "$HOME/.ssh/id_ed25519".into(),
            to: "$PROJECT/leak".into(),
            follow_symlink: false,
            empty_path: false,
        });

        assert!(!evaluate_gate(&baseline, &source, &policy).allowed);

        let mut destination = BehaviorLock::new();
        destination.insert(Behavior::HardlinkCreate {
            from: "$PROJECT/source".into(),
            to: "$HOME/.ssh/id_ed25519".into(),
            follow_symlink: false,
            empty_path: false,
        });

        assert!(!evaluate_gate(&baseline, &destination, &policy).allowed);
    }

    #[test]
    fn flagged_hardlink_uses_existing_link_scope() {
        let policy = GatePolicy {
            allow_link: vec!["$PROJECT/safe/**".into()],
            ..GatePolicy::default()
        };

        let baseline = BehaviorLock::new();

        let mut observed = BehaviorLock::new();
        observed.insert(Behavior::HardlinkCreate {
            from: "$PROJECT/safe/source".into(),
            to: "$PROJECT/safe/out".into(),
            follow_symlink: true,
            empty_path: false,
        });

        assert!(evaluate_gate(&baseline, &observed, &policy).allowed);
    }

    #[test]
    fn scoped_abstract_unix_connect_is_allowed() {
        let policy = GatePolicy {
            allow_unix: vec!["prefix:@runprint-".into()],
            ..GatePolicy::default()
        };

        let baseline = BehaviorLock::new();

        let mut observed = BehaviorLock::new();
        observed.insert(Behavior::UnixAbstractConnect {
            address: "@runprint-abstract".into(),
        });

        assert!(evaluate_gate(&baseline, &observed, &policy).allowed);
    }

    /// An abstract address always carries its `@` marker, so a pathname rule
    /// cannot be satisfied by an abstract socket of the same name.
    #[test]
    fn pathname_unix_rule_does_not_match_abstract_socket() {
        let policy = GatePolicy {
            allow_unix: vec!["exact:runprint-abstract".into()],
            ..GatePolicy::default()
        };

        let baseline = BehaviorLock::new();

        let mut observed = BehaviorLock::new();
        observed.insert(Behavior::UnixAbstractConnect {
            address: "@runprint-abstract".into(),
        });

        assert!(!evaluate_gate(&baseline, &observed, &policy).allowed);
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
            allow_network: vec!["prefix:127.0.0.1:".into()],
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
    fn any_host_on_port_is_allowed_with_explicit_suffix() {
        let policy = GatePolicy {
            allow_network: vec!["suffix::443".into()],
            ..GatePolicy::default()
        };

        let baseline = BehaviorLock::new();

        let mut ipv4 = BehaviorLock::new();
        ipv4.insert(Behavior::NetworkConnect {
            address: "203.0.113.10:443".into(),
        });
        assert!(evaluate_gate(&baseline, &ipv4, &policy).allowed);

        let mut ipv6 = BehaviorLock::new();
        ipv6.insert(Behavior::NetworkConnect {
            address: "[2001:db8::10]:443".into(),
        });
        assert!(evaluate_gate(&baseline, &ipv6, &policy).allowed);
    }

    /// A host prefix must not be satisfied by a different host that merely
    /// starts with the same digits.
    #[test]
    fn network_host_prefix_requires_the_port_separator() {
        let policy = GatePolicy {
            allow_network: vec!["prefix:127.0.0.1:".into()],
            ..GatePolicy::default()
        };

        let baseline = BehaviorLock::new();

        let mut observed = BehaviorLock::new();
        observed.insert(Behavior::NetworkConnect {
            address: "127.0.0.10:80".into(),
        });

        assert!(!evaluate_gate(&baseline, &observed, &policy).allowed);
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
            deny_network: vec!["prefix:169.254.169.254:".into()],
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
