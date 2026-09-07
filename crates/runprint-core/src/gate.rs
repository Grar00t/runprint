use crate::{Behavior, BehaviorLock};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateResult {
    pub allowed: bool,
    pub violations: Vec<Behavior>,
}

pub fn evaluate_gate(baseline: &BehaviorLock, observed: &BehaviorLock) -> GateResult {
    let violations = observed
        .behaviors
        .difference(&baseline.behaviors)
        .filter(|behavior| is_restricted_new_behavior(behavior))
        .cloned()
        .collect::<Vec<_>>();

    GateResult {
        allowed: violations.is_empty(),
        violations,
    }
}

fn is_restricted_new_behavior(behavior: &Behavior) -> bool {
    !matches!(behavior, Behavior::FileRead { .. })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Behavior;

    #[test]
    fn new_read_is_allowed() {
        let baseline = BehaviorLock::new();

        let mut observed = BehaviorLock::new();
        observed.insert(Behavior::FileRead {
            path: "$PROJECT/new.txt".into(),
        });

        let result = evaluate_gate(&baseline, &observed);

        assert!(result.allowed);
        assert!(result.violations.is_empty());
    }

    #[test]
    fn new_write_is_denied() {
        let baseline = BehaviorLock::new();

        let mut observed = BehaviorLock::new();
        observed.insert(Behavior::FileWrite {
            path: "$PROJECT/new.txt".into(),
        });

        let result = evaluate_gate(&baseline, &observed);

        assert!(!result.allowed);
        assert_eq!(result.violations.len(), 1);
    }

    #[test]
    fn baseline_write_is_allowed() {
        let mut baseline = BehaviorLock::new();
        baseline.insert(Behavior::FileWrite {
            path: "$PROJECT/output.txt".into(),
        });

        let observed = baseline.clone();

        let result = evaluate_gate(&baseline, &observed);

        assert!(result.allowed);
        assert!(result.violations.is_empty());
    }

    #[test]
    fn new_network_is_denied() {
        let baseline = BehaviorLock::new();

        let mut observed = BehaviorLock::new();
        observed.insert(Behavior::NetworkConnect {
            address: "203.0.113.10:443".into(),
        });

        let result = evaluate_gate(&baseline, &observed);

        assert!(!result.allowed);
        assert_eq!(result.violations.len(), 1);
    }
}
