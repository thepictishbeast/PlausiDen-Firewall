//! nftables state tracker — track desired vs actual firewall state.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A nftables table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NftTable {
    pub name: String,
    pub family: Family,
    pub chains: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Family {
    Ip,      // IPv4
    Ip6,     // IPv6
    Inet,    // dual-stack
    Arp,
    Bridge,
    Netdev,
}

/// A chain definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NftChain {
    pub table: String,
    pub name: String,
    pub chain_type: ChainType,
    pub hook: Option<Hook>,
    pub priority: i32,
    pub policy: Policy,
    pub rule_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChainType {
    Filter,
    Nat,
    Route,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Hook {
    Prerouting,
    Input,
    Forward,
    Output,
    Postrouting,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Policy {
    Accept,
    Drop,
}

/// A drift issue between desired and actual state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftIssue {
    pub kind: DriftKind,
    pub detail: String,
    pub detected_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DriftKind {
    MissingTable,
    ExtraTable,
    MissingChain,
    ExtraChain,
    PolicyMismatch,
    RuleCountDrift,
}

/// nftables state tracker.
pub struct NftStateTracker {
    desired_tables: HashMap<String, NftTable>,
    desired_chains: HashMap<String, NftChain>, // key: table/chain
    actual_tables: HashMap<String, NftTable>,
    actual_chains: HashMap<String, NftChain>,
    drift_history: Vec<DriftIssue>,
}

impl NftStateTracker {
    pub fn new() -> Self {
        Self {
            desired_tables: HashMap::new(),
            desired_chains: HashMap::new(),
            actual_tables: HashMap::new(),
            actual_chains: HashMap::new(),
            drift_history: Vec::new(),
        }
    }

    /// Declare desired state.
    pub fn declare_table(&mut self, table: NftTable) {
        self.desired_tables.insert(table.name.clone(), table);
    }

    pub fn declare_chain(&mut self, chain: NftChain) {
        let key = format!("{}/{}", chain.table, chain.name);
        self.desired_chains.insert(key, chain);
    }

    /// Update actual state (as observed from nftables).
    pub fn observe_table(&mut self, table: NftTable) {
        self.actual_tables.insert(table.name.clone(), table);
    }

    pub fn observe_chain(&mut self, chain: NftChain) {
        let key = format!("{}/{}", chain.table, chain.name);
        self.actual_chains.insert(key, chain);
    }

    /// Compute drift between desired and actual state.
    pub fn compute_drift(&mut self) -> Vec<DriftIssue> {
        let mut issues = Vec::new();
        let now = Utc::now();

        for name in self.desired_tables.keys() {
            if !self.actual_tables.contains_key(name) {
                issues.push(DriftIssue {
                    kind: DriftKind::MissingTable,
                    detail: format!("desired table {} not present", name),
                    detected_at: now,
                });
            }
        }
        for name in self.actual_tables.keys() {
            if !self.desired_tables.contains_key(name) {
                issues.push(DriftIssue {
                    kind: DriftKind::ExtraTable,
                    detail: format!("extra table {} not in desired state", name),
                    detected_at: now,
                });
            }
        }

        for (key, desired) in &self.desired_chains {
            match self.actual_chains.get(key) {
                None => issues.push(DriftIssue {
                    kind: DriftKind::MissingChain,
                    detail: format!("desired chain {} missing", key),
                    detected_at: now,
                }),
                Some(actual) => {
                    if desired.policy != actual.policy {
                        issues.push(DriftIssue {
                            kind: DriftKind::PolicyMismatch,
                            detail: format!("{}: expected {:?}, got {:?}",
                                key, desired.policy, actual.policy),
                            detected_at: now,
                        });
                    }
                    if desired.rule_count != actual.rule_count {
                        issues.push(DriftIssue {
                            kind: DriftKind::RuleCountDrift,
                            detail: format!("{}: expected {} rules, got {}",
                                key, desired.rule_count, actual.rule_count),
                            detected_at: now,
                        });
                    }
                }
            }
        }
        for key in self.actual_chains.keys() {
            if !self.desired_chains.contains_key(key) {
                issues.push(DriftIssue {
                    kind: DriftKind::ExtraChain,
                    detail: format!("extra chain {} not in desired state", key),
                    detected_at: now,
                });
            }
        }

        self.drift_history.extend(issues.clone());
        issues
    }

    /// Is state in sync?
    pub fn in_sync(&mut self) -> bool {
        self.compute_drift().is_empty()
    }

    /// Drift history.
    pub fn drift_history(&self) -> &[DriftIssue] {
        &self.drift_history
    }

    pub fn desired_table_count(&self) -> usize { self.desired_tables.len() }
    pub fn actual_table_count(&self) -> usize { self.actual_tables.len() }
}

impl Default for NftStateTracker {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(name: &str) -> NftTable {
        NftTable {
            name: name.into(),
            family: Family::Inet,
            chains: Vec::new(),
        }
    }

    fn chain(table: &str, name: &str, rules: usize, policy: Policy) -> NftChain {
        NftChain {
            table: table.into(),
            name: name.into(),
            chain_type: ChainType::Filter,
            hook: Some(Hook::Input),
            priority: 0,
            policy,
            rule_count: rules,
        }
    }

    #[test]
    fn test_synced_state() {
        let mut t = NftStateTracker::new();
        t.declare_table(table("filter"));
        t.observe_table(table("filter"));
        assert!(t.in_sync());
    }

    #[test]
    fn test_missing_table() {
        let mut t = NftStateTracker::new();
        t.declare_table(table("filter"));
        let drift = t.compute_drift();
        assert!(drift.iter().any(|d| d.kind == DriftKind::MissingTable));
    }

    #[test]
    fn test_extra_table() {
        let mut t = NftStateTracker::new();
        t.observe_table(table("unexpected"));
        let drift = t.compute_drift();
        assert!(drift.iter().any(|d| d.kind == DriftKind::ExtraTable));
    }

    #[test]
    fn test_policy_mismatch() {
        let mut t = NftStateTracker::new();
        t.declare_table(table("filter"));
        t.observe_table(table("filter"));
        t.declare_chain(chain("filter", "input", 5, Policy::Drop));
        t.observe_chain(chain("filter", "input", 5, Policy::Accept));
        let drift = t.compute_drift();
        assert!(drift.iter().any(|d| d.kind == DriftKind::PolicyMismatch));
    }

    #[test]
    fn test_rule_count_drift() {
        let mut t = NftStateTracker::new();
        t.declare_table(table("filter"));
        t.observe_table(table("filter"));
        t.declare_chain(chain("filter", "input", 10, Policy::Drop));
        t.observe_chain(chain("filter", "input", 5, Policy::Drop));
        let drift = t.compute_drift();
        assert!(drift.iter().any(|d| d.kind == DriftKind::RuleCountDrift));
    }

    #[test]
    fn test_missing_chain() {
        let mut t = NftStateTracker::new();
        t.declare_table(table("filter"));
        t.observe_table(table("filter"));
        t.declare_chain(chain("filter", "input", 5, Policy::Drop));
        let drift = t.compute_drift();
        assert!(drift.iter().any(|d| d.kind == DriftKind::MissingChain));
    }

    #[test]
    fn test_drift_history_accumulates() {
        let mut t = NftStateTracker::new();
        t.declare_table(table("filter"));
        t.compute_drift();
        t.compute_drift();
        assert!(t.drift_history().len() >= 2);
    }
}
