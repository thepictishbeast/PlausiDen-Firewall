//! Windows Filtering Platform (WFP) backend — rule generation for Windows.

use crate::rules::{RuleAction, RuleSet};
use serde::{Deserialize, Serialize};

/// WFP filter representation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WfpFilter {
    pub name: String,
    pub action: WfpAction,
    pub layer: WfpLayer,
    pub conditions: Vec<WfpCondition>,
    pub weight: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum WfpAction { Permit, Block, Callout }

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum WfpLayer { InboundTransport, OutboundTransport, InboundNetwork, OutboundNetwork }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WfpCondition {
    RemoteAddress(String),
    RemotePort(u16),
    LocalPort(u16),
    Protocol(u8),
    ApplicationPath(String),
}

/// Windows firewall backend — generates WFP filter definitions.
pub struct WindowsBackend {
    sublayer_name: String,
}

impl WindowsBackend {
    pub fn new() -> Self { Self { sublayer_name: "PlausiDen".into() } }

    /// Generate WFP filters from a rule set.
    pub fn generate_filters(&self, rules: &RuleSet) -> Vec<WfpFilter> {
        let mut filters = Vec::new();

        // Default block filter (lowest weight)
        filters.push(WfpFilter {
            name: format!("{} Default Block", self.sublayer_name),
            action: WfpAction::Block,
            layer: WfpLayer::OutboundTransport,
            conditions: vec![],
            weight: 0,
        });

        for (i, rule) in rules.rules().iter().enumerate() {
            if !rule.enabled { continue; }
            let action = match rule.action {
                RuleAction::Allow => WfpAction::Permit,
                RuleAction::Deny => WfpAction::Block,
                _ => continue,
            };

            let mut conditions = Vec::new();
            let m = &rule.rule_match;

            if let Some(ref ip) = m.dest_ip { conditions.push(WfpCondition::RemoteAddress(ip.to_string())); }
            if let Some((port, _)) = m.dest_port_range { conditions.push(WfpCondition::RemotePort(port)); }
            if let Some(ref app) = m.application { conditions.push(WfpCondition::ApplicationPath(app.clone())); }

            let layer = if m.source_ip.is_some() { WfpLayer::InboundTransport } else { WfpLayer::OutboundTransport };

            filters.push(WfpFilter {
                name: format!("{} Rule {}", self.sublayer_name, rule.name),
                action, layer, conditions,
                weight: 1000 - i as u64,
            });
        }

        filters
    }

    /// Generate a PowerShell script to apply filters (for testing/deployment).
    pub fn generate_powershell(&self, filters: &[WfpFilter]) -> String {
        let mut lines = vec![
            "# PlausiDen Firewall — WFP PowerShell Script".into(),
            "# Run as Administrator".into(),
            String::new(),
        ];

        for filter in filters {
            let action = match filter.action {
                WfpAction::Permit => "Allow",
                WfpAction::Block => "Block",
                WfpAction::Callout => continue,
            };
            let direction = match filter.layer {
                WfpLayer::InboundTransport | WfpLayer::InboundNetwork => "Inbound",
                WfpLayer::OutboundTransport | WfpLayer::OutboundNetwork => "Outbound",
            };
            lines.push(format!("New-NetFirewallRule -DisplayName '{}' -Direction {} -Action {} -Enabled True",
                filter.name, direction, action));
        }

        lines.join("\n")
    }

    pub fn filter_count(&self, filters: &[WfpFilter]) -> usize { filters.len() }
}

impl Default for WindowsBackend { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_block_filter() {
        let backend = WindowsBackend::new();
        let rules = RuleSet::new();
        let filters = backend.generate_filters(&rules);
        assert!(!filters.is_empty());
        assert!(matches!(filters[0].action, WfpAction::Block));
    }

    #[test]
    fn test_generate_filters_from_rules() {
        let backend = WindowsBackend::new();
        let mut rules = RuleSet::new();
        rules.add_rule(crate::rules::FirewallRule {
            id: uuid::Uuid::new_v4(), name: "test".into(), priority: 100,
            rule_match: crate::rules::RuleMatch {
                source_ip: None, source_port_range: None,
                dest_ip: Some("10.0.0.1".parse().unwrap()),
                dest_port_range: Some((443, 443)),
                protocol: None, application: None, domain_pattern: None,
            },
            action: RuleAction::Allow, enabled: true,
        }).unwrap();
        let filters = backend.generate_filters(&rules);
        assert!(filters.len() >= 2); // default block + 1 rule
    }

    #[test]
    fn test_powershell_generation() {
        let backend = WindowsBackend::new();
        let filters = vec![WfpFilter {
            name: "Test Rule".into(), action: WfpAction::Permit,
            layer: WfpLayer::OutboundTransport, conditions: vec![], weight: 100,
        }];
        let ps = backend.generate_powershell(&filters);
        assert!(ps.contains("New-NetFirewallRule"));
        assert!(ps.contains("Allow"));
    }
}
