//! nftables backend — generates kernel netfilter rules from our rule engine.

use crate::rules::{FirewallRule, RuleAction, RuleSet};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TableFamily { Inet4, Inet6, Inet }

/// A generated nftables ruleset.
#[derive(Debug, Clone)]
pub struct NftRuleset {
    pub commands: Vec<String>,
}

impl NftRuleset {
    pub fn to_script(&self) -> String { self.commands.join("\n") }
    pub fn rule_count(&self) -> usize { self.commands.iter().filter(|c| c.starts_with("add rule")).count() }
}

/// Translates our RuleSet into nft commands.
pub struct NftablesBackend {
    table_name: String,
    family: TableFamily,
}

impl NftablesBackend {
    pub fn new(table_name: &str, family: TableFamily) -> Self {
        Self { table_name: table_name.to_string(), family }
    }

    pub fn generate_ruleset(&self, ruleset: &RuleSet) -> NftRuleset {
        let f = self.family_str();
        let t = &self.table_name;
        let mut cmds = vec![
            format!("flush table {f} {t}"),
            format!("add table {f} {t}"),
            format!("add chain {f} {t} input {{ type filter hook input priority 0; policy drop; }}"),
            format!("add chain {f} {t} output {{ type filter hook output priority 0; policy drop; }}"),
            format!("add rule {f} {t} input ct state established,related accept"),
            format!("add rule {f} {t} output ct state established,related accept"),
            format!("add rule {f} {t} input iif lo accept"),
            format!("add rule {f} {t} output oif lo accept"),
        ];

        for rule in ruleset.rules() {
            if !rule.enabled { continue; }
            if let Some(cmd) = self.translate_rule(rule) {
                cmds.push(cmd);
            }
        }

        NftRuleset { commands: cmds }
    }

    /// Generate rate-limiting rules for brute-force protection.
    pub fn generate_rate_limits(&self) -> Vec<String> {
        let f = self.family_str();
        let t = &self.table_name;
        vec![
            // SSH brute-force protection: 4 new connections per minute.
            format!("add rule {f} {t} input tcp dport 22 ct state new meter ssh_meter {{ ip saddr limit rate 4/minute }} accept"),
            format!("add rule {f} {t} input tcp dport 22 ct state new drop"),
            // HTTP flood protection: 100 new connections per second.
            format!("add rule {f} {t} input tcp dport {{ 80, 443 }} ct state new meter http_meter {{ ip saddr limit rate 100/second }} accept"),
            format!("add rule {f} {t} input tcp dport {{ 80, 443 }} ct state new drop"),
            // ICMP rate limit: 10 per second.
            format!("add rule {f} {t} input icmp type echo-request limit rate 10/second accept"),
            format!("add rule {f} {t} input icmp type echo-request drop"),
        ]
    }

    /// Generate anti-spoofing rules.
    pub fn generate_anti_spoof(&self) -> Vec<String> {
        let f = self.family_str();
        let t = &self.table_name;
        vec![
            // Drop packets with impossible source addresses.
            format!("add rule {f} {t} input ip saddr 0.0.0.0/8 drop"),
            format!("add rule {f} {t} input ip saddr 127.0.0.0/8 iif != lo drop"),
            format!("add rule {f} {t} input ip saddr 169.254.0.0/16 drop"),
            format!("add rule {f} {t} input ip saddr 224.0.0.0/4 drop"),
            format!("add rule {f} {t} input ip saddr 240.0.0.0/4 drop"),
            // Drop invalid packets.
            format!("add rule {f} {t} input ct state invalid drop"),
        ]
    }

    /// Generate a comprehensive hardened ruleset including rate limits and anti-spoof.
    pub fn generate_hardened_ruleset(&self, ruleset: &RuleSet) -> NftRuleset {
        let base = self.generate_ruleset(ruleset);
        let mut cmds = base.commands;
        cmds.extend(self.generate_anti_spoof());
        cmds.extend(self.generate_rate_limits());
        NftRuleset { commands: cmds }
    }

    fn translate_rule(&self, rule: &FirewallRule) -> Option<String> {
        let f = self.family_str();
        let t = &self.table_name;
        let action = match &rule.action {
            RuleAction::Allow => "accept",
            RuleAction::Deny => "drop",
            RuleAction::Log => "log",
            _ => return None,
        };

        let m = &rule.rule_match;
        let mut conds = Vec::new();

        if let Some(ip) = &m.source_ip { conds.push(format!("ip saddr {ip}")); }
        if let Some(ip) = &m.dest_ip { conds.push(format!("ip daddr {ip}")); }
        if let Some((min, max)) = m.dest_port_range {
            if min == max { conds.push(format!("tcp dport {min}")); }
            else { conds.push(format!("tcp dport {min}-{max}")); }
        }
        if let Some(proto) = &m.protocol {
            conds.push(format!("meta l4proto {:?}", proto).to_lowercase());
        }

        let chain = if m.source_ip.is_some() { "input" } else { "output" };
        let c = if conds.is_empty() { String::new() } else { conds.join(" ") + " " };

        Some(format!("add rule {f} {t} {chain} {c}{action}"))
    }

    fn family_str(&self) -> &str {
        match self.family {
            TableFamily::Inet4 => "ip",
            TableFamily::Inet6 => "ip6",
            TableFamily::Inet => "inet",
        }
    }
}

impl Default for NftablesBackend {
    fn default() -> Self { Self::new("plausiden", TableFamily::Inet) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::*;
    use std::net::IpAddr;

    fn make_rule(action: RuleAction, dest_ip: Option<&str>, dest_port: Option<u16>) -> FirewallRule {
        FirewallRule {
            id: uuid::Uuid::new_v4(),
            name: "test".into(),
            priority: 100,
            rule_match: RuleMatch {
                source_ip: None,
                source_port_range: None,
                dest_ip: dest_ip.map(|s| s.parse::<IpAddr>().unwrap()),
                dest_port_range: dest_port.map(|p| (p, p)),
                protocol: None,
                application: None,
                domain_pattern: None,
            },
            action,
            enabled: true,
        }
    }

    #[test]
    fn test_empty_ruleset() {
        let backend = NftablesBackend::default();
        let nft = backend.generate_ruleset(&RuleSet::new());
        let script = nft.to_script();
        assert!(script.contains("flush table"));
        assert!(script.contains("policy drop"));
    }

    #[test]
    fn test_allow_rule() {
        let backend = NftablesBackend::default();
        let mut rs = RuleSet::new();
        rs.add_rule(make_rule(RuleAction::Allow, Some("93.184.216.34"), Some(443))).unwrap();
        let nft = backend.generate_ruleset(&rs);
        let script = nft.to_script();
        assert!(script.contains("93.184.216.34"));
        assert!(script.contains("443"));
        assert!(script.contains("accept"));
    }

    #[test]
    fn test_deny_rule() {
        let backend = NftablesBackend::default();
        let mut rs = RuleSet::new();
        rs.add_rule(make_rule(RuleAction::Deny, Some("10.0.0.1"), None)).unwrap();
        let nft = backend.generate_ruleset(&rs);
        assert!(nft.to_script().contains("drop"));
    }

    #[test]
    fn test_loopback_allowed() {
        let backend = NftablesBackend::default();
        let nft = backend.generate_ruleset(&RuleSet::new());
        assert!(nft.to_script().contains("iif lo accept"));
    }

    #[test]
    fn test_rule_count() {
        let backend = NftablesBackend::default();
        let mut rs = RuleSet::new();
        for i in 0..3 {
            rs.add_rule(make_rule(RuleAction::Allow, Some(&format!("10.0.0.{i}")), Some(80))).unwrap();
        }
        let nft = backend.generate_ruleset(&rs);
        assert!(nft.rule_count() >= 3);
    }

    #[test]
    fn test_rate_limits() {
        let backend = NftablesBackend::default();
        let rules = backend.generate_rate_limits();
        assert!(rules.iter().any(|r| r.contains("ssh_meter")));
        assert!(rules.iter().any(|r| r.contains("http_meter")));
        assert!(rules.iter().any(|r| r.contains("icmp")));
    }

    #[test]
    fn test_anti_spoof() {
        let backend = NftablesBackend::default();
        let rules = backend.generate_anti_spoof();
        assert!(rules.iter().any(|r| r.contains("0.0.0.0/8")));
        assert!(rules.iter().any(|r| r.contains("169.254.0.0/16")));
        assert!(rules.iter().any(|r| r.contains("invalid")));
    }

    #[test]
    fn test_hardened_ruleset() {
        let backend = NftablesBackend::default();
        let mut rs = RuleSet::new();
        rs.add_rule(make_rule(RuleAction::Allow, None, Some(443))).unwrap();
        let nft = backend.generate_hardened_ruleset(&rs);
        let script = nft.to_script();
        // Should have base rules + anti-spoof + rate limits.
        assert!(script.contains("flush table"));
        assert!(script.contains("0.0.0.0/8"));
        assert!(script.contains("ssh_meter"));
        assert!(script.contains("443"));
    }

    #[test]
    fn test_inet6_family() {
        let backend = NftablesBackend::new("plausiden", TableFamily::Inet6);
        let nft = backend.generate_ruleset(&RuleSet::new());
        assert!(nft.to_script().contains("ip6"));
    }
}
