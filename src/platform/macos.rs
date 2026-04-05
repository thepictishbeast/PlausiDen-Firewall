//! macOS firewall backend — pf.conf rule generation.

use crate::rules::{FirewallRule, RuleAction, RuleSet};
/// macOS pf.conf rule generator.
pub struct MacosBackend {
    interface: String,
}

impl MacosBackend {
    pub fn new(interface: &str) -> Self {
        Self { interface: interface.into() }
    }

    /// Generate pf.conf content from a rule set.
    pub fn generate_pf_conf(&self, rules: &RuleSet) -> String {
        let mut lines = Vec::new();

        // Default settings
        lines.push("# PlausiDen Firewall — generated pf.conf".into());
        lines.push(format!("ext_if = \"{}\"", self.interface));
        lines.push(String::new());
        lines.push("set skip on lo0".into());
        lines.push("set block-policy drop".into());
        lines.push(String::new());

        // Default deny
        lines.push("block all".into());
        lines.push(String::new());

        // Allow established
        lines.push("pass out on $ext_if proto tcp from any to any flags S/SA keep state".into());
        lines.push("pass in on $ext_if proto tcp from any to any flags S/SA keep state".into());
        lines.push(String::new());

        // Translate rules
        for rule in rules.rules() {
            if !rule.enabled { continue; }
            if let Some(pf_rule) = self.translate_rule(rule) {
                lines.push(pf_rule);
            }
        }

        lines.join("\n")
    }

    fn translate_rule(&self, rule: &FirewallRule) -> Option<String> {
        let action = match rule.action {
            RuleAction::Allow => "pass",
            RuleAction::Deny => "block",
            RuleAction::Log => "block log",
            _ => return None,
        };

        let m = &rule.rule_match;
        let mut parts = vec![action.to_string()];

        let direction = if m.source_ip.is_some() { "in" } else { "out" };
        parts.push(direction.into());
        parts.push("on $ext_if".to_string());

        if let Some(ref proto) = m.protocol {
            parts.push(format!("proto {:?}", proto).to_lowercase());
        }

        if let Some(ref ip) = m.source_ip {
            parts.push(format!("from {ip}"));
        }
        if let Some(ref ip) = m.dest_ip {
            parts.push(format!("to {ip}"));
        }
        if let Some((min, max)) = m.dest_port_range {
            if min == max {
                parts.push(format!("port {min}"));
            } else {
                parts.push(format!("port {min}:{max}"));
            }
        }

        Some(parts.join(" "))
    }
}

impl Default for MacosBackend {
    fn default() -> Self { Self::new("en0") }
}

/// Windows Filtering Platform backend.
pub struct WindowsBackend;

impl WindowsBackend {
    pub fn new() -> Self { Self }
}

impl Default for WindowsBackend {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pf_conf_generation() {
        let backend = MacosBackend::default();
        let rules = RuleSet::new();
        let conf = backend.generate_pf_conf(&rules);
        assert!(conf.contains("block all"));
        assert!(conf.contains("set skip on lo0"));
        assert!(conf.contains("ext_if"));
    }

    #[test]
    fn test_pf_conf_with_rules() {
        let backend = MacosBackend::default();
        let mut rules = RuleSet::new();
        rules.add_rule(crate::rules::FirewallRule {
            id: uuid::Uuid::new_v4(),
            name: "allow https".into(),
            priority: 100,
            rule_match: crate::rules::RuleMatch {
                source_ip: None, source_port_range: None,
                dest_ip: Some("93.184.216.34".parse().unwrap()),
                dest_port_range: Some((443, 443)),
                protocol: None, application: None, domain_pattern: None,
            },
            action: RuleAction::Allow,
            enabled: true,
        }).unwrap();
        let conf = backend.generate_pf_conf(&rules);
        assert!(conf.contains("pass"));
        assert!(conf.contains("93.184.216.34"));
        assert!(conf.contains("443"));
    }
}
