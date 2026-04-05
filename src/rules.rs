//! Firewall rule engine with priority ordering and default-deny semantics.
//!
//! Rules are matched in priority order (lower number = higher priority).
//! If no rule matches, the default action is **deny**.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

/// Errors that can occur during rule operations.
#[derive(Debug, Error)]
pub enum RuleError {
    /// Two rules with conflicting actions match the same traffic.
    #[error("conflicting rules: rule '{0}' and rule '{1}' overlap with opposing actions")]
    ConflictingRules(String, String),

    /// A rule has an invalid configuration.
    #[error("invalid rule: {0}")]
    InvalidRule(String),
}

/// Action to take when a rule matches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleAction {
    /// Allow the traffic through.
    Allow,
    /// Deny (drop) the traffic.
    Deny,
    /// Log the traffic but take no blocking action.
    Log,
    /// Rate-limit the traffic to the specified packets per second.
    RateLimit(u32),
    /// Redirect traffic to the specified address and port.
    Redirect(IpAddr, u16),
}

/// Network protocol to match against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Protocol {
    /// Transmission Control Protocol.
    Tcp,
    /// User Datagram Protocol.
    Udp,
    /// Internet Control Message Protocol.
    Icmp,
}

/// Criteria for matching traffic against a rule.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RuleMatch {
    /// Source IP address to match. `None` means any.
    pub source_ip: Option<IpAddr>,
    /// Source port range (inclusive). `None` means any.
    pub source_port_range: Option<(u16, u16)>,
    /// Destination IP address to match. `None` means any.
    pub dest_ip: Option<IpAddr>,
    /// Destination port range (inclusive). `None` means any.
    pub dest_port_range: Option<(u16, u16)>,
    /// Protocol to match. `None` means any.
    pub protocol: Option<Protocol>,
    /// Application name to match (e.g., "firefox", "curl"). `None` means any.
    pub application: Option<String>,
    /// Domain pattern to match (e.g., "*.example.com"). `None` means any.
    pub domain_pattern: Option<String>,
}

impl RuleMatch {
    /// Check whether this match criteria overlaps with another.
    ///
    /// Two matches overlap if every field is either identical or at least one is `None` (wildcard).
    fn overlaps_with(&self, other: &Self) -> bool {
        let ip_overlaps = |a: &Option<IpAddr>, b: &Option<IpAddr>| -> bool {
            match (a, b) {
                (Some(x), Some(y)) => x == y,
                _ => true,
            }
        };

        let port_overlaps =
            |a: &Option<(u16, u16)>, b: &Option<(u16, u16)>| -> bool {
                match (a, b) {
                    (Some((a_lo, a_hi)), Some((b_lo, b_hi))) => a_lo <= b_hi && b_lo <= a_hi,
                    _ => true,
                }
            };

        let proto_overlaps =
            |a: &Option<Protocol>, b: &Option<Protocol>| -> bool {
                match (a, b) {
                    (Some(x), Some(y)) => x == y,
                    _ => true,
                }
            };

        let str_overlaps = |a: &Option<String>, b: &Option<String>| -> bool {
            match (a, b) {
                (Some(x), Some(y)) => x == y,
                _ => true,
            }
        };

        ip_overlaps(&self.source_ip, &other.source_ip)
            && port_overlaps(&self.source_port_range, &other.source_port_range)
            && ip_overlaps(&self.dest_ip, &other.dest_ip)
            && port_overlaps(&self.dest_port_range, &other.dest_port_range)
            && proto_overlaps(&self.protocol, &other.protocol)
            && str_overlaps(&self.application, &other.application)
            && str_overlaps(&self.domain_pattern, &other.domain_pattern)
    }

    /// Check whether the given traffic parameters match this rule's criteria.
    #[allow(clippy::too_many_arguments)]
    pub fn matches(
        &self,
        source_ip: Option<IpAddr>,
        source_port: Option<u16>,
        dest_ip: Option<IpAddr>,
        dest_port: Option<u16>,
        protocol: Option<Protocol>,
        application: Option<&str>,
        domain: Option<&str>,
    ) -> bool {
        if let Some(ref rule_ip) = self.source_ip {
            match source_ip {
                Some(ref pkt_ip) if pkt_ip != rule_ip => return false,
                None => return false,
                _ => {}
            }
        }

        if let Some((lo, hi)) = self.source_port_range {
            match source_port {
                Some(p) if p < lo || p > hi => return false,
                None => return false,
                _ => {}
            }
        }

        if let Some(ref rule_ip) = self.dest_ip {
            match dest_ip {
                Some(ref pkt_ip) if pkt_ip != rule_ip => return false,
                None => return false,
                _ => {}
            }
        }

        if let Some((lo, hi)) = self.dest_port_range {
            match dest_port {
                Some(p) if p < lo || p > hi => return false,
                None => return false,
                _ => {}
            }
        }

        if let Some(ref rule_proto) = self.protocol {
            match protocol {
                Some(ref pkt_proto) if pkt_proto != rule_proto => return false,
                None => return false,
                _ => {}
            }
        }

        if let Some(ref rule_app) = self.application {
            match application {
                Some(pkt_app) if pkt_app != rule_app => return false,
                None => return false,
                _ => {}
            }
        }

        if let Some(ref rule_domain) = self.domain_pattern {
            match domain {
                Some(pkt_domain) => {
                    if !domain_matches_pattern(pkt_domain, rule_domain) {
                        return false;
                    }
                }
                None => return false,
            }
        }

        true
    }
}

/// Check if a domain matches a pattern (supports leading `*.` wildcard).
fn domain_matches_pattern(domain: &str, pattern: &str) -> bool {
    if let Some(suffix) = pattern.strip_prefix("*.") {
        domain == suffix || domain.ends_with(&format!(".{suffix}"))
    } else {
        domain == pattern
    }
}

/// A single firewall rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRule {
    /// Unique identifier for this rule.
    pub id: Uuid,
    /// Human-readable name.
    pub name: String,
    /// Priority (lower number = higher priority, evaluated first).
    pub priority: u32,
    /// Match criteria for this rule.
    pub rule_match: RuleMatch,
    /// Action to take when matched.
    pub action: RuleAction,
    /// Whether this rule is currently enabled.
    pub enabled: bool,
}

/// An ordered set of firewall rules with default-deny semantics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleSet {
    /// Rules sorted by priority (lower number first).
    rules: Vec<FirewallRule>,
}

impl Default for RuleSet {
    fn default() -> Self {
        Self::new()
    }
}

impl RuleSet {
    /// Create a new empty rule set.
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Add a rule, maintaining priority order.
    ///
    /// # Errors
    ///
    /// Returns `RuleError::InvalidRule` if port ranges are inverted.
    /// Returns `RuleError::ConflictingRules` if an existing rule with an opposing
    /// Allow/Deny action overlaps at the same priority.
    pub fn add_rule(&mut self, rule: FirewallRule) -> Result<(), RuleError> {
        // Validate port ranges.
        if let Some((lo, hi)) = rule.rule_match.source_port_range
            && lo > hi
        {
            return Err(RuleError::InvalidRule(format!(
                "source port range {lo}-{hi} is inverted"
            )));
        }
        if let Some((lo, hi)) = rule.rule_match.dest_port_range
            && lo > hi
        {
            return Err(RuleError::InvalidRule(format!(
                "dest port range {lo}-{hi} is inverted"
            )));
        }

        // Check for conflicting rules (overlapping match with opposing Allow/Deny at same priority).
        for existing in &self.rules {
            if existing.priority == rule.priority
                && existing.enabled
                && rule.enabled
                && is_opposing_action(&existing.action, &rule.action)
                && existing.rule_match.overlaps_with(&rule.rule_match)
            {
                return Err(RuleError::ConflictingRules(
                    existing.name.clone(),
                    rule.name.clone(),
                ));
            }
        }

        self.rules.push(rule);
        self.rules.sort_by_key(|r| r.priority);
        Ok(())
    }

    /// Remove a rule by its ID.
    pub fn remove_rule(&mut self, id: &Uuid) -> bool {
        let before = self.rules.len();
        self.rules.retain(|r| r.id != *id);
        self.rules.len() < before
    }

    /// Evaluate traffic against the rule set. Returns the action from the first matching rule,
    /// or `RuleAction::Deny` if nothing matches (default-deny).
    #[allow(clippy::too_many_arguments)]
    pub fn evaluate(
        &self,
        source_ip: Option<IpAddr>,
        source_port: Option<u16>,
        dest_ip: Option<IpAddr>,
        dest_port: Option<u16>,
        protocol: Option<Protocol>,
        application: Option<&str>,
        domain: Option<&str>,
    ) -> RuleAction {
        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }
            if rule.rule_match.matches(
                source_ip,
                source_port,
                dest_ip,
                dest_port,
                protocol,
                application,
                domain,
            ) {
                return rule.action.clone();
            }
        }
        // Default deny.
        RuleAction::Deny
    }

    /// Return a reference to all rules.
    pub fn rules(&self) -> &[FirewallRule] {
        &self.rules
    }
}

/// Check whether two actions are opposing (one Allow, the other Deny).
fn is_opposing_action(a: &RuleAction, b: &RuleAction) -> bool {
    matches!(
        (a, b),
        (RuleAction::Allow, RuleAction::Deny) | (RuleAction::Deny, RuleAction::Allow)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn make_rule(name: &str, priority: u32, action: RuleAction, rule_match: RuleMatch) -> FirewallRule {
        FirewallRule {
            id: Uuid::new_v4(),
            name: name.to_string(),
            priority,
            rule_match,
            action,
            enabled: true,
        }
    }

    #[test]
    fn test_match_source_ip() {
        let rule_match = RuleMatch {
            source_ip: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))),
            ..Default::default()
        };
        assert!(rule_match.matches(
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))),
            None, None, None, None, None, None,
        ));
        assert!(!rule_match.matches(
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            None, None, None, None, None, None,
        ));
    }

    #[test]
    fn test_match_dest_port_range() {
        let rule_match = RuleMatch {
            dest_port_range: Some((80, 443)),
            ..Default::default()
        };
        assert!(rule_match.matches(None, None, None, Some(80), None, None, None));
        assert!(rule_match.matches(None, None, None, Some(443), None, None, None));
        assert!(rule_match.matches(None, None, None, Some(200), None, None, None));
        assert!(!rule_match.matches(None, None, None, Some(79), None, None, None));
        assert!(!rule_match.matches(None, None, None, Some(444), None, None, None));
    }

    #[test]
    fn test_match_protocol() {
        let rule_match = RuleMatch {
            protocol: Some(Protocol::Tcp),
            ..Default::default()
        };
        assert!(rule_match.matches(None, None, None, None, Some(Protocol::Tcp), None, None));
        assert!(!rule_match.matches(None, None, None, None, Some(Protocol::Udp), None, None));
        assert!(!rule_match.matches(None, None, None, None, Some(Protocol::Icmp), None, None));
    }

    #[test]
    fn test_match_application() {
        let rule_match = RuleMatch {
            application: Some("firefox".to_string()),
            ..Default::default()
        };
        assert!(rule_match.matches(None, None, None, None, None, Some("firefox"), None));
        assert!(!rule_match.matches(None, None, None, None, None, Some("chrome"), None));
        assert!(!rule_match.matches(None, None, None, None, None, None, None));
    }

    #[test]
    fn test_match_domain_exact() {
        let rule_match = RuleMatch {
            domain_pattern: Some("example.com".to_string()),
            ..Default::default()
        };
        assert!(rule_match.matches(None, None, None, None, None, None, Some("example.com")));
        assert!(!rule_match.matches(None, None, None, None, None, None, Some("other.com")));
    }

    #[test]
    fn test_match_domain_wildcard() {
        let rule_match = RuleMatch {
            domain_pattern: Some("*.example.com".to_string()),
            ..Default::default()
        };
        assert!(rule_match.matches(None, None, None, None, None, None, Some("sub.example.com")));
        assert!(rule_match.matches(None, None, None, None, None, None, Some("example.com")));
        assert!(!rule_match.matches(None, None, None, None, None, None, Some("other.com")));
    }

    #[test]
    fn test_match_ipv6() {
        let rule_match = RuleMatch {
            source_ip: Some(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            ..Default::default()
        };
        assert!(rule_match.matches(
            Some(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            None, None, None, None, None, None,
        ));
        assert!(!rule_match.matches(
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            None, None, None, None, None, None,
        ));
    }

    #[test]
    fn test_default_deny_blocks_unknown() {
        let ruleset = RuleSet::new();
        let action = ruleset.evaluate(
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            Some(12345),
            Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
            Some(443),
            Some(Protocol::Tcp),
            Some("unknown_app"),
            None,
        );
        assert_eq!(action, RuleAction::Deny);
    }

    #[test]
    fn test_explicit_allow_passes() {
        let mut ruleset = RuleSet::new();
        let rule = make_rule(
            "allow-dns",
            10,
            RuleAction::Allow,
            RuleMatch {
                dest_port_range: Some((53, 53)),
                protocol: Some(Protocol::Udp),
                ..Default::default()
            },
        );
        ruleset.add_rule(rule).unwrap();

        let action = ruleset.evaluate(
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            Some(50000),
            Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
            Some(53),
            Some(Protocol::Udp),
            None,
            None,
        );
        assert_eq!(action, RuleAction::Allow);
    }

    #[test]
    fn test_priority_ordering() {
        let mut ruleset = RuleSet::new();

        // Lower priority number = higher priority = evaluated first.
        let deny_all = make_rule(
            "deny-all-http",
            20,
            RuleAction::Deny,
            RuleMatch {
                dest_port_range: Some((80, 80)),
                ..Default::default()
            },
        );
        let allow_specific = make_rule(
            "allow-trusted-http",
            10,
            RuleAction::Allow,
            RuleMatch {
                dest_ip: Some(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))),
                dest_port_range: Some((80, 80)),
                ..Default::default()
            },
        );

        ruleset.add_rule(deny_all).unwrap();
        ruleset.add_rule(allow_specific).unwrap();

        // Trusted IP on port 80 should be allowed (priority 10 > priority 20).
        let action = ruleset.evaluate(
            None,
            None,
            Some(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))),
            Some(80),
            None,
            None,
            None,
        );
        assert_eq!(action, RuleAction::Allow);

        // Untrusted IP on port 80 should be denied (only priority-20 rule matches).
        let action = ruleset.evaluate(
            None,
            None,
            Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))),
            Some(80),
            None,
            None,
            None,
        );
        assert_eq!(action, RuleAction::Deny);
    }

    #[test]
    fn test_rule_validation_rejects_inverted_port_range() {
        let mut ruleset = RuleSet::new();
        let bad_rule = make_rule(
            "bad-ports",
            10,
            RuleAction::Allow,
            RuleMatch {
                dest_port_range: Some((443, 80)), // inverted
                ..Default::default()
            },
        );
        let result = ruleset.add_rule(bad_rule);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("inverted"));
    }

    #[test]
    fn test_rule_validation_rejects_conflicting_rules() {
        let mut ruleset = RuleSet::new();
        let allow_rule = make_rule(
            "allow-http",
            10,
            RuleAction::Allow,
            RuleMatch {
                dest_port_range: Some((80, 80)),
                protocol: Some(Protocol::Tcp),
                ..Default::default()
            },
        );
        let deny_rule = make_rule(
            "deny-http",
            10,
            RuleAction::Deny,
            RuleMatch {
                dest_port_range: Some((80, 80)),
                protocol: Some(Protocol::Tcp),
                ..Default::default()
            },
        );
        ruleset.add_rule(allow_rule).unwrap();
        let result = ruleset.add_rule(deny_rule);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("conflicting"));
    }

    #[test]
    fn test_combined_match_criteria() {
        let rule_match = RuleMatch {
            source_ip: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50))),
            dest_port_range: Some((443, 443)),
            protocol: Some(Protocol::Tcp),
            application: Some("curl".to_string()),
            ..Default::default()
        };

        // All fields match.
        assert!(rule_match.matches(
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50))),
            None,
            None,
            Some(443),
            Some(Protocol::Tcp),
            Some("curl"),
            None,
        ));

        // Wrong app.
        assert!(!rule_match.matches(
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50))),
            None,
            None,
            Some(443),
            Some(Protocol::Tcp),
            Some("wget"),
            None,
        ));
    }

    #[test]
    fn test_disabled_rule_skipped() {
        let mut ruleset = RuleSet::new();
        let mut rule = make_rule(
            "allow-all",
            1,
            RuleAction::Allow,
            RuleMatch::default(),
        );
        rule.enabled = false;
        ruleset.add_rule(rule).unwrap();

        // Disabled rule should not match; default deny kicks in.
        let action = ruleset.evaluate(None, None, None, None, None, None, None);
        assert_eq!(action, RuleAction::Deny);
    }

    #[test]
    fn test_remove_rule() {
        let mut ruleset = RuleSet::new();
        let rule = make_rule(
            "temp",
            10,
            RuleAction::Allow,
            RuleMatch::default(),
        );
        let id = rule.id;
        ruleset.add_rule(rule).unwrap();
        assert_eq!(ruleset.rules().len(), 1);

        assert!(ruleset.remove_rule(&id));
        assert_eq!(ruleset.rules().len(), 0);

        // Removing non-existent rule returns false.
        assert!(!ruleset.remove_rule(&Uuid::new_v4()));
    }
}
