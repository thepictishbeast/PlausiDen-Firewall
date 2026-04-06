//! IPv6 prefix filter — block or allow IPv6 ranges, handle link-local/ULA
//! addresses, and detect 6to4 tunneling.

use serde::{Deserialize, Serialize};
use std::net::Ipv6Addr;

/// Categorization of an IPv6 address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Ipv6Scope {
    Loopback,
    LinkLocal,       // fe80::/10
    UniqueLocal,     // fc00::/7 (ULA)
    Multicast,       // ff00::/8
    Documentation,   // 2001:db8::/32
    SixToFour,       // 2002::/16
    Teredo,          // 2001::/32
    GlobalUnicast,
    Unspecified,
}

/// Identify the scope of an IPv6 address.
pub fn classify(addr: &Ipv6Addr) -> Ipv6Scope {
    if addr.is_unspecified() {
        return Ipv6Scope::Unspecified;
    }
    if addr.is_loopback() {
        return Ipv6Scope::Loopback;
    }
    if addr.is_multicast() {
        return Ipv6Scope::Multicast;
    }

    let segments = addr.segments();
    // Link-local fe80::/10
    if segments[0] & 0xffc0 == 0xfe80 {
        return Ipv6Scope::LinkLocal;
    }
    // ULA fc00::/7
    if segments[0] & 0xfe00 == 0xfc00 {
        return Ipv6Scope::UniqueLocal;
    }
    // Documentation 2001:db8::/32
    if segments[0] == 0x2001 && segments[1] == 0x0db8 {
        return Ipv6Scope::Documentation;
    }
    // 6to4 2002::/16
    if segments[0] == 0x2002 {
        return Ipv6Scope::SixToFour;
    }
    // Teredo 2001:0000::/32
    if segments[0] == 0x2001 && segments[1] == 0x0000 {
        return Ipv6Scope::Teredo;
    }
    Ipv6Scope::GlobalUnicast
}

/// A prefix rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrefixRule {
    pub id: String,
    pub prefix: Ipv6Addr,
    pub length: u8,
    pub action: PrefixAction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PrefixAction {
    Allow,
    Block,
    Log,
}

/// Whether an address falls inside a prefix.
pub fn matches_prefix(addr: &Ipv6Addr, prefix: &Ipv6Addr, length: u8) -> bool {
    let addr_bits = addr.octets();
    let prefix_bits = prefix.octets();
    let full_bytes = (length / 8) as usize;
    let remainder = length % 8;

    for i in 0..full_bytes {
        if addr_bits[i] != prefix_bits[i] {
            return false;
        }
    }
    if remainder > 0 && full_bytes < 16 {
        let mask = 0xffu8 << (8 - remainder);
        if (addr_bits[full_bytes] & mask) != (prefix_bits[full_bytes] & mask) {
            return false;
        }
    }
    true
}

/// IPv6 filter.
pub struct Ipv6Filter {
    rules: Vec<PrefixRule>,
    /// Default action for addresses not matching any rule.
    default_action: PrefixAction,
    /// Block 6to4 and Teredo tunneling by default.
    block_tunneling: bool,
}

impl Ipv6Filter {
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            default_action: PrefixAction::Allow,
            block_tunneling: true,
        }
    }

    pub fn default_deny() -> Self {
        Self {
            rules: Vec::new(),
            default_action: PrefixAction::Block,
            block_tunneling: true,
        }
    }

    /// Add a prefix rule.
    pub fn add_rule(&mut self, rule: PrefixRule) {
        self.rules.push(rule);
    }

    /// Remove a rule.
    pub fn remove_rule(&mut self, rule_id: &str) -> bool {
        let before = self.rules.len();
        self.rules.retain(|r| r.id != rule_id);
        self.rules.len() != before
    }

    /// Evaluate an address.
    pub fn evaluate(&self, addr: &Ipv6Addr) -> PrefixAction {
        let scope = classify(addr);
        if self.block_tunneling
            && (scope == Ipv6Scope::SixToFour || scope == Ipv6Scope::Teredo)
        {
            return PrefixAction::Block;
        }
        for rule in &self.rules {
            if matches_prefix(addr, &rule.prefix, rule.length) {
                return rule.action.clone();
            }
        }
        self.default_action.clone()
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

impl Default for Ipv6Filter {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Ipv6Addr { s.parse().unwrap() }

    #[test]
    fn test_loopback() {
        assert_eq!(classify(&parse("::1")), Ipv6Scope::Loopback);
    }

    #[test]
    fn test_link_local() {
        assert_eq!(classify(&parse("fe80::1")), Ipv6Scope::LinkLocal);
    }

    #[test]
    fn test_unique_local() {
        assert_eq!(classify(&parse("fc00::1")), Ipv6Scope::UniqueLocal);
        assert_eq!(classify(&parse("fd12:3456::1")), Ipv6Scope::UniqueLocal);
    }

    #[test]
    fn test_multicast() {
        assert_eq!(classify(&parse("ff02::1")), Ipv6Scope::Multicast);
    }

    #[test]
    fn test_documentation() {
        assert_eq!(classify(&parse("2001:db8::1")), Ipv6Scope::Documentation);
    }

    #[test]
    fn test_six_to_four() {
        assert_eq!(classify(&parse("2002::1")), Ipv6Scope::SixToFour);
    }

    #[test]
    fn test_teredo() {
        assert_eq!(classify(&parse("2001::1")), Ipv6Scope::Teredo);
    }

    #[test]
    fn test_global_unicast() {
        assert_eq!(classify(&parse("2a00:1450::1")), Ipv6Scope::GlobalUnicast);
    }

    #[test]
    fn test_prefix_match_full() {
        let addr = parse("2001:db8::1");
        let prefix = parse("2001:db8::");
        assert!(matches_prefix(&addr, &prefix, 32));
    }

    #[test]
    fn test_prefix_mismatch() {
        let addr = parse("2001:db8::1");
        let prefix = parse("2a00::");
        assert!(!matches_prefix(&addr, &prefix, 16));
    }

    #[test]
    fn test_filter_default_allow() {
        let f = Ipv6Filter::new();
        assert_eq!(f.evaluate(&parse("2a00:1450::1")), PrefixAction::Allow);
    }

    #[test]
    fn test_filter_default_deny() {
        let f = Ipv6Filter::default_deny();
        assert_eq!(f.evaluate(&parse("2a00:1450::1")), PrefixAction::Block);
    }

    #[test]
    fn test_filter_blocks_6to4_by_default() {
        let f = Ipv6Filter::new();
        assert_eq!(f.evaluate(&parse("2002::1")), PrefixAction::Block);
    }

    #[test]
    fn test_filter_blocks_teredo_by_default() {
        let f = Ipv6Filter::new();
        assert_eq!(f.evaluate(&parse("2001::1")), PrefixAction::Block);
    }

    #[test]
    fn test_rule_overrides_default() {
        let mut f = Ipv6Filter::default_deny();
        f.add_rule(PrefixRule {
            id: "r1".into(),
            prefix: parse("2a00::"),
            length: 12,
            action: PrefixAction::Allow,
        });
        assert_eq!(f.evaluate(&parse("2a00:1450::1")), PrefixAction::Allow);
    }

    #[test]
    fn test_remove_rule() {
        let mut f = Ipv6Filter::new();
        f.add_rule(PrefixRule {
            id: "r1".into(),
            prefix: parse("2a00::"),
            length: 12,
            action: PrefixAction::Block,
        });
        assert!(f.remove_rule("r1"));
        assert_eq!(f.rule_count(), 0);
    }
}
