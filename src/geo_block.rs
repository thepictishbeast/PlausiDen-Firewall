//! Geographic blocking — block traffic to/from specific countries.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::IpAddr;

/// Action to take for traffic from a country.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GeoAction {
    Allow,
    Block,
    Log,
}

/// Geographic blocking policy.
pub struct GeoBlocker {
    /// ISO country codes to block.
    blocked_countries: HashSet<String>,
    /// ISO country codes explicitly allowed (whitelist mode).
    allowed_countries: HashSet<String>,
    /// Whether to use whitelist mode (allow only listed countries).
    whitelist_mode: bool,
    /// Default action for unknown countries.
    default_action: GeoAction,
}

impl GeoBlocker {
    pub fn new() -> Self {
        Self {
            blocked_countries: HashSet::new(),
            allowed_countries: HashSet::new(),
            whitelist_mode: false,
            default_action: GeoAction::Allow,
        }
    }

    /// Block a country by ISO code.
    pub fn block_country(&mut self, code: &str) {
        self.blocked_countries.insert(code.to_uppercase());
    }

    /// Allow a country (used in whitelist mode).
    pub fn allow_country(&mut self, code: &str) {
        self.allowed_countries.insert(code.to_uppercase());
    }

    /// Enable whitelist mode (only allowed countries pass).
    pub fn enable_whitelist(&mut self) {
        self.whitelist_mode = true;
    }

    /// Set the default action for unknown countries.
    pub fn set_default(&mut self, action: GeoAction) {
        self.default_action = action;
    }

    /// Check if traffic to/from a country should be allowed.
    pub fn check_country(&self, code: &str) -> GeoAction {
        let code = code.to_uppercase();

        if self.whitelist_mode {
            if self.allowed_countries.contains(&code) {
                return GeoAction::Allow;
            }
            return GeoAction::Block;
        }

        if self.blocked_countries.contains(&code) {
            return GeoAction::Block;
        }

        self.default_action.clone()
    }

    /// Quick check for whether a country is blocked.
    pub fn is_blocked(&self, code: &str) -> bool {
        matches!(self.check_country(code), GeoAction::Block)
    }

    /// Apply common security blocklists (high-risk countries for cyber attacks).
    pub fn apply_high_risk_blocklist(&mut self) {
        // This is a generic example. Users should customize for their threat model.
        for code in &["KP", "IR", "SY"] { // Example: sanctioned countries
            self.block_country(code);
        }
    }

    pub fn blocked_count(&self) -> usize { self.blocked_countries.len() }
    pub fn allowed_count(&self) -> usize { self.allowed_countries.len() }
    pub fn is_whitelist_mode(&self) -> bool { self.whitelist_mode }
}

impl Default for GeoBlocker {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_country() {
        let mut blocker = GeoBlocker::new();
        blocker.block_country("US");
        assert!(blocker.is_blocked("US"));
        assert!(blocker.is_blocked("us")); // Case insensitive.
    }

    #[test]
    fn test_default_allow() {
        let blocker = GeoBlocker::new();
        assert_eq!(blocker.check_country("CA"), GeoAction::Allow);
    }

    #[test]
    fn test_whitelist_mode() {
        let mut blocker = GeoBlocker::new();
        blocker.enable_whitelist();
        blocker.allow_country("US");
        blocker.allow_country("CA");
        assert!(!blocker.is_blocked("US"));
        assert!(blocker.is_blocked("CN")); // Not in whitelist.
    }

    #[test]
    fn test_blocklist_overrides_default() {
        let mut blocker = GeoBlocker::new();
        blocker.set_default(GeoAction::Allow);
        blocker.block_country("XX");
        assert!(blocker.is_blocked("XX"));
        assert!(!blocker.is_blocked("YY"));
    }

    #[test]
    fn test_high_risk_blocklist() {
        let mut blocker = GeoBlocker::new();
        blocker.apply_high_risk_blocklist();
        assert!(blocker.blocked_count() >= 3);
    }

    #[test]
    fn test_log_default() {
        let mut blocker = GeoBlocker::new();
        blocker.set_default(GeoAction::Log);
        assert_eq!(blocker.check_country("XX"), GeoAction::Log);
    }
}
