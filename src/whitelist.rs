//! Application/domain whitelist management.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::IpAddr;

/// A whitelist entry.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WhitelistEntry {
    Domain(String),
    Subdomain(String),
    IpAddress(IpAddr),
    IpRange { network: IpAddr, prefix: u8 },
    Application(String),
}

/// Whitelist manager.
pub struct Whitelist {
    domains: HashSet<String>,
    subdomains: HashSet<String>,
    ips: HashSet<IpAddr>,
    ip_ranges: Vec<(IpAddr, u8)>,
    apps: HashSet<String>,
    /// Whether to be in default-allow or default-deny mode.
    default_deny: bool,
}

impl Whitelist {
    pub fn new(default_deny: bool) -> Self {
        Self {
            domains: HashSet::new(),
            subdomains: HashSet::new(),
            ips: HashSet::new(),
            ip_ranges: Vec::new(),
            apps: HashSet::new(),
            default_deny,
        }
    }

    /// Add an entry.
    pub fn add(&mut self, entry: WhitelistEntry) {
        match entry {
            WhitelistEntry::Domain(d) => { self.domains.insert(d.to_lowercase()); }
            WhitelistEntry::Subdomain(d) => { self.subdomains.insert(d.to_lowercase()); }
            WhitelistEntry::IpAddress(ip) => { self.ips.insert(ip); }
            WhitelistEntry::IpRange { network, prefix } => { self.ip_ranges.push((network, prefix)); }
            WhitelistEntry::Application(app) => { self.apps.insert(app); }
        }
    }

    /// Check if a domain is whitelisted.
    pub fn check_domain(&self, domain: &str) -> bool {
        let lower = domain.to_lowercase();
        if self.domains.contains(&lower) {
            return true;
        }
        // Subdomain wildcard match.
        for sub in &self.subdomains {
            if lower == *sub || lower.ends_with(&format!(".{sub}")) {
                return true;
            }
        }
        !self.default_deny
    }

    /// Check if an IP is whitelisted.
    pub fn check_ip(&self, ip: &IpAddr) -> bool {
        if self.ips.contains(ip) {
            return true;
        }
        // CIDR range check.
        for (network, prefix) in &self.ip_ranges {
            if ip_in_range(ip, network, *prefix) {
                return true;
            }
        }
        !self.default_deny
    }

    /// Check if an application is whitelisted.
    pub fn check_app(&self, app: &str) -> bool {
        if self.apps.contains(app) {
            return true;
        }
        !self.default_deny
    }

    pub fn domain_count(&self) -> usize { self.domains.len() + self.subdomains.len() }
    pub fn ip_count(&self) -> usize { self.ips.len() + self.ip_ranges.len() }
    pub fn app_count(&self) -> usize { self.apps.len() }
}

impl Default for Whitelist {
    fn default() -> Self { Self::new(false) }
}

fn ip_in_range(ip: &IpAddr, network: &IpAddr, prefix: u8) -> bool {
    match (ip, network) {
        (IpAddr::V4(a), IpAddr::V4(n)) => {
            let a_bits = u32::from(*a);
            let n_bits = u32::from(*n);
            let mask = if prefix >= 32 { u32::MAX } else { !((1u32 << (32 - prefix)) - 1) };
            (a_bits & mask) == (n_bits & mask)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr { s.parse().unwrap() }

    #[test]
    fn test_default_allow() {
        let wl = Whitelist::default();
        assert!(wl.check_domain("anything.com"));
        assert!(wl.check_ip(&ip("1.2.3.4")));
    }

    #[test]
    fn test_default_deny() {
        let wl = Whitelist::new(true);
        assert!(!wl.check_domain("anything.com"));
        assert!(!wl.check_ip(&ip("1.2.3.4")));
    }

    #[test]
    fn test_exact_domain() {
        let mut wl = Whitelist::new(true);
        wl.add(WhitelistEntry::Domain("example.com".into()));
        assert!(wl.check_domain("example.com"));
        assert!(!wl.check_domain("sub.example.com"));
    }

    #[test]
    fn test_subdomain_wildcard() {
        let mut wl = Whitelist::new(true);
        wl.add(WhitelistEntry::Subdomain("example.com".into()));
        assert!(wl.check_domain("example.com"));
        assert!(wl.check_domain("sub.example.com"));
        assert!(wl.check_domain("deep.sub.example.com"));
        assert!(!wl.check_domain("notexample.com"));
    }

    #[test]
    fn test_ip_address() {
        let mut wl = Whitelist::new(true);
        wl.add(WhitelistEntry::IpAddress(ip("1.2.3.4")));
        assert!(wl.check_ip(&ip("1.2.3.4")));
        assert!(!wl.check_ip(&ip("1.2.3.5")));
    }

    #[test]
    fn test_ip_range() {
        let mut wl = Whitelist::new(true);
        wl.add(WhitelistEntry::IpRange { network: ip("10.0.0.0"), prefix: 24 });
        assert!(wl.check_ip(&ip("10.0.0.1")));
        assert!(wl.check_ip(&ip("10.0.0.254")));
        assert!(!wl.check_ip(&ip("10.0.1.1")));
    }

    #[test]
    fn test_application() {
        let mut wl = Whitelist::new(true);
        wl.add(WhitelistEntry::Application("firefox".into()));
        assert!(wl.check_app("firefox"));
        assert!(!wl.check_app("chrome"));
    }

    #[test]
    fn test_counts() {
        let mut wl = Whitelist::new(true);
        wl.add(WhitelistEntry::Domain("a.com".into()));
        wl.add(WhitelistEntry::Subdomain("b.com".into()));
        wl.add(WhitelistEntry::IpAddress(ip("1.1.1.1")));
        wl.add(WhitelistEntry::IpRange { network: ip("10.0.0.0"), prefix: 8 });
        wl.add(WhitelistEntry::Application("app".into()));
        assert_eq!(wl.domain_count(), 2);
        assert_eq!(wl.ip_count(), 2);
        assert_eq!(wl.app_count(), 1);
    }
}
