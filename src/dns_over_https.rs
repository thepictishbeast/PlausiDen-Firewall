//! DNS-over-HTTPS configuration and validation.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// A DoH provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DohProvider {
    pub name: String,
    pub url: String,
    pub server_ips: Vec<String>,
    pub trusted: bool,
    pub no_logs: bool,
    pub jurisdiction: String,
}

/// DoH configuration.
pub struct DohConfig {
    providers: Vec<DohProvider>,
    blocked_providers: HashSet<String>,
    /// Force DoH (block plain DNS).
    force_doh: bool,
}

impl DohConfig {
    pub fn new() -> Self {
        Self {
            providers: Self::default_providers(),
            blocked_providers: HashSet::new(),
            force_doh: false,
        }
    }

    /// Common privacy-respecting DoH providers.
    fn default_providers() -> Vec<DohProvider> {
        vec![
            DohProvider {
                name: "Quad9".into(),
                url: "https://dns.quad9.net/dns-query".into(),
                server_ips: vec!["9.9.9.9".into(), "149.112.112.112".into()],
                trusted: true,
                no_logs: true,
                jurisdiction: "Switzerland".into(),
            },
            DohProvider {
                name: "Mullvad DNS".into(),
                url: "https://dns.mullvad.net/dns-query".into(),
                server_ips: vec!["194.242.2.2".into(), "194.242.2.3".into()],
                trusted: true,
                no_logs: true,
                jurisdiction: "Sweden".into(),
            },
            DohProvider {
                name: "NextDNS".into(),
                url: "https://dns.nextdns.io".into(),
                server_ips: vec!["45.90.28.0".into(), "45.90.30.0".into()],
                trusted: true,
                no_logs: true,
                jurisdiction: "France".into(),
            },
            DohProvider {
                name: "Cloudflare".into(),
                url: "https://cloudflare-dns.com/dns-query".into(),
                server_ips: vec!["1.1.1.1".into(), "1.0.0.1".into()],
                trusted: true,
                no_logs: false,
                jurisdiction: "US".into(),
            },
        ]
    }

    /// Add a custom provider.
    pub fn add_provider(&mut self, provider: DohProvider) {
        self.providers.push(provider);
    }

    /// Block a provider.
    pub fn block_provider(&mut self, name: &str) {
        self.blocked_providers.insert(name.into());
    }

    /// Get all trusted, unblocked providers.
    pub fn available_providers(&self) -> Vec<&DohProvider> {
        self.providers.iter()
            .filter(|p| p.trusted && !self.blocked_providers.contains(&p.name))
            .collect()
    }

    /// Get providers with no-logs policy.
    pub fn no_logs_providers(&self) -> Vec<&DohProvider> {
        self.providers.iter()
            .filter(|p| p.no_logs && !self.blocked_providers.contains(&p.name))
            .collect()
    }

    /// Get providers in a specific jurisdiction.
    pub fn by_jurisdiction(&self, jurisdiction: &str) -> Vec<&DohProvider> {
        self.providers.iter()
            .filter(|p| p.jurisdiction.to_lowercase() == jurisdiction.to_lowercase())
            .collect()
    }

    /// Set force-DoH mode.
    pub fn set_force_doh(&mut self, force: bool) {
        self.force_doh = force;
    }

    pub fn is_force_doh(&self) -> bool { self.force_doh }
    pub fn provider_count(&self) -> usize { self.providers.len() }
}

impl Default for DohConfig {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_providers() {
        let config = DohConfig::new();
        assert!(config.provider_count() >= 4);
    }

    #[test]
    fn test_available_providers() {
        let config = DohConfig::new();
        let available = config.available_providers();
        assert!(!available.is_empty());
    }

    #[test]
    fn test_no_logs_providers() {
        let config = DohConfig::new();
        let no_logs = config.no_logs_providers();
        // Quad9, Mullvad, NextDNS — at least 3.
        assert!(no_logs.len() >= 3);
    }

    #[test]
    fn test_block_provider() {
        let mut config = DohConfig::new();
        config.block_provider("Cloudflare");
        let available = config.available_providers();
        assert!(!available.iter().any(|p| p.name == "Cloudflare"));
    }

    #[test]
    fn test_by_jurisdiction() {
        let config = DohConfig::new();
        let swiss = config.by_jurisdiction("switzerland");
        assert!(!swiss.is_empty());
    }

    #[test]
    fn test_force_doh() {
        let mut config = DohConfig::new();
        assert!(!config.is_force_doh());
        config.set_force_doh(true);
        assert!(config.is_force_doh());
    }

    #[test]
    fn test_add_custom_provider() {
        let mut config = DohConfig::new();
        let count = config.provider_count();
        config.add_provider(DohProvider {
            name: "Custom".into(),
            url: "https://custom.example/dns".into(),
            server_ips: vec!["1.2.3.4".into()],
            trusted: true,
            no_logs: true,
            jurisdiction: "EU".into(),
        });
        assert_eq!(config.provider_count(), count + 1);
    }
}
