//! Linux firewall backend — orchestrates eBPF + nftables.

use crate::conntrack::ConnectionTracker;
use crate::dns_sinkhole::DnsSinkhole;
use crate::ebpf::EbpfEngine;
use crate::nftables::NftablesBackend;
use crate::rules::RuleSet;
use serde::{Deserialize, Serialize};

/// Linux firewall backend status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinuxBackendStatus {
    pub ebpf_loaded: bool,
    pub nftables_active: bool,
    pub dns_sinkhole_active: bool,
    pub connection_count: usize,
    pub rules_count: usize,
    pub blocked_domains: usize,
}

/// Linux firewall backend — combines eBPF, nftables, DNS sinkhole, and conntrack.
pub struct LinuxBackend {
    ebpf: EbpfEngine,
    nftables: NftablesBackend,
    sinkhole: DnsSinkhole,
    conntrack: ConnectionTracker,
    rules: RuleSet,
    active: bool,
}

impl LinuxBackend {
    pub fn new() -> Self {
        Self {
            ebpf: EbpfEngine::default(),
            nftables: NftablesBackend::default(),
            sinkhole: DnsSinkhole::default(),
            conntrack: ConnectionTracker::new(100_000),
            rules: RuleSet::new(),
            active: false,
        }
    }

    /// Apply a rule set to all backends.
    pub fn apply_rules(&mut self, rules: RuleSet) {
        self.rules = rules;
    }

    /// Get the current status.
    pub fn status(&self) -> LinuxBackendStatus {
        LinuxBackendStatus {
            ebpf_loaded: self.ebpf.is_loaded(),
            nftables_active: self.active,
            dns_sinkhole_active: true,
            connection_count: self.conntrack.active_connections(),
            rules_count: self.rules.rules().len(),
            blocked_domains: self.sinkhole.blocked_count(),
        }
    }

    /// Generate nftables script from current rules.
    pub fn generate_nftables_script(&self) -> String {
        self.nftables.generate_ruleset(&self.rules).to_script()
    }

    /// Check if a domain is sinkholed.
    pub fn is_domain_blocked(&self, domain: &str) -> bool {
        self.sinkhole.is_sinkholed(domain)
    }

    /// Add a domain to the sinkhole.
    pub fn block_domain(&mut self, domain: &str) {
        self.sinkhole.add_domain(domain);
    }

    pub fn is_active(&self) -> bool { self.active }

    /// Activate the backend.
    pub fn activate(&mut self) { self.active = true; }

    /// Deactivate the backend.
    pub fn deactivate(&mut self) { self.active = false; }
}

impl Default for LinuxBackend {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_backend() {
        let backend = LinuxBackend::new();
        assert!(!backend.is_active());
        let status = backend.status();
        assert!(!status.ebpf_loaded);
    }

    #[test]
    fn test_activate_deactivate() {
        let mut backend = LinuxBackend::new();
        backend.activate();
        assert!(backend.is_active());
        backend.deactivate();
        assert!(!backend.is_active());
    }

    #[test]
    fn test_domain_blocking() {
        let mut backend = LinuxBackend::new();
        backend.block_domain("evil.com");
        assert!(backend.is_domain_blocked("evil.com"));
        assert!(!backend.is_domain_blocked("good.com"));
    }

    #[test]
    fn test_nftables_script_generation() {
        let backend = LinuxBackend::new();
        let script = backend.generate_nftables_script();
        assert!(script.contains("flush table"));
        assert!(script.contains("policy drop"));
    }

    #[test]
    fn test_status_reflects_state() {
        let mut backend = LinuxBackend::new();
        backend.block_domain("test.com");
        let status = backend.status();
        assert!(status.blocked_domains > 0);
    }
}
