//! DNS resolver pinning — enforce a fixed set of DNS resolvers.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

/// A pinned DNS resolver entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinnedResolver {
    pub name: String,
    pub address: IpAddr,
    pub protocol: DnsProtocol,
    pub port: u16,
    pub tls_hostname: Option<String>,
    pub priority: i32,
    pub enabled: bool,
    pub added_at: DateTime<Utc>,
    pub total_queries: u64,
    pub failed_queries: u64,
    pub last_success: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DnsProtocol {
    Plain,        // UDP/TCP 53
    Dot,          // DNS-over-TLS, port 853
    Doh,          // DNS-over-HTTPS, port 443
    Doq,          // DNS-over-QUIC, port 853
}

/// Outcome of evaluating a DNS query.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResolutionDecision {
    /// Use the matching pinned resolver.
    UsePinned(String),
    /// Block — non-pinned resolver attempt.
    BlockNonPinned,
    /// No enabled pinned resolvers available.
    NoResolversAvailable,
}

/// DNS resolver pinning engine.
pub struct DnsPinning {
    resolvers: HashMap<String, PinnedResolver>,
    strict_mode: bool,
    total_blocked: u64,
}

impl DnsPinning {
    pub fn new(strict_mode: bool) -> Self {
        Self {
            resolvers: HashMap::new(),
            strict_mode,
            total_blocked: 0,
        }
    }

    /// Add a pinned resolver.
    pub fn add(&mut self, resolver: PinnedResolver) {
        self.resolvers.insert(resolver.name.clone(), resolver);
    }

    /// Remove a resolver.
    pub fn remove(&mut self, name: &str) -> bool {
        self.resolvers.remove(name).is_some()
    }

    /// Enable or disable a resolver.
    pub fn set_enabled(&mut self, name: &str, enabled: bool) -> bool {
        if let Some(r) = self.resolvers.get_mut(name) {
            r.enabled = enabled;
            true
        } else {
            false
        }
    }

    /// Evaluate a requested resolver address.
    pub fn evaluate(&mut self, address: &IpAddr, port: u16) -> ResolutionDecision {
        // Does it match any pinned resolver?
        let matching = self.resolvers.values()
            .find(|r| r.enabled && r.address == *address && r.port == port);

        if let Some(r) = matching {
            return ResolutionDecision::UsePinned(r.name.clone());
        }

        if self.strict_mode {
            self.total_blocked += 1;
            return ResolutionDecision::BlockNonPinned;
        }

        // Non-strict: fall back to the best enabled resolver.
        let best = self.best_resolver();
        match best {
            Some(name) => ResolutionDecision::UsePinned(name),
            None => ResolutionDecision::NoResolversAvailable,
        }
    }

    /// Record a successful query.
    pub fn record_success(&mut self, name: &str) {
        if let Some(r) = self.resolvers.get_mut(name) {
            r.total_queries += 1;
            r.last_success = Some(Utc::now());
        }
    }

    /// Record a failed query.
    pub fn record_failure(&mut self, name: &str) {
        if let Some(r) = self.resolvers.get_mut(name) {
            r.total_queries += 1;
            r.failed_queries += 1;
        }
    }

    /// Best resolver by priority and success rate.
    pub fn best_resolver(&self) -> Option<String> {
        self.resolvers.values()
            .filter(|r| r.enabled)
            .max_by(|a, b| {
                a.priority.cmp(&b.priority)
                    .then(a.success_rate().partial_cmp(&b.success_rate()).unwrap())
            })
            .map(|r| r.name.clone())
    }

    /// All enabled resolvers.
    pub fn enabled_resolvers(&self) -> Vec<&PinnedResolver> {
        self.resolvers.values().filter(|r| r.enabled).collect()
    }

    /// Resolvers using a specific protocol.
    pub fn by_protocol(&self, protocol: &DnsProtocol) -> Vec<&PinnedResolver> {
        self.resolvers.values().filter(|r| &r.protocol == protocol).collect()
    }

    /// Resolvers with excessive failures.
    pub fn failing_resolvers(&self, min_fail_rate: f64) -> Vec<&PinnedResolver> {
        self.resolvers.values()
            .filter(|r| 1.0 - r.success_rate() >= min_fail_rate && r.total_queries > 10)
            .collect()
    }

    pub fn total_blocked(&self) -> u64 { self.total_blocked }
    pub fn resolver_count(&self) -> usize { self.resolvers.len() }
}

impl PinnedResolver {
    pub fn success_rate(&self) -> f64 {
        if self.total_queries == 0 {
            return 1.0;
        }
        1.0 - (self.failed_queries as f64 / self.total_queries as f64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resolver(name: &str, ip: &str, priority: i32, protocol: DnsProtocol, port: u16) -> PinnedResolver {
        PinnedResolver {
            name: name.into(),
            address: ip.parse().unwrap(),
            protocol,
            port,
            tls_hostname: None,
            priority,
            enabled: true,
            added_at: Utc::now(),
            total_queries: 0,
            failed_queries: 0,
            last_success: None,
        }
    }

    #[test]
    fn test_add_and_count() {
        let mut p = DnsPinning::new(true);
        p.add(resolver("cloudflare", "1.1.1.1", 100, DnsProtocol::Dot, 853));
        assert_eq!(p.resolver_count(), 1);
    }

    #[test]
    fn test_strict_blocks_unpinned() {
        let mut p = DnsPinning::new(true);
        p.add(resolver("cloudflare", "1.1.1.1", 100, DnsProtocol::Dot, 853));
        let decision = p.evaluate(&"8.8.8.8".parse().unwrap(), 53);
        assert_eq!(decision, ResolutionDecision::BlockNonPinned);
    }

    #[test]
    fn test_strict_allows_pinned() {
        let mut p = DnsPinning::new(true);
        p.add(resolver("cloudflare", "1.1.1.1", 100, DnsProtocol::Dot, 853));
        let decision = p.evaluate(&"1.1.1.1".parse().unwrap(), 853);
        assert_eq!(decision, ResolutionDecision::UsePinned("cloudflare".into()));
    }

    #[test]
    fn test_non_strict_falls_back() {
        let mut p = DnsPinning::new(false);
        p.add(resolver("cloudflare", "1.1.1.1", 100, DnsProtocol::Dot, 853));
        let decision = p.evaluate(&"8.8.8.8".parse().unwrap(), 53);
        assert_eq!(decision, ResolutionDecision::UsePinned("cloudflare".into()));
    }

    #[test]
    fn test_best_resolver_priority() {
        let mut p = DnsPinning::new(true);
        p.add(resolver("low", "1.1.1.1", 10, DnsProtocol::Dot, 853));
        p.add(resolver("high", "9.9.9.9", 100, DnsProtocol::Dot, 853));
        assert_eq!(p.best_resolver(), Some("high".into()));
    }

    #[test]
    fn test_disabled_resolver_not_used() {
        let mut p = DnsPinning::new(false);
        p.add(resolver("a", "1.1.1.1", 100, DnsProtocol::Dot, 853));
        p.set_enabled("a", false);
        assert!(p.best_resolver().is_none());
    }

    #[test]
    fn test_record_success_and_failure() {
        let mut p = DnsPinning::new(true);
        p.add(resolver("a", "1.1.1.1", 100, DnsProtocol::Dot, 853));
        p.record_success("a");
        p.record_failure("a");
        let rate = p.resolvers.get("a").unwrap().success_rate();
        assert!((rate - 0.5).abs() < 0.01);
    }

    #[test]
    fn test_by_protocol() {
        let mut p = DnsPinning::new(true);
        p.add(resolver("a", "1.1.1.1", 100, DnsProtocol::Dot, 853));
        p.add(resolver("b", "8.8.8.8", 100, DnsProtocol::Doh, 443));
        assert_eq!(p.by_protocol(&DnsProtocol::Doh).len(), 1);
    }

    #[test]
    fn test_failing_resolvers() {
        let mut p = DnsPinning::new(true);
        p.add(resolver("flaky", "1.1.1.1", 100, DnsProtocol::Dot, 853));
        for _ in 0..20 { p.record_failure("flaky"); }
        assert_eq!(p.failing_resolvers(0.5).len(), 1);
    }

    #[test]
    fn test_no_resolvers_available() {
        let mut p = DnsPinning::new(false);
        let decision = p.evaluate(&"8.8.8.8".parse().unwrap(), 53);
        assert_eq!(decision, ResolutionDecision::NoResolversAvailable);
    }
}
