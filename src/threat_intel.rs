//! Threat intelligence feed — maintains lists of known-bad IPs and domains.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::IpAddr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelFeed {
    pub name: String,
    pub source_url: String,
    pub last_updated: DateTime<Utc>,
    pub ip_blocklist: HashSet<IpAddr>,
    pub domain_blocklist: HashSet<String>,
}

pub struct ThreatIntelManager {
    feeds: Vec<ThreatIntelFeed>,
}

impl ThreatIntelManager {
    pub fn new() -> Self { Self { feeds: Vec::new() } }

    pub fn add_feed(&mut self, feed: ThreatIntelFeed) { self.feeds.push(feed); }

    pub fn is_ip_blocked(&self, ip: &IpAddr) -> bool {
        self.feeds.iter().any(|f| f.ip_blocklist.contains(ip))
    }

    pub fn is_domain_blocked(&self, domain: &str) -> bool {
        self.feeds.iter().any(|f| f.domain_blocklist.contains(domain))
    }

    pub fn total_blocked_ips(&self) -> usize {
        self.feeds.iter().map(|f| f.ip_blocklist.len()).sum()
    }

    pub fn total_blocked_domains(&self) -> usize {
        self.feeds.iter().map(|f| f.domain_blocklist.len()).sum()
    }

    pub fn feed_count(&self) -> usize { self.feeds.len() }
}

impl Default for ThreatIntelManager { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_blocked() {
        let mut mgr = ThreatIntelManager::new();
        let mut ips = HashSet::new();
        ips.insert("10.0.0.1".parse().unwrap());
        mgr.add_feed(ThreatIntelFeed { name: "test".into(), source_url: "local".into(), last_updated: Utc::now(), ip_blocklist: ips, domain_blocklist: HashSet::new() });
        assert!(mgr.is_ip_blocked(&"10.0.0.1".parse().unwrap()));
        assert!(!mgr.is_ip_blocked(&"10.0.0.2".parse().unwrap()));
    }

    #[test]
    fn test_domain_blocked() {
        let mut mgr = ThreatIntelManager::new();
        let mut domains = HashSet::new();
        domains.insert("evil.com".into());
        mgr.add_feed(ThreatIntelFeed { name: "test".into(), source_url: "local".into(), last_updated: Utc::now(), ip_blocklist: HashSet::new(), domain_blocklist: domains });
        assert!(mgr.is_domain_blocked("evil.com"));
        assert!(!mgr.is_domain_blocked("good.com"));
    }

    #[test]
    fn test_totals() {
        let mut mgr = ThreatIntelManager::new();
        let mut ips = HashSet::new();
        ips.insert("1.1.1.1".parse().unwrap());
        ips.insert("2.2.2.2".parse().unwrap());
        let mut domains = HashSet::new();
        domains.insert("bad.com".into());
        mgr.add_feed(ThreatIntelFeed { name: "f1".into(), source_url: "".into(), last_updated: Utc::now(), ip_blocklist: ips, domain_blocklist: domains });
        assert_eq!(mgr.total_blocked_ips(), 2);
        assert_eq!(mgr.total_blocked_domains(), 1);
    }
}
