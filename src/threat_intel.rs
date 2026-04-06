//! Threat intelligence feed — maintains lists of known-bad IPs, domains,
//! and CIDR ranges with confidence scoring and time-based expiry.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

/// Threat category for intelligence entries.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ThreatType {
    Malware,
    Phishing,
    CnC,        // Command & Control
    Spam,
    Scanner,
    Botnet,
    Tor,
    Vpn,
    DDoS,
    Exploit,
    Unknown,
}

/// Confidence level for a threat indicator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Confidence {
    Low,
    Medium,
    High,
    Confirmed,
}

/// A single IP threat indicator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpIndicator {
    pub ip: IpAddr,
    pub threat_type: ThreatType,
    pub confidence: Confidence,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub source: String,
    pub description: Option<String>,
}

/// A single domain threat indicator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainIndicator {
    pub domain: String,
    pub threat_type: ThreatType,
    pub confidence: Confidence,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub source: String,
    pub is_wildcard: bool,
}

/// A CIDR range indicator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CidrIndicator {
    pub network: IpAddr,
    pub prefix_len: u8,
    pub threat_type: ThreatType,
    pub confidence: Confidence,
    pub source: String,
}

impl CidrIndicator {
    /// Check if an IP falls within this CIDR range.
    pub fn contains(&self, ip: &IpAddr) -> bool {
        match (self.network, ip) {
            (IpAddr::V4(net), IpAddr::V4(target)) => {
                let net_bits = u32::from(net);
                let target_bits = u32::from(*target);
                let mask = if self.prefix_len >= 32 { u32::MAX } else { !((1u32 << (32 - self.prefix_len)) - 1) };
                (net_bits & mask) == (target_bits & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(target)) => {
                let net_bits = u128::from(net);
                let target_bits = u128::from(*target);
                let mask = if self.prefix_len >= 128 { u128::MAX } else { !((1u128 << (128 - self.prefix_len)) - 1) };
                (net_bits & mask) == (target_bits & mask)
            }
            _ => false, // IPv4/IPv6 mismatch
        }
    }
}

/// A threat intelligence feed from a source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelFeed {
    pub name: String,
    pub source_url: String,
    pub last_updated: DateTime<Utc>,
    pub ip_blocklist: HashSet<IpAddr>,
    pub domain_blocklist: HashSet<String>,
}

/// Result of a threat lookup.
#[derive(Debug, Clone)]
pub struct ThreatMatch {
    pub threat_type: ThreatType,
    pub confidence: Confidence,
    pub source: String,
    pub description: Option<String>,
}

/// Enhanced threat intelligence manager with CIDR, wildcards, and scoring.
pub struct ThreatIntelManager {
    feeds: Vec<ThreatIntelFeed>,
    ip_indicators: HashMap<IpAddr, IpIndicator>,
    domain_indicators: Vec<DomainIndicator>,
    cidr_indicators: Vec<CidrIndicator>,
    /// Minimum confidence level for blocking.
    min_block_confidence: Confidence,
}

impl ThreatIntelManager {
    pub fn new() -> Self {
        Self {
            feeds: Vec::new(),
            ip_indicators: HashMap::new(),
            domain_indicators: Vec::new(),
            cidr_indicators: Vec::new(),
            min_block_confidence: Confidence::Medium,
        }
    }

    /// Set minimum confidence for automatic blocking.
    pub fn set_min_confidence(&mut self, min: Confidence) {
        self.min_block_confidence = min;
    }

    /// Add a legacy feed (for backward compat).
    pub fn add_feed(&mut self, feed: ThreatIntelFeed) {
        self.feeds.push(feed);
    }

    /// Add an IP indicator with full metadata.
    pub fn add_ip_indicator(&mut self, indicator: IpIndicator) {
        self.ip_indicators.insert(indicator.ip, indicator);
    }

    /// Add a domain indicator.
    pub fn add_domain_indicator(&mut self, indicator: DomainIndicator) {
        self.domain_indicators.push(indicator);
    }

    /// Add a CIDR range indicator.
    pub fn add_cidr_indicator(&mut self, indicator: CidrIndicator) {
        self.cidr_indicators.push(indicator);
    }

    /// Check if an IP is blocked (from feeds or indicators).
    pub fn is_ip_blocked(&self, ip: &IpAddr) -> bool {
        // Legacy feeds.
        if self.feeds.iter().any(|f| f.ip_blocklist.contains(ip)) {
            return true;
        }
        // IP indicators.
        if let Some(ind) = self.ip_indicators.get(ip) {
            if ind.confidence >= self.min_block_confidence && !self.is_expired_opt(ind.expires_at) {
                return true;
            }
        }
        // CIDR indicators.
        self.cidr_indicators.iter().any(|c| c.confidence >= self.min_block_confidence && c.contains(ip))
    }

    /// Lookup full threat info for an IP.
    pub fn lookup_ip(&self, ip: &IpAddr) -> Vec<ThreatMatch> {
        let mut matches = Vec::new();

        // From indicators.
        if let Some(ind) = self.ip_indicators.get(ip) {
            if !self.is_expired_opt(ind.expires_at) {
                matches.push(ThreatMatch {
                    threat_type: ind.threat_type.clone(),
                    confidence: ind.confidence,
                    source: ind.source.clone(),
                    description: ind.description.clone(),
                });
            }
        }

        // From CIDR.
        for c in &self.cidr_indicators {
            if c.contains(ip) {
                matches.push(ThreatMatch {
                    threat_type: c.threat_type.clone(),
                    confidence: c.confidence,
                    source: c.source.clone(),
                    description: None,
                });
            }
        }

        matches
    }

    /// Check if a domain is blocked.
    pub fn is_domain_blocked(&self, domain: &str) -> bool {
        let lower = domain.to_lowercase();

        // Legacy feeds.
        if self.feeds.iter().any(|f| f.domain_blocklist.contains(&lower)) {
            return true;
        }

        // Domain indicators (exact + wildcard).
        for ind in &self.domain_indicators {
            if ind.confidence < self.min_block_confidence {
                continue;
            }
            if self.is_expired_opt(ind.expires_at) {
                continue;
            }
            if ind.is_wildcard {
                // Wildcard: *.evil.com matches sub.evil.com, evil.com itself
                let base = ind.domain.trim_start_matches("*.");
                if lower == base || lower.ends_with(&format!(".{base}")) {
                    return true;
                }
            } else if lower == ind.domain {
                return true;
            }
        }

        false
    }

    /// Remove expired indicators.
    pub fn purge_expired(&mut self) -> usize {
        let now = Utc::now();
        let before = self.ip_indicators.len() + self.domain_indicators.len();
        self.ip_indicators.retain(|_, v| v.expires_at.map(|e| e > now).unwrap_or(true));
        self.domain_indicators.retain(|v| v.expires_at.map(|e| e > now).unwrap_or(true));
        let after = self.ip_indicators.len() + self.domain_indicators.len();
        before - after
    }

    fn is_expired_opt(&self, expires_at: Option<DateTime<Utc>>) -> bool {
        expires_at.map(|e| e < Utc::now()).unwrap_or(false)
    }

    pub fn total_blocked_ips(&self) -> usize {
        let feed_ips: usize = self.feeds.iter().map(|f| f.ip_blocklist.len()).sum();
        feed_ips + self.ip_indicators.len()
    }

    pub fn total_blocked_domains(&self) -> usize {
        let feed_domains: usize = self.feeds.iter().map(|f| f.domain_blocklist.len()).sum();
        feed_domains + self.domain_indicators.len()
    }

    pub fn feed_count(&self) -> usize { self.feeds.len() }
    pub fn cidr_count(&self) -> usize { self.cidr_indicators.len() }

    /// Get threat type breakdown.
    pub fn threat_breakdown(&self) -> HashMap<ThreatType, usize> {
        let mut counts = HashMap::new();
        for ind in self.ip_indicators.values() {
            *counts.entry(ind.threat_type.clone()).or_default() += 1;
        }
        for ind in &self.domain_indicators {
            *counts.entry(ind.threat_type.clone()).or_default() += 1;
        }
        for ind in &self.cidr_indicators {
            *counts.entry(ind.threat_type.clone()).or_default() += 1;
        }
        counts
    }
}

impl Default for ThreatIntelManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ip_indicator(ip: &str, threat: ThreatType, conf: Confidence) -> IpIndicator {
        IpIndicator {
            ip: ip.parse().unwrap(),
            threat_type: threat,
            confidence: conf,
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            expires_at: None,
            source: "test".into(),
            description: None,
        }
    }

    fn make_domain_indicator(domain: &str, wildcard: bool) -> DomainIndicator {
        DomainIndicator {
            domain: domain.into(),
            threat_type: ThreatType::Malware,
            confidence: Confidence::High,
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            expires_at: None,
            source: "test".into(),
            is_wildcard: wildcard,
        }
    }

    #[test]
    fn test_ip_blocked_legacy() {
        let mut mgr = ThreatIntelManager::new();
        let mut ips = HashSet::new();
        ips.insert("10.0.0.1".parse().unwrap());
        mgr.add_feed(ThreatIntelFeed {
            name: "test".into(), source_url: "local".into(),
            last_updated: Utc::now(), ip_blocklist: ips, domain_blocklist: HashSet::new(),
        });
        assert!(mgr.is_ip_blocked(&"10.0.0.1".parse().unwrap()));
        assert!(!mgr.is_ip_blocked(&"10.0.0.2".parse().unwrap()));
    }

    #[test]
    fn test_ip_indicator_blocking() {
        let mut mgr = ThreatIntelManager::new();
        mgr.add_ip_indicator(make_ip_indicator("192.168.1.100", ThreatType::CnC, Confidence::High));
        assert!(mgr.is_ip_blocked(&"192.168.1.100".parse().unwrap()));
        assert!(!mgr.is_ip_blocked(&"192.168.1.101".parse().unwrap()));
    }

    #[test]
    fn test_confidence_filtering() {
        let mut mgr = ThreatIntelManager::new();
        mgr.set_min_confidence(Confidence::High);
        mgr.add_ip_indicator(make_ip_indicator("1.2.3.4", ThreatType::Spam, Confidence::Low));
        // Low confidence < High min → not blocked.
        assert!(!mgr.is_ip_blocked(&"1.2.3.4".parse().unwrap()));
    }

    #[test]
    fn test_cidr_matching() {
        let mut mgr = ThreatIntelManager::new();
        mgr.add_cidr_indicator(CidrIndicator {
            network: "10.0.0.0".parse().unwrap(),
            prefix_len: 24,
            threat_type: ThreatType::Botnet,
            confidence: Confidence::High,
            source: "test".into(),
        });
        assert!(mgr.is_ip_blocked(&"10.0.0.1".parse().unwrap()));
        assert!(mgr.is_ip_blocked(&"10.0.0.254".parse().unwrap()));
        assert!(!mgr.is_ip_blocked(&"10.0.1.1".parse().unwrap()));
    }

    #[test]
    fn test_domain_blocked_legacy() {
        let mut mgr = ThreatIntelManager::new();
        let mut domains = HashSet::new();
        domains.insert("evil.com".into());
        mgr.add_feed(ThreatIntelFeed {
            name: "test".into(), source_url: "local".into(),
            last_updated: Utc::now(), ip_blocklist: HashSet::new(), domain_blocklist: domains,
        });
        assert!(mgr.is_domain_blocked("evil.com"));
        assert!(!mgr.is_domain_blocked("good.com"));
    }

    #[test]
    fn test_wildcard_domain() {
        let mut mgr = ThreatIntelManager::new();
        mgr.add_domain_indicator(make_domain_indicator("*.evil.com", true));
        assert!(mgr.is_domain_blocked("sub.evil.com"));
        assert!(mgr.is_domain_blocked("deep.sub.evil.com"));
        assert!(mgr.is_domain_blocked("evil.com"));
        assert!(!mgr.is_domain_blocked("notevil.com"));
    }

    #[test]
    fn test_exact_domain() {
        let mut mgr = ThreatIntelManager::new();
        mgr.add_domain_indicator(make_domain_indicator("bad.com", false));
        assert!(mgr.is_domain_blocked("bad.com"));
        assert!(!mgr.is_domain_blocked("sub.bad.com")); // Exact match only.
    }

    #[test]
    fn test_expiry() {
        let mut mgr = ThreatIntelManager::new();
        let mut ind = make_ip_indicator("5.5.5.5", ThreatType::Malware, Confidence::High);
        ind.expires_at = Some(Utc::now() - Duration::hours(1)); // Already expired.
        mgr.add_ip_indicator(ind);
        assert!(!mgr.is_ip_blocked(&"5.5.5.5".parse().unwrap()));
    }

    #[test]
    fn test_purge_expired() {
        let mut mgr = ThreatIntelManager::new();
        let mut expired = make_ip_indicator("1.1.1.1", ThreatType::Scanner, Confidence::High);
        expired.expires_at = Some(Utc::now() - Duration::hours(1));
        let still_valid = make_ip_indicator("2.2.2.2", ThreatType::Scanner, Confidence::High);

        mgr.add_ip_indicator(expired);
        mgr.add_ip_indicator(still_valid);
        let purged = mgr.purge_expired();
        assert_eq!(purged, 1);
        assert_eq!(mgr.ip_indicators.len(), 1);
    }

    #[test]
    fn test_lookup_ip() {
        let mut mgr = ThreatIntelManager::new();
        mgr.add_ip_indicator(make_ip_indicator("3.3.3.3", ThreatType::CnC, Confidence::Confirmed));
        let matches = mgr.lookup_ip(&"3.3.3.3".parse().unwrap());
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].threat_type, ThreatType::CnC);
    }

    #[test]
    fn test_threat_breakdown() {
        let mut mgr = ThreatIntelManager::new();
        mgr.add_ip_indicator(make_ip_indicator("1.1.1.1", ThreatType::Malware, Confidence::High));
        mgr.add_ip_indicator(make_ip_indicator("2.2.2.2", ThreatType::Malware, Confidence::High));
        mgr.add_ip_indicator(make_ip_indicator("3.3.3.3", ThreatType::CnC, Confidence::High));
        let breakdown = mgr.threat_breakdown();
        assert_eq!(*breakdown.get(&ThreatType::Malware).unwrap(), 2);
        assert_eq!(*breakdown.get(&ThreatType::CnC).unwrap(), 1);
    }

    #[test]
    fn test_totals() {
        let mut mgr = ThreatIntelManager::new();
        let mut ips = HashSet::new();
        ips.insert("1.1.1.1".parse().unwrap());
        ips.insert("2.2.2.2".parse().unwrap());
        let mut domains = HashSet::new();
        domains.insert("bad.com".into());
        mgr.add_feed(ThreatIntelFeed {
            name: "f1".into(), source_url: "".into(),
            last_updated: Utc::now(), ip_blocklist: ips, domain_blocklist: domains,
        });
        mgr.add_ip_indicator(make_ip_indicator("3.3.3.3", ThreatType::Spam, Confidence::Low));
        assert_eq!(mgr.total_blocked_ips(), 3);
        assert_eq!(mgr.total_blocked_domains(), 1);
    }
}
