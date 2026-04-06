//! DNS tunneling detection — identifies data exfiltration via DNS queries.
//!
//! Attackers encode data in DNS query names (subdomains) to exfiltrate through
//! firewalls that allow DNS. This module detects high-entropy labels, unusually
//! long queries, TXT record abuse, and volume anomalies.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A DNS query for tunneling analysis.
#[derive(Debug, Clone)]
pub struct DnsQueryEvent {
    pub domain: String,
    pub query_type: String,
    pub timestamp: DateTime<Utc>,
    pub source_ip: String,
    pub response_size: u32,
}

/// Tunneling indicators for a domain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelingIndicators {
    pub domain: String,
    pub query_count: u64,
    pub avg_label_length: f64,
    pub max_label_length: usize,
    pub avg_entropy: f64,
    pub txt_record_ratio: f64,
    pub unique_subdomains: usize,
    pub total_query_bytes: u64,
    pub risk_score: f64,
    pub indicators: Vec<String>,
}

/// DNS tunneling detector.
pub struct DnsTunnelDetector {
    /// Queries per base domain.
    domain_queries: HashMap<String, Vec<DnsQueryEvent>>,
    /// Entropy threshold for suspicious labels.
    entropy_threshold: f64,
    /// Label length threshold.
    label_length_threshold: usize,
    /// Minimum queries before analysis.
    min_queries: usize,
    /// Analysis window in seconds.
    window_secs: i64,
}

impl DnsTunnelDetector {
    pub fn new() -> Self {
        Self {
            domain_queries: HashMap::new(),
            entropy_threshold: 3.5,
            label_length_threshold: 30,
            min_queries: 10,
            window_secs: 300,
        }
    }

    /// Record a DNS query for analysis.
    pub fn record_query(&mut self, query: DnsQueryEvent) {
        let base = extract_base_domain(&query.domain);
        self.domain_queries.entry(base).or_default().push(query);
    }

    /// Analyze all tracked domains for tunneling indicators.
    pub fn analyze(&self) -> Vec<TunnelingIndicators> {
        let cutoff = Utc::now() - Duration::seconds(self.window_secs);
        let mut results = Vec::new();

        for (domain, queries) in &self.domain_queries {
            let recent: Vec<&DnsQueryEvent> = queries.iter()
                .filter(|q| q.timestamp > cutoff)
                .collect();

            if recent.len() < self.min_queries {
                continue;
            }

            let indicators = self.analyze_domain(domain, &recent);
            if indicators.risk_score > 0.3 {
                results.push(indicators);
            }
        }

        results.sort_by(|a, b| b.risk_score.partial_cmp(&a.risk_score).unwrap_or(std::cmp::Ordering::Equal));
        results
    }

    fn analyze_domain(&self, domain: &str, queries: &[&DnsQueryEvent]) -> TunnelingIndicators {
        let mut indicators_list = Vec::new();
        let mut risk = 0.0f64;

        // Label length analysis.
        let label_lengths: Vec<usize> = queries.iter()
            .flat_map(|q| extract_labels(&q.domain, domain))
            .map(|l| l.len())
            .collect();

        let avg_label = if label_lengths.is_empty() { 0.0 }
        else { label_lengths.iter().sum::<usize>() as f64 / label_lengths.len() as f64 };
        let max_label = label_lengths.iter().copied().max().unwrap_or(0);

        if avg_label > 15.0 {
            indicators_list.push(format!("High avg label length: {avg_label:.1}"));
            risk += 0.2;
        }
        if max_label > self.label_length_threshold {
            indicators_list.push(format!("Max label length: {max_label}"));
            risk += 0.15;
        }

        // Entropy analysis.
        let entropies: Vec<f64> = queries.iter()
            .flat_map(|q| extract_labels(&q.domain, domain))
            .filter(|l| l.len() > 5)
            .map(|l| shannon_entropy(&l))
            .collect();

        let avg_entropy = if entropies.is_empty() { 0.0 }
        else { entropies.iter().sum::<f64>() / entropies.len() as f64 };

        if avg_entropy > self.entropy_threshold {
            indicators_list.push(format!("High entropy: {avg_entropy:.2}"));
            risk += 0.25;
        }

        // TXT record ratio.
        let txt_count = queries.iter().filter(|q| q.query_type.to_uppercase() == "TXT").count();
        let txt_ratio = txt_count as f64 / queries.len() as f64;
        if txt_ratio > 0.3 {
            indicators_list.push(format!("High TXT ratio: {:.0}%", txt_ratio * 100.0));
            risk += 0.2;
        }

        // Unique subdomain count (high = data encoding).
        let unique_subs: std::collections::HashSet<String> = queries.iter()
            .filter_map(|q| {
                let labels = extract_labels(&q.domain, domain);
                labels.first().cloned()
            })
            .collect();

        if unique_subs.len() > queries.len() / 2 {
            indicators_list.push(format!("High subdomain uniqueness: {}", unique_subs.len()));
            risk += 0.15;
        }

        // Volume analysis.
        let total_bytes: u64 = queries.iter().map(|q| q.domain.len() as u64).sum();
        if total_bytes > 5000 {
            indicators_list.push(format!("High query volume: {} bytes", total_bytes));
            risk += 0.1;
        }

        TunnelingIndicators {
            domain: domain.to_string(),
            query_count: queries.len() as u64,
            avg_label_length: avg_label,
            max_label_length: max_label,
            avg_entropy,
            txt_record_ratio: txt_ratio,
            unique_subdomains: unique_subs.len(),
            total_query_bytes: total_bytes,
            risk_score: risk.min(1.0),
            indicators: indicators_list,
        }
    }

    /// Clean up old queries outside the analysis window.
    pub fn cleanup(&mut self) -> usize {
        let cutoff = Utc::now() - Duration::seconds(self.window_secs * 2);
        let mut cleaned = 0usize;
        for queries in self.domain_queries.values_mut() {
            let before = queries.len();
            queries.retain(|q| q.timestamp > cutoff);
            cleaned += before - queries.len();
        }
        self.domain_queries.retain(|_, v| !v.is_empty());
        cleaned
    }

    /// Number of domains being tracked.
    pub fn tracked_domains(&self) -> usize {
        self.domain_queries.len()
    }
}

impl Default for DnsTunnelDetector {
    fn default() -> Self { Self::new() }
}

/// Extract the base domain (last 2 labels) from a FQDN.
fn extract_base_domain(domain: &str) -> String {
    let parts: Vec<&str> = domain.trim_end_matches('.').split('.').collect();
    if parts.len() <= 2 {
        domain.to_string()
    } else {
        parts[parts.len() - 2..].join(".")
    }
}

/// Extract subdomain labels (everything before the base domain).
fn extract_labels(query: &str, base: &str) -> Vec<String> {
    let q = query.trim_end_matches('.').to_lowercase();
    let b = base.trim_end_matches('.').to_lowercase();
    if let Some(prefix) = q.strip_suffix(&b) {
        let prefix = prefix.trim_end_matches('.');
        if prefix.is_empty() {
            return Vec::new();
        }
        prefix.split('.').map(|s| s.to_string()).collect()
    } else {
        Vec::new()
    }
}

/// Calculate Shannon entropy of a string.
fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() { return 0.0; }
    let mut freq: HashMap<char, usize> = HashMap::new();
    for c in s.chars() {
        *freq.entry(c).or_default() += 1;
    }
    let len = s.len() as f64;
    freq.values()
        .map(|&count| {
            let p = count as f64 / len;
            -p * p.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_query(domain: &str, qtype: &str) -> DnsQueryEvent {
        DnsQueryEvent {
            domain: domain.into(),
            query_type: qtype.into(),
            timestamp: Utc::now(),
            source_ip: "10.0.0.1".into(),
            response_size: 100,
        }
    }

    #[test]
    fn test_base_domain_extraction() {
        assert_eq!(extract_base_domain("sub.evil.com"), "evil.com");
        assert_eq!(extract_base_domain("deep.sub.evil.com"), "evil.com");
        assert_eq!(extract_base_domain("evil.com"), "evil.com");
    }

    #[test]
    fn test_label_extraction() {
        let labels = extract_labels("aabbccdd.evil.com", "evil.com");
        assert_eq!(labels, vec!["aabbccdd"]);
    }

    #[test]
    fn test_multi_label_extraction() {
        let labels = extract_labels("data.chunk1.evil.com", "evil.com");
        assert_eq!(labels, vec!["data", "chunk1"]);
    }

    #[test]
    fn test_entropy_high() {
        // Random-looking string should have high entropy.
        let e = shannon_entropy("a8f3b9c2d1e7f4a0b6c3d8e2f1a7b4c0");
        assert!(e > 3.0);
    }

    #[test]
    fn test_entropy_low() {
        // Repetitive string should have low entropy.
        let e = shannon_entropy("aaaaaaaaaa");
        assert!(e < 0.01);
    }

    #[test]
    fn test_normal_traffic_no_alert() {
        let mut det = DnsTunnelDetector::new();
        for _ in 0..15 {
            det.record_query(make_query("www.google.com", "A"));
        }
        let results = det.analyze();
        // Normal short queries should have low risk.
        assert!(results.is_empty() || results[0].risk_score < 0.5);
    }

    #[test]
    fn test_tunnel_traffic_detected() {
        let mut det = DnsTunnelDetector::new();
        // Simulate DNS tunneling: long, high-entropy subdomains.
        for i in 0..20 {
            let encoded = format!("a8f3b9c2d1e7f4a0b6c3d8e2f1a7b4c0{i:04x}.tunnel.evil.com");
            det.record_query(make_query(&encoded, "TXT"));
        }
        let results = det.analyze();
        assert!(!results.is_empty());
        assert!(results[0].risk_score > 0.5);
    }

    #[test]
    fn test_txt_ratio() {
        let mut det = DnsTunnelDetector::new();
        for i in 0..15 {
            let encoded = format!("data{i}.evil.com");
            det.record_query(make_query(&encoded, "TXT"));
        }
        let results = det.analyze();
        if !results.is_empty() {
            assert!(results[0].txt_record_ratio > 0.5);
        }
    }

    #[test]
    fn test_tracked_domains() {
        let mut det = DnsTunnelDetector::new();
        det.record_query(make_query("a.evil.com", "A"));
        det.record_query(make_query("b.good.com", "A"));
        assert_eq!(det.tracked_domains(), 2);
    }

    #[test]
    fn test_min_query_threshold() {
        let mut det = DnsTunnelDetector::new();
        // Only 3 queries — below min_queries (10).
        for i in 0..3 {
            det.record_query(make_query(&format!("sub{i}.evil.com"), "A"));
        }
        let results = det.analyze();
        assert!(results.is_empty()); // Not enough data to analyze.
    }
}
