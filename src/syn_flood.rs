//! SYN flood detection — identifies and mitigates SYN flood attacks.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

/// SYN packet record.
#[derive(Debug, Clone)]
struct SynRecord {
    timestamp: DateTime<Utc>,
    completed: bool,
}

/// SYN flood detector with per-source tracking.
pub struct SynFloodDetector {
    /// SYN packets per source IP.
    syn_records: HashMap<IpAddr, Vec<SynRecord>>,
    /// Window for analysis (seconds).
    window_secs: i64,
    /// SYN-to-completion ratio threshold.
    completion_threshold: f64,
    /// Per-source SYN rate threshold (per second).
    syn_rate_threshold: u32,
}

impl SynFloodDetector {
    pub fn new() -> Self {
        Self {
            syn_records: HashMap::new(),
            window_secs: 10,
            completion_threshold: 0.5,
            syn_rate_threshold: 100,
        }
    }

    /// Record a SYN packet.
    pub fn record_syn(&mut self, source: IpAddr) {
        self.syn_records.entry(source).or_default().push(SynRecord {
            timestamp: Utc::now(),
            completed: false,
        });
    }

    /// Mark a SYN as having completed handshake (received ACK).
    pub fn mark_completed(&mut self, source: IpAddr) {
        if let Some(records) = self.syn_records.get_mut(&source) {
            // Mark the most recent uncompleted as completed.
            for r in records.iter_mut().rev() {
                if !r.completed {
                    r.completed = true;
                    break;
                }
            }
        }
    }

    /// Check if a source is currently flooding.
    pub fn is_flooding(&self, source: &IpAddr) -> bool {
        let cutoff = Utc::now() - Duration::seconds(self.window_secs);
        if let Some(records) = self.syn_records.get(source) {
            let recent: Vec<&SynRecord> = records.iter()
                .filter(|r| r.timestamp > cutoff)
                .collect();

            if recent.is_empty() {
                return false;
            }

            // Check rate.
            let rate = recent.len() as f64 / self.window_secs as f64;
            if rate > self.syn_rate_threshold as f64 {
                return true;
            }

            // Check completion ratio.
            let completed = recent.iter().filter(|r| r.completed).count();
            let ratio = completed as f64 / recent.len() as f64;
            if recent.len() >= 50 && ratio < self.completion_threshold {
                return true;
            }
        }
        false
    }

    /// Get all currently flooding sources.
    pub fn flooding_sources(&self) -> Vec<IpAddr> {
        self.syn_records.keys()
            .filter(|ip| self.is_flooding(ip))
            .copied()
            .collect()
    }

    /// Cleanup old records.
    pub fn cleanup(&mut self) -> usize {
        let cutoff = Utc::now() - Duration::seconds(self.window_secs * 5);
        let mut removed = 0;
        for records in self.syn_records.values_mut() {
            let before = records.len();
            records.retain(|r| r.timestamp > cutoff);
            removed += before - records.len();
        }
        self.syn_records.retain(|_, v| !v.is_empty());
        removed
    }

    pub fn tracked_sources(&self) -> usize { self.syn_records.len() }

    /// Stats: total SYNs and completed handshakes.
    pub fn stats(&self) -> (u64, u64) {
        let mut syns = 0;
        let mut completed = 0;
        for records in self.syn_records.values() {
            syns += records.len() as u64;
            completed += records.iter().filter(|r| r.completed).count() as u64;
        }
        (syns, completed)
    }
}

impl Default for SynFloodDetector {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr { s.parse().unwrap() }

    #[test]
    fn test_record_syn() {
        let mut det = SynFloodDetector::new();
        det.record_syn(ip("1.2.3.4"));
        assert_eq!(det.tracked_sources(), 1);
    }

    #[test]
    fn test_no_flood_normal() {
        let mut det = SynFloodDetector::new();
        det.record_syn(ip("1.2.3.4"));
        det.mark_completed(ip("1.2.3.4"));
        assert!(!det.is_flooding(&ip("1.2.3.4")));
    }

    #[test]
    fn test_flood_high_rate() {
        let mut det = SynFloodDetector::new();
        let src = ip("10.0.0.1");
        // Simulate 2000 SYNs in window — well above rate threshold.
        for _ in 0..2000 {
            det.record_syn(src);
        }
        assert!(det.is_flooding(&src));
    }

    #[test]
    fn test_flood_low_completion() {
        let mut det = SynFloodDetector::new();
        let src = ip("10.0.0.1");
        // 100 SYNs, only 10 completed — 10% completion.
        for _ in 0..100 {
            det.record_syn(src);
        }
        for _ in 0..10 {
            det.mark_completed(src);
        }
        assert!(det.is_flooding(&src));
    }

    #[test]
    fn test_flooding_sources() {
        let mut det = SynFloodDetector::new();
        let attacker = ip("10.0.0.1");
        let normal = ip("10.0.0.2");
        for _ in 0..2000 { det.record_syn(attacker); }
        det.record_syn(normal);
        det.mark_completed(normal);
        let flooding = det.flooding_sources();
        assert!(flooding.contains(&attacker));
        assert!(!flooding.contains(&normal));
    }

    #[test]
    fn test_stats() {
        let mut det = SynFloodDetector::new();
        det.record_syn(ip("1.1.1.1"));
        det.record_syn(ip("1.1.1.1"));
        det.mark_completed(ip("1.1.1.1"));
        let (syns, completed) = det.stats();
        assert_eq!(syns, 2);
        assert_eq!(completed, 1);
    }

    #[test]
    fn test_unknown_source_not_flooding() {
        let det = SynFloodDetector::new();
        assert!(!det.is_flooding(&ip("9.9.9.9")));
    }
}
