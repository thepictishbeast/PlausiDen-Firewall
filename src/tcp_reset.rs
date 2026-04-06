//! TCP RST detection — identify connection reset attacks.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

/// TCP RST event record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RstEvent {
    pub source_ip: IpAddr,
    pub dest_ip: IpAddr,
    pub source_port: u16,
    pub dest_port: u16,
    pub timestamp: DateTime<Utc>,
    pub is_for_established: bool,
}

/// TCP RST detector.
pub struct RstDetector {
    events: Vec<RstEvent>,
    /// Per-source RST counts.
    by_source: HashMap<IpAddr, u32>,
    /// Window for tracking.
    window_secs: i64,
    /// Threshold for attack detection.
    attack_threshold: u32,
}

impl RstDetector {
    pub fn new() -> Self {
        Self {
            events: Vec::new(),
            by_source: HashMap::new(),
            window_secs: 60,
            attack_threshold: 20,
        }
    }

    /// Record an RST event.
    pub fn record(&mut self, event: RstEvent) {
        *self.by_source.entry(event.source_ip).or_default() += 1;
        self.events.push(event);
    }

    /// Check if a source is performing an RST flood.
    pub fn is_flooding(&self, source: &IpAddr) -> bool {
        let cutoff = Utc::now() - Duration::seconds(self.window_secs);
        let count = self.events.iter()
            .filter(|e| e.source_ip == *source && e.timestamp > cutoff)
            .count();
        count >= self.attack_threshold as usize
    }

    /// Detect RST injection (RSTs for established connections from unusual sources).
    pub fn detect_injection(&self) -> Vec<&RstEvent> {
        let cutoff = Utc::now() - Duration::seconds(self.window_secs);
        self.events.iter()
            .filter(|e| e.is_for_established && e.timestamp > cutoff)
            .collect()
    }

    /// Get all flooding sources.
    pub fn flooding_sources(&self) -> Vec<IpAddr> {
        self.by_source.keys()
            .filter(|ip| self.is_flooding(ip))
            .copied()
            .collect()
    }

    /// Cleanup old events.
    pub fn cleanup(&mut self) -> usize {
        let cutoff = Utc::now() - Duration::seconds(self.window_secs * 2);
        let before = self.events.len();
        self.events.retain(|e| e.timestamp > cutoff);
        before - self.events.len()
    }

    pub fn event_count(&self) -> usize { self.events.len() }
    pub fn source_count(&self) -> usize { self.by_source.len() }
}

impl Default for RstDetector {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr { s.parse().unwrap() }

    fn make_event(src: &str, dst: &str, for_established: bool) -> RstEvent {
        RstEvent {
            source_ip: ip(src),
            dest_ip: ip(dst),
            source_port: 443,
            dest_port: 54321,
            timestamp: Utc::now(),
            is_for_established: for_established,
        }
    }

    #[test]
    fn test_record() {
        let mut det = RstDetector::new();
        det.record(make_event("1.2.3.4", "5.6.7.8", false));
        assert_eq!(det.event_count(), 1);
    }

    #[test]
    fn test_flood_detection() {
        let mut det = RstDetector::new();
        for _ in 0..25 {
            det.record(make_event("10.99.99.99", "10.0.0.1", false));
        }
    }

    #[test]
    fn test_flooding_attacker() {
        let mut det = RstDetector::new();
        for _ in 0..25 {
            det.record(make_event("10.0.0.1", "10.0.0.2", false));
        }
        assert!(det.is_flooding(&ip("10.0.0.1")));
    }

    #[test]
    fn test_not_flooding_low_volume() {
        let mut det = RstDetector::new();
        for _ in 0..5 {
            det.record(make_event("10.0.0.1", "10.0.0.2", false));
        }
        assert!(!det.is_flooding(&ip("10.0.0.1")));
    }

    #[test]
    fn test_injection_detection() {
        let mut det = RstDetector::new();
        det.record(make_event("10.99.99.99", "10.99.99.1", true));
        det.record(make_event("10.99.99.50", "10.99.99.200", false));
        let injections = det.detect_injection();
        assert_eq!(injections.len(), 1);
    }

    #[test]
    fn test_flooding_sources() {
        let mut det = RstDetector::new();
        for _ in 0..25 {
            det.record(make_event("10.0.0.1", "10.99.99.100", false));
        }
        det.record(make_event("10.0.0.2", "10.99.99.100", false));
        let flooding = det.flooding_sources();
        assert!(flooding.contains(&ip("10.0.0.1")));
        assert!(!flooding.contains(&ip("10.0.0.2")));
    }
}
