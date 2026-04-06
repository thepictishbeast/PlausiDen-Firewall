//! Port scan detector — flag fast or distributed port scanning activity.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

/// A single connection-attempt observation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnAttempt {
    pub source: IpAddr,
    pub dest_port: u16,
    pub timestamp: DateTime<Utc>,
    pub succeeded: bool,
}

/// Port scan alert.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanAlert {
    pub source: IpAddr,
    pub scan_type: ScanType,
    pub unique_ports: usize,
    pub window_seconds: i64,
    pub confidence: u8, // 0-100
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScanType {
    Vertical,  // many ports, one host
    Horizontal, // one port, many hosts (when paired with peer data)
    Stealth,   // slow, spread over time
    Flood,     // fast burst
}

/// Detector configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    pub ports_for_alert: usize,
    pub window_secs: i64,
    pub stealth_window_secs: i64,
    pub flood_threshold_per_sec: f64,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            ports_for_alert: 15,
            window_secs: 60,
            stealth_window_secs: 3600,
            flood_threshold_per_sec: 10.0,
        }
    }
}

/// Port scan detector.
pub struct PortScanDetector {
    config: ScanConfig,
    attempts: Vec<ConnAttempt>,
    alerts: Vec<ScanAlert>,
}

impl PortScanDetector {
    pub fn new(config: ScanConfig) -> Self {
        Self {
            config,
            attempts: Vec::new(),
            alerts: Vec::new(),
        }
    }

    /// Record a connection attempt and check for scan behavior.
    pub fn observe(&mut self, attempt: ConnAttempt) -> Option<ScanAlert> {
        let source = attempt.source;
        self.attempts.push(attempt);
        self.prune_old();
        self.check_scan(source)
    }

    fn check_scan(&mut self, source: IpAddr) -> Option<ScanAlert> {
        let now = Utc::now();
        let window_start = now - chrono::Duration::seconds(self.config.window_secs);
        let stealth_start = now - chrono::Duration::seconds(self.config.stealth_window_secs);

        // Fast scan check.
        let recent: Vec<&ConnAttempt> = self.attempts.iter()
            .filter(|a| a.source == source && a.timestamp >= window_start)
            .collect();
        let unique_ports: HashSet<u16> = recent.iter().map(|a| a.dest_port).collect();

        if unique_ports.len() >= self.config.ports_for_alert {
            let rate = recent.len() as f64 / self.config.window_secs as f64;
            let (scan_type, confidence) = if rate > self.config.flood_threshold_per_sec {
                (ScanType::Flood, 95)
            } else {
                (ScanType::Vertical, 85)
            };
            let alert = ScanAlert {
                source,
                scan_type,
                unique_ports: unique_ports.len(),
                window_seconds: self.config.window_secs,
                confidence,
            };
            self.alerts.push(alert.clone());
            return Some(alert);
        }

        // Stealth scan — spread over hours.
        let stealth: Vec<&ConnAttempt> = self.attempts.iter()
            .filter(|a| a.source == source && a.timestamp >= stealth_start)
            .collect();
        let stealth_ports: HashSet<u16> = stealth.iter().map(|a| a.dest_port).collect();
        if stealth_ports.len() >= self.config.ports_for_alert && recent.len() < 5 {
            let alert = ScanAlert {
                source,
                scan_type: ScanType::Stealth,
                unique_ports: stealth_ports.len(),
                window_seconds: self.config.stealth_window_secs,
                confidence: 70,
            };
            self.alerts.push(alert.clone());
            return Some(alert);
        }

        None
    }

    fn prune_old(&mut self) {
        let cutoff = Utc::now() - chrono::Duration::seconds(self.config.stealth_window_secs * 2);
        self.attempts.retain(|a| a.timestamp >= cutoff);
    }

    /// Source IPs that have alerted at least once.
    pub fn scanners(&self) -> Vec<IpAddr> {
        let mut set = HashSet::new();
        for a in &self.alerts { set.insert(a.source); }
        set.into_iter().collect()
    }

    /// Alert count.
    pub fn alert_count(&self) -> usize {
        self.alerts.len()
    }

    /// All alerts.
    pub fn alerts(&self) -> &[ScanAlert] {
        &self.alerts
    }

    /// Per-source alert distribution.
    pub fn alerts_by_source(&self) -> HashMap<IpAddr, usize> {
        let mut map = HashMap::new();
        for a in &self.alerts {
            *map.entry(a.source).or_insert(0) += 1;
        }
        map
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr { s.parse().unwrap() }

    fn attempt(src: &str, port: u16) -> ConnAttempt {
        ConnAttempt {
            source: ip(src),
            dest_port: port,
            timestamp: Utc::now(),
            succeeded: false,
        }
    }

    #[test]
    fn test_single_port_no_alert() {
        let mut d = PortScanDetector::new(ScanConfig::default());
        assert!(d.observe(attempt("10.0.0.1", 80)).is_none());
        assert_eq!(d.alert_count(), 0);
    }

    #[test]
    fn test_vertical_scan_detected() {
        let mut d = PortScanDetector::new(ScanConfig {
            ports_for_alert: 5,
            ..ScanConfig::default()
        });
        let mut alert = None;
        for port in 1..=10 {
            alert = d.observe(attempt("10.0.0.1", port));
        }
        assert!(alert.is_some());
        let alert = alert.unwrap();
        assert!(matches!(alert.scan_type, ScanType::Vertical | ScanType::Flood));
    }

    #[test]
    fn test_scanners_list() {
        let mut d = PortScanDetector::new(ScanConfig {
            ports_for_alert: 3,
            ..ScanConfig::default()
        });
        for port in 1..=5 {
            d.observe(attempt("10.0.0.1", port));
        }
        for port in 1..=5 {
            d.observe(attempt("10.0.0.2", port));
        }
        assert_eq!(d.scanners().len(), 2);
    }

    #[test]
    fn test_different_sources_not_combined() {
        let mut d = PortScanDetector::new(ScanConfig {
            ports_for_alert: 5,
            ..ScanConfig::default()
        });
        d.observe(attempt("10.0.0.1", 80));
        d.observe(attempt("10.0.0.2", 443));
        d.observe(attempt("10.0.0.3", 22));
        assert_eq!(d.alert_count(), 0);
    }

    #[test]
    fn test_flood_higher_confidence_than_vertical() {
        // Flood means ports >= threshold AND rate above flood_threshold.
        let mut d = PortScanDetector::new(ScanConfig {
            ports_for_alert: 5,
            flood_threshold_per_sec: 0.01, // trivially triggered
            ..ScanConfig::default()
        });
        let mut final_alert = None;
        for port in 1..=10 {
            final_alert = d.observe(attempt("10.0.0.1", port));
        }
        let alert = final_alert.unwrap();
        assert_eq!(alert.scan_type, ScanType::Flood);
        assert_eq!(alert.confidence, 95);
    }

    #[test]
    fn test_alerts_by_source() {
        let mut d = PortScanDetector::new(ScanConfig {
            ports_for_alert: 3,
            ..ScanConfig::default()
        });
        for port in 1..=5 { d.observe(attempt("10.0.0.1", port)); }
        let by = d.alerts_by_source();
        assert!(by.contains_key(&ip("10.0.0.1")));
    }

    #[test]
    fn test_config_paranoid() {
        let cfg = ScanConfig {
            ports_for_alert: 3,
            window_secs: 10,
            stealth_window_secs: 300,
            flood_threshold_per_sec: 1.0,
        };
        let mut d = PortScanDetector::new(cfg);
        for port in [21, 22, 23, 25] {
            d.observe(attempt("10.0.0.1", port));
        }
        assert!(d.alert_count() >= 1);
    }
}
