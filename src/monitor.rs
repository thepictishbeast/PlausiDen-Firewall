//! Real-time firewall monitoring — tracks blocked connections, bandwidth, alerts.

use crate::conntrack::ConnectionTracker;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

/// Firewall monitoring dashboard data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallMonitor {
    pub blocked_count_1h: u64,
    pub allowed_count_1h: u64,
    pub dns_blocked_1h: u64,
    pub doh_bypass_attempts: u64,
    pub top_blocked_ips: Vec<(String, u64)>,
    pub top_blocked_domains: Vec<(String, u64)>,
    pub bandwidth_in_bytes: u64,
    pub bandwidth_out_bytes: u64,
    pub active_connections: usize,
    pub alerts: Vec<FirewallAlert>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallAlert {
    pub timestamp: DateTime<Utc>,
    pub severity: AlertSeverity,
    pub message: String,
    pub source_ip: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AlertSeverity { Info, Warning, High, Critical }

/// Alert buffer with max capacity.
pub struct AlertBuffer {
    alerts: VecDeque<FirewallAlert>,
    max_size: usize,
}

impl AlertBuffer {
    pub fn new(max_size: usize) -> Self { Self { alerts: VecDeque::new(), max_size } }

    pub fn push(&mut self, alert: FirewallAlert) {
        self.alerts.push_back(alert);
        while self.alerts.len() > self.max_size { self.alerts.pop_front(); }
    }

    pub fn recent(&self, count: usize) -> Vec<&FirewallAlert> {
        self.alerts.iter().rev().take(count).collect()
    }

    pub fn by_severity(&self, min: AlertSeverity) -> Vec<&FirewallAlert> {
        self.alerts.iter().filter(|a| a.severity >= min).collect()
    }

    pub fn count(&self) -> usize { self.alerts.len() }
    pub fn clear(&mut self) { self.alerts.clear(); }
}

impl Default for AlertBuffer { fn default() -> Self { Self::new(1000) } }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alert_buffer() {
        let mut buf = AlertBuffer::new(3);
        for i in 0..5 {
            buf.push(FirewallAlert { timestamp: Utc::now(), severity: AlertSeverity::Info, message: format!("alert {i}"), source_ip: None });
        }
        assert_eq!(buf.count(), 3); // Oldest evicted
    }

    #[test]
    fn test_filter_by_severity() {
        let mut buf = AlertBuffer::new(100);
        buf.push(FirewallAlert { timestamp: Utc::now(), severity: AlertSeverity::Info, message: "info".into(), source_ip: None });
        buf.push(FirewallAlert { timestamp: Utc::now(), severity: AlertSeverity::Critical, message: "critical".into(), source_ip: None });
        let critical = buf.by_severity(AlertSeverity::Critical);
        assert_eq!(critical.len(), 1);
        assert_eq!(critical[0].message, "critical");
    }

    #[test]
    fn test_recent_ordering() {
        let mut buf = AlertBuffer::new(100);
        buf.push(FirewallAlert { timestamp: Utc::now(), severity: AlertSeverity::Info, message: "first".into(), source_ip: None });
        buf.push(FirewallAlert { timestamp: Utc::now(), severity: AlertSeverity::Info, message: "second".into(), source_ip: None });
        let recent = buf.recent(1);
        assert_eq!(recent[0].message, "second"); // Most recent first
    }
}
