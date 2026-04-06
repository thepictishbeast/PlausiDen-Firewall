//! ARP monitoring — detect ARP spoofing and poisoning.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

/// An ARP entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArpEntry {
    pub ip: IpAddr,
    pub mac: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub change_count: u32,
}

/// ARP monitor.
pub struct ArpMonitor {
    /// Map: IP → most recent ARP entry.
    entries: HashMap<IpAddr, ArpEntry>,
    /// Alert history.
    alerts: Vec<ArpAlert>,
}

/// ARP alert.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArpAlert {
    pub ip: IpAddr,
    pub old_mac: String,
    pub new_mac: String,
    pub timestamp: DateTime<Utc>,
    pub alert_type: AlertType,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AlertType {
    MacChange,
    Broadcast,
    Gratuitous,
    DuplicateIp,
}

impl ArpMonitor {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            alerts: Vec::new(),
        }
    }

    /// Record an ARP observation.
    pub fn observe(&mut self, ip: IpAddr, mac: &str) {
        let now = Utc::now();
        match self.entries.get_mut(&ip) {
            Some(entry) => {
                if entry.mac != mac {
                    // MAC changed - potential ARP spoofing.
                    self.alerts.push(ArpAlert {
                        ip,
                        old_mac: entry.mac.clone(),
                        new_mac: mac.into(),
                        timestamp: now,
                        alert_type: AlertType::MacChange,
                    });
                    entry.mac = mac.into();
                    entry.change_count += 1;
                }
                entry.last_seen = now;
            }
            None => {
                self.entries.insert(ip, ArpEntry {
                    ip,
                    mac: mac.into(),
                    first_seen: now,
                    last_seen: now,
                    change_count: 0,
                });
            }
        }
    }

    /// Check if an IP is under ARP attack (frequent MAC changes).
    pub fn is_under_attack(&self, ip: &IpAddr) -> bool {
        self.entries.get(ip)
            .map(|e| e.change_count >= 3)
            .unwrap_or(false)
    }

    /// Get the current MAC for an IP.
    pub fn get_mac(&self, ip: &IpAddr) -> Option<&str> {
        self.entries.get(ip).map(|e| e.mac.as_str())
    }

    /// Get recent alerts.
    pub fn recent_alerts(&self, n: usize) -> Vec<&ArpAlert> {
        let start = self.alerts.len().saturating_sub(n);
        self.alerts.iter().skip(start).collect()
    }

    /// Find duplicate IPs (rare — usually means spoofing).
    pub fn find_duplicates(&self, all_observations: &[(IpAddr, String)]) -> Vec<IpAddr> {
        let mut macs_per_ip: HashMap<IpAddr, std::collections::HashSet<String>> = HashMap::new();
        for (ip, mac) in all_observations {
            macs_per_ip.entry(*ip).or_default().insert(mac.clone());
        }
        macs_per_ip.into_iter()
            .filter(|(_, macs)| macs.len() > 1)
            .map(|(ip, _)| ip)
            .collect()
    }

    pub fn entry_count(&self) -> usize { self.entries.len() }
    pub fn alert_count(&self) -> usize { self.alerts.len() }
}

impl Default for ArpMonitor {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr { s.parse().unwrap() }

    #[test]
    fn test_first_observation() {
        let mut mon = ArpMonitor::new();
        mon.observe(ip("192.168.1.1"), "aa:bb:cc:dd:ee:ff");
        assert_eq!(mon.entry_count(), 1);
        assert_eq!(mon.alert_count(), 0);
    }

    #[test]
    fn test_mac_change_alert() {
        let mut mon = ArpMonitor::new();
        mon.observe(ip("192.168.1.1"), "aa:bb:cc:dd:ee:ff");
        mon.observe(ip("192.168.1.1"), "11:22:33:44:55:66");
        assert_eq!(mon.alert_count(), 1);
    }

    #[test]
    fn test_same_mac_no_alert() {
        let mut mon = ArpMonitor::new();
        mon.observe(ip("192.168.1.1"), "aa:bb:cc:dd:ee:ff");
        mon.observe(ip("192.168.1.1"), "aa:bb:cc:dd:ee:ff");
        assert_eq!(mon.alert_count(), 0);
    }

    #[test]
    fn test_under_attack() {
        let mut mon = ArpMonitor::new();
        let target = ip("192.168.1.1");
        mon.observe(target, "aa:bb:cc:dd:ee:01");
        mon.observe(target, "aa:bb:cc:dd:ee:02");
        mon.observe(target, "aa:bb:cc:dd:ee:03");
        mon.observe(target, "aa:bb:cc:dd:ee:04");
        assert!(mon.is_under_attack(&target));
    }

    #[test]
    fn test_get_mac() {
        let mut mon = ArpMonitor::new();
        mon.observe(ip("10.0.0.1"), "aa:bb:cc:dd:ee:ff");
        assert_eq!(mon.get_mac(&ip("10.0.0.1")), Some("aa:bb:cc:dd:ee:ff"));
    }

    #[test]
    fn test_recent_alerts() {
        let mut mon = ArpMonitor::new();
        mon.observe(ip("10.0.0.1"), "aa:bb:cc:dd:ee:01");
        mon.observe(ip("10.0.0.1"), "aa:bb:cc:dd:ee:02");
        mon.observe(ip("10.0.0.1"), "aa:bb:cc:dd:ee:03");
        let recent = mon.recent_alerts(2);
        assert_eq!(recent.len(), 2);
    }

    #[test]
    fn test_find_duplicates() {
        let mon = ArpMonitor::new();
        let observations = vec![
            (ip("10.0.0.1"), "mac1".into()),
            (ip("10.0.0.1"), "mac2".into()), // Duplicate!
            (ip("10.0.0.2"), "mac3".into()),
        ];
        let dupes = mon.find_duplicates(&observations);
        assert_eq!(dupes.len(), 1);
    }
}
