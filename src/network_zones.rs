//! Network zones — segment networks with different trust levels.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

/// Trust level for a network zone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TrustLevel {
    Untrusted,
    Public,
    Limited,
    Trusted,
    Internal,
}

/// A network zone definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkZone {
    pub name: String,
    pub trust_level: TrustLevel,
    pub cidr_ranges: Vec<(IpAddr, u8)>,
    pub allowed_ports: Vec<u16>,
    pub blocked_ports: Vec<u16>,
}

/// Zone manager.
pub struct ZoneManager {
    zones: HashMap<String, NetworkZone>,
}

impl ZoneManager {
    pub fn new() -> Self {
        let mut mgr = Self { zones: HashMap::new() };
        mgr.add_default_zones();
        mgr
    }

    fn add_default_zones(&mut self) {
        // Loopback - fully trusted.
        self.add_zone(NetworkZone {
            name: "loopback".into(),
            trust_level: TrustLevel::Internal,
            cidr_ranges: vec![("127.0.0.0".parse().unwrap(), 8)],
            allowed_ports: vec![],
            blocked_ports: vec![],
        });
        // Private networks - trusted.
        self.add_zone(NetworkZone {
            name: "private".into(),
            trust_level: TrustLevel::Trusted,
            cidr_ranges: vec![
                ("10.0.0.0".parse().unwrap(), 8),
                ("172.16.0.0".parse().unwrap(), 12),
                ("192.168.0.0".parse().unwrap(), 16),
            ],
            allowed_ports: vec![],
            blocked_ports: vec![],
        });
        // Internet - untrusted by default.
        self.add_zone(NetworkZone {
            name: "internet".into(),
            trust_level: TrustLevel::Untrusted,
            cidr_ranges: vec![("0.0.0.0".parse().unwrap(), 0)],
            allowed_ports: vec![80, 443, 53],
            blocked_ports: vec![135, 139, 445, 3389, 5900],
        });
    }

    /// Add a custom zone.
    pub fn add_zone(&mut self, zone: NetworkZone) {
        self.zones.insert(zone.name.clone(), zone);
    }

    /// Find which zone an IP belongs to.
    pub fn zone_for_ip(&self, ip: &IpAddr) -> Option<&NetworkZone> {
        // Check zones from most-specific to least-specific.
        let mut matches: Vec<&NetworkZone> = self.zones.values()
            .filter(|z| z.cidr_ranges.iter().any(|(net, prefix)| ip_in_range(ip, net, *prefix)))
            .collect();
        matches.sort_by(|a, b| b.trust_level.cmp(&a.trust_level));
        matches.into_iter().next()
    }

    /// Check if a port is allowed in a zone.
    pub fn is_port_allowed(&self, zone_name: &str, port: u16) -> bool {
        if let Some(zone) = self.zones.get(zone_name) {
            if zone.blocked_ports.contains(&port) { return false; }
            if zone.allowed_ports.is_empty() { return true; }
            zone.allowed_ports.contains(&port)
        } else {
            true
        }
    }

    /// Get a zone by name.
    pub fn get(&self, name: &str) -> Option<&NetworkZone> {
        self.zones.get(name)
    }

    pub fn zone_count(&self) -> usize { self.zones.len() }
}

impl Default for ZoneManager {
    fn default() -> Self { Self::new() }
}

fn ip_in_range(ip: &IpAddr, network: &IpAddr, prefix: u8) -> bool {
    match (ip, network) {
        (IpAddr::V4(a), IpAddr::V4(n)) => {
            let a_bits = u32::from(*a);
            let n_bits = u32::from(*n);
            let mask = if prefix >= 32 { u32::MAX } else if prefix == 0 { 0 } else { !((1u32 << (32 - prefix)) - 1) };
            (a_bits & mask) == (n_bits & mask)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr { s.parse().unwrap() }

    #[test]
    fn test_default_zones() {
        let mgr = ZoneManager::new();
        assert!(mgr.zone_count() >= 3);
    }

    #[test]
    fn test_loopback_zone() {
        let mgr = ZoneManager::new();
        let zone = mgr.zone_for_ip(&ip("127.0.0.1")).unwrap();
        assert_eq!(zone.name, "loopback");
        assert_eq!(zone.trust_level, TrustLevel::Internal);
    }

    #[test]
    fn test_private_zone() {
        let mgr = ZoneManager::new();
        let zone = mgr.zone_for_ip(&ip("192.168.1.1")).unwrap();
        assert_eq!(zone.name, "private");
    }

    #[test]
    fn test_internet_zone() {
        let mgr = ZoneManager::new();
        let zone = mgr.zone_for_ip(&ip("8.8.8.8")).unwrap();
        assert_eq!(zone.name, "internet");
    }

    #[test]
    fn test_port_blocked() {
        let mgr = ZoneManager::new();
        assert!(!mgr.is_port_allowed("internet", 445)); // SMB blocked.
        assert!(mgr.is_port_allowed("internet", 443)); // HTTPS allowed.
    }

    #[test]
    fn test_unknown_zone_allows() {
        let mgr = ZoneManager::new();
        assert!(mgr.is_port_allowed("unknown", 22));
    }

    #[test]
    fn test_trust_ordering() {
        assert!(TrustLevel::Internal > TrustLevel::Trusted);
        assert!(TrustLevel::Trusted > TrustLevel::Public);
        assert!(TrustLevel::Public > TrustLevel::Untrusted);
    }
}
