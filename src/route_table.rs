//! Route table manager — monitor and validate the system routing table.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

/// A routing table entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Route {
    pub id: String,
    pub destination: IpAddr,
    pub prefix_length: u8,
    pub gateway: Option<IpAddr>,
    pub interface: String,
    pub metric: u32,
    pub scope: RouteScope,
    pub protocol: RouteProtocol,
    pub added_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RouteScope {
    Host,
    Link,
    Universe,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RouteProtocol {
    Kernel,
    Static,
    Dhcp,
    Ra,      // IPv6 Router Advertisement
    Bgp,
    Ospf,
    Bird,
    Unknown,
}

/// An observed route change.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteChange {
    pub route_id: String,
    pub change_type: ChangeType,
    pub before: Option<Route>,
    pub after: Option<Route>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChangeType {
    Added,
    Removed,
    Modified,
}

/// Route table manager.
pub struct RouteTable {
    routes: HashMap<String, Route>,
    changes: Vec<RouteChange>,
    history_limit: usize,
    expected_default_gateway: Option<IpAddr>,
}

impl RouteTable {
    pub fn new() -> Self {
        Self {
            routes: HashMap::new(),
            changes: Vec::new(),
            history_limit: 500,
            expected_default_gateway: None,
        }
    }

    /// Set the expected default gateway for hijack detection.
    pub fn set_expected_gateway(&mut self, gw: IpAddr) {
        self.expected_default_gateway = Some(gw);
    }

    /// Add or update a route.
    pub fn observe(&mut self, route: Route) {
        let now = Utc::now();
        let route_id = route.id.clone();
        let change = match self.routes.get(&route_id) {
            Some(existing) if existing != &route => Some(RouteChange {
                route_id: route_id.clone(),
                change_type: ChangeType::Modified,
                before: Some(existing.clone()),
                after: Some(route.clone()),
                timestamp: now,
            }),
            Some(_) => None,
            None => Some(RouteChange {
                route_id: route_id.clone(),
                change_type: ChangeType::Added,
                before: None,
                after: Some(route.clone()),
                timestamp: now,
            }),
        };
        if let Some(c) = change {
            self.changes.push(c);
        }
        self.routes.insert(route_id, route);
        self.trim_changes();
    }

    /// Remove a route.
    pub fn remove(&mut self, route_id: &str) -> bool {
        if let Some(route) = self.routes.remove(route_id) {
            self.changes.push(RouteChange {
                route_id: route_id.into(),
                change_type: ChangeType::Removed,
                before: Some(route),
                after: None,
                timestamp: Utc::now(),
            });
            self.trim_changes();
            return true;
        }
        false
    }

    fn trim_changes(&mut self) {
        if self.changes.len() > self.history_limit {
            let excess = self.changes.len() - self.history_limit;
            self.changes.drain(0..excess);
        }
    }

    /// Find the default route(s).
    pub fn default_routes(&self) -> Vec<&Route> {
        self.routes.values()
            .filter(|r| r.prefix_length == 0)
            .collect()
    }

    /// Check whether the default gateway is the expected one.
    pub fn gateway_hijacked(&self) -> bool {
        let expected = match self.expected_default_gateway {
            Some(gw) => gw,
            None => return false,
        };
        let defaults = self.default_routes();
        if defaults.is_empty() { return false; }
        !defaults.iter().any(|r| r.gateway == Some(expected))
    }

    /// Routes by interface.
    pub fn by_interface(&self, interface: &str) -> Vec<&Route> {
        self.routes.values().filter(|r| r.interface == interface).collect()
    }

    /// Routes by protocol.
    pub fn by_protocol(&self, protocol: &RouteProtocol) -> Vec<&Route> {
        self.routes.values().filter(|r| &r.protocol == protocol).collect()
    }

    /// Static routes (user/admin added).
    pub fn static_routes(&self) -> Vec<&Route> {
        self.by_protocol(&RouteProtocol::Static)
    }

    /// Recent route changes.
    pub fn recent_changes(&self, n: usize) -> Vec<&RouteChange> {
        let start = self.changes.len().saturating_sub(n);
        self.changes.iter().skip(start).collect()
    }

    /// Route count.
    pub fn route_count(&self) -> usize { self.routes.len() }
    pub fn change_count(&self) -> usize { self.changes.len() }
}

impl Default for RouteTable {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr { s.parse().unwrap() }

    fn route(id: &str, dest: &str, prefix: u8, gw: Option<&str>, iface: &str, protocol: RouteProtocol) -> Route {
        Route {
            id: id.into(),
            destination: ip(dest),
            prefix_length: prefix,
            gateway: gw.map(|g| ip(g)),
            interface: iface.into(),
            metric: 100,
            scope: RouteScope::Universe,
            protocol,
            added_at: Utc::now(),
        }
    }

    #[test]
    fn test_observe_new_route() {
        let mut t = RouteTable::new();
        t.observe(route("r1", "0.0.0.0", 0, Some("192.168.1.1"), "eth0", RouteProtocol::Dhcp));
        assert_eq!(t.route_count(), 1);
    }

    #[test]
    fn test_default_routes() {
        let mut t = RouteTable::new();
        t.observe(route("r1", "0.0.0.0", 0, Some("192.168.1.1"), "eth0", RouteProtocol::Dhcp));
        t.observe(route("r2", "10.0.0.0", 8, None, "eth0", RouteProtocol::Kernel));
        assert_eq!(t.default_routes().len(), 1);
    }

    #[test]
    fn test_gateway_hijack_detection() {
        let mut t = RouteTable::new();
        t.set_expected_gateway(ip("192.168.1.1"));
        t.observe(route("r1", "0.0.0.0", 0, Some("10.99.99.99"), "eth0", RouteProtocol::Dhcp));
        assert!(t.gateway_hijacked());
    }

    #[test]
    fn test_no_hijack_when_match() {
        let mut t = RouteTable::new();
        t.set_expected_gateway(ip("192.168.1.1"));
        t.observe(route("r1", "0.0.0.0", 0, Some("192.168.1.1"), "eth0", RouteProtocol::Dhcp));
        assert!(!t.gateway_hijacked());
    }

    #[test]
    fn test_route_change_recorded() {
        let mut t = RouteTable::new();
        t.observe(route("r1", "0.0.0.0", 0, Some("192.168.1.1"), "eth0", RouteProtocol::Dhcp));
        let mut modified = route("r1", "0.0.0.0", 0, Some("10.0.0.1"), "eth0", RouteProtocol::Dhcp);
        modified.added_at = Utc::now();
        t.observe(modified);
        assert!(t.change_count() >= 2);
        assert!(t.recent_changes(10).iter().any(|c| c.change_type == ChangeType::Modified));
    }

    #[test]
    fn test_remove_route() {
        let mut t = RouteTable::new();
        t.observe(route("r1", "0.0.0.0", 0, Some("192.168.1.1"), "eth0", RouteProtocol::Dhcp));
        assert!(t.remove("r1"));
        assert_eq!(t.route_count(), 0);
    }

    #[test]
    fn test_by_interface() {
        let mut t = RouteTable::new();
        t.observe(route("r1", "10.0.0.0", 8, None, "eth0", RouteProtocol::Kernel));
        t.observe(route("r2", "172.16.0.0", 12, None, "wlan0", RouteProtocol::Kernel));
        assert_eq!(t.by_interface("eth0").len(), 1);
    }

    #[test]
    fn test_static_routes() {
        let mut t = RouteTable::new();
        t.observe(route("r1", "10.0.0.0", 8, None, "eth0", RouteProtocol::Static));
        t.observe(route("r2", "172.16.0.0", 12, None, "wlan0", RouteProtocol::Kernel));
        assert_eq!(t.static_routes().len(), 1);
    }

    #[test]
    fn test_no_hijack_without_expected() {
        let mut t = RouteTable::new();
        t.observe(route("r1", "0.0.0.0", 0, Some("10.99.99.99"), "eth0", RouteProtocol::Dhcp));
        assert!(!t.gateway_hijacked());
    }
}
