//! Geographic routing — force traffic through specific egress points based on
//! destination geography.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

/// Country/region code.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RegionCode(pub String);

/// An egress point (VPN exit, relay, direct).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EgressPoint {
    pub id: String,
    pub label: String,
    pub region: RegionCode,
    pub egress_type: EgressType,
    pub capacity: u32,
    pub current_load: u32,
    pub enabled: bool,
    pub last_checked: Option<DateTime<Utc>>,
    pub latency_ms: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EgressType {
    Direct,
    Vpn,
    Tor,
    Relay,
}

impl EgressPoint {
    pub fn load_ratio(&self) -> f64 {
        if self.capacity == 0 { return 1.0; }
        self.current_load as f64 / self.capacity as f64
    }

    pub fn has_capacity(&self) -> bool {
        self.enabled && self.current_load < self.capacity
    }
}

/// Routing policy for a destination region.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingPolicy {
    pub region: RegionCode,
    pub preferred_egress_type: EgressType,
    pub allowed_types: Vec<EgressType>,
    pub blocked: bool,
}

/// Routing decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RouteDecision {
    UseEgress(String),
    Block,
    NoRouteFound,
}

/// Geographic router.
pub struct GeoRouter {
    egress_points: HashMap<String, EgressPoint>,
    policies: HashMap<RegionCode, RoutingPolicy>,
    default_egress: Option<String>,
}

impl GeoRouter {
    pub fn new() -> Self {
        Self {
            egress_points: HashMap::new(),
            policies: HashMap::new(),
            default_egress: None,
        }
    }

    /// Add an egress point.
    pub fn add_egress(&mut self, egress: EgressPoint) {
        self.egress_points.insert(egress.id.clone(), egress);
    }

    /// Remove an egress point.
    pub fn remove_egress(&mut self, id: &str) -> bool {
        self.egress_points.remove(id).is_some()
    }

    /// Set a routing policy.
    pub fn set_policy(&mut self, policy: RoutingPolicy) {
        self.policies.insert(policy.region.clone(), policy);
    }

    /// Set a default egress when no policy matches.
    pub fn set_default(&mut self, id: &str) {
        self.default_egress = Some(id.into());
    }

    /// Route traffic to a given destination region.
    pub fn route(&self, dest_region: &RegionCode) -> RouteDecision {
        let policy = match self.policies.get(dest_region) {
            Some(p) => p,
            None => {
                return self.default_egress.as_ref()
                    .map(|id| RouteDecision::UseEgress(id.clone()))
                    .unwrap_or(RouteDecision::NoRouteFound);
            }
        };

        if policy.blocked {
            return RouteDecision::Block;
        }

        // Find best egress of preferred type with capacity.
        let mut candidates: Vec<&EgressPoint> = self.egress_points.values()
            .filter(|e| e.has_capacity())
            .filter(|e| policy.allowed_types.contains(&e.egress_type))
            .collect();

        // Prefer preferred type.
        let preferred: Vec<&EgressPoint> = candidates.iter()
            .filter(|e| e.egress_type == policy.preferred_egress_type)
            .copied()
            .collect();
        if !preferred.is_empty() {
            candidates = preferred;
        }

        candidates.sort_by(|a, b| {
            a.load_ratio().partial_cmp(&b.load_ratio()).unwrap()
        });

        candidates.first()
            .map(|e| RouteDecision::UseEgress(e.id.clone()))
            .unwrap_or(RouteDecision::NoRouteFound)
    }

    /// Lookup an egress point.
    pub fn get_egress(&self, id: &str) -> Option<&EgressPoint> {
        self.egress_points.get(id)
    }

    /// Increment load on an egress.
    pub fn increment_load(&mut self, id: &str) -> bool {
        if let Some(e) = self.egress_points.get_mut(id) {
            e.current_load += 1;
            return true;
        }
        false
    }

    /// Decrement load.
    pub fn decrement_load(&mut self, id: &str) -> bool {
        if let Some(e) = self.egress_points.get_mut(id) {
            if e.current_load > 0 {
                e.current_load -= 1;
                return true;
            }
        }
        false
    }

    /// Egress points by type.
    pub fn by_type(&self, egress_type: &EgressType) -> Vec<&EgressPoint> {
        self.egress_points.values().filter(|e| &e.egress_type == egress_type).collect()
    }

    /// Egress points by region.
    pub fn by_region(&self, region: &RegionCode) -> Vec<&EgressPoint> {
        self.egress_points.values().filter(|e| &e.region == region).collect()
    }

    pub fn egress_count(&self) -> usize { self.egress_points.len() }
    pub fn policy_count(&self) -> usize { self.policies.len() }
}

impl Default for GeoRouter {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn egress(id: &str, region: &str, t: EgressType, capacity: u32) -> EgressPoint {
        EgressPoint {
            id: id.into(),
            label: format!("{} egress", id),
            region: RegionCode(region.into()),
            egress_type: t,
            capacity,
            current_load: 0,
            enabled: true,
            last_checked: None,
            latency_ms: Some(50),
        }
    }

    #[test]
    fn test_add_egress() {
        let mut r = GeoRouter::new();
        r.add_egress(egress("us1", "US", EgressType::Vpn, 100));
        assert_eq!(r.egress_count(), 1);
    }

    #[test]
    fn test_route_to_policy() {
        let mut r = GeoRouter::new();
        r.add_egress(egress("us1", "US", EgressType::Vpn, 100));
        r.set_policy(RoutingPolicy {
            region: RegionCode("US".into()),
            preferred_egress_type: EgressType::Vpn,
            allowed_types: vec![EgressType::Vpn, EgressType::Direct],
            blocked: false,
        });
        let decision = r.route(&RegionCode("US".into()));
        assert_eq!(decision, RouteDecision::UseEgress("us1".into()));
    }

    #[test]
    fn test_blocked_region() {
        let mut r = GeoRouter::new();
        r.set_policy(RoutingPolicy {
            region: RegionCode("XX".into()),
            preferred_egress_type: EgressType::Vpn,
            allowed_types: vec![],
            blocked: true,
        });
        let decision = r.route(&RegionCode("XX".into()));
        assert_eq!(decision, RouteDecision::Block);
    }

    #[test]
    fn test_no_policy_uses_default() {
        let mut r = GeoRouter::new();
        r.add_egress(egress("default", "GLOBAL", EgressType::Direct, 100));
        r.set_default("default");
        let decision = r.route(&RegionCode("FR".into()));
        assert_eq!(decision, RouteDecision::UseEgress("default".into()));
    }

    #[test]
    fn test_no_route_found() {
        let r = GeoRouter::new();
        let decision = r.route(&RegionCode("US".into()));
        assert_eq!(decision, RouteDecision::NoRouteFound);
    }

    #[test]
    fn test_load_balancing() {
        let mut r = GeoRouter::new();
        let mut hot = egress("hot", "US", EgressType::Vpn, 100);
        hot.current_load = 90;
        let cold = egress("cold", "US", EgressType::Vpn, 100);
        r.add_egress(hot);
        r.add_egress(cold);
        r.set_policy(RoutingPolicy {
            region: RegionCode("US".into()),
            preferred_egress_type: EgressType::Vpn,
            allowed_types: vec![EgressType::Vpn],
            blocked: false,
        });
        assert_eq!(r.route(&RegionCode("US".into())), RouteDecision::UseEgress("cold".into()));
    }

    #[test]
    fn test_increment_decrement_load() {
        let mut r = GeoRouter::new();
        r.add_egress(egress("e", "US", EgressType::Vpn, 100));
        r.increment_load("e");
        r.increment_load("e");
        assert_eq!(r.get_egress("e").unwrap().current_load, 2);
        r.decrement_load("e");
        assert_eq!(r.get_egress("e").unwrap().current_load, 1);
    }

    #[test]
    fn test_by_type() {
        let mut r = GeoRouter::new();
        r.add_egress(egress("a", "US", EgressType::Vpn, 100));
        r.add_egress(egress("b", "US", EgressType::Tor, 100));
        assert_eq!(r.by_type(&EgressType::Vpn).len(), 1);
    }

    #[test]
    fn test_by_region() {
        let mut r = GeoRouter::new();
        r.add_egress(egress("us1", "US", EgressType::Vpn, 100));
        r.add_egress(egress("fr1", "FR", EgressType::Vpn, 100));
        assert_eq!(r.by_region(&RegionCode("US".into())).len(), 1);
    }

    #[test]
    fn test_full_egress_no_capacity() {
        let mut full = egress("full", "US", EgressType::Vpn, 10);
        full.current_load = 10;
        assert!(!full.has_capacity());
    }
}
