//! IP reputation — score IPs based on observed behavior.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IpScore {
    pub blocked_count: u64,
    pub allowed_count: u64,
    pub suspicious_events: u64,
    pub first_seen_epoch: i64,
}

impl IpScore {
    pub fn reputation(&self) -> f64 {
        let total = self.blocked_count + self.allowed_count;
        if total == 0 { return 0.5; }
        let base = self.allowed_count as f64 / total as f64;
        let penalty = (self.suspicious_events as f64 * 0.1).min(0.5);
        (base - penalty).clamp(0.0, 1.0)
    }

    pub fn is_suspicious(&self) -> bool { self.reputation() < 0.3 }
}

pub struct IpReputationDb {
    scores: HashMap<String, IpScore>,
}

impl IpReputationDb {
    pub fn new() -> Self { Self { scores: HashMap::new() } }
    pub fn record_blocked(&mut self, ip: &str) { self.scores.entry(ip.into()).or_default().blocked_count += 1; }
    pub fn record_allowed(&mut self, ip: &str) { self.scores.entry(ip.into()).or_default().allowed_count += 1; }
    pub fn record_suspicious(&mut self, ip: &str) { self.scores.entry(ip.into()).or_default().suspicious_events += 1; }
    pub fn get_score(&self, ip: &str) -> Option<&IpScore> { self.scores.get(ip) }
    pub fn suspicious_ips(&self) -> Vec<(&str, f64)> { self.scores.iter().filter(|(_, s)| s.is_suspicious()).map(|(ip, s)| (ip.as_str(), s.reputation())).collect() }
    pub fn tracked_count(&self) -> usize { self.scores.len() }
}

impl Default for IpReputationDb { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_good_ip() {
        let mut db = IpReputationDb::new();
        for _ in 0..10 { db.record_allowed("1.1.1.1"); }
        assert!(db.get_score("1.1.1.1").unwrap().reputation() > 0.8);
    }

    #[test]
    fn test_bad_ip() {
        let mut db = IpReputationDb::new();
        for _ in 0..10 { db.record_blocked("bad"); db.record_suspicious("bad"); }
        assert!(db.get_score("bad").unwrap().is_suspicious());
    }

    #[test]
    fn test_suspicious_list() {
        let mut db = IpReputationDb::new();
        for _ in 0..10 { db.record_blocked("evil"); db.record_suspicious("evil"); }
        for _ in 0..10 { db.record_allowed("good"); }
        let susp = db.suspicious_ips();
        assert_eq!(susp.len(), 1);
        assert_eq!(susp[0].0, "evil");
    }
}
