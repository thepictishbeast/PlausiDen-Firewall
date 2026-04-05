//! Bandwidth limiter — per-application and per-destination rate control.

use std::collections::HashMap;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BandwidthLimit {
    pub target: String,
    pub max_bytes_per_second: u64,
    pub current_usage: u64,
    pub window_start: DateTime<Utc>,
}

pub struct BandwidthLimiter {
    limits: HashMap<String, BandwidthLimit>,
    global_limit: Option<u64>,
    global_usage: u64,
    window_start: DateTime<Utc>,
}

impl BandwidthLimiter {
    pub fn new(global_limit: Option<u64>) -> Self {
        Self { limits: HashMap::new(), global_limit, global_usage: 0, window_start: Utc::now() }
    }

    pub fn set_limit(&mut self, target: &str, max_bps: u64) {
        self.limits.insert(target.to_string(), BandwidthLimit {
            target: target.to_string(), max_bytes_per_second: max_bps, current_usage: 0, window_start: Utc::now(),
        });
    }

    pub fn check_allowed(&self, target: &str, bytes: u64) -> bool {
        if let Some(global) = self.global_limit {
            if self.global_usage + bytes > global { return false; }
        }
        if let Some(limit) = self.limits.get(target) {
            if limit.current_usage + bytes > limit.max_bytes_per_second { return false; }
        }
        true
    }

    pub fn record_usage(&mut self, target: &str, bytes: u64) {
        self.global_usage += bytes;
        if let Some(limit) = self.limits.get_mut(target) { limit.current_usage += bytes; }
    }

    pub fn reset_window(&mut self) {
        self.global_usage = 0;
        self.window_start = Utc::now();
        for limit in self.limits.values_mut() { limit.current_usage = 0; limit.window_start = Utc::now(); }
    }

    pub fn utilization(&self, target: &str) -> f64 {
        self.limits.get(target).map(|l| {
            if l.max_bytes_per_second == 0 { 0.0 } else { l.current_usage as f64 / l.max_bytes_per_second as f64 }
        }).unwrap_or(0.0)
    }

    pub fn limit_count(&self) -> usize { self.limits.len() }
}

impl Default for BandwidthLimiter { fn default() -> Self { Self::new(None) } }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_within_limit() {
        let mut limiter = BandwidthLimiter::new(None);
        limiter.set_limit("app1", 1000);
        assert!(limiter.check_allowed("app1", 500));
    }

    #[test]
    fn test_exceeds_limit() {
        let mut limiter = BandwidthLimiter::new(None);
        limiter.set_limit("app1", 1000);
        limiter.record_usage("app1", 900);
        assert!(!limiter.check_allowed("app1", 200));
    }

    #[test]
    fn test_global_limit() {
        let mut limiter = BandwidthLimiter::new(Some(5000));
        limiter.record_usage("any", 4500);
        assert!(!limiter.check_allowed("any", 1000));
    }

    #[test]
    fn test_reset_window() {
        let mut limiter = BandwidthLimiter::new(Some(1000));
        limiter.record_usage("x", 900);
        limiter.reset_window();
        assert!(limiter.check_allowed("x", 900));
    }

    #[test]
    fn test_utilization() {
        let mut limiter = BandwidthLimiter::new(None);
        limiter.set_limit("app", 1000);
        limiter.record_usage("app", 500);
        assert!((limiter.utilization("app") - 0.5).abs() < 0.01);
    }
}
