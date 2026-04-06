//! Shaping queue — token-bucket bandwidth shaping per traffic class.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A token bucket for shaping.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenBucket {
    pub class: String,
    /// Refill rate in bytes per second.
    pub refill_rate_bps: u64,
    /// Current bucket level (bytes).
    pub tokens: u64,
    /// Maximum bucket capacity (burst).
    pub capacity: u64,
    pub last_refill: DateTime<Utc>,
}

impl TokenBucket {
    pub fn new(class: &str, refill_rate_bps: u64, capacity: u64) -> Self {
        Self {
            class: class.into(),
            refill_rate_bps,
            tokens: capacity,
            capacity,
            last_refill: Utc::now(),
        }
    }

    /// Refill tokens based on elapsed time.
    pub fn refill(&mut self) {
        let now = Utc::now();
        let elapsed_secs = (now - self.last_refill).num_milliseconds() as f64 / 1000.0;
        let new_tokens = (self.refill_rate_bps as f64 * elapsed_secs) as u64;
        self.tokens = (self.tokens + new_tokens).min(self.capacity);
        self.last_refill = now;
    }

    /// Consume tokens. Returns true if successful.
    pub fn consume(&mut self, bytes: u64) -> bool {
        self.refill();
        if self.tokens >= bytes {
            self.tokens -= bytes;
            true
        } else {
            false
        }
    }

    /// Available tokens after refill.
    pub fn available(&mut self) -> u64 {
        self.refill();
        self.tokens
    }

    /// Utilization ratio (0.0 = full, 1.0 = empty).
    pub fn utilization(&self) -> f64 {
        if self.capacity == 0 { return 1.0; }
        1.0 - (self.tokens as f64 / self.capacity as f64)
    }
}

/// Shaping decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShapeDecision {
    Pass,
    Throttled,
    Dropped,
}

/// Traffic shaping queue.
pub struct ShapingQueue {
    buckets: HashMap<String, TokenBucket>,
    drops: HashMap<String, u64>,
    passes: HashMap<String, u64>,
}

impl ShapingQueue {
    pub fn new() -> Self {
        Self {
            buckets: HashMap::new(),
            drops: HashMap::new(),
            passes: HashMap::new(),
        }
    }

    /// Add a class with a token bucket.
    pub fn add_class(&mut self, class: &str, refill_rate_bps: u64, capacity: u64) {
        self.buckets.insert(class.into(),
            TokenBucket::new(class, refill_rate_bps, capacity));
    }

    /// Remove a class.
    pub fn remove_class(&mut self, class: &str) -> bool {
        self.buckets.remove(class).is_some()
    }

    /// Process a packet of given size for a class.
    pub fn process(&mut self, class: &str, size: u64) -> ShapeDecision {
        let bucket = match self.buckets.get_mut(class) {
            Some(b) => b,
            None => return ShapeDecision::Pass, // unclassified pass-through
        };
        if bucket.consume(size) {
            *self.passes.entry(class.into()).or_insert(0) += 1;
            ShapeDecision::Pass
        } else {
            *self.drops.entry(class.into()).or_insert(0) += 1;
            ShapeDecision::Dropped
        }
    }

    /// Update class bandwidth.
    pub fn set_rate(&mut self, class: &str, refill_rate_bps: u64) -> bool {
        if let Some(b) = self.buckets.get_mut(class) {
            b.refill_rate_bps = refill_rate_bps;
            return true;
        }
        false
    }

    /// Per-class drop counts.
    pub fn drop_count(&self, class: &str) -> u64 {
        *self.drops.get(class).unwrap_or(&0)
    }

    /// Per-class pass counts.
    pub fn pass_count(&self, class: &str) -> u64 {
        *self.passes.get(class).unwrap_or(&0)
    }

    /// Drop rate for a class.
    pub fn drop_rate(&self, class: &str) -> f64 {
        let drops = self.drop_count(class);
        let passes = self.pass_count(class);
        let total = drops + passes;
        if total == 0 { return 0.0; }
        drops as f64 / total as f64
    }

    /// Get bucket info.
    pub fn bucket(&mut self, class: &str) -> Option<&mut TokenBucket> {
        self.buckets.get_mut(class)
    }

    pub fn class_count(&self) -> usize { self.buckets.len() }
}

impl Default for ShapingQueue {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_token_bucket_consume() {
        let mut b = TokenBucket::new("c", 1000, 5000);
        assert!(b.consume(2000));
        assert!(b.consume(3000));
    }

    #[test]
    fn test_bucket_runs_dry() {
        let mut b = TokenBucket::new("c", 1000, 1000);
        assert!(b.consume(1000));
        assert!(!b.consume(500));
    }

    #[test]
    fn test_bucket_refill() {
        let mut b = TokenBucket::new("c", 1000, 1000);
        b.consume(1000);
        thread::sleep(Duration::from_millis(50));
        b.refill();
        assert!(b.tokens > 0);
    }

    #[test]
    fn test_shaping_pass() {
        let mut q = ShapingQueue::new();
        q.add_class("interactive", 10_000, 50_000);
        assert_eq!(q.process("interactive", 1000), ShapeDecision::Pass);
    }

    #[test]
    fn test_shaping_drop_when_dry() {
        let mut q = ShapingQueue::new();
        q.add_class("c", 100, 1000);
        assert_eq!(q.process("c", 1000), ShapeDecision::Pass);
        assert_eq!(q.process("c", 1000), ShapeDecision::Dropped);
    }

    #[test]
    fn test_unclassified_passes() {
        let mut q = ShapingQueue::new();
        assert_eq!(q.process("unknown", 1000), ShapeDecision::Pass);
    }

    #[test]
    fn test_drop_rate() {
        let mut q = ShapingQueue::new();
        q.add_class("c", 100, 1000);
        q.process("c", 1000); // pass
        q.process("c", 1000); // drop
        q.process("c", 1000); // drop
        assert!((q.drop_rate("c") - 2.0/3.0).abs() < 0.01);
    }

    #[test]
    fn test_set_rate() {
        let mut q = ShapingQueue::new();
        q.add_class("c", 100, 1000);
        q.set_rate("c", 5000);
        assert_eq!(q.bucket("c").unwrap().refill_rate_bps, 5000);
    }

    #[test]
    fn test_remove_class() {
        let mut q = ShapingQueue::new();
        q.add_class("c", 100, 1000);
        assert!(q.remove_class("c"));
        assert_eq!(q.class_count(), 0);
    }

    #[test]
    fn test_utilization() {
        let mut b = TokenBucket::new("c", 1000, 10000);
        b.consume(5000);
        assert!((b.utilization() - 0.5).abs() < 0.01);
    }
}
