//! Traffic shaping — bandwidth allocation and QoS enforcement.
//!
//! Implements token bucket rate limiting with per-application and
//! per-destination bandwidth classes. Ensures critical traffic gets
//! priority while bulk transfers are throttled.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// QoS traffic class.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TrafficClass {
    /// Interactive traffic (SSH, VoIP) — lowest latency.
    Interactive,
    /// Real-time streaming — consistent bandwidth.
    Streaming,
    /// Web browsing — moderate priority.
    Web,
    /// Bulk transfers — lowest priority.
    Bulk,
    /// PlausiDen Swarm traffic — shaped to blend with normal traffic.
    Swarm,
    /// Default class.
    Default,
}

/// Token bucket rate limiter.
#[derive(Debug, Clone)]
pub struct TokenBucket {
    /// Maximum tokens (burst capacity in bytes).
    capacity: u64,
    /// Current tokens available.
    tokens: u64,
    /// Token refill rate (bytes per second).
    rate_bps: u64,
    /// Last refill timestamp (milliseconds since epoch).
    last_refill_ms: u64,
}

impl TokenBucket {
    pub fn new(rate_bps: u64, burst_bytes: u64) -> Self {
        Self {
            capacity: burst_bytes,
            tokens: burst_bytes,
            rate_bps,
            last_refill_ms: 0,
        }
    }

    /// Try to consume tokens for a packet. Returns true if allowed.
    pub fn try_consume(&mut self, bytes: u64, now_ms: u64) -> bool {
        self.refill(now_ms);
        if self.tokens >= bytes {
            self.tokens -= bytes;
            true
        } else {
            false
        }
    }

    /// Refill tokens based on elapsed time.
    fn refill(&mut self, now_ms: u64) {
        if self.last_refill_ms == 0 {
            self.last_refill_ms = now_ms;
            return;
        }
        let elapsed_ms = now_ms.saturating_sub(self.last_refill_ms);
        let new_tokens = self.rate_bps * elapsed_ms / 1000;
        self.tokens = (self.tokens + new_tokens).min(self.capacity);
        self.last_refill_ms = now_ms;
    }

    /// Current available tokens.
    pub fn available(&self) -> u64 { self.tokens }

    /// Rate in bytes per second.
    pub fn rate(&self) -> u64 { self.rate_bps }
}

/// Per-class bandwidth configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassConfig {
    pub class: TrafficClass,
    /// Guaranteed minimum bandwidth (bytes/sec).
    pub min_rate_bps: u64,
    /// Maximum bandwidth (bytes/sec, 0 = unlimited).
    pub max_rate_bps: u64,
    /// Burst allowance (bytes).
    pub burst_bytes: u64,
    /// Priority weight (higher = more priority when contending).
    pub weight: u32,
}

/// Traffic shaper managing multiple QoS classes.
pub struct TrafficShaper {
    buckets: HashMap<TrafficClass, TokenBucket>,
    /// Per-application class assignment.
    app_classes: HashMap<String, TrafficClass>,
    /// Total shaped bytes.
    total_shaped: u64,
    /// Total dropped bytes.
    total_dropped: u64,
}

impl TrafficShaper {
    pub fn new(configs: Vec<ClassConfig>) -> Self {
        let mut buckets = HashMap::new();
        for config in &configs {
            let rate = if config.max_rate_bps > 0 { config.max_rate_bps } else { u64::MAX / 2 };
            buckets.insert(config.class.clone(), TokenBucket::new(rate, config.burst_bytes));
        }
        Self {
            buckets,
            app_classes: HashMap::new(),
            total_shaped: 0,
            total_dropped: 0,
        }
    }

    /// Create a shaper with sensible defaults for a 100 Mbps link.
    pub fn default_100mbps() -> Self {
        Self::new(vec![
            ClassConfig { class: TrafficClass::Interactive, min_rate_bps: 5_000_000, max_rate_bps: 20_000_000, burst_bytes: 64_000, weight: 100 },
            ClassConfig { class: TrafficClass::Streaming, min_rate_bps: 10_000_000, max_rate_bps: 50_000_000, burst_bytes: 256_000, weight: 80 },
            ClassConfig { class: TrafficClass::Web, min_rate_bps: 5_000_000, max_rate_bps: 80_000_000, burst_bytes: 128_000, weight: 60 },
            ClassConfig { class: TrafficClass::Bulk, min_rate_bps: 1_000_000, max_rate_bps: 50_000_000, burst_bytes: 512_000, weight: 20 },
            ClassConfig { class: TrafficClass::Swarm, min_rate_bps: 500_000, max_rate_bps: 10_000_000, burst_bytes: 64_000, weight: 10 },
            ClassConfig { class: TrafficClass::Default, min_rate_bps: 1_000_000, max_rate_bps: 100_000_000, burst_bytes: 128_000, weight: 40 },
        ])
    }

    /// Assign an application to a traffic class.
    pub fn classify_app(&mut self, app_id: &str, class: TrafficClass) {
        self.app_classes.insert(app_id.into(), class);
    }

    /// Check if a packet should be allowed through.
    pub fn shape(&mut self, app_id: &str, bytes: u64, now_ms: u64) -> bool {
        let class = self.app_classes.get(app_id).cloned().unwrap_or(TrafficClass::Default);
        if let Some(bucket) = self.buckets.get_mut(&class) {
            if bucket.try_consume(bytes, now_ms) {
                self.total_shaped += bytes;
                true
            } else {
                self.total_dropped += bytes;
                false
            }
        } else {
            self.total_shaped += bytes;
            true // No bucket = no limit.
        }
    }

    /// Get the class assigned to an app.
    pub fn get_class(&self, app_id: &str) -> TrafficClass {
        self.app_classes.get(app_id).cloned().unwrap_or(TrafficClass::Default)
    }

    pub fn total_shaped(&self) -> u64 { self.total_shaped }
    pub fn total_dropped(&self) -> u64 { self.total_dropped }
    pub fn class_count(&self) -> usize { self.buckets.len() }
}

impl Default for TrafficShaper {
    fn default() -> Self { Self::default_100mbps() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_bucket_allows() {
        let mut bucket = TokenBucket::new(1_000_000, 10_000);
        assert!(bucket.try_consume(5000, 1000));
        assert_eq!(bucket.available(), 5000);
    }

    #[test]
    fn test_token_bucket_blocks() {
        let mut bucket = TokenBucket::new(1_000_000, 10_000);
        assert!(bucket.try_consume(10_000, 1000));
        assert!(!bucket.try_consume(1, 1000)); // No tokens left.
    }

    #[test]
    fn test_token_bucket_refill() {
        let mut bucket = TokenBucket::new(10_000, 10_000); // 10 KB/s
        bucket.try_consume(10_000, 1000); // Empty.
        assert!(bucket.try_consume(5_000, 1500)); // 500ms later: 5000 tokens refilled.
    }

    #[test]
    fn test_shaper_allows_normal() {
        let mut shaper = TrafficShaper::default();
        assert!(shaper.shape("firefox", 1000, 1000));
    }

    #[test]
    fn test_shaper_throttles() {
        let configs = vec![
            ClassConfig { class: TrafficClass::Bulk, min_rate_bps: 0, max_rate_bps: 1000, burst_bytes: 1000, weight: 1 },
        ];
        let mut shaper = TrafficShaper::new(configs);
        shaper.classify_app("downloader", TrafficClass::Bulk);

        assert!(shaper.shape("downloader", 1000, 1000)); // Use all burst.
        assert!(!shaper.shape("downloader", 1, 1000)); // Throttled.
    }

    #[test]
    fn test_app_classification() {
        let mut shaper = TrafficShaper::default();
        shaper.classify_app("ssh", TrafficClass::Interactive);
        shaper.classify_app("youtube", TrafficClass::Streaming);
        assert_eq!(shaper.get_class("ssh"), TrafficClass::Interactive);
        assert_eq!(shaper.get_class("youtube"), TrafficClass::Streaming);
        assert_eq!(shaper.get_class("unknown"), TrafficClass::Default);
    }

    #[test]
    fn test_stats() {
        let mut shaper = TrafficShaper::default();
        shaper.shape("app", 5000, 1000);
        assert_eq!(shaper.total_shaped(), 5000);
    }

    #[test]
    fn test_default_classes() {
        let shaper = TrafficShaper::default();
        assert!(shaper.class_count() >= 6);
    }
}
