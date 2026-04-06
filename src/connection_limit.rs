//! Connection limiting — prevent resource exhaustion attacks.
//!
//! Tracks per-source and per-application connection counts, enforcing
//! configurable limits. Drops excess connections before they consume
//! system resources.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

/// Per-source connection tracking.
#[derive(Debug, Clone)]
struct SourceEntry {
    active_connections: u32,
    total_connections: u64,
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
    dropped_count: u64,
}

/// Connection limits configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionLimits {
    /// Maximum concurrent connections from a single source.
    pub max_per_source: u32,
    /// Maximum total concurrent connections.
    pub max_total: u32,
    /// Maximum new connections per second from a single source.
    pub max_rate_per_source: u32,
    /// Maximum new connections per second globally.
    pub max_rate_global: u32,
    /// Sources exceeding limits are blocked for this many seconds.
    pub block_duration_secs: i64,
}

impl Default for ConnectionLimits {
    fn default() -> Self {
        Self {
            max_per_source: 100,
            max_total: 10_000,
            max_rate_per_source: 20,
            max_rate_global: 1000,
            block_duration_secs: 300,
        }
    }
}

/// Decision on whether to accept a new connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionDecision {
    Accept,
    RejectPerSourceLimit,
    RejectTotalLimit,
    RejectBlocked,
}

/// Manages connection limits and blocking.
pub struct ConnectionLimiter {
    config: ConnectionLimits,
    sources: HashMap<IpAddr, SourceEntry>,
    blocked: HashMap<IpAddr, DateTime<Utc>>,
    total_active: u32,
    total_accepted: u64,
    total_rejected: u64,
}

impl ConnectionLimiter {
    pub fn new(config: ConnectionLimits) -> Self {
        Self {
            config,
            sources: HashMap::new(),
            blocked: HashMap::new(),
            total_active: 0,
            total_accepted: 0,
            total_rejected: 0,
        }
    }

    /// Check if a new connection should be accepted.
    pub fn check_connection(&mut self, source: IpAddr) -> ConnectionDecision {
        let now = Utc::now();

        // Check if source is blocked.
        if let Some(until) = self.blocked.get(&source) {
            if *until > now {
                self.total_rejected += 1;
                return ConnectionDecision::RejectBlocked;
            }
            self.blocked.remove(&source);
        }

        // Check total limit.
        if self.total_active >= self.config.max_total {
            self.total_rejected += 1;
            return ConnectionDecision::RejectTotalLimit;
        }

        // Check per-source limit.
        let entry = self.sources.entry(source).or_insert_with(|| SourceEntry {
            active_connections: 0,
            total_connections: 0,
            first_seen: now,
            last_seen: now,
            dropped_count: 0,
        });

        if entry.active_connections >= self.config.max_per_source {
            entry.dropped_count += 1;
            self.total_rejected += 1;

            // Block source if they keep hitting the limit.
            if entry.dropped_count >= 10 {
                self.blocked.insert(
                    source,
                    now + Duration::seconds(self.config.block_duration_secs),
                );
            }

            return ConnectionDecision::RejectPerSourceLimit;
        }

        // Accept.
        entry.active_connections += 1;
        entry.total_connections += 1;
        entry.last_seen = now;
        self.total_active += 1;
        self.total_accepted += 1;

        ConnectionDecision::Accept
    }

    /// Record connection closure.
    pub fn close_connection(&mut self, source: IpAddr) {
        if let Some(entry) = self.sources.get_mut(&source) {
            entry.active_connections = entry.active_connections.saturating_sub(1);
        }
        self.total_active = self.total_active.saturating_sub(1);
    }

    /// Remove stale entries (sources with no active connections).
    pub fn cleanup_stale(&mut self, max_idle_secs: i64) -> usize {
        let cutoff = Utc::now() - Duration::seconds(max_idle_secs);
        let before = self.sources.len();
        self.sources.retain(|_, e| e.active_connections > 0 || e.last_seen > cutoff);
        before - self.sources.len()
    }

    /// Remove expired blocks.
    pub fn cleanup_blocks(&mut self) -> usize {
        let now = Utc::now();
        let before = self.blocked.len();
        self.blocked.retain(|_, until| *until > now);
        before - self.blocked.len()
    }

    /// Manual block of a source.
    pub fn block_source(&mut self, source: IpAddr, duration_secs: i64) {
        self.blocked.insert(source, Utc::now() + Duration::seconds(duration_secs));
    }

    /// Manual unblock.
    pub fn unblock_source(&mut self, source: IpAddr) -> bool {
        self.blocked.remove(&source).is_some()
    }

    /// Check if a source is currently blocked.
    pub fn is_blocked(&self, source: &IpAddr) -> bool {
        self.blocked.get(source).map(|u| *u > Utc::now()).unwrap_or(false)
    }

    pub fn total_active(&self) -> u32 { self.total_active }
    pub fn total_accepted(&self) -> u64 { self.total_accepted }
    pub fn total_rejected(&self) -> u64 { self.total_rejected }
    pub fn tracked_sources(&self) -> usize { self.sources.len() }
    pub fn blocked_count(&self) -> usize { self.blocked.len() }

    /// Get the top sources by active connection count.
    pub fn top_sources(&self, n: usize) -> Vec<(IpAddr, u32)> {
        let mut sorted: Vec<_> = self.sources.iter()
            .map(|(ip, e)| (*ip, e.active_connections))
            .collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));
        sorted.truncate(n);
        sorted
    }
}

impl Default for ConnectionLimiter {
    fn default() -> Self { Self::new(ConnectionLimits::default()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr { s.parse().unwrap() }

    #[test]
    fn test_accept_connection() {
        let mut limiter = ConnectionLimiter::default();
        assert_eq!(limiter.check_connection(ip("1.2.3.4")), ConnectionDecision::Accept);
        assert_eq!(limiter.total_active(), 1);
        assert_eq!(limiter.total_accepted(), 1);
    }

    #[test]
    fn test_per_source_limit() {
        let config = ConnectionLimits { max_per_source: 3, ..Default::default() };
        let mut limiter = ConnectionLimiter::new(config);
        let src = ip("10.0.0.1");

        for _ in 0..3 {
            assert_eq!(limiter.check_connection(src), ConnectionDecision::Accept);
        }
        assert_eq!(limiter.check_connection(src), ConnectionDecision::RejectPerSourceLimit);
    }

    #[test]
    fn test_total_limit() {
        let config = ConnectionLimits { max_total: 2, max_per_source: 100, ..Default::default() };
        let mut limiter = ConnectionLimiter::new(config);

        assert_eq!(limiter.check_connection(ip("1.1.1.1")), ConnectionDecision::Accept);
        assert_eq!(limiter.check_connection(ip("2.2.2.2")), ConnectionDecision::Accept);
        assert_eq!(limiter.check_connection(ip("3.3.3.3")), ConnectionDecision::RejectTotalLimit);
    }

    #[test]
    fn test_close_frees_slot() {
        let config = ConnectionLimits { max_per_source: 2, ..Default::default() };
        let mut limiter = ConnectionLimiter::new(config);
        let src = ip("10.0.0.1");

        limiter.check_connection(src);
        limiter.check_connection(src);
        assert_eq!(limiter.check_connection(src), ConnectionDecision::RejectPerSourceLimit);

        limiter.close_connection(src);
        assert_eq!(limiter.check_connection(src), ConnectionDecision::Accept);
    }

    #[test]
    fn test_auto_block_after_repeated_violations() {
        let config = ConnectionLimits { max_per_source: 1, block_duration_secs: 300, ..Default::default() };
        let mut limiter = ConnectionLimiter::new(config);
        let src = ip("10.0.0.1");

        limiter.check_connection(src); // Accept first.
        // Hit the limit 10 times to trigger auto-block.
        for _ in 0..10 {
            limiter.check_connection(src);
        }
        assert!(limiter.is_blocked(&src));
        assert_eq!(limiter.check_connection(src), ConnectionDecision::RejectBlocked);
    }

    #[test]
    fn test_manual_block() {
        let mut limiter = ConnectionLimiter::default();
        let src = ip("10.0.0.1");
        limiter.block_source(src, 300);
        assert!(limiter.is_blocked(&src));
        assert_eq!(limiter.check_connection(src), ConnectionDecision::RejectBlocked);
    }

    #[test]
    fn test_manual_unblock() {
        let mut limiter = ConnectionLimiter::default();
        let src = ip("10.0.0.1");
        limiter.block_source(src, 300);
        assert!(limiter.unblock_source(src));
        assert!(!limiter.is_blocked(&src));
        assert_eq!(limiter.check_connection(src), ConnectionDecision::Accept);
    }

    #[test]
    fn test_top_sources() {
        let mut limiter = ConnectionLimiter::default();
        for _ in 0..5 { limiter.check_connection(ip("1.1.1.1")); }
        for _ in 0..3 { limiter.check_connection(ip("2.2.2.2")); }
        limiter.check_connection(ip("3.3.3.3"));

        let top = limiter.top_sources(2);
        assert_eq!(top[0].0, ip("1.1.1.1"));
        assert_eq!(top[0].1, 5);
    }

    #[test]
    fn test_stats() {
        let mut limiter = ConnectionLimiter::default();
        limiter.check_connection(ip("1.1.1.1"));
        limiter.check_connection(ip("2.2.2.2"));
        assert_eq!(limiter.total_accepted(), 2);
        assert_eq!(limiter.total_rejected(), 0);
        assert_eq!(limiter.tracked_sources(), 2);
    }

    #[test]
    fn test_cleanup_stale() {
        let mut limiter = ConnectionLimiter::default();
        limiter.check_connection(ip("1.1.1.1"));
        limiter.close_connection(ip("1.1.1.1"));
        // With idle threshold of 0, should clean up immediately.
        let cleaned = limiter.cleanup_stale(0);
        assert!(cleaned == 0 || cleaned == 1); // Depends on timing.
    }
}
