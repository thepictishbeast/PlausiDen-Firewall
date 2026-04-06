//! ICMP rate limiter — throttle ping floods and ICMP reconnaissance.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

/// ICMP message type.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IcmpType {
    EchoRequest,
    EchoReply,
    DestinationUnreachable,
    TimeExceeded,
    Redirect,
    ParameterProblem,
    Timestamp,
    TimestampReply,
    AddressMask,
    AddressMaskReply,
    Other(u8),
}

/// An ICMP observation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IcmpPacket {
    pub source: IpAddr,
    pub dest: IpAddr,
    pub icmp_type: IcmpType,
    pub size_bytes: u32,
    pub timestamp: DateTime<Utc>,
}

/// Rate limit configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IcmpRateConfig {
    /// Max echo requests per source per second.
    pub echo_per_sec: u32,
    /// Max total ICMP packets per source per second.
    pub total_per_sec: u32,
    /// Window for rate calculation (seconds).
    pub window_secs: i64,
    /// Block source after exceeding burst threshold.
    pub burst_threshold: u32,
    /// Block duration in seconds.
    pub block_duration_secs: i64,
}

impl Default for IcmpRateConfig {
    fn default() -> Self {
        Self {
            echo_per_sec: 10,
            total_per_sec: 20,
            window_secs: 60,
            burst_threshold: 100,
            block_duration_secs: 300,
        }
    }
}

/// Rate limit decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IcmpDecision {
    Allow,
    RateLimited,
    Blocked,
}

/// Per-source rate tracking record.
#[derive(Debug, Clone)]
struct SourceState {
    echo_timestamps: Vec<DateTime<Utc>>,
    total_timestamps: Vec<DateTime<Utc>>,
    blocked_until: Option<DateTime<Utc>>,
    total_sent: u64,
    total_blocked: u64,
}

/// ICMP rate limiter.
pub struct IcmpRateLimiter {
    config: IcmpRateConfig,
    sources: HashMap<IpAddr, SourceState>,
}

impl IcmpRateLimiter {
    pub fn new(config: IcmpRateConfig) -> Self {
        Self { config, sources: HashMap::new() }
    }

    /// Evaluate an incoming packet.
    pub fn evaluate(&mut self, packet: &IcmpPacket) -> IcmpDecision {
        let now = Utc::now();
        let state = self.sources.entry(packet.source).or_insert_with(|| SourceState {
            echo_timestamps: Vec::new(),
            total_timestamps: Vec::new(),
            blocked_until: None,
            total_sent: 0,
            total_blocked: 0,
        });

        // Check if currently blocked.
        if let Some(until) = state.blocked_until {
            if now < until {
                state.total_blocked += 1;
                return IcmpDecision::Blocked;
            } else {
                state.blocked_until = None;
            }
        }

        // Prune old entries.
        let cutoff = now - chrono::Duration::seconds(self.config.window_secs);
        state.echo_timestamps.retain(|t| *t >= cutoff);
        state.total_timestamps.retain(|t| *t >= cutoff);

        // Check burst threshold.
        if state.total_timestamps.len() as u32 >= self.config.burst_threshold {
            state.blocked_until = Some(now + chrono::Duration::seconds(self.config.block_duration_secs));
            state.total_blocked += 1;
            return IcmpDecision::Blocked;
        }

        // Per-second rate.
        let one_sec_ago = now - chrono::Duration::seconds(1);
        let recent_total = state.total_timestamps.iter()
            .filter(|t| **t >= one_sec_ago).count() as u32;
        let recent_echo = state.echo_timestamps.iter()
            .filter(|t| **t >= one_sec_ago).count() as u32;

        if recent_total >= self.config.total_per_sec {
            state.total_blocked += 1;
            return IcmpDecision::RateLimited;
        }
        if packet.icmp_type == IcmpType::EchoRequest && recent_echo >= self.config.echo_per_sec {
            state.total_blocked += 1;
            return IcmpDecision::RateLimited;
        }

        // Record.
        state.total_timestamps.push(now);
        state.total_sent += 1;
        if packet.icmp_type == IcmpType::EchoRequest {
            state.echo_timestamps.push(now);
        }

        IcmpDecision::Allow
    }

    /// Block a source for a configured duration.
    pub fn block(&mut self, source: IpAddr) {
        let state = self.sources.entry(source).or_insert_with(|| SourceState {
            echo_timestamps: Vec::new(),
            total_timestamps: Vec::new(),
            blocked_until: None,
            total_sent: 0,
            total_blocked: 0,
        });
        state.blocked_until = Some(Utc::now() + chrono::Duration::seconds(self.config.block_duration_secs));
    }

    /// Unblock a source.
    pub fn unblock(&mut self, source: &IpAddr) {
        if let Some(state) = self.sources.get_mut(source) {
            state.blocked_until = None;
        }
    }

    /// Currently blocked sources.
    pub fn blocked_sources(&self) -> Vec<IpAddr> {
        let now = Utc::now();
        self.sources.iter()
            .filter(|(_, s)| s.blocked_until.map(|u| u > now).unwrap_or(false))
            .map(|(ip, _)| *ip)
            .collect()
    }

    /// Sent/blocked counts for a source.
    pub fn stats_for(&self, source: &IpAddr) -> Option<(u64, u64)> {
        self.sources.get(source).map(|s| (s.total_sent, s.total_blocked))
    }

    pub fn source_count(&self) -> usize { self.sources.len() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr { s.parse().unwrap() }

    fn packet(src: &str, t: IcmpType) -> IcmpPacket {
        IcmpPacket {
            source: ip(src),
            dest: ip("10.0.0.1"),
            icmp_type: t,
            size_bytes: 64,
            timestamp: Utc::now(),
        }
    }

    #[test]
    fn test_allow_first() {
        let mut l = IcmpRateLimiter::new(IcmpRateConfig::default());
        assert_eq!(l.evaluate(&packet("10.0.0.2", IcmpType::EchoRequest)), IcmpDecision::Allow);
    }

    #[test]
    fn test_echo_rate_limited() {
        let mut l = IcmpRateLimiter::new(IcmpRateConfig {
            echo_per_sec: 2,
            total_per_sec: 100,
            ..IcmpRateConfig::default()
        });
        l.evaluate(&packet("10.0.0.2", IcmpType::EchoRequest));
        l.evaluate(&packet("10.0.0.2", IcmpType::EchoRequest));
        assert_eq!(
            l.evaluate(&packet("10.0.0.2", IcmpType::EchoRequest)),
            IcmpDecision::RateLimited
        );
    }

    #[test]
    fn test_total_rate_limited() {
        let mut l = IcmpRateLimiter::new(IcmpRateConfig {
            total_per_sec: 2,
            echo_per_sec: 100,
            ..IcmpRateConfig::default()
        });
        l.evaluate(&packet("10.0.0.2", IcmpType::TimeExceeded));
        l.evaluate(&packet("10.0.0.2", IcmpType::TimeExceeded));
        assert_eq!(
            l.evaluate(&packet("10.0.0.2", IcmpType::TimeExceeded)),
            IcmpDecision::RateLimited
        );
    }

    #[test]
    fn test_burst_triggers_block() {
        let mut l = IcmpRateLimiter::new(IcmpRateConfig {
            burst_threshold: 5,
            total_per_sec: 1000,
            echo_per_sec: 1000,
            ..IcmpRateConfig::default()
        });
        // Fill up to threshold.
        for _ in 0..5 { l.evaluate(&packet("10.0.0.2", IcmpType::EchoRequest)); }
        assert_eq!(
            l.evaluate(&packet("10.0.0.2", IcmpType::EchoRequest)),
            IcmpDecision::Blocked
        );
    }

    #[test]
    fn test_manual_block() {
        let mut l = IcmpRateLimiter::new(IcmpRateConfig::default());
        l.block(ip("10.0.0.2"));
        assert_eq!(
            l.evaluate(&packet("10.0.0.2", IcmpType::EchoRequest)),
            IcmpDecision::Blocked
        );
    }

    #[test]
    fn test_unblock() {
        let mut l = IcmpRateLimiter::new(IcmpRateConfig::default());
        l.block(ip("10.0.0.2"));
        l.unblock(&ip("10.0.0.2"));
        assert_eq!(
            l.evaluate(&packet("10.0.0.2", IcmpType::EchoRequest)),
            IcmpDecision::Allow
        );
    }

    #[test]
    fn test_blocked_sources() {
        let mut l = IcmpRateLimiter::new(IcmpRateConfig::default());
        l.block(ip("10.0.0.2"));
        assert_eq!(l.blocked_sources().len(), 1);
    }

    #[test]
    fn test_different_sources_isolated() {
        let mut l = IcmpRateLimiter::new(IcmpRateConfig {
            echo_per_sec: 1,
            ..IcmpRateConfig::default()
        });
        l.evaluate(&packet("10.0.0.2", IcmpType::EchoRequest));
        // Different source not affected.
        assert_eq!(
            l.evaluate(&packet("10.0.0.3", IcmpType::EchoRequest)),
            IcmpDecision::Allow
        );
    }

    #[test]
    fn test_stats_tracking() {
        let mut l = IcmpRateLimiter::new(IcmpRateConfig::default());
        l.evaluate(&packet("10.0.0.2", IcmpType::EchoRequest));
        l.evaluate(&packet("10.0.0.2", IcmpType::EchoRequest));
        let (sent, _) = l.stats_for(&ip("10.0.0.2")).unwrap();
        assert_eq!(sent, 2);
    }
}
