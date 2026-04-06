//! Port knocking — hidden service activation via knock sequence.
//!
//! Allows opening a service port only after the correct sequence of
//! connection attempts to specific ports. Useful for hiding SSH or
//! VPN services from port scanners.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

/// A port knock sequence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnockSequence {
    pub name: String,
    pub ports: Vec<u16>,
    /// Service to unlock when sequence completes.
    pub unlock_port: u16,
    /// How long unlock lasts (seconds).
    pub unlock_duration_secs: i64,
    /// Maximum time between knocks (seconds).
    pub max_interval_secs: i64,
}

/// Per-source knock state.
#[derive(Debug, Clone)]
struct KnockState {
    knocks_received: Vec<u16>,
    last_knock: DateTime<Utc>,
    unlocked_until: Option<DateTime<Utc>>,
}

/// Port knock listener.
pub struct PortKnocker {
    sequences: Vec<KnockSequence>,
    /// State per source IP.
    state: HashMap<IpAddr, KnockState>,
}

impl PortKnocker {
    pub fn new() -> Self {
        Self {
            sequences: Vec::new(),
            state: HashMap::new(),
        }
    }

    /// Register a knock sequence.
    pub fn register_sequence(&mut self, sequence: KnockSequence) {
        self.sequences.push(sequence);
    }

    /// Process a connection attempt to a specific port.
    pub fn record_knock(&mut self, source: IpAddr, port: u16) -> KnockResult {
        let now = Utc::now();
        let state = self.state.entry(source).or_insert(KnockState {
            knocks_received: Vec::new(),
            last_knock: now,
            unlocked_until: None,
        });

        // Check max interval — if too long, reset.
        for seq in &self.sequences {
            if (now - state.last_knock).num_seconds() > seq.max_interval_secs && !state.knocks_received.is_empty() {
                state.knocks_received.clear();
                break;
            }
        }

        state.knocks_received.push(port);
        state.last_knock = now;

        // Check if any sequence is satisfied.
        for seq in &self.sequences {
            // Check if the tail of received knocks matches this sequence.
            if state.knocks_received.len() >= seq.ports.len() {
                let start = state.knocks_received.len() - seq.ports.len();
                if &state.knocks_received[start..] == seq.ports.as_slice() {
                    state.unlocked_until = Some(now + Duration::seconds(seq.unlock_duration_secs));
                    state.knocks_received.clear();
                    return KnockResult::Unlocked {
                        sequence_name: seq.name.clone(),
                        unlock_port: seq.unlock_port,
                        until: state.unlocked_until.unwrap(),
                    };
                }
            }
        }

        KnockResult::Recorded {
            knocks_so_far: state.knocks_received.len(),
        }
    }

    /// Check if a source is currently unlocked.
    pub fn is_unlocked(&self, source: &IpAddr) -> bool {
        self.state.get(source)
            .and_then(|s| s.unlocked_until)
            .map(|until| until > Utc::now())
            .unwrap_or(false)
    }

    /// Clean up expired states.
    pub fn cleanup(&mut self) -> usize {
        let cutoff = Utc::now() - Duration::hours(1);
        let before = self.state.len();
        self.state.retain(|_, s| s.last_knock > cutoff || s.unlocked_until.map(|u| u > Utc::now()).unwrap_or(false));
        before - self.state.len()
    }

    pub fn sequence_count(&self) -> usize { self.sequences.len() }
    pub fn tracked_sources(&self) -> usize { self.state.len() }
}

impl Default for PortKnocker {
    fn default() -> Self { Self::new() }
}

/// Result of a knock attempt.
#[derive(Debug, Clone)]
pub enum KnockResult {
    Recorded { knocks_so_far: usize },
    Unlocked { sequence_name: String, unlock_port: u16, until: DateTime<Utc> },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_seq() -> KnockSequence {
        KnockSequence {
            name: "ssh-unlock".into(),
            ports: vec![1000, 2000, 3000],
            unlock_port: 22,
            unlock_duration_secs: 30,
            max_interval_secs: 10,
        }
    }

    fn ip(s: &str) -> IpAddr { s.parse().unwrap() }

    #[test]
    fn test_register_sequence() {
        let mut k = PortKnocker::new();
        k.register_sequence(test_seq());
        assert_eq!(k.sequence_count(), 1);
    }

    #[test]
    fn test_correct_sequence_unlocks() {
        let mut k = PortKnocker::new();
        k.register_sequence(test_seq());
        let src = ip("10.0.0.1");

        let r1 = k.record_knock(src, 1000);
        assert!(matches!(r1, KnockResult::Recorded { .. }));
        let r2 = k.record_knock(src, 2000);
        assert!(matches!(r2, KnockResult::Recorded { .. }));
        let r3 = k.record_knock(src, 3000);
        assert!(matches!(r3, KnockResult::Unlocked { .. }));
        assert!(k.is_unlocked(&src));
    }

    #[test]
    fn test_wrong_sequence_no_unlock() {
        let mut k = PortKnocker::new();
        k.register_sequence(test_seq());
        let src = ip("10.0.0.1");

        k.record_knock(src, 1000);
        k.record_knock(src, 5000); // Wrong port.
        let r = k.record_knock(src, 3000);
        assert!(matches!(r, KnockResult::Recorded { .. }));
        assert!(!k.is_unlocked(&src));
    }

    #[test]
    fn test_per_source_isolation() {
        let mut k = PortKnocker::new();
        k.register_sequence(test_seq());
        let src1 = ip("10.0.0.1");
        let src2 = ip("10.0.0.2");

        k.record_knock(src1, 1000);
        k.record_knock(src1, 2000);
        k.record_knock(src1, 3000);

        // src2 hasn't knocked.
        assert!(k.is_unlocked(&src1));
        assert!(!k.is_unlocked(&src2));
    }

    #[test]
    fn test_cleanup() {
        let mut k = PortKnocker::new();
        k.register_sequence(test_seq());
        let src = ip("10.0.0.1");
        k.record_knock(src, 1000);
        assert_eq!(k.tracked_sources(), 1);
        // No cleanup since recent — should still be tracked.
        let removed = k.cleanup();
        assert_eq!(removed, 0);
    }

    #[test]
    fn test_multiple_sequences() {
        let mut k = PortKnocker::new();
        k.register_sequence(test_seq());
        let mut alt = test_seq();
        alt.name = "vpn-unlock".into();
        alt.ports = vec![5000, 6000];
        alt.unlock_port = 51820;
        k.register_sequence(alt);

        let src = ip("10.0.0.1");
        k.record_knock(src, 5000);
        let r = k.record_knock(src, 6000);
        match r {
            KnockResult::Unlocked { sequence_name, unlock_port, .. } => {
                assert_eq!(sequence_name, "vpn-unlock");
                assert_eq!(unlock_port, 51820);
            }
            _ => panic!("Expected unlock"),
        }
    }
}
