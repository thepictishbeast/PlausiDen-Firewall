//! Stateful connection tracking for the PlausiDen firewall.
//!
//! Maintains a table of active connections and their states, enabling stateful
//! packet inspection. Tracks TCP state transitions, byte/packet counters, and
//! provides analytics such as top talkers and connection rate monitoring.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::rules::Protocol;

/// Errors from connection tracking operations.
#[derive(Debug, Error)]
pub enum ConntrackError {
    /// The connection table has reached its maximum capacity.
    #[error("connection table full: limit is {0}")]
    TableFull(usize),
}

/// Direction of a tracked packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    /// Traffic flowing from the connection initiator toward the responder.
    Outbound,
    /// Traffic flowing from the responder back toward the initiator.
    Inbound,
}

/// TCP connection state for stateful tracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TcpState {
    /// A new connection that has not yet been fully established.
    New,
    /// A fully established, bidirectional connection.
    Established,
    /// A connection related to an existing established connection (e.g., FTP data).
    Related,
    /// Connection is in the TIME_WAIT phase after a close sequence.
    TimeWait,
    /// Connection has been fully closed.
    Closed,
}

/// Unique key identifying a connection in the tracking table.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ConnectionKey {
    /// Source IP address (as string to support both IPv4 and IPv6).
    pub src_ip: String,
    /// Source port number.
    pub src_port: u16,
    /// Destination IP address.
    pub dst_ip: String,
    /// Destination port number.
    pub dst_port: u16,
    /// Network protocol of the connection.
    pub protocol: Protocol,
}

/// Per-connection state and traffic counters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionState {
    /// Current TCP state of the connection.
    pub state: TcpState,
    /// Timestamp when this connection was first observed.
    pub created_at: DateTime<Utc>,
    /// Timestamp of the most recent packet on this connection.
    pub last_activity: DateTime<Utc>,
    /// Total bytes sent from source to destination.
    pub bytes_sent: u64,
    /// Total bytes received from destination to source.
    pub bytes_received: u64,
    /// Total packets sent from source to destination.
    pub packets_sent: u64,
    /// Total packets received from destination to source.
    pub packets_received: u64,
}

/// Stateful connection tracker maintaining a table of active connections.
///
/// Provides connection lifecycle management, traffic accounting, and
/// analytics for the firewall's stateful inspection engine.
pub struct ConnectionTracker {
    /// Active connection table keyed by the 5-tuple.
    connections: HashMap<ConnectionKey, ConnectionState>,
    /// Maximum number of simultaneous connections allowed.
    max_connections: usize,
}

impl ConnectionTracker {
    /// Create a new connection tracker with the specified maximum table size.
    pub fn new(max_connections: usize) -> Self {
        Self {
            connections: HashMap::new(),
            max_connections,
        }
    }

    /// Track a packet, updating an existing connection or creating a new entry.
    ///
    /// For new connections the state starts as [`TcpState::New`]. When an inbound
    /// reply is seen the state transitions to [`TcpState::Established`].
    ///
    /// # Errors
    ///
    /// Returns [`ConntrackError::TableFull`] if the table has reached capacity
    /// and the packet would create a new connection.
    #[allow(clippy::too_many_arguments)]
    pub fn track_packet(
        &mut self,
        src_ip: &str,
        src_port: u16,
        dst_ip: &str,
        dst_port: u16,
        protocol: Protocol,
        direction: Direction,
        bytes: u64,
    ) -> Result<&ConnectionState, ConntrackError> {
        let key = ConnectionKey {
            src_ip: src_ip.to_string(),
            src_port,
            dst_ip: dst_ip.to_string(),
            dst_port,
            protocol,
        };

        let now = Utc::now();

        if !self.connections.contains_key(&key) {
            if self.connections.len() >= self.max_connections {
                return Err(ConntrackError::TableFull(self.max_connections));
            }

            let state = ConnectionState {
                state: TcpState::New,
                created_at: now,
                last_activity: now,
                bytes_sent: 0,
                bytes_received: 0,
                packets_sent: 0,
                packets_received: 0,
            };
            self.connections.insert(key.clone(), state);
        }

        let conn = self.connections.get_mut(&key).expect("just inserted");

        conn.last_activity = now;

        match direction {
            Direction::Outbound => {
                conn.bytes_sent += bytes;
                conn.packets_sent += 1;
            }
            Direction::Inbound => {
                conn.bytes_received += bytes;
                conn.packets_received += 1;
                // Seeing a reply means the connection is established.
                if conn.state == TcpState::New {
                    conn.state = TcpState::Established;
                }
            }
        }

        Ok(&self.connections[&key])
    }

    /// Look up the current state of a connection.
    pub fn get_connection(&self, key: &ConnectionKey) -> Option<&ConnectionState> {
        self.connections.get(key)
    }

    /// Return the number of currently tracked connections.
    pub fn active_connections(&self) -> usize {
        self.connections.len()
    }

    /// Return all connections currently in the specified state.
    pub fn connections_by_state(&self, state: TcpState) -> Vec<(&ConnectionKey, &ConnectionState)> {
        self.connections
            .iter()
            .filter(|(_, cs)| cs.state == state)
            .collect()
    }

    /// Remove connections whose last activity is older than `timeout_secs` seconds.
    ///
    /// Returns the number of connections removed.
    pub fn cleanup_stale(&mut self, timeout_secs: i64) -> usize {
        let cutoff = Utc::now() - chrono::Duration::seconds(timeout_secs);
        let before = self.connections.len();
        self.connections
            .retain(|_, cs| cs.last_activity > cutoff);
        before - self.connections.len()
    }

    /// Return the top `n` connections ranked by total bytes transferred.
    pub fn top_talkers(&self, n: usize) -> Vec<(&ConnectionKey, &ConnectionState)> {
        let mut entries: Vec<_> = self.connections.iter().collect();
        entries.sort_by(|a, b| {
            let total_b = b.1.bytes_sent + b.1.bytes_received;
            let total_a = a.1.bytes_sent + a.1.bytes_received;
            total_b.cmp(&total_a)
        });
        entries.truncate(n);
        entries
    }

    /// Calculate the rate of new connections created within the last `window_secs` seconds.
    ///
    /// Returns the number of connections whose `created_at` falls within the window,
    /// divided by the window duration.
    pub fn connection_rate(&self, window_secs: i64) -> f64 {
        if window_secs <= 0 {
            return 0.0;
        }
        let cutoff = Utc::now() - chrono::Duration::seconds(window_secs);
        let count = self
            .connections
            .values()
            .filter(|cs| cs.created_at > cutoff)
            .count();
        count as f64 / window_secs as f64
    }

    /// Manually set the state of an existing connection.
    ///
    /// Returns `true` if the connection was found and updated, `false` otherwise.
    pub fn set_state(&mut self, key: &ConnectionKey, state: TcpState) -> bool {
        if let Some(conn) = self.connections.get_mut(key) {
            conn.state = state;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_key(src_port: u16, dst_port: u16) -> ConnectionKey {
        ConnectionKey {
            src_ip: "192.168.1.100".to_string(),
            src_port,
            dst_ip: "10.0.0.1".to_string(),
            dst_port,
            protocol: Protocol::Tcp,
        }
    }

    #[test]
    fn test_track_new_connection() {
        let mut tracker = ConnectionTracker::new(100);
        let result = tracker.track_packet(
            "192.168.1.100", 50000,
            "10.0.0.1", 443,
            Protocol::Tcp,
            Direction::Outbound,
            64,
        );
        assert!(result.is_ok());
        let conn = result.unwrap();
        assert_eq!(conn.state, TcpState::New);
        assert_eq!(conn.bytes_sent, 64);
        assert_eq!(conn.packets_sent, 1);
        assert_eq!(conn.bytes_received, 0);
        assert_eq!(conn.packets_received, 0);
        assert_eq!(tracker.active_connections(), 1);
    }

    #[test]
    fn test_inbound_reply_establishes_connection() {
        let mut tracker = ConnectionTracker::new(100);
        tracker.track_packet(
            "192.168.1.100", 50000,
            "10.0.0.1", 443,
            Protocol::Tcp,
            Direction::Outbound,
            64,
        ).unwrap();

        // Inbound reply should transition state to Established.
        let conn = tracker.track_packet(
            "192.168.1.100", 50000,
            "10.0.0.1", 443,
            Protocol::Tcp,
            Direction::Inbound,
            128,
        ).unwrap();

        assert_eq!(conn.state, TcpState::Established);
        assert_eq!(conn.bytes_sent, 64);
        assert_eq!(conn.bytes_received, 128);
        assert_eq!(conn.packets_sent, 1);
        assert_eq!(conn.packets_received, 1);
    }

    #[test]
    fn test_table_full_rejects_new_connections() {
        let mut tracker = ConnectionTracker::new(1);
        tracker.track_packet(
            "192.168.1.100", 50000,
            "10.0.0.1", 443,
            Protocol::Tcp,
            Direction::Outbound,
            64,
        ).unwrap();

        // Second connection should be rejected.
        let result = tracker.track_packet(
            "192.168.1.100", 50001,
            "10.0.0.1", 80,
            Protocol::Tcp,
            Direction::Outbound,
            64,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("table full"));
    }

    #[test]
    fn test_get_connection_lookup() {
        let mut tracker = ConnectionTracker::new(100);
        tracker.track_packet(
            "192.168.1.100", 50000,
            "10.0.0.1", 443,
            Protocol::Tcp,
            Direction::Outbound,
            64,
        ).unwrap();

        let key = make_key(50000, 443);
        let conn = tracker.get_connection(&key);
        assert!(conn.is_some());
        assert_eq!(conn.unwrap().state, TcpState::New);

        // Non-existent connection.
        let missing_key = make_key(60000, 80);
        assert!(tracker.get_connection(&missing_key).is_none());
    }

    #[test]
    fn test_connections_by_state() {
        let mut tracker = ConnectionTracker::new(100);

        // Create two New connections.
        tracker.track_packet(
            "192.168.1.100", 50000, "10.0.0.1", 443,
            Protocol::Tcp, Direction::Outbound, 64,
        ).unwrap();
        tracker.track_packet(
            "192.168.1.100", 50001, "10.0.0.1", 80,
            Protocol::Tcp, Direction::Outbound, 64,
        ).unwrap();

        // Establish one of them.
        tracker.track_packet(
            "192.168.1.100", 50000, "10.0.0.1", 443,
            Protocol::Tcp, Direction::Inbound, 128,
        ).unwrap();

        let new_conns = tracker.connections_by_state(TcpState::New);
        assert_eq!(new_conns.len(), 1);
        assert_eq!(new_conns[0].0.dst_port, 80);

        let established = tracker.connections_by_state(TcpState::Established);
        assert_eq!(established.len(), 1);
        assert_eq!(established[0].0.dst_port, 443);
    }

    #[test]
    fn test_cleanup_stale_connections() {
        let mut tracker = ConnectionTracker::new(100);
        tracker.track_packet(
            "192.168.1.100", 50000, "10.0.0.1", 443,
            Protocol::Tcp, Direction::Outbound, 64,
        ).unwrap();
        tracker.track_packet(
            "192.168.1.100", 50001, "10.0.0.1", 80,
            Protocol::Tcp, Direction::Outbound, 64,
        ).unwrap();

        assert_eq!(tracker.active_connections(), 2);

        // With timeout of 0 seconds, nothing recent enough to survive.
        // But connections were just created, so last_activity > cutoff.
        let removed = tracker.cleanup_stale(3600);
        assert_eq!(removed, 0);
        assert_eq!(tracker.active_connections(), 2);

        // Manually backdate a connection to force stale removal.
        let key = make_key(50000, 443);
        if let Some(conn) = tracker.connections.get_mut(&key) {
            conn.last_activity = Utc::now() - chrono::Duration::seconds(7200);
        }
        let removed = tracker.cleanup_stale(3600);
        assert_eq!(removed, 1);
        assert_eq!(tracker.active_connections(), 1);
    }

    #[test]
    fn test_top_talkers_ordering() {
        let mut tracker = ConnectionTracker::new(100);

        // Connection A: 100 bytes total.
        tracker.track_packet(
            "192.168.1.100", 50000, "10.0.0.1", 443,
            Protocol::Tcp, Direction::Outbound, 50,
        ).unwrap();
        tracker.track_packet(
            "192.168.1.100", 50000, "10.0.0.1", 443,
            Protocol::Tcp, Direction::Inbound, 50,
        ).unwrap();

        // Connection B: 1000 bytes total.
        tracker.track_packet(
            "192.168.1.100", 50001, "10.0.0.1", 80,
            Protocol::Tcp, Direction::Outbound, 500,
        ).unwrap();
        tracker.track_packet(
            "192.168.1.100", 50001, "10.0.0.1", 80,
            Protocol::Tcp, Direction::Inbound, 500,
        ).unwrap();

        // Connection C: 10 bytes total.
        tracker.track_packet(
            "192.168.1.100", 50002, "10.0.0.1", 22,
            Protocol::Tcp, Direction::Outbound, 10,
        ).unwrap();

        let top = tracker.top_talkers(2);
        assert_eq!(top.len(), 2);
        // First should be the 1000-byte connection.
        assert_eq!(top[0].0.dst_port, 80);
        assert_eq!(top[0].1.bytes_sent + top[0].1.bytes_received, 1000);
        // Second should be the 100-byte connection.
        assert_eq!(top[1].0.dst_port, 443);
        assert_eq!(top[1].1.bytes_sent + top[1].1.bytes_received, 100);
    }

    #[test]
    fn test_connection_rate() {
        let mut tracker = ConnectionTracker::new(100);

        // Create several connections (all within the current window).
        for port in 50000..50005 {
            tracker.track_packet(
                "192.168.1.100", port, "10.0.0.1", 443,
                Protocol::Tcp, Direction::Outbound, 64,
            ).unwrap();
        }

        // All 5 connections created within last 60 seconds.
        let rate = tracker.connection_rate(60);
        assert!((rate - 5.0 / 60.0).abs() < 0.01);

        // Zero window should return 0.
        assert_eq!(tracker.connection_rate(0), 0.0);
        assert_eq!(tracker.connection_rate(-1), 0.0);
    }

    #[test]
    fn test_set_state_transitions() {
        let mut tracker = ConnectionTracker::new(100);
        tracker.track_packet(
            "192.168.1.100", 50000, "10.0.0.1", 443,
            Protocol::Tcp, Direction::Outbound, 64,
        ).unwrap();

        let key = make_key(50000, 443);
        assert_eq!(tracker.get_connection(&key).unwrap().state, TcpState::New);

        assert!(tracker.set_state(&key, TcpState::TimeWait));
        assert_eq!(tracker.get_connection(&key).unwrap().state, TcpState::TimeWait);

        assert!(tracker.set_state(&key, TcpState::Closed));
        assert_eq!(tracker.get_connection(&key).unwrap().state, TcpState::Closed);

        // Non-existent connection returns false.
        let missing = make_key(60000, 80);
        assert!(!tracker.set_state(&missing, TcpState::Closed));
    }

    #[test]
    fn test_udp_connection_tracking() {
        let mut tracker = ConnectionTracker::new(100);
        let result = tracker.track_packet(
            "192.168.1.100", 50000,
            "8.8.8.8", 53,
            Protocol::Udp,
            Direction::Outbound,
            40,
        );
        assert!(result.is_ok());
        let conn = result.unwrap();
        assert_eq!(conn.state, TcpState::New);

        let key = ConnectionKey {
            src_ip: "192.168.1.100".to_string(),
            src_port: 50000,
            dst_ip: "8.8.8.8".to_string(),
            dst_port: 53,
            protocol: Protocol::Udp,
        };
        assert!(tracker.get_connection(&key).is_some());
    }
}
