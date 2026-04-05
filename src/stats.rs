//! Aggregated traffic statistics for the PlausiDen firewall dashboard.
//!
//! Collects per-packet telemetry and exposes summary metrics: packet rates,
//! block percentages, top destination ports, and most-blocked source IPs.
//! Supports both human-readable text and machine-readable JSON rendering.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::Serialize;

/// Aggregated traffic statistics collected by the firewall.
///
/// Call [`TrafficStats::record_packet`] for every packet decision. The struct
/// maintains running counters and per-key breakdowns that can be queried for
/// dashboard rendering or exported as JSON.
#[derive(Debug, Clone, Serialize)]
pub struct TrafficStats {
    /// Total number of packets observed (allowed + blocked).
    total_packets: u64,
    /// Total bytes across all observed packets.
    total_bytes: u64,
    /// Number of packets that were blocked by a firewall rule.
    blocked_packets: u64,
    /// Number of packets that were allowed through.
    allowed_packets: u64,
    /// Packet counts broken down by protocol name (e.g. "TCP", "UDP").
    by_protocol: HashMap<String, u64>,
    /// Packet counts broken down by destination port number.
    by_destination_port: HashMap<u16, u64>,
    /// Per-source-IP count of blocked packets, for top-blocked analysis.
    blocked_sources: HashMap<String, u64>,
    /// Timestamp when this statistics window was started or last reset.
    start_time: DateTime<Utc>,
}

/// A single entry in a top-N ranking: an identifier paired with its count.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RankedEntry<K: Serialize> {
    /// The key being ranked (port number, IP address, etc.).
    pub key: K,
    /// The associated packet count.
    pub count: u64,
}

impl Default for TrafficStats {
    fn default() -> Self {
        Self::new()
    }
}

impl TrafficStats {
    /// Create a new, empty statistics collector starting from the current time.
    pub fn new() -> Self {
        Self {
            total_packets: 0,
            total_bytes: 0,
            blocked_packets: 0,
            allowed_packets: 0,
            by_protocol: HashMap::new(),
            by_destination_port: HashMap::new(),
            blocked_sources: HashMap::new(),
            start_time: Utc::now(),
        }
    }

    /// Record a single packet decision.
    ///
    /// # Arguments
    ///
    /// * `allowed` — `true` if the packet was permitted, `false` if blocked.
    /// * `protocol` — Protocol name (e.g. `"TCP"`, `"UDP"`, `"ICMP"`).
    /// * `dest_port` — Destination port number.
    /// * `src_ip` — Source IP address as a string.
    /// * `bytes` — Size of the packet in bytes.
    pub fn record_packet(
        &mut self,
        allowed: bool,
        protocol: &str,
        dest_port: u16,
        src_ip: &str,
        bytes: u64,
    ) {
        self.total_packets += 1;
        self.total_bytes += bytes;

        if allowed {
            self.allowed_packets += 1;
        } else {
            self.blocked_packets += 1;
            *self.blocked_sources.entry(src_ip.to_string()).or_insert(0) += 1;
        }

        *self
            .by_protocol
            .entry(protocol.to_string())
            .or_insert(0) += 1;

        *self.by_destination_port.entry(dest_port).or_insert(0) += 1;
    }

    /// Calculate the average packet rate (packets per second) since `start_time`.
    ///
    /// Returns `0.0` if no time has elapsed.
    pub fn packets_per_second(&self) -> f64 {
        let elapsed = Utc::now()
            .signed_duration_since(self.start_time)
            .num_milliseconds();
        if elapsed <= 0 {
            return 0.0;
        }
        (self.total_packets as f64) / (elapsed as f64 / 1000.0)
    }

    /// Return the percentage of packets that were blocked (0.0–100.0).
    ///
    /// Returns `0.0` if no packets have been recorded.
    pub fn block_rate(&self) -> f64 {
        if self.total_packets == 0 {
            return 0.0;
        }
        (self.blocked_packets as f64 / self.total_packets as f64) * 100.0
    }

    /// Return the `n` most active destination ports, ranked by packet count.
    pub fn top_ports(&self, n: usize) -> Vec<RankedEntry<u16>> {
        let mut entries: Vec<_> = self
            .by_destination_port
            .iter()
            .map(|(&port, &count)| RankedEntry { key: port, count })
            .collect();
        entries.sort_by(|a, b| b.count.cmp(&a.count));
        entries.truncate(n);
        entries
    }

    /// Return the `n` most-blocked source IPs, ranked by blocked packet count.
    pub fn top_blocked(&self, n: usize) -> Vec<RankedEntry<String>> {
        let mut entries: Vec<_> = self
            .blocked_sources
            .iter()
            .map(|(ip, &count)| RankedEntry {
                key: ip.clone(),
                count,
            })
            .collect();
        entries.sort_by(|a, b| b.count.cmp(&a.count));
        entries.truncate(n);
        entries
    }

    /// Render the statistics as a human-readable text block for dashboard display.
    pub fn render_text(&self) -> String {
        let mut lines = Vec::new();

        lines.push("=== PlausiDen Firewall Traffic Statistics ===".to_string());
        lines.push(format!(
            "Window start: {}",
            self.start_time.format("%Y-%m-%d %H:%M:%S UTC")
        ));
        lines.push(format!("Total packets: {}", self.total_packets));
        lines.push(format!("Total bytes:   {}", self.total_bytes));
        lines.push(format!(
            "Allowed:       {} | Blocked: {}",
            self.allowed_packets, self.blocked_packets
        ));
        lines.push(format!("Block rate:    {:.1}%", self.block_rate()));

        if !self.by_protocol.is_empty() {
            lines.push(String::new());
            lines.push("By protocol:".to_string());
            let mut protos: Vec<_> = self.by_protocol.iter().collect();
            protos.sort_by(|a, b| b.1.cmp(a.1));
            for (proto, count) in protos {
                lines.push(format!("  {proto}: {count}"));
            }
        }

        let top_ports = self.top_ports(5);
        if !top_ports.is_empty() {
            lines.push(String::new());
            lines.push("Top destination ports:".to_string());
            for entry in &top_ports {
                lines.push(format!("  port {}: {} packets", entry.key, entry.count));
            }
        }

        let top_blocked = self.top_blocked(5);
        if !top_blocked.is_empty() {
            lines.push(String::new());
            lines.push("Top blocked sources:".to_string());
            for entry in &top_blocked {
                lines.push(format!("  {}: {} blocked", entry.key, entry.count));
            }
        }

        lines.join("\n")
    }

    /// Render the statistics as a JSON string.
    ///
    /// Uses the `Serialize` derive on [`TrafficStats`] to produce a complete
    /// JSON representation of all fields.
    ///
    /// # Errors
    ///
    /// Returns a `serde_json::Error` if serialization fails (should not happen
    /// with the types used here).
    pub fn render_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Reset all counters and restart the statistics window from the current time.
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    /// Return the total number of packets recorded.
    pub fn total_packets(&self) -> u64 {
        self.total_packets
    }

    /// Return the total bytes recorded.
    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    /// Return the number of blocked packets.
    pub fn blocked_packets(&self) -> u64 {
        self.blocked_packets
    }

    /// Return the number of allowed packets.
    pub fn allowed_packets(&self) -> u64 {
        self.allowed_packets
    }

    /// Return the window start time.
    pub fn start_time(&self) -> DateTime<Utc> {
        self.start_time
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_and_counters() {
        let mut stats = TrafficStats::new();

        stats.record_packet(true, "TCP", 443, "10.0.0.1", 1500);
        stats.record_packet(true, "TCP", 443, "10.0.0.2", 800);
        stats.record_packet(false, "UDP", 53, "192.168.1.99", 64);

        assert_eq!(stats.total_packets(), 3);
        assert_eq!(stats.total_bytes(), 1500 + 800 + 64);
        assert_eq!(stats.allowed_packets(), 2);
        assert_eq!(stats.blocked_packets(), 1);
    }

    #[test]
    fn test_block_rate() {
        let mut stats = TrafficStats::new();
        // No packets yet — should be 0%.
        assert!((stats.block_rate() - 0.0).abs() < f64::EPSILON);

        stats.record_packet(true, "TCP", 80, "10.0.0.1", 100);
        stats.record_packet(false, "TCP", 80, "10.0.0.2", 100);
        stats.record_packet(false, "TCP", 80, "10.0.0.3", 100);

        // 2 out of 3 blocked = 66.67%.
        let rate = stats.block_rate();
        assert!((rate - 200.0 / 3.0).abs() < 0.01);
    }

    #[test]
    fn test_top_ports() {
        let mut stats = TrafficStats::new();
        // 3 packets on port 443, 1 on port 80, 2 on port 22.
        for _ in 0..3 {
            stats.record_packet(true, "TCP", 443, "10.0.0.1", 100);
        }
        stats.record_packet(true, "TCP", 80, "10.0.0.1", 100);
        stats.record_packet(true, "TCP", 22, "10.0.0.1", 100);
        stats.record_packet(true, "TCP", 22, "10.0.0.1", 100);

        let top = stats.top_ports(2);
        assert_eq!(top.len(), 2);
        assert_eq!(top[0].key, 443);
        assert_eq!(top[0].count, 3);
        assert_eq!(top[1].key, 22);
        assert_eq!(top[1].count, 2);
    }

    #[test]
    fn test_top_blocked_sources() {
        let mut stats = TrafficStats::new();
        // Block 5 packets from attacker-A, 2 from attacker-B, 1 from attacker-C.
        for _ in 0..5 {
            stats.record_packet(false, "TCP", 443, "192.168.1.50", 64);
        }
        for _ in 0..2 {
            stats.record_packet(false, "TCP", 80, "192.168.1.51", 64);
        }
        stats.record_packet(false, "UDP", 53, "192.168.1.52", 64);

        // Allowed packets should NOT appear in blocked sources.
        stats.record_packet(true, "TCP", 443, "10.0.0.1", 1500);

        let top = stats.top_blocked(2);
        assert_eq!(top.len(), 2);
        assert_eq!(top[0].key, "192.168.1.50");
        assert_eq!(top[0].count, 5);
        assert_eq!(top[1].key, "192.168.1.51");
        assert_eq!(top[1].count, 2);
    }

    #[test]
    fn test_reset_clears_all() {
        let mut stats = TrafficStats::new();
        stats.record_packet(true, "TCP", 443, "10.0.0.1", 1500);
        stats.record_packet(false, "UDP", 53, "192.168.1.99", 64);
        assert_eq!(stats.total_packets(), 2);

        stats.reset();

        assert_eq!(stats.total_packets(), 0);
        assert_eq!(stats.total_bytes(), 0);
        assert_eq!(stats.allowed_packets(), 0);
        assert_eq!(stats.blocked_packets(), 0);
        assert!(stats.top_ports(10).is_empty());
        assert!(stats.top_blocked(10).is_empty());
    }

    #[test]
    fn test_render_text_contains_key_sections() {
        let mut stats = TrafficStats::new();
        stats.record_packet(true, "TCP", 443, "10.0.0.1", 1500);
        stats.record_packet(false, "UDP", 53, "192.168.1.99", 64);

        let text = stats.render_text();
        assert!(text.contains("Traffic Statistics"));
        assert!(text.contains("Total packets: 2"));
        assert!(text.contains("Allowed:       1"));
        assert!(text.contains("Blocked: 1"));
        assert!(text.contains("Block rate:    50.0%"));
        assert!(text.contains("TCP"));
        assert!(text.contains("UDP"));
        assert!(text.contains("port 443"));
        assert!(text.contains("192.168.1.99"));
    }

    #[test]
    fn test_render_json_roundtrip() {
        let mut stats = TrafficStats::new();
        stats.record_packet(true, "TCP", 443, "10.0.0.1", 1500);
        stats.record_packet(false, "UDP", 53, "192.168.1.99", 64);

        let json = stats.render_json().expect("serialization should succeed");
        let parsed: serde_json::Value =
            serde_json::from_str(&json).expect("should be valid JSON");

        assert_eq!(parsed["total_packets"], 2);
        assert_eq!(parsed["total_bytes"], 1564);
        assert_eq!(parsed["blocked_packets"], 1);
        assert_eq!(parsed["allowed_packets"], 1);
    }

    #[test]
    fn test_packets_per_second_zero_on_empty() {
        let stats = TrafficStats::new();
        // Freshly created with no packets — should not panic, returns 0 or small value.
        let pps = stats.packets_per_second();
        assert!(pps >= 0.0);
        assert!(pps.is_finite());
    }
}
