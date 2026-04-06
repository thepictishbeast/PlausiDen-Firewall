//! Packet logging module for the PlausiDen firewall.
//!
//! Maintains a bounded ring buffer of packet log entries for forensic review,
//! search, and export. Supports filtering by action (blocked-only mode),
//! free-text search across IP addresses, ports, and rule names, and a
//! human-readable pcap-style summary export.

use std::collections::VecDeque;
use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// The firewall's decision for a given packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PacketAction {
    /// The packet was permitted through the firewall.
    Allowed,
    /// The packet was dropped by a firewall rule.
    Blocked,
    /// The packet was neither allowed nor blocked but recorded for auditing.
    Logged,
}

impl fmt::Display for PacketAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allowed => write!(f, "ALLOWED"),
            Self::Blocked => write!(f, "BLOCKED"),
            Self::Logged => write!(f, "LOGGED"),
        }
    }
}

/// A single log entry representing one observed packet and its disposition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketLogEntry {
    /// Timestamp when the packet was observed.
    pub timestamp: DateTime<Utc>,
    /// Source IP address (supports both IPv4 and IPv6 as strings).
    pub src_ip: String,
    /// Destination IP address.
    pub dst_ip: String,
    /// Source port number.
    pub src_port: u16,
    /// Destination port number.
    pub dst_port: u16,
    /// Protocol name (e.g. `"TCP"`, `"UDP"`, `"ICMP"`).
    pub protocol: String,
    /// Size of the packet in bytes.
    pub bytes: u64,
    /// The firewall action taken on this packet.
    pub action: PacketAction,
    /// The name of the rule that matched, if any.
    pub rule_name: Option<String>,
}

/// Summary counters returned by [`PacketLogger::stats`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PacketLogStats {
    /// Number of allowed packets in the log buffer.
    pub allowed: usize,
    /// Number of blocked packets in the log buffer.
    pub blocked: usize,
    /// Number of logged (audit-only) packets in the log buffer.
    pub logged: usize,
}

/// A bounded ring-buffer packet logger with search, filtering, and export.
///
/// When the buffer reaches `max_entries`, the oldest entries are evicted
/// automatically on the next [`log_packet`](PacketLogger::log_packet) call.
/// If `log_blocked_only` is set, only packets with [`PacketAction::Blocked`]
/// are recorded.
pub struct PacketLogger {
    /// Ring buffer of log entries, newest at the back.
    entries: VecDeque<PacketLogEntry>,
    /// Maximum number of entries retained before eviction.
    max_entries: usize,
    /// When `true`, only blocked packets are stored.
    log_blocked_only: bool,
}

impl PacketLogger {
    /// Create a new packet logger with the given capacity and filter mode.
    ///
    /// # Arguments
    ///
    /// * `max_entries` — Upper bound on retained log entries.
    /// * `log_blocked_only` — If `true`, only [`PacketAction::Blocked`] packets
    ///   are recorded; all others are silently discarded.
    pub fn new(max_entries: usize, log_blocked_only: bool) -> Self {
        Self {
            entries: VecDeque::with_capacity(max_entries.min(1024)),
            max_entries,
            log_blocked_only,
        }
    }

    /// Record a packet log entry.
    ///
    /// If `log_blocked_only` is enabled and the entry's action is not
    /// [`PacketAction::Blocked`], the entry is silently dropped. When the
    /// buffer is full the oldest entry is evicted first.
    pub fn log_packet(&mut self, entry: PacketLogEntry) {
        if self.log_blocked_only && entry.action != PacketAction::Blocked {
            return;
        }
        if self.entries.len() >= self.max_entries {
            self.entries.pop_front();
        }
        self.entries.push_back(entry);
    }

    /// Return the most recent `count` entries, ordered oldest-to-newest.
    ///
    /// If `count` exceeds the number of stored entries, all entries are returned.
    pub fn recent(&self, count: usize) -> Vec<&PacketLogEntry> {
        let len = self.entries.len();
        let start = len.saturating_sub(count);
        self.entries.iter().skip(start).collect()
    }

    /// Return only the entries whose action is [`PacketAction::Blocked`].
    pub fn blocked_packets(&self) -> Vec<&PacketLogEntry> {
        self.entries
            .iter()
            .filter(|e| e.action == PacketAction::Blocked)
            .collect()
    }

    /// Search entries by a free-text query.
    ///
    /// Matches against source IP, destination IP, source port, destination port,
    /// protocol, and rule name (case-insensitive). An entry matches if **any**
    /// of those fields contains the query string.
    pub fn search(&self, query: &str) -> Vec<&PacketLogEntry> {
        let q = query.to_lowercase();
        self.entries
            .iter()
            .filter(|e| {
                e.src_ip.to_lowercase().contains(&q)
                    || e.dst_ip.to_lowercase().contains(&q)
                    || e.src_port.to_string().contains(&q)
                    || e.dst_port.to_string().contains(&q)
                    || e.protocol.to_lowercase().contains(&q)
                    || e.rule_name
                        .as_deref()
                        .is_some_and(|r| r.to_lowercase().contains(&q))
            })
            .collect()
    }

    /// Produce a human-readable pcap-style summary of all logged entries.
    ///
    /// Each line follows the format:
    /// ```text
    /// <timestamp> <protocol> <src_ip>:<src_port> -> <dst_ip>:<dst_port> <bytes>B <ACTION> [rule: <name>]
    /// ```
    pub fn export_pcap_summary(&self) -> String {
        let mut lines = Vec::with_capacity(self.entries.len() + 1);
        lines.push(format!(
            "=== PlausiDen Packet Log ({} entries) ===",
            self.entries.len()
        ));

        for entry in &self.entries {
            let rule_part = match &entry.rule_name {
                Some(name) => format!(" [rule: {name}]"),
                None => String::new(),
            };
            lines.push(format!(
                "{} {} {}:{} -> {}:{} {}B {}{}",
                entry.timestamp.format("%Y-%m-%d %H:%M:%S%.3f"),
                entry.protocol,
                entry.src_ip,
                entry.src_port,
                entry.dst_ip,
                entry.dst_port,
                entry.bytes,
                entry.action,
                rule_part,
            ));
        }

        lines.join("\n")
    }

    /// Compute summary counts of allowed, blocked, and logged entries.
    pub fn stats(&self) -> PacketLogStats {
        let mut allowed = 0usize;
        let mut blocked = 0usize;
        let mut logged = 0usize;

        for entry in &self.entries {
            match entry.action {
                PacketAction::Allowed => allowed += 1,
                PacketAction::Blocked => blocked += 1,
                PacketAction::Logged => logged += 1,
            }
        }

        PacketLogStats {
            allowed,
            blocked,
            logged,
        }
    }

    /// Return the number of entries currently stored.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return `true` if the log buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: build a log entry with sensible defaults and the given action.
    fn make_entry(
        src_ip: &str,
        dst_ip: &str,
        src_port: u16,
        dst_port: u16,
        action: PacketAction,
        rule_name: Option<&str>,
    ) -> PacketLogEntry {
        PacketLogEntry {
            timestamp: Utc::now(),
            src_ip: src_ip.to_string(),
            dst_ip: dst_ip.to_string(),
            src_port,
            dst_port,
            protocol: "TCP".to_string(),
            bytes: 128,
            action,
            rule_name: rule_name.map(|s| s.to_string()),
        }
    }

    #[test]
    fn test_log_and_recent() {
        let mut logger = PacketLogger::new(100, false);

        logger.log_packet(make_entry("10.0.0.1", "10.0.0.2", 50000, 443, PacketAction::Allowed, None));
        logger.log_packet(make_entry("10.0.0.3", "10.0.0.4", 50001, 80, PacketAction::Blocked, Some("block-http")));
        logger.log_packet(make_entry("10.0.0.5", "10.0.0.6", 50002, 22, PacketAction::Logged, None));

        assert_eq!(logger.len(), 3);

        // recent(2) should return the last two entries.
        let last_two = logger.recent(2);
        assert_eq!(last_two.len(), 2);
        assert_eq!(last_two[0].src_ip, "10.0.0.3");
        assert_eq!(last_two[1].src_ip, "10.0.0.5");

        // recent(100) should return all entries when fewer exist.
        let all = logger.recent(100);
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn test_ring_buffer_eviction() {
        let mut logger = PacketLogger::new(2, false);

        logger.log_packet(make_entry("10.0.0.1", "10.0.0.2", 50000, 443, PacketAction::Allowed, None));
        logger.log_packet(make_entry("10.0.0.3", "10.0.0.4", 50001, 80, PacketAction::Blocked, None));
        // This should evict the first entry.
        logger.log_packet(make_entry("10.0.0.5", "10.0.0.6", 50002, 22, PacketAction::Logged, None));

        assert_eq!(logger.len(), 2);
        let all = logger.recent(10);
        assert_eq!(all[0].src_ip, "10.0.0.3");
        assert_eq!(all[1].src_ip, "10.0.0.5");
    }

    #[test]
    fn test_blocked_only_mode() {
        let mut logger = PacketLogger::new(100, true);

        logger.log_packet(make_entry("10.0.0.1", "10.0.0.2", 50000, 443, PacketAction::Allowed, None));
        logger.log_packet(make_entry("10.0.0.3", "10.0.0.4", 50001, 80, PacketAction::Blocked, Some("deny-all")));
        logger.log_packet(make_entry("10.0.0.5", "10.0.0.6", 50002, 22, PacketAction::Logged, None));

        // Only the blocked packet should be retained.
        assert_eq!(logger.len(), 1);
        assert_eq!(logger.recent(10)[0].action, PacketAction::Blocked);
    }

    #[test]
    fn test_blocked_packets_filter() {
        let mut logger = PacketLogger::new(100, false);

        logger.log_packet(make_entry("10.0.0.1", "10.0.0.2", 50000, 443, PacketAction::Allowed, None));
        logger.log_packet(make_entry("10.0.0.3", "10.0.0.4", 50001, 80, PacketAction::Blocked, Some("rule-a")));
        logger.log_packet(make_entry("10.0.0.5", "10.0.0.6", 50002, 22, PacketAction::Allowed, None));
        logger.log_packet(make_entry("10.0.0.7", "10.0.0.8", 50003, 53, PacketAction::Blocked, Some("rule-b")));

        let blocked = logger.blocked_packets();
        assert_eq!(blocked.len(), 2);
        assert!(blocked.iter().all(|e| e.action == PacketAction::Blocked));
    }

    #[test]
    fn test_search_by_ip_port_and_rule() {
        let mut logger = PacketLogger::new(100, false);

        logger.log_packet(make_entry("192.168.1.100", "10.0.0.1", 50000, 443, PacketAction::Allowed, Some("allow-https")));
        logger.log_packet(make_entry("172.16.0.5", "10.0.0.1", 50001, 80, PacketAction::Blocked, Some("block-http")));
        logger.log_packet(make_entry("192.168.1.200", "10.0.0.2", 50002, 22, PacketAction::Logged, Some("log-ssh")));

        // Search by partial IP.
        let results = logger.search("192.168");
        assert_eq!(results.len(), 2);

        // Search by port number (as string).
        let results = logger.search("443");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].dst_port, 443);

        // Search by rule name.
        let results = logger.search("block-http");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].src_ip, "172.16.0.5");

        // Case-insensitive search.
        let results = logger.search("BLOCK-HTTP");
        assert_eq!(results.len(), 1);

        // No match.
        let results = logger.search("nonexistent");
        assert!(results.is_empty());
    }

    #[test]
    fn test_stats_counts() {
        let mut logger = PacketLogger::new(100, false);

        logger.log_packet(make_entry("10.0.0.1", "10.0.0.2", 50000, 443, PacketAction::Allowed, None));
        logger.log_packet(make_entry("10.0.0.3", "10.0.0.4", 50001, 80, PacketAction::Allowed, None));
        logger.log_packet(make_entry("10.0.0.5", "10.0.0.6", 50002, 22, PacketAction::Blocked, Some("deny")));
        logger.log_packet(make_entry("10.0.0.7", "10.0.0.8", 50003, 53, PacketAction::Logged, None));
        logger.log_packet(make_entry("10.0.0.9", "10.0.0.10", 50004, 8080, PacketAction::Blocked, Some("deny")));

        let s = logger.stats();
        assert_eq!(s, PacketLogStats { allowed: 2, blocked: 2, logged: 1 });
    }

    #[test]
    fn test_export_pcap_summary_format() {
        let mut logger = PacketLogger::new(100, false);

        logger.log_packet(make_entry("10.0.0.1", "10.0.0.2", 50000, 443, PacketAction::Allowed, None));
        logger.log_packet(make_entry("10.0.0.3", "10.0.0.4", 50001, 80, PacketAction::Blocked, Some("deny-http")));

        let summary = logger.export_pcap_summary();

        assert!(summary.contains("PlausiDen Packet Log (2 entries)"));
        assert!(summary.contains("10.0.0.1:50000 -> 10.0.0.2:443"));
        assert!(summary.contains("ALLOWED"));
        assert!(summary.contains("10.0.0.3:50001 -> 10.0.0.4:80"));
        assert!(summary.contains("BLOCKED"));
        assert!(summary.contains("[rule: deny-http]"));
        // Entries without a rule name should not have the [rule: ...] suffix.
        let lines: Vec<&str> = summary.lines().collect();
        assert!(!lines[1].contains("[rule:"));
    }

    #[test]
    fn test_empty_logger() {
        let logger = PacketLogger::new(100, false);

        assert!(logger.is_empty());
        assert_eq!(logger.len(), 0);
        assert!(logger.recent(10).is_empty());
        assert!(logger.blocked_packets().is_empty());
        assert!(logger.search("anything").is_empty());
        assert_eq!(logger.stats(), PacketLogStats { allowed: 0, blocked: 0, logged: 0 });

        let summary = logger.export_pcap_summary();
        assert!(summary.contains("0 entries"));
    }
}
