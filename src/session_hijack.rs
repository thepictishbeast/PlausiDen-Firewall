//! Session hijack detector — detect suspicious changes in TCP session state.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

/// A tracked TCP session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpSession {
    pub session_id: String,
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    pub established_at: DateTime<Utc>,
    pub last_activity: DateTime<Utc>,
    pub state: SessionState,
    pub seq_number: u32,
    pub ack_number: u32,
    pub fingerprint_hash: String,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionState {
    SynSent,
    Established,
    FinWait,
    Closed,
}

/// A hijack alert.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HijackAlert {
    pub session_id: String,
    pub alert_type: HijackType,
    pub confidence: f64,
    pub detected_at: DateTime<Utc>,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HijackType {
    /// TLS/SSH fingerprint changed mid-session.
    FingerprintChange,
    /// Source IP changed (NAT aside).
    SourceIpChange,
    /// Sequence number jump beyond expected.
    SequenceAnomaly,
    /// Mid-session MAC change (tied to ARP monitor).
    MacChange,
    /// Dramatic traffic pattern shift.
    TrafficPatternShift,
}

/// Session hijack detector.
pub struct HijackDetector {
    sessions: HashMap<String, TcpSession>,
    alerts: Vec<HijackAlert>,
    /// Maximum sequence number jump allowed without alert (bytes).
    max_seq_jump: u32,
}

impl HijackDetector {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            alerts: Vec::new(),
            max_seq_jump: 65_536,
        }
    }

    /// Start tracking a session.
    pub fn start_session(&mut self, session: TcpSession) {
        self.sessions.insert(session.session_id.clone(), session);
    }

    /// Observe a session update.
    pub fn observe_update(
        &mut self,
        session_id: &str,
        new_src_ip: IpAddr,
        new_seq: u32,
        new_fingerprint: &str,
        bytes_in_delta: u64,
        bytes_out_delta: u64,
    ) -> Vec<HijackAlert> {
        let mut alerts = Vec::new();
        let session = match self.sessions.get_mut(session_id) {
            Some(s) => s,
            None => return alerts,
        };

        let now = Utc::now();

        // Source IP change.
        if session.src_ip != new_src_ip {
            alerts.push(HijackAlert {
                session_id: session_id.into(),
                alert_type: HijackType::SourceIpChange,
                confidence: 0.85,
                detected_at: now,
                detail: format!("src {} -> {}", session.src_ip, new_src_ip),
            });
        }

        // Fingerprint change.
        if !session.fingerprint_hash.is_empty() && session.fingerprint_hash != new_fingerprint {
            alerts.push(HijackAlert {
                session_id: session_id.into(),
                alert_type: HijackType::FingerprintChange,
                confidence: 0.9,
                detected_at: now,
                detail: format!("TLS/SSH fingerprint changed"),
            });
        }

        // Sequence anomaly.
        let expected = session.seq_number;
        if new_seq > expected.saturating_add(self.max_seq_jump) {
            alerts.push(HijackAlert {
                session_id: session_id.into(),
                alert_type: HijackType::SequenceAnomaly,
                confidence: 0.7,
                detected_at: now,
                detail: format!("seq {} -> {} (jump {})", expected, new_seq, new_seq - expected),
            });
        }

        // Traffic pattern shift.
        let before_total = session.bytes_in + session.bytes_out;
        let delta_total = bytes_in_delta + bytes_out_delta;
        if before_total >= 1_000 && delta_total > before_total * 5 {
            alerts.push(HijackAlert {
                session_id: session_id.into(),
                alert_type: HijackType::TrafficPatternShift,
                confidence: 0.6,
                detected_at: now,
                detail: format!("burst of {} bytes after {}", delta_total, before_total),
            });
        }

        session.src_ip = new_src_ip;
        session.seq_number = new_seq;
        session.fingerprint_hash = new_fingerprint.into();
        session.bytes_in += bytes_in_delta;
        session.bytes_out += bytes_out_delta;
        session.last_activity = now;

        self.alerts.extend(alerts.clone());
        alerts
    }

    /// Close a session.
    pub fn close_session(&mut self, session_id: &str) -> bool {
        if let Some(s) = self.sessions.get_mut(session_id) {
            s.state = SessionState::Closed;
            return true;
        }
        false
    }

    /// All alerts for a session.
    pub fn alerts_for_session(&self, session_id: &str) -> Vec<&HijackAlert> {
        self.alerts.iter().filter(|a| a.session_id == session_id).collect()
    }

    /// Alerts by type.
    pub fn alerts_by_type(&self, kind: &HijackType) -> Vec<&HijackAlert> {
        self.alerts.iter().filter(|a| &a.alert_type == kind).collect()
    }

    pub fn session_count(&self) -> usize { self.sessions.len() }
    pub fn alert_count(&self) -> usize { self.alerts.len() }
}

impl Default for HijackDetector {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr { s.parse().unwrap() }

    fn session(id: &str, src: &str, fingerprint: &str) -> TcpSession {
        TcpSession {
            session_id: id.into(),
            src_ip: ip(src),
            src_port: 12345,
            dst_ip: ip("10.0.0.1"),
            dst_port: 443,
            established_at: Utc::now(),
            last_activity: Utc::now(),
            state: SessionState::Established,
            seq_number: 1000,
            ack_number: 2000,
            fingerprint_hash: fingerprint.into(),
            bytes_in: 0,
            bytes_out: 0,
        }
    }

    #[test]
    fn test_start_session() {
        let mut d = HijackDetector::new();
        d.start_session(session("s1", "192.168.1.10", "tls-abc"));
        assert_eq!(d.session_count(), 1);
    }

    #[test]
    fn test_source_ip_change_alert() {
        let mut d = HijackDetector::new();
        d.start_session(session("s1", "192.168.1.10", "tls-abc"));
        let alerts = d.observe_update("s1", ip("10.99.99.99"), 1100, "tls-abc", 100, 100);
        assert!(alerts.iter().any(|a| a.alert_type == HijackType::SourceIpChange));
    }

    #[test]
    fn test_fingerprint_change() {
        let mut d = HijackDetector::new();
        d.start_session(session("s1", "192.168.1.10", "tls-abc"));
        let alerts = d.observe_update("s1", ip("192.168.1.10"), 1100, "tls-xyz", 100, 100);
        assert!(alerts.iter().any(|a| a.alert_type == HijackType::FingerprintChange));
    }

    #[test]
    fn test_sequence_anomaly() {
        let mut d = HijackDetector::new();
        d.start_session(session("s1", "192.168.1.10", "tls-abc"));
        let alerts = d.observe_update("s1", ip("192.168.1.10"), 2_000_000, "tls-abc", 100, 100);
        assert!(alerts.iter().any(|a| a.alert_type == HijackType::SequenceAnomaly));
    }

    #[test]
    fn test_no_alerts_on_clean_update() {
        let mut d = HijackDetector::new();
        d.start_session(session("s1", "192.168.1.10", "tls-abc"));
        let alerts = d.observe_update("s1", ip("192.168.1.10"), 1500, "tls-abc", 100, 100);
        assert!(alerts.is_empty());
    }

    #[test]
    fn test_traffic_pattern_shift() {
        let mut d = HijackDetector::new();
        d.start_session(session("s1", "192.168.1.10", "tls-abc"));
        // Build baseline traffic.
        d.observe_update("s1", ip("192.168.1.10"), 1500, "tls-abc", 5000, 5000);
        // Now dramatic burst.
        let alerts = d.observe_update("s1", ip("192.168.1.10"), 2000, "tls-abc", 60_000, 60_000);
        assert!(alerts.iter().any(|a| a.alert_type == HijackType::TrafficPatternShift));
    }

    #[test]
    fn test_close_session() {
        let mut d = HijackDetector::new();
        d.start_session(session("s1", "192.168.1.10", "tls-abc"));
        assert!(d.close_session("s1"));
    }

    #[test]
    fn test_unknown_session_no_alert() {
        let mut d = HijackDetector::new();
        let alerts = d.observe_update("unknown", ip("10.0.0.1"), 1000, "f", 0, 0);
        assert!(alerts.is_empty());
    }
}
