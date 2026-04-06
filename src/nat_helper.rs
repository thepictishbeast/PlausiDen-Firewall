//! NAT application-layer helpers (ALGs).
//!
//! Some protocols negotiate secondary channels on dynamic ports — FTP active
//! mode opens a separate data connection, SIP/RTSP negotiate RTP streams, and
//! so on. A stateless firewall without application awareness would either
//! block these channels (breaking the protocol) or permit them too broadly
//! (weakening the policy).
//!
//! This module tracks "expected" secondary flows derived from inspecting the
//! primary control channel. When a matching flow arrives, the firewall can
//! consult [`NatHelper::is_expected`] to let it through with a tightly
//! scoped lifetime. Only the flows that were actually advertised on a
//! tracked control channel are permitted.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Supported application-layer helper protocols.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HelperKind {
    FtpActive,
    FtpPassive,
    Sip,
    Rtsp,
    Irc,
    Tftp,
}

/// A single expected secondary flow.
#[derive(Debug, Clone)]
pub struct ExpectedFlow {
    pub kind: HelperKind,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    pub created_at: Instant,
    pub expires_at: Instant,
    pub used: bool,
}

impl ExpectedFlow {
    pub fn matches(&self, src: &IpAddr, dst: &IpAddr, dst_port: u16) -> bool {
        &self.src_ip == src && &self.dst_ip == dst && self.dst_port == dst_port
    }

    pub fn is_expired(&self, now: Instant) -> bool {
        now >= self.expires_at
    }
}

/// Statistics snapshot.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HelperStats {
    pub expected_open: usize,
    pub expected_created: u64,
    pub expected_matched: u64,
    pub expected_expired: u64,
    pub parse_errors: u64,
}

/// NAT application-layer helper tracker.
pub struct NatHelper {
    expected: HashMap<u64, ExpectedFlow>,
    next_id: u64,
    default_ttl: Duration,
    stats: HelperStats,
}

impl NatHelper {
    pub fn new() -> Self {
        Self::with_ttl(Duration::from_secs(60))
    }

    pub fn with_ttl(default_ttl: Duration) -> Self {
        Self {
            expected: HashMap::new(),
            next_id: 1,
            default_ttl,
            stats: HelperStats::default(),
        }
    }

    fn register(
        &mut self,
        kind: HelperKind,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        dst_port: u16,
    ) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        let now = Instant::now();
        self.expected.insert(
            id,
            ExpectedFlow {
                kind,
                src_ip,
                dst_ip,
                dst_port,
                created_at: now,
                expires_at: now + self.default_ttl,
                used: false,
            },
        );
        self.stats.expected_created += 1;
        self.stats.expected_open = self.expected.len();
        id
    }

    /// Parse a FTP `PORT` command and register the expected data flow.
    ///
    /// Format: `PORT h1,h2,h3,h4,p1,p2` where the IP is `h1.h2.h3.h4` and
    /// the port is `p1*256 + p2`. The data connection in active mode comes
    /// from the server (source = server IP) to the negotiated address.
    pub fn on_ftp_port(&mut self, server_ip: IpAddr, command: &str) -> Option<u64> {
        let trimmed = command.trim().strip_prefix("PORT ").or_else(|| {
            command
                .trim()
                .strip_prefix("port ")
                .or_else(|| command.trim().strip_prefix("Port "))
        })?;
        let parts: Vec<&str> = trimmed.split(',').collect();
        if parts.len() != 6 {
            self.stats.parse_errors += 1;
            return None;
        }
        let nums: Result<Vec<u16>, _> = parts.iter().map(|p| p.trim().parse::<u16>()).collect();
        let nums = match nums {
            Ok(n) if n.iter().all(|&v| v <= 255) => n,
            _ => {
                self.stats.parse_errors += 1;
                return None;
            }
        };
        let ip = IpAddr::from([nums[0] as u8, nums[1] as u8, nums[2] as u8, nums[3] as u8]);
        let port = (nums[4] << 8) | nums[5];
        Some(self.register(HelperKind::FtpActive, server_ip, ip, port))
    }

    /// Parse a FTP `227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)` response.
    pub fn on_ftp_pasv(&mut self, client_ip: IpAddr, response: &str) -> Option<u64> {
        match Self::parse_pasv(response) {
            Some((ip, port)) => Some(self.register(HelperKind::FtpPassive, client_ip, ip, port)),
            None => {
                self.stats.parse_errors += 1;
                None
            }
        }
    }

    fn parse_pasv(response: &str) -> Option<(IpAddr, u16)> {
        let start = response.find('(')?;
        let end = response.find(')')?;
        if end <= start + 1 {
            return None;
        }
        let inner = &response[start + 1..end];
        let parts: Vec<&str> = inner.split(',').collect();
        if parts.len() != 6 {
            return None;
        }
        let nums: Result<Vec<u16>, _> = parts.iter().map(|p| p.trim().parse::<u16>()).collect();
        let nums = nums.ok()?;
        if !nums.iter().all(|&v| v <= 255) {
            return None;
        }
        let ip = IpAddr::from([nums[0] as u8, nums[1] as u8, nums[2] as u8, nums[3] as u8]);
        let port = (nums[4] << 8) | nums[5];
        Some((ip, port))
    }

    /// Register an expected RTP/RTCP flow from a SIP SDP offer.
    pub fn on_sip_sdp(
        &mut self,
        offering_party: IpAddr,
        media_ip: IpAddr,
        media_port: u16,
    ) -> u64 {
        self.register(HelperKind::Sip, offering_party, media_ip, media_port)
    }

    /// Register an expected RTSP interleaved channel or UDP transport.
    pub fn on_rtsp_setup(
        &mut self,
        client_ip: IpAddr,
        server_ip: IpAddr,
        server_port: u16,
    ) -> u64 {
        self.register(HelperKind::Rtsp, client_ip, server_ip, server_port)
    }

    /// Is a new flow expected by any open helper entry?
    pub fn is_expected(&mut self, src: &IpAddr, dst: &IpAddr, dst_port: u16) -> bool {
        let mut matched_id: Option<u64> = None;
        for (&id, flow) in self.expected.iter() {
            if flow.matches(src, dst, dst_port) && !flow.used {
                matched_id = Some(id);
                break;
            }
        }
        if let Some(id) = matched_id
            && let Some(flow) = self.expected.get_mut(&id)
        {
            flow.used = true;
            self.stats.expected_matched += 1;
            return true;
        }
        false
    }

    /// Drop expired entries; returns the number removed.
    pub fn reap(&mut self) -> usize {
        let now = Instant::now();
        let before = self.expected.len();
        self.expected.retain(|_, f| !f.is_expired(now));
        let removed = before - self.expected.len();
        self.stats.expected_expired += removed as u64;
        self.stats.expected_open = self.expected.len();
        removed
    }

    pub fn stats(&self) -> HelperStats {
        let mut stats = self.stats.clone();
        stats.expected_open = self.expected.len();
        stats
    }

    pub fn expected_count(&self) -> usize {
        self.expected.len()
    }

    pub fn clear(&mut self) {
        self.expected.clear();
        self.stats.expected_open = 0;
    }
}

impl Default for NatHelper {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn test_ftp_port_registers_expected() {
        let mut h = NatHelper::new();
        let id = h
            .on_ftp_port(ip(10, 0, 0, 1), "PORT 192,168,1,100,20,21")
            .expect("valid PORT");
        assert!(id > 0);
        assert_eq!(h.expected_count(), 1);
        // Port is 20*256 + 21 = 5141
        assert!(h.is_expected(&ip(10, 0, 0, 1), &ip(192, 168, 1, 100), 5141));
    }

    #[test]
    fn test_ftp_pasv_registers_expected() {
        let mut h = NatHelper::new();
        let id = h
            .on_ftp_pasv(
                ip(10, 0, 0, 2),
                "227 Entering Passive Mode (192,168,1,5,78,52)",
            )
            .expect("valid PASV");
        assert!(id > 0);
        assert!(h.is_expected(&ip(10, 0, 0, 2), &ip(192, 168, 1, 5), (78 << 8) | 52));
    }

    #[test]
    fn test_ftp_port_bad_format_counts_error() {
        let mut h = NatHelper::new();
        assert!(h.on_ftp_port(ip(10, 0, 0, 1), "PORT notnumbers").is_none());
        assert_eq!(h.stats().parse_errors, 1);
    }

    #[test]
    fn test_sip_sdp_registers() {
        let mut h = NatHelper::new();
        let id = h.on_sip_sdp(ip(10, 0, 0, 1), ip(10, 0, 0, 9), 49170);
        assert!(id > 0);
        assert!(h.is_expected(&ip(10, 0, 0, 1), &ip(10, 0, 0, 9), 49170));
    }

    #[test]
    fn test_rtsp_setup_registers() {
        let mut h = NatHelper::new();
        h.on_rtsp_setup(ip(10, 0, 0, 1), ip(10, 0, 0, 2), 8554);
        assert!(h.is_expected(&ip(10, 0, 0, 1), &ip(10, 0, 0, 2), 8554));
    }

    #[test]
    fn test_is_expected_consumes_entry() {
        let mut h = NatHelper::new();
        h.on_sip_sdp(ip(10, 0, 0, 1), ip(10, 0, 0, 2), 5000);
        assert!(h.is_expected(&ip(10, 0, 0, 1), &ip(10, 0, 0, 2), 5000));
        // Used flows are single-shot.
        assert!(!h.is_expected(&ip(10, 0, 0, 1), &ip(10, 0, 0, 2), 5000));
    }

    #[test]
    fn test_reap_drops_expired() {
        let mut h = NatHelper::with_ttl(Duration::from_millis(1));
        h.on_sip_sdp(ip(1, 1, 1, 1), ip(2, 2, 2, 2), 1000);
        std::thread::sleep(Duration::from_millis(5));
        let removed = h.reap();
        assert_eq!(removed, 1);
        assert_eq!(h.expected_count(), 0);
    }

    #[test]
    fn test_unknown_flow_not_expected() {
        let mut h = NatHelper::new();
        h.on_sip_sdp(ip(1, 1, 1, 1), ip(2, 2, 2, 2), 1000);
        assert!(!h.is_expected(&ip(3, 3, 3, 3), &ip(4, 4, 4, 4), 2000));
    }

    #[test]
    fn test_stats_counts_matched() {
        let mut h = NatHelper::new();
        h.on_sip_sdp(ip(1, 1, 1, 1), ip(2, 2, 2, 2), 1000);
        h.is_expected(&ip(1, 1, 1, 1), &ip(2, 2, 2, 2), 1000);
        assert_eq!(h.stats().expected_matched, 1);
        assert_eq!(h.stats().expected_created, 1);
    }

    #[test]
    fn test_clear_empties_state() {
        let mut h = NatHelper::new();
        h.on_sip_sdp(ip(1, 1, 1, 1), ip(2, 2, 2, 2), 1000);
        h.clear();
        assert_eq!(h.expected_count(), 0);
    }

    #[test]
    fn test_ftp_port_case_insensitive_prefix() {
        let mut h = NatHelper::new();
        assert!(h.on_ftp_port(ip(10, 0, 0, 1), "port 192,168,1,1,1,1").is_some());
        assert!(h.on_ftp_port(ip(10, 0, 0, 1), "Port 192,168,1,1,2,2").is_some());
    }

    #[test]
    fn test_ftp_pasv_bad_format_counts_error() {
        let mut h = NatHelper::new();
        assert!(h.on_ftp_pasv(ip(10, 0, 0, 1), "227 no parens here").is_none());
        assert_eq!(h.stats().parse_errors, 1);
    }
}
