//! Protocol-level filtering — block specific application protocols.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AppProtocol { Http, Https, Ssh, Ftp, Smtp, Imap, Pop3, Dns, DnsOverHttps, Rdp, Vnc, Telnet, Torrent, Tor }

pub struct ProtocolFilter {
    blocked: HashSet<AppProtocol>,
    logged: HashSet<AppProtocol>,
}

impl ProtocolFilter {
    pub fn new() -> Self { Self { blocked: HashSet::new(), logged: HashSet::new() } }
    pub fn block(&mut self, proto: AppProtocol) { self.blocked.insert(proto); }
    pub fn unblock(&mut self, proto: &AppProtocol) { self.blocked.remove(proto); }
    pub fn log_protocol(&mut self, proto: AppProtocol) { self.logged.insert(proto); }
    pub fn is_blocked(&self, proto: &AppProtocol) -> bool { self.blocked.contains(proto) }
    pub fn should_log(&self, proto: &AppProtocol) -> bool { self.logged.contains(proto) }
    pub fn blocked_count(&self) -> usize { self.blocked.len() }

    /// Default restrictive policy — block known risky protocols.
    pub fn restrictive() -> Self {
        let mut f = Self::new();
        f.block(AppProtocol::Telnet);
        f.block(AppProtocol::Ftp);
        f.block(AppProtocol::Rdp);
        f.block(AppProtocol::Vnc);
        f.log_protocol(AppProtocol::Torrent);
        f.log_protocol(AppProtocol::Tor);
        f
    }
}

impl Default for ProtocolFilter { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_and_check() {
        let mut f = ProtocolFilter::new();
        f.block(AppProtocol::Telnet);
        assert!(f.is_blocked(&AppProtocol::Telnet));
        assert!(!f.is_blocked(&AppProtocol::Https));
    }

    #[test]
    fn test_restrictive_default() {
        let f = ProtocolFilter::restrictive();
        assert!(f.is_blocked(&AppProtocol::Telnet));
        assert!(f.is_blocked(&AppProtocol::Ftp));
        assert!(f.should_log(&AppProtocol::Tor));
        assert!(!f.is_blocked(&AppProtocol::Https));
    }

    #[test]
    fn test_unblock() {
        let mut f = ProtocolFilter::restrictive();
        f.unblock(&AppProtocol::Ftp);
        assert!(!f.is_blocked(&AppProtocol::Ftp));
    }
}
