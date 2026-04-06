//! Proxy/VPN detection — identifies traffic going through proxies, VPNs, and Tor.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::IpAddr;

/// Type of detected proxy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProxyType {
    Tor,
    OpenVpn,
    Wireguard,
    Ipsec,
    SocksProxy,
    HttpProxy,
    Squid,
    Cloud,
    Unknown,
}

/// A detected proxy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedProxy {
    pub ip: IpAddr,
    pub port: u16,
    pub proxy_type: ProxyType,
    pub confidence: f64,
}

/// Proxy detection engine.
pub struct ProxyDetector {
    /// Known Tor exit relay IPs.
    tor_exits: HashSet<IpAddr>,
    /// Known VPN provider IP ranges.
    known_vpn_ips: HashSet<IpAddr>,
    /// Common proxy ports.
    proxy_ports: HashSet<u16>,
}

impl ProxyDetector {
    pub fn new() -> Self {
        let mut proxy_ports = HashSet::new();
        // SOCKS, HTTP proxies.
        proxy_ports.insert(1080);
        proxy_ports.insert(3128);
        proxy_ports.insert(8080);
        proxy_ports.insert(8888);
        // VPN protocols.
        proxy_ports.insert(1194); // OpenVPN
        proxy_ports.insert(51820); // WireGuard
        proxy_ports.insert(500);  // IKE
        proxy_ports.insert(4500); // IPsec NAT-T
        // Tor.
        proxy_ports.insert(9001);
        proxy_ports.insert(9030);
        proxy_ports.insert(9050);

        Self {
            tor_exits: HashSet::new(),
            known_vpn_ips: HashSet::new(),
            proxy_ports,
        }
    }

    /// Add a known Tor exit relay.
    pub fn add_tor_exit(&mut self, ip: IpAddr) {
        self.tor_exits.insert(ip);
    }

    /// Add a known VPN IP.
    pub fn add_vpn_ip(&mut self, ip: IpAddr) {
        self.known_vpn_ips.insert(ip);
    }

    /// Detect proxy type for a connection.
    pub fn detect(&self, ip: &IpAddr, port: u16) -> Option<DetectedProxy> {
        // Check Tor exits first (high confidence).
        if self.tor_exits.contains(ip) {
            return Some(DetectedProxy {
                ip: *ip,
                port,
                proxy_type: ProxyType::Tor,
                confidence: 0.99,
            });
        }

        // Known VPN IPs.
        if self.known_vpn_ips.contains(ip) {
            return Some(DetectedProxy {
                ip: *ip,
                port,
                proxy_type: ProxyType::OpenVpn,
                confidence: 0.9,
            });
        }

        // Port-based detection.
        match port {
            1080 => Some(DetectedProxy { ip: *ip, port, proxy_type: ProxyType::SocksProxy, confidence: 0.7 }),
            3128 => Some(DetectedProxy { ip: *ip, port, proxy_type: ProxyType::Squid, confidence: 0.6 }),
            8080 | 8888 => Some(DetectedProxy { ip: *ip, port, proxy_type: ProxyType::HttpProxy, confidence: 0.5 }),
            1194 => Some(DetectedProxy { ip: *ip, port, proxy_type: ProxyType::OpenVpn, confidence: 0.8 }),
            51820 => Some(DetectedProxy { ip: *ip, port, proxy_type: ProxyType::Wireguard, confidence: 0.85 }),
            500 | 4500 => Some(DetectedProxy { ip: *ip, port, proxy_type: ProxyType::Ipsec, confidence: 0.7 }),
            9001 | 9030 | 9050 => Some(DetectedProxy { ip: *ip, port, proxy_type: ProxyType::Tor, confidence: 0.7 }),
            _ => None,
        }
    }

    /// Check if traffic is likely going through any proxy.
    pub fn is_proxy_traffic(&self, ip: &IpAddr, port: u16) -> bool {
        self.detect(ip, port).is_some()
    }

    pub fn tor_exit_count(&self) -> usize { self.tor_exits.len() }
    pub fn vpn_ip_count(&self) -> usize { self.known_vpn_ips.len() }
}

impl Default for ProxyDetector {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr { s.parse().unwrap() }

    #[test]
    fn test_tor_detection() {
        let mut det = ProxyDetector::new();
        det.add_tor_exit(ip("1.2.3.4"));
        let result = det.detect(&ip("1.2.3.4"), 443).unwrap();
        assert_eq!(result.proxy_type, ProxyType::Tor);
    }

    #[test]
    fn test_vpn_detection() {
        let mut det = ProxyDetector::new();
        det.add_vpn_ip(ip("10.0.0.1"));
        let result = det.detect(&ip("10.0.0.1"), 443).unwrap();
        assert_eq!(result.proxy_type, ProxyType::OpenVpn);
    }

    #[test]
    fn test_socks_port() {
        let det = ProxyDetector::new();
        let result = det.detect(&ip("1.2.3.4"), 1080).unwrap();
        assert_eq!(result.proxy_type, ProxyType::SocksProxy);
    }

    #[test]
    fn test_wireguard_port() {
        let det = ProxyDetector::new();
        let result = det.detect(&ip("1.2.3.4"), 51820).unwrap();
        assert_eq!(result.proxy_type, ProxyType::Wireguard);
    }

    #[test]
    fn test_squid_port() {
        let det = ProxyDetector::new();
        let result = det.detect(&ip("1.2.3.4"), 3128).unwrap();
        assert_eq!(result.proxy_type, ProxyType::Squid);
    }

    #[test]
    fn test_normal_port_no_detect() {
        let det = ProxyDetector::new();
        assert!(det.detect(&ip("1.2.3.4"), 443).is_none());
    }

    #[test]
    fn test_is_proxy_traffic() {
        let det = ProxyDetector::new();
        assert!(det.is_proxy_traffic(&ip("1.2.3.4"), 1080));
        assert!(!det.is_proxy_traffic(&ip("1.2.3.4"), 443));
    }

    #[test]
    fn test_tor_exit_count() {
        let mut det = ProxyDetector::new();
        det.add_tor_exit(ip("1.1.1.1"));
        det.add_tor_exit(ip("2.2.2.2"));
        assert_eq!(det.tor_exit_count(), 2);
    }
}
