//! Deep packet inspection — protocol detection, TLS fingerprinting, payload analysis.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DetectedProtocol {
    Http,
    Https,
    Dns,
    DnsOverHttps,
    Ssh,
    Smtp,
    Imap,
    Ftp,
    BitTorrent,
    Wireguard,
    OpenVpn,
    Tor,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InspectionResult {
    pub protocol: DetectedProtocol,
    pub tls_fingerprint: Option<String>,
    pub suspicious: bool,
    pub description: String,
    pub confidence: f64,
}

/// Deep packet inspection engine.
pub struct DpiEngine {
    known_bad_ja3: Vec<String>,
}

impl DpiEngine {
    pub fn new() -> Self {
        Self {
            known_bad_ja3: vec![
                "72a589da586844d7f0818ce684948eea".into(), // Cobalt Strike
                "5d65ea3fb1d4aa7d826733d2f2cbbb1d".into(), // Metasploit
                "a0e9f5d64349fb13191bc781f81f42e1".into(), // Cobalt Strike 4.x
            ],
        }
    }

    /// Detect protocol from packet payload.
    pub fn detect_protocol(&self, payload: &[u8], dest_port: u16) -> DetectedProtocol {
        if payload.is_empty() {
            return DetectedProtocol::Unknown;
        }

        // TLS Client Hello
        if payload.len() > 5 && payload[0] == 0x16 && payload[1] == 0x03 {
            return DetectedProtocol::Https;
        }

        // SSH
        if payload.starts_with(b"SSH-") {
            return DetectedProtocol::Ssh;
        }

        // HTTP
        if payload.starts_with(b"GET ") || payload.starts_with(b"POST ")
            || payload.starts_with(b"PUT ") || payload.starts_with(b"DELETE ")
            || payload.starts_with(b"HEAD ") || payload.starts_with(b"HTTP/")
        {
            return DetectedProtocol::Http;
        }

        // DNS (standard format: first 2 bytes = length for TCP, or directly for UDP)
        if dest_port == 53 && payload.len() > 12 {
            return DetectedProtocol::Dns;
        }

        // SMTP
        if payload.starts_with(b"220 ") || payload.starts_with(b"EHLO ")
            || payload.starts_with(b"HELO ")
        {
            return DetectedProtocol::Smtp;
        }

        // BitTorrent
        if payload.len() > 20 && payload[0] == 19 && &payload[1..20] == b"BitTorrent protocol" {
            return DetectedProtocol::BitTorrent;
        }

        // WireGuard (first byte is message type 1-4, next 3 are reserved zeros)
        if payload.len() >= 4 && payload[0] >= 1 && payload[0] <= 4
            && payload[1] == 0 && payload[2] == 0 && payload[3] == 0
            && dest_port == 51820
        {
            return DetectedProtocol::Wireguard;
        }

        // OpenVPN (starts with 0x38 or 0x40 on port 1194)
        if dest_port == 1194 && payload.len() > 2 {
            return DetectedProtocol::OpenVpn;
        }

        // Tor (TLS on port 9001 or 9030)
        if (dest_port == 9001 || dest_port == 9030) && payload.len() > 5
            && payload[0] == 0x16 && payload[1] == 0x03
        {
            return DetectedProtocol::Tor;
        }

        // Port-based fallback
        match dest_port {
            443 => DetectedProtocol::Https,
            80 => DetectedProtocol::Http,
            53 => DetectedProtocol::Dns,
            22 => DetectedProtocol::Ssh,
            25 | 587 => DetectedProtocol::Smtp,
            143 | 993 => DetectedProtocol::Imap,
            20 | 21 => DetectedProtocol::Ftp,
            _ => DetectedProtocol::Unknown,
        }
    }

    /// Extract JA3 fingerprint from a TLS Client Hello.
    ///
    /// Returns None if the payload is not a valid Client Hello.
    pub fn extract_ja3(&self, payload: &[u8]) -> Option<String> {
        // Minimal TLS Client Hello detection
        if payload.len() < 43 || payload[0] != 0x16 || payload[1] != 0x03 {
            return None;
        }

        // Real JA3 extraction requires parsing the full Client Hello
        // (TLS version, cipher suites, extensions, elliptic curves, EC point formats)
        // For now, hash the relevant bytes as a simplified fingerprint
        let hash = blake3::hash(&payload[..payload.len().min(512)]);
        Some(format!("{:032x}", u128::from_le_bytes(hash.as_bytes()[..16].try_into().unwrap())))
    }

    /// Check if a JA3 hash is known-bad.
    pub fn is_suspicious_ja3(&self, ja3: &str) -> bool {
        self.known_bad_ja3.contains(&ja3.to_string())
    }

    /// Full packet inspection.
    pub fn inspect(&self, payload: &[u8], dest_port: u16) -> InspectionResult {
        let protocol = self.detect_protocol(payload, dest_port);

        let tls_fp = if matches!(protocol, DetectedProtocol::Https | DetectedProtocol::Tor) {
            self.extract_ja3(payload)
        } else {
            None
        };

        let suspicious = tls_fp.as_ref().is_some_and(|fp| self.is_suspicious_ja3(fp));

        let description = if suspicious {
            format!("Suspicious TLS fingerprint detected on port {dest_port}")
        } else {
            format!("{:?} traffic on port {dest_port}", protocol)
        };

        InspectionResult {
            protocol,
            tls_fingerprint: tls_fp,
            suspicious,
            description,
            confidence: if protocol == DetectedProtocol::Unknown { 0.2 } else { 0.9 },
        }
    }
}

impl Default for DpiEngine {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_http() {
        let dpi = DpiEngine::new();
        assert_eq!(dpi.detect_protocol(b"GET / HTTP/1.1\r\n", 80), DetectedProtocol::Http);
        assert_eq!(dpi.detect_protocol(b"POST /api HTTP/1.1\r\n", 80), DetectedProtocol::Http);
    }

    #[test]
    fn test_detect_tls() {
        let dpi = DpiEngine::new();
        let client_hello = [0x16, 0x03, 0x01, 0x00, 0x05, 0x01];
        assert_eq!(dpi.detect_protocol(&client_hello, 443), DetectedProtocol::Https);
    }

    #[test]
    fn test_detect_ssh() {
        let dpi = DpiEngine::new();
        assert_eq!(dpi.detect_protocol(b"SSH-2.0-OpenSSH_8.9\r\n", 22), DetectedProtocol::Ssh);
    }

    #[test]
    fn test_detect_dns() {
        let dpi = DpiEngine::new();
        let dns_query = [0x00; 20]; // Minimal DNS-like payload
        assert_eq!(dpi.detect_protocol(&dns_query, 53), DetectedProtocol::Dns);
    }

    #[test]
    fn test_detect_smtp() {
        let dpi = DpiEngine::new();
        assert_eq!(dpi.detect_protocol(b"220 mail.example.com ESMTP", 25), DetectedProtocol::Smtp);
    }

    #[test]
    fn test_port_fallback() {
        let dpi = DpiEngine::new();
        assert_eq!(dpi.detect_protocol(&[0x00], 443), DetectedProtocol::Https);
        assert_eq!(dpi.detect_protocol(&[0x00], 22), DetectedProtocol::Ssh);
    }

    #[test]
    fn test_unknown_protocol() {
        let dpi = DpiEngine::new();
        assert_eq!(dpi.detect_protocol(&[0xAB, 0xCD], 12345), DetectedProtocol::Unknown);
    }

    #[test]
    fn test_inspect_returns_result() {
        let dpi = DpiEngine::new();
        let result = dpi.inspect(b"GET / HTTP/1.1\r\n", 80);
        assert_eq!(result.protocol, DetectedProtocol::Http);
        assert!(!result.suspicious);
        assert!(result.confidence > 0.5);
    }

    #[test]
    fn test_known_bad_ja3() {
        let dpi = DpiEngine::new();
        assert!(dpi.is_suspicious_ja3("72a589da586844d7f0818ce684948eea"));
        assert!(!dpi.is_suspicious_ja3("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
    }

    #[test]
    fn test_empty_payload() {
        let dpi = DpiEngine::new();
        assert_eq!(dpi.detect_protocol(&[], 443), DetectedProtocol::Unknown);
    }
}
