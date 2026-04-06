//! SSL/TLS inspection — analyze encrypted traffic metadata without decryption.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsMetadata {
    pub server_name: String,
    pub tls_version: String,
    pub cipher_suite: String,
    pub certificate_issuer: Option<String>,
    pub certificate_days_remaining: Option<i32>,
    pub ja3_hash: Option<String>,
}

pub struct SslInspector {
    pinned_certs: HashMap<String, String>, // domain → expected issuer
    suspicious_issuers: Vec<String>,
}

impl SslInspector {
    pub fn new() -> Self {
        Self {
            pinned_certs: HashMap::new(),
            suspicious_issuers: vec!["Let's Encrypt".into()], // Not suspicious by default, but flagged for monitoring on high-value targets
        }
    }

    pub fn pin_certificate(&mut self, domain: &str, issuer: &str) { self.pinned_certs.insert(domain.into(), issuer.into()); }

    pub fn check_pin(&self, metadata: &TlsMetadata) -> bool {
        if let Some(expected) = self.pinned_certs.get(&metadata.server_name) {
            metadata.certificate_issuer.as_deref() == Some(expected)
        } else { true } // No pin = pass
    }

    pub fn check_expiring(&self, metadata: &TlsMetadata, warn_days: i32) -> bool {
        metadata.certificate_days_remaining.map(|d| d < warn_days).unwrap_or(false)
    }

    pub fn check_weak_cipher(&self, metadata: &TlsMetadata) -> bool {
        let weak = ["RC4", "DES", "3DES", "NULL", "EXPORT", "anon"];
        weak.iter().any(|w| metadata.cipher_suite.contains(w))
    }

    pub fn pinned_count(&self) -> usize { self.pinned_certs.len() }
}

impl Default for SslInspector { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(sni: &str, issuer: &str, cipher: &str) -> TlsMetadata {
        TlsMetadata { server_name: sni.into(), tls_version: "TLS 1.3".into(), cipher_suite: cipher.into(), certificate_issuer: Some(issuer.into()), certificate_days_remaining: Some(90), ja3_hash: None }
    }

    #[test]
    fn test_pin_check_pass() {
        let mut inspector = SslInspector::new();
        inspector.pin_certificate("bank.com", "DigiCert");
        assert!(inspector.check_pin(&meta("bank.com", "DigiCert", "AES256-GCM")));
    }

    #[test]
    fn test_pin_check_fail() {
        let mut inspector = SslInspector::new();
        inspector.pin_certificate("bank.com", "DigiCert");
        assert!(!inspector.check_pin(&meta("bank.com", "Evil CA", "AES256-GCM")));
    }

    #[test]
    fn test_weak_cipher() {
        let inspector = SslInspector::new();
        assert!(inspector.check_weak_cipher(&meta("site.com", "CA", "RC4-SHA")));
        assert!(!inspector.check_weak_cipher(&meta("site.com", "CA", "AES256-GCM-SHA384")));
    }

    #[test]
    fn test_expiring() {
        let inspector = SslInspector::new();
        let mut m = meta("site.com", "CA", "AES");
        m.certificate_days_remaining = Some(5);
        assert!(inspector.check_expiring(&m, 30));
    }
}
