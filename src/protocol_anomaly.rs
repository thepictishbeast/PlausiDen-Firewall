//! Protocol anomaly detection — detects malformed or unusual protocol traffic.

use serde::{Deserialize, Serialize};

/// A protocol anomaly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolAnomaly {
    pub protocol: String,
    pub anomaly_type: AnomalyType,
    pub description: String,
    pub severity: AnomalySeverity,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AnomalyType {
    PortMismatch,
    MalformedHeader,
    InvalidLength,
    UnexpectedDirection,
    UnusualVersion,
    PayloadAnomaly,
    HandshakeFailure,
    Truncation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AnomalySeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Protocol anomaly detector.
pub struct ProtocolAnomalyDetector {
    /// Map of port to expected protocol.
    expected_protocols: std::collections::HashMap<u16, &'static str>,
}

impl ProtocolAnomalyDetector {
    pub fn new() -> Self {
        let mut expected = std::collections::HashMap::new();
        expected.insert(22, "ssh");
        expected.insert(25, "smtp");
        expected.insert(53, "dns");
        expected.insert(80, "http");
        expected.insert(443, "tls");
        expected.insert(3389, "rdp");
        expected.insert(3306, "mysql");
        expected.insert(5432, "postgresql");
        expected.insert(6379, "redis");
        Self { expected_protocols: expected }
    }

    /// Check if traffic on a port matches the expected protocol.
    pub fn check_port_protocol(&self, port: u16, observed_protocol: &str) -> Option<ProtocolAnomaly> {
        if let Some(expected) = self.expected_protocols.get(&port) {
            if observed_protocol != *expected {
                return Some(ProtocolAnomaly {
                    protocol: observed_protocol.into(),
                    anomaly_type: AnomalyType::PortMismatch,
                    description: format!(
                        "Expected {expected} on port {port}, observed {observed_protocol}"
                    ),
                    severity: AnomalySeverity::High,
                });
            }
        }
        None
    }

    /// Check HTTP request for anomalies.
    pub fn check_http(&self, method: &str, version: &str, headers: &[(String, String)]) -> Vec<ProtocolAnomaly> {
        let mut anomalies = Vec::new();

        // Unusual method.
        let valid_methods = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE"];
        if !valid_methods.contains(&method) {
            anomalies.push(ProtocolAnomaly {
                protocol: "http".into(),
                anomaly_type: AnomalyType::MalformedHeader,
                description: format!("Unknown HTTP method: {method}"),
                severity: AnomalySeverity::Medium,
            });
        }

        // Old HTTP version.
        if version == "HTTP/0.9" || version == "HTTP/1.0" {
            anomalies.push(ProtocolAnomaly {
                protocol: "http".into(),
                anomaly_type: AnomalyType::UnusualVersion,
                description: format!("Old HTTP version: {version}"),
                severity: AnomalySeverity::Low,
            });
        }

        // Missing Host header (required in HTTP/1.1).
        if version == "HTTP/1.1" && !headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("Host")) {
            anomalies.push(ProtocolAnomaly {
                protocol: "http".into(),
                anomaly_type: AnomalyType::MalformedHeader,
                description: "Missing Host header in HTTP/1.1".into(),
                severity: AnomalySeverity::Medium,
            });
        }

        anomalies
    }

    /// Check DNS query for anomalies.
    pub fn check_dns(&self, query_size: usize, qname_length: usize) -> Vec<ProtocolAnomaly> {
        let mut anomalies = Vec::new();

        if query_size > 512 {
            anomalies.push(ProtocolAnomaly {
                protocol: "dns".into(),
                anomaly_type: AnomalyType::InvalidLength,
                description: format!("Oversized DNS query: {query_size} bytes (>512)"),
                severity: AnomalySeverity::Medium,
            });
        }

        if qname_length > 100 {
            anomalies.push(ProtocolAnomaly {
                protocol: "dns".into(),
                anomaly_type: AnomalyType::PayloadAnomaly,
                description: format!("Excessively long DNS name: {qname_length} chars"),
                severity: AnomalySeverity::High,
            });
        }

        anomalies
    }

    /// Check TLS record for anomalies.
    pub fn check_tls(&self, version: &str, has_sni: bool) -> Vec<ProtocolAnomaly> {
        let mut anomalies = Vec::new();

        // Old TLS versions.
        if version == "TLS 1.0" || version == "TLS 1.1" || version == "SSL 3.0" {
            anomalies.push(ProtocolAnomaly {
                protocol: "tls".into(),
                anomaly_type: AnomalyType::UnusualVersion,
                description: format!("Deprecated TLS version: {version}"),
                severity: AnomalySeverity::High,
            });
        }

        // Missing SNI (unusual for modern web).
        if !has_sni {
            anomalies.push(ProtocolAnomaly {
                protocol: "tls".into(),
                anomaly_type: AnomalyType::MalformedHeader,
                description: "TLS ClientHello without SNI".into(),
                severity: AnomalySeverity::Low,
            });
        }

        anomalies
    }

    pub fn known_port_count(&self) -> usize { self.expected_protocols.len() }
}

impl Default for ProtocolAnomalyDetector {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_port_match() {
        let det = ProtocolAnomalyDetector::new();
        assert!(det.check_port_protocol(80, "http").is_none());
        assert!(det.check_port_protocol(443, "tls").is_none());
    }

    #[test]
    fn test_port_mismatch() {
        let det = ProtocolAnomalyDetector::new();
        let anomaly = det.check_port_protocol(22, "http");
        assert!(anomaly.is_some());
        assert_eq!(anomaly.unwrap().anomaly_type, AnomalyType::PortMismatch);
    }

    #[test]
    fn test_http_unknown_method() {
        let det = ProtocolAnomalyDetector::new();
        let anomalies = det.check_http("INVALID", "HTTP/1.1", &[]);
        assert!(!anomalies.is_empty());
    }

    #[test]
    fn test_http_old_version() {
        let det = ProtocolAnomalyDetector::new();
        let anomalies = det.check_http("GET", "HTTP/1.0", &[]);
        assert!(anomalies.iter().any(|a| a.anomaly_type == AnomalyType::UnusualVersion));
    }

    #[test]
    fn test_http_missing_host() {
        let det = ProtocolAnomalyDetector::new();
        let anomalies = det.check_http("GET", "HTTP/1.1", &[]);
        assert!(anomalies.iter().any(|a| a.description.contains("Host")));
    }

    #[test]
    fn test_http_clean() {
        let det = ProtocolAnomalyDetector::new();
        let headers = vec![("Host".into(), "example.com".into())];
        let anomalies = det.check_http("GET", "HTTP/1.1", &headers);
        assert!(anomalies.is_empty());
    }

    #[test]
    fn test_dns_oversized() {
        let det = ProtocolAnomalyDetector::new();
        let anomalies = det.check_dns(1024, 50);
        assert!(!anomalies.is_empty());
    }

    #[test]
    fn test_dns_long_name() {
        let det = ProtocolAnomalyDetector::new();
        let anomalies = det.check_dns(200, 200);
        assert!(anomalies.iter().any(|a| a.anomaly_type == AnomalyType::PayloadAnomaly));
    }

    #[test]
    fn test_tls_deprecated() {
        let det = ProtocolAnomalyDetector::new();
        let anomalies = det.check_tls("TLS 1.0", true);
        assert!(anomalies.iter().any(|a| a.anomaly_type == AnomalyType::UnusualVersion));
    }

    #[test]
    fn test_tls_modern() {
        let det = ProtocolAnomalyDetector::new();
        let anomalies = det.check_tls("TLS 1.3", true);
        assert!(anomalies.is_empty());
    }
}
