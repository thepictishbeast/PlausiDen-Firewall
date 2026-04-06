//! Payload inspector — scan packet payloads for malicious patterns.

use serde::{Deserialize, Serialize};

/// A payload finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadFinding {
    pub category: PayloadCategory,
    pub pattern: String,
    pub offset: usize,
    pub confidence: f64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PayloadCategory {
    SqlInjection,
    XssPayload,
    CommandInjection,
    PathTraversal,
    XmlEntity,
    SsrfAttempt,
    LdapInjection,
    NoSqlInjection,
}

/// Payload inspector.
pub struct PayloadInspector {
    sql_patterns: Vec<&'static str>,
    xss_patterns: Vec<&'static str>,
    cmd_patterns: Vec<&'static str>,
    traversal_patterns: Vec<&'static str>,
}

impl PayloadInspector {
    pub fn new() -> Self {
        Self {
            sql_patterns: vec![
                " UNION SELECT ", " or 1=1", "' OR '1'='1",
                "; DROP TABLE ", "; DELETE FROM ",
                "INFORMATION_SCHEMA", "@@version",
                "SLEEP(", "BENCHMARK(",
                "xp_cmdshell", "EXEC sp_",
            ],
            xss_patterns: vec![
                "<script>", "<script ", "</script>",
                "javascript:", "onerror=", "onload=",
                "<iframe", "<object", "<embed",
                "alert(", "prompt(", "confirm(",
                "document.cookie",
            ],
            cmd_patterns: vec![
                "; cat ", "; ls ", "; rm ",
                "| nc ", "| curl ", "| wget ",
                "$(curl ", "$(wget ", "`curl ",
                "&& cat ", "&& whoami",
                "${IFS}", "$IFS",
                ";cat /etc/passwd",
            ],
            traversal_patterns: vec![
                "../", "..\\", "%2e%2e%2f", "%2e%2e/",
                "..%2f", "%252e%252e%252f",
                "/etc/passwd", "/etc/shadow",
                "C:\\Windows\\System32\\config\\SAM",
            ],
        }
    }

    /// Scan a payload for malicious patterns.
    pub fn scan(&self, payload: &str) -> Vec<PayloadFinding> {
        let mut findings = Vec::new();
        let lower = payload.to_lowercase();

        for pattern in &self.sql_patterns {
            if let Some(offset) = lower.find(&pattern.to_lowercase()) {
                findings.push(PayloadFinding {
                    category: PayloadCategory::SqlInjection,
                    pattern: pattern.to_string(),
                    offset,
                    confidence: 0.85,
                });
            }
        }

        for pattern in &self.xss_patterns {
            if let Some(offset) = lower.find(&pattern.to_lowercase()) {
                findings.push(PayloadFinding {
                    category: PayloadCategory::XssPayload,
                    pattern: pattern.to_string(),
                    offset,
                    confidence: 0.85,
                });
            }
        }

        for pattern in &self.cmd_patterns {
            if let Some(offset) = lower.find(&pattern.to_lowercase()) {
                findings.push(PayloadFinding {
                    category: PayloadCategory::CommandInjection,
                    pattern: pattern.to_string(),
                    offset,
                    confidence: 0.9,
                });
            }
        }

        for pattern in &self.traversal_patterns {
            if let Some(offset) = lower.find(&pattern.to_lowercase()) {
                findings.push(PayloadFinding {
                    category: PayloadCategory::PathTraversal,
                    pattern: pattern.to_string(),
                    offset,
                    confidence: 0.9,
                });
            }
        }

        // XXE detection.
        if payload.contains("<!ENTITY") && payload.contains("SYSTEM") {
            findings.push(PayloadFinding {
                category: PayloadCategory::XmlEntity,
                pattern: "external entity".into(),
                offset: 0,
                confidence: 0.95,
            });
        }

        // SSRF detection.
        if lower.contains("file://") || lower.contains("gopher://") || lower.contains("dict://") {
            findings.push(PayloadFinding {
                category: PayloadCategory::SsrfAttempt,
                pattern: "URL scheme abuse".into(),
                offset: 0,
                confidence: 0.85,
            });
        }

        // LDAP injection.
        if lower.contains("(&(") || lower.contains(")(|") || lower.contains("*)(uid=*") {
            findings.push(PayloadFinding {
                category: PayloadCategory::LdapInjection,
                pattern: "LDAP filter manipulation".into(),
                offset: 0,
                confidence: 0.85,
            });
        }

        // NoSQL injection.
        if lower.contains("$ne") || lower.contains("$gt") || lower.contains("$where") {
            findings.push(PayloadFinding {
                category: PayloadCategory::NoSqlInjection,
                pattern: "MongoDB operator injection".into(),
                offset: 0,
                confidence: 0.8,
            });
        }

        findings
    }

    pub fn pattern_count(&self) -> usize {
        self.sql_patterns.len() + self.xss_patterns.len()
            + self.cmd_patterns.len() + self.traversal_patterns.len()
    }
}

impl Default for PayloadInspector {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clean_payload() {
        let det = PayloadInspector::new();
        let findings = det.scan("normal=request&value=42");
        assert!(findings.is_empty());
    }

    #[test]
    fn test_sql_injection() {
        let det = PayloadInspector::new();
        let findings = det.scan("id=1' OR '1'='1");
        assert!(findings.iter().any(|f| f.category == PayloadCategory::SqlInjection));
    }

    #[test]
    fn test_xss() {
        let det = PayloadInspector::new();
        let findings = det.scan("<script>alert('xss')</script>");
        assert!(findings.iter().any(|f| f.category == PayloadCategory::XssPayload));
    }

    #[test]
    fn test_command_injection() {
        let det = PayloadInspector::new();
        let findings = det.scan("filename=test.txt; cat /etc/passwd");
        assert!(findings.iter().any(|f| f.category == PayloadCategory::CommandInjection));
    }

    #[test]
    fn test_path_traversal() {
        let det = PayloadInspector::new();
        let findings = det.scan("file=../../../etc/passwd");
        assert!(findings.iter().any(|f| f.category == PayloadCategory::PathTraversal));
    }

    #[test]
    fn test_xxe() {
        let det = PayloadInspector::new();
        let xml = "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>";
        let findings = det.scan(xml);
        assert!(findings.iter().any(|f| f.category == PayloadCategory::XmlEntity));
    }

    #[test]
    fn test_ssrf() {
        let det = PayloadInspector::new();
        let findings = det.scan("url=file:///etc/passwd");
        assert!(findings.iter().any(|f| f.category == PayloadCategory::SsrfAttempt));
    }

    #[test]
    fn test_ldap_injection() {
        let det = PayloadInspector::new();
        let findings = det.scan("user=(&(uid=admin)(password=*))");
        assert!(findings.iter().any(|f| f.category == PayloadCategory::LdapInjection));
    }

    #[test]
    fn test_nosql_injection() {
        let det = PayloadInspector::new();
        let findings = det.scan("password[$ne]=null");
        assert!(findings.iter().any(|f| f.category == PayloadCategory::NoSqlInjection));
    }

    #[test]
    fn test_pattern_count() {
        let det = PayloadInspector::new();
        assert!(det.pattern_count() >= 30);
    }
}
