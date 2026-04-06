//! Deep packet inspection — protocol detection, TLS fingerprinting, payload analysis.
//!
//! Provides real TLS ClientHello parsing with SNI extraction and JA3 fingerprinting,
//! HTTP request analysis with injection detection, DNS wire format parsing with
//! tunneling indicators, and protocol anomaly detection.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

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

/// Result of a full deep packet inspection pass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InspectionResult {
    pub protocol: DetectedProtocol,
    pub tls_fingerprint: Option<String>,
    pub suspicious: bool,
    pub description: String,
    pub confidence: f64,
    /// SNI hostname extracted from a TLS ClientHello, if present.
    pub sni: Option<String>,
    /// Cipher suites advertised in a TLS ClientHello.
    pub cipher_suites: Vec<u16>,
    /// Parsed HTTP request metadata, if applicable.
    pub http_info: Option<HttpRequestInfo>,
    /// Parsed DNS query metadata, if applicable.
    pub dns_info: Option<DnsQueryInfo>,
    /// Protocol anomalies detected during inspection.
    pub anomalies: Vec<ProtocolAnomaly>,
}

/// Metadata extracted from an HTTP/1.x request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRequestInfo {
    pub method: String,
    pub path: String,
    pub host: Option<String>,
    pub user_agent: Option<String>,
    /// Suspicious patterns found in the request (path probing, injection, etc.).
    pub threat_indicators: Vec<String>,
}

/// Metadata extracted from a DNS wire-format query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsQueryInfo {
    pub query_name: String,
    pub query_type: u16,
    pub query_class: u16,
    /// Indicators of possible DNS tunneling.
    pub tunneling_indicators: Vec<String>,
}

/// A protocol-level anomaly detected during inspection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolAnomaly {
    pub kind: AnomalyKind,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AnomalyKind {
    /// Protocol signature does not match the destination port.
    PortProtocolMismatch,
    /// Malformed or truncated header detected.
    MalformedHeader,
    /// DNS query exceeds expected size.
    OversizedDnsQuery,
}

// ---------------------------------------------------------------------------
// TLS parsing helpers
// ---------------------------------------------------------------------------

/// Parsed fields from a TLS ClientHello needed for JA3 computation.
#[derive(Debug, Clone, Default)]
struct ClientHelloParsed {
    tls_version: u16,
    cipher_suites: Vec<u16>,
    extensions: Vec<u16>,
    elliptic_curves: Vec<u16>,
    ec_point_formats: Vec<u8>,
    sni: Option<String>,
}

/// GREASE values defined in RFC 8701 that must be excluded from JA3.
fn is_grease(val: u16) -> bool {
    matches!(
        val,
        0x0a0a
            | 0x1a1a
            | 0x2a2a
            | 0x3a3a
            | 0x4a4a
            | 0x5a5a
            | 0x6a6a
            | 0x7a7a
            | 0x8a8a
            | 0x9a9a
            | 0xaaaa
            | 0xbaba
            | 0xcaca
            | 0xdada
            | 0xeaea
            | 0xfafa
    )
}

/// Read a big-endian u16 from `data` at `offset`, returning `None` on underflow.
fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    if offset + 2 > data.len() {
        return None;
    }
    Some(u16::from_be_bytes([data[offset], data[offset + 1]]))
}

/// Read a big-endian u24 (as u32) from `data` at `offset`.
fn read_u24(data: &[u8], offset: usize) -> Option<u32> {
    if offset + 3 > data.len() {
        return None;
    }
    Some(((data[offset] as u32) << 16) | ((data[offset + 1] as u32) << 8) | data[offset + 2] as u32)
}

/// Parse a TLS ClientHello from the raw TLS record payload.
///
/// Returns `None` if the payload is not a valid ClientHello or is too short.
fn parse_client_hello(payload: &[u8]) -> Option<ClientHelloParsed> {
    // Minimum: 5 (record header) + 4 (handshake header) + 34 (version + random)
    if payload.len() < 43 {
        return None;
    }

    // --- TLS record layer ---
    // content_type == 0x16 (Handshake)
    if payload[0] != 0x16 {
        return None;
    }
    // record version (0x0301 .. 0x0303 typically, but we accept any 0x03xx)
    if payload[1] != 0x03 {
        return None;
    }
    let record_length = read_u16(payload, 3)? as usize;
    let record_end = 5usize.checked_add(record_length)?;

    // Ensure we have enough data (but cap at what we actually received).
    let available = payload.len().min(record_end);
    if available < 43 {
        return None;
    }

    // --- Handshake header ---
    // handshake_type == 1 (ClientHello)
    if payload[5] != 0x01 {
        return None;
    }
    let _handshake_length = read_u24(payload, 6)?;

    let mut result = ClientHelloParsed {
        tls_version: read_u16(payload, 9)?,
        ..ClientHelloParsed::default()
    };

    // 32 bytes of random at offset 11..43
    let mut pos = 43;

    // Session ID (1-byte length + data)
    if pos >= available {
        return None;
    }
    let session_id_len = payload[pos] as usize;
    pos += 1 + session_id_len;
    if pos + 2 > available {
        return None;
    }

    // --- Cipher suites ---
    let cs_len = read_u16(payload, pos)? as usize;
    pos += 2;
    if pos + cs_len > available {
        return None;
    }
    let cs_end = pos + cs_len;
    while pos + 1 < cs_end {
        let cs = read_u16(payload, pos)?;
        if !is_grease(cs) {
            result.cipher_suites.push(cs);
        }
        pos += 2;
    }
    pos = cs_end;

    // --- Compression methods ---
    if pos >= available {
        return None;
    }
    let comp_len = payload[pos] as usize;
    pos += 1 + comp_len;

    // --- Extensions ---
    if pos + 2 > available {
        // No extensions present; that's still a valid ClientHello.
        return Some(result);
    }
    let ext_total_len = read_u16(payload, pos)? as usize;
    pos += 2;
    let ext_end = (pos + ext_total_len).min(available);

    while pos + 4 <= ext_end {
        let ext_type = read_u16(payload, pos)?;
        let ext_len = read_u16(payload, pos + 2)? as usize;
        pos += 4;
        let ext_data_end = (pos + ext_len).min(ext_end);

        if !is_grease(ext_type) {
            result.extensions.push(ext_type);
        }

        match ext_type {
            // SNI (Server Name Indication) — extension type 0x0000
            0x0000 => {
                if ext_len >= 5 && ext_data_end <= available {
                    // SNI list length (2 bytes), then type (1 byte, 0 = hostname),
                    // then name length (2 bytes), then name.
                    let _list_len = read_u16(payload, pos);
                    let name_type = payload.get(pos + 2).copied();
                    if name_type == Some(0)
                        && let Some(name_len) = read_u16(payload, pos + 3)
                    {
                        let name_start = pos + 5;
                        let name_end = name_start + name_len as usize;
                        if name_end <= ext_data_end {
                            result.sni = std::str::from_utf8(&payload[name_start..name_end])
                                .ok()
                                .map(|s| s.to_string());
                        }
                    }
                }
            }
            // Supported Groups (Elliptic Curves) — extension type 0x000a
            0x000a => {
                if ext_len >= 2 && pos + 2 <= ext_data_end {
                    let groups_len = read_u16(payload, pos).unwrap_or(0) as usize;
                    let mut gpos = pos + 2;
                    let groups_end = (gpos + groups_len).min(ext_data_end);
                    while gpos + 1 < groups_end {
                        if let Some(g) = read_u16(payload, gpos)
                            && !is_grease(g)
                        {
                            result.elliptic_curves.push(g);
                        }
                        gpos += 2;
                    }
                }
            }
            // EC Point Formats — extension type 0x000b
            0x000b => {
                if ext_len >= 1 && pos < ext_data_end {
                    let fmt_len = payload[pos] as usize;
                    let fmt_end = (pos + 1 + fmt_len).min(ext_data_end);
                    for &b in &payload[pos + 1..fmt_end] {
                        result.ec_point_formats.push(b);
                    }
                }
            }
            _ => {}
        }

        pos = ext_data_end;
    }

    Some(result)
}

/// Compute the JA3 fingerprint string and its MD5 hash.
///
/// Format: `SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats`
/// Each list is dash-separated. The final fingerprint is the MD5 hex digest.
fn compute_ja3(parsed: &ClientHelloParsed) -> (String, String) {
    let ciphers = parsed
        .cipher_suites
        .iter()
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join("-");
    let extensions = parsed
        .extensions
        .iter()
        .map(|e| e.to_string())
        .collect::<Vec<_>>()
        .join("-");
    let curves = parsed
        .elliptic_curves
        .iter()
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join("-");
    let point_formats = parsed
        .ec_point_formats
        .iter()
        .map(|f| f.to_string())
        .collect::<Vec<_>>()
        .join("-");

    let ja3_string = format!(
        "{},{},{},{},{}",
        parsed.tls_version, ciphers, extensions, curves, point_formats
    );

    let digest = md5::compute(ja3_string.as_bytes());
    let ja3_hash = format!("{digest:032x}");

    (ja3_string, ja3_hash)
}

// ---------------------------------------------------------------------------
// HTTP parsing helpers
// ---------------------------------------------------------------------------

/// Suspicious paths commonly probed by scanners and attackers.
const SUSPICIOUS_PATHS: &[&str] = &[
    "/wp-admin",
    "/wp-login",
    "/wp-content/uploads",
    "/phpmyadmin",
    "/phpMyAdmin",
    "/shell",
    "/cmd",
    "/console",
    "/.env",
    "/.git",
    "/.aws",
    "/actuator",
    "/actuator/env",
    "/actuator/health",
    "/manager/html",
    "/admin",
    "/cgi-bin",
    "/debug",
    "/server-status",
    "/solr/admin",
    "/config.json",
    "/backup",
    "/db",
    "/api/v1/pods",
    "/eval",
    "/exec",
];

/// SQL injection indicator patterns (case-insensitive matching performed by caller).
const SQLI_PATTERNS: &[&str] = &[
    "' or ",
    "' and ",
    "union select",
    "union all select",
    "1=1",
    "1'='1",
    "drop table",
    "insert into",
    "select * from",
    "' --",
    "';--",
    "sleep(",
    "benchmark(",
    "waitfor delay",
    "pg_sleep",
    "load_file(",
    "into outfile",
    "char(",
    "0x",
];

/// Command injection indicator patterns.
const CMDI_PATTERNS: &[&str] = &[
    ";ls",
    ";cat ",
    "|cat ",
    "$(cat",
    "`cat",
    ";id",
    "|id",
    ";whoami",
    "|whoami",
    ";wget ",
    ";curl ",
    "&&curl",
    ";bash ",
    "|bash ",
    ";sh ",
    "|sh ",
    ";nc ",
    ";python",
    "/etc/passwd",
    "/etc/shadow",
    "${IFS}",
    "$((",
    "${jndi:",
];

/// Parse an HTTP/1.x request from the payload, extracting method, path, host,
/// user-agent, and detecting threat indicators.
fn parse_http_request(payload: &[u8]) -> Option<HttpRequestInfo> {
    let text = std::str::from_utf8(payload).ok()?;

    // First line: METHOD PATH HTTP/1.x
    let first_line = text.lines().next()?;
    let mut parts = first_line.splitn(3, ' ');
    let method = parts.next()?.to_string();
    let path = parts.next()?.to_string();
    // Remaining is the HTTP version string; we don't need it.

    // Validate method.
    let valid_methods = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE", "CONNECT"];
    if !valid_methods.contains(&method.as_str()) {
        return None;
    }

    // Extract headers.
    let mut host = None;
    let mut user_agent = None;
    for line in text.lines().skip(1) {
        if line.is_empty() || line == "\r" {
            break;
        }
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("host:") {
            host = Some(line[5..].trim().to_string());
        } else if lower.starts_with("user-agent:") {
            user_agent = Some(line[11..].trim().to_string());
        }
    }

    // Detect threat indicators.
    let mut threat_indicators = Vec::new();
    let path_lower = path.to_ascii_lowercase();

    // Path probing.
    for &suspicious in SUSPICIOUS_PATHS {
        if path_lower.contains(&suspicious.to_ascii_lowercase()) {
            threat_indicators.push(format!("suspicious_path:{suspicious}"));
        }
    }

    // Path traversal.
    if path.contains("../") || path.contains("..\\") {
        threat_indicators.push("path_traversal".to_string());
    }

    // Decode percent-encoded characters for injection detection.
    let decoded_path = percent_decode(&path_lower);

    // SQL injection.
    for &pattern in SQLI_PATTERNS {
        if decoded_path.contains(pattern) {
            threat_indicators.push(format!("sqli:{pattern}"));
        }
    }

    // Command injection.
    for &pattern in CMDI_PATTERNS {
        if decoded_path.contains(pattern) {
            threat_indicators.push(format!("cmdi:{pattern}"));
        }
    }

    Some(HttpRequestInfo {
        method,
        path,
        host,
        user_agent,
        threat_indicators,
    })
}

/// Minimal percent-decoding for injection detection (handles %XX sequences).
fn percent_decode(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = hex_digit(bytes[i + 1]);
            let lo = hex_digit(bytes[i + 2]);
            if let (Some(h), Some(l)) = (hi, lo) {
                output.push((h << 4 | l) as char);
                i += 3;
                continue;
            }
        }
        output.push(bytes[i] as char);
        i += 1;
    }
    output
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// DNS parsing helpers
// ---------------------------------------------------------------------------

/// Parse a DNS query name from wire format starting at `offset`.
///
/// Returns `(domain_name, new_offset)` or `None` on parse failure.
fn parse_dns_name(data: &[u8], mut offset: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut jumps = 0;
    let mut final_offset = None;

    loop {
        if offset >= data.len() || jumps > 10 {
            return None;
        }
        let label_len = data[offset] as usize;

        // Pointer (top 2 bits set).
        if label_len & 0xC0 == 0xC0 {
            if offset + 1 >= data.len() {
                return None;
            }
            if final_offset.is_none() {
                final_offset = Some(offset + 2);
            }
            let ptr = ((label_len & 0x3F) << 8) | data[offset + 1] as usize;
            offset = ptr;
            jumps += 1;
            continue;
        }

        // Root label (length 0) = end.
        if label_len == 0 {
            if final_offset.is_none() {
                final_offset = Some(offset + 1);
            }
            break;
        }

        // Normal label.
        if offset + 1 + label_len > data.len() {
            return None;
        }
        let label = std::str::from_utf8(&data[offset + 1..offset + 1 + label_len])
            .ok()?
            .to_string();
        labels.push(label);
        offset += 1 + label_len;
    }

    let name = labels.join(".");
    Some((name, final_offset.unwrap_or(offset)))
}

/// Compute the Shannon entropy of a byte slice (used for tunneling detection).
fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut entropy = 0.0f64;
    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Parse a DNS query from a UDP payload on port 53.
///
/// Returns the query info plus tunneling indicators.
fn parse_dns_query(payload: &[u8]) -> Option<DnsQueryInfo> {
    // DNS header is 12 bytes minimum.
    if payload.len() < 12 {
        return None;
    }

    // QR bit (bit 15 of flags) must be 0 for a query.
    let flags = read_u16(payload, 2)?;
    if flags & 0x8000 != 0 {
        // This is a response, not a query.
        return None;
    }

    let qdcount = read_u16(payload, 4)? as usize;
    if qdcount == 0 {
        return None;
    }

    // Parse the first question.
    let (query_name, pos) = parse_dns_name(payload, 12)?;
    if pos + 4 > payload.len() {
        return None;
    }
    let query_type = read_u16(payload, pos)?;
    let query_class = read_u16(payload, pos + 2)?;

    // Tunneling indicators.
    let mut tunneling_indicators = Vec::new();

    // Check for long labels (> 30 chars per label is unusual).
    for label in query_name.split('.') {
        if label.len() > 30 {
            tunneling_indicators
                .push(format!("long_label:{}chars", label.len()));
        }
    }

    // High entropy in the query name (encoded data).
    let name_entropy = shannon_entropy(query_name.as_bytes());
    if name_entropy > 3.5 && query_name.len() > 20 {
        tunneling_indicators.push(format!("high_entropy:{name_entropy:.2}"));
    }

    // TXT record queries are commonly used for tunneling.
    if query_type == 16 {
        tunneling_indicators.push("txt_query".to_string());
    }

    // NULL record queries (type 10) are used by iodine-style tunnels.
    if query_type == 10 {
        tunneling_indicators.push("null_query".to_string());
    }

    // Very long query name overall.
    if query_name.len() > 100 {
        tunneling_indicators.push(format!("long_name:{}chars", query_name.len()));
    }

    // Many labels (deeply nested subdomains).
    let label_count = query_name.split('.').count();
    if label_count > 6 {
        tunneling_indicators.push(format!("many_labels:{label_count}"));
    }

    Some(DnsQueryInfo {
        query_name,
        query_type,
        query_class,
        tunneling_indicators,
    })
}

// ---------------------------------------------------------------------------
// Protocol anomaly detection
// ---------------------------------------------------------------------------

/// Detect protocol/port mismatches and structural anomalies.
fn detect_anomalies(payload: &[u8], dest_port: u16, protocol: DetectedProtocol) -> Vec<ProtocolAnomaly> {
    let mut anomalies = Vec::new();

    // Port/protocol mismatch detection.
    match protocol {
        DetectedProtocol::Ssh => {
            if dest_port == 80 || dest_port == 443 || dest_port == 8080 {
                anomalies.push(ProtocolAnomaly {
                    kind: AnomalyKind::PortProtocolMismatch,
                    detail: format!("SSH traffic on HTTP port {dest_port}"),
                });
            }
        }
        DetectedProtocol::Http => {
            if dest_port == 22 || dest_port == 53 || dest_port == 25 {
                anomalies.push(ProtocolAnomaly {
                    kind: AnomalyKind::PortProtocolMismatch,
                    detail: format!("HTTP traffic on non-HTTP port {dest_port}"),
                });
            }
        }
        DetectedProtocol::Https => {
            if dest_port != 443 && dest_port != 8443 && dest_port != 9001 && dest_port != 9030 {
                // TLS on non-standard port may be legitimate but worth noting.
                if dest_port == 22 || dest_port == 53 || dest_port == 25 || dest_port == 80 {
                    anomalies.push(ProtocolAnomaly {
                        kind: AnomalyKind::PortProtocolMismatch,
                        detail: format!("TLS traffic on unexpected port {dest_port}"),
                    });
                }
            }
        }
        DetectedProtocol::Dns => {
            if dest_port != 53 {
                anomalies.push(ProtocolAnomaly {
                    kind: AnomalyKind::PortProtocolMismatch,
                    detail: format!("DNS traffic on non-DNS port {dest_port}"),
                });
            }
            // Oversized DNS query.
            if payload.len() > 512 {
                anomalies.push(ProtocolAnomaly {
                    kind: AnomalyKind::OversizedDnsQuery,
                    detail: format!("DNS query is {} bytes (> 512)", payload.len()),
                });
            }
        }
        _ => {}
    }

    // Malformed HTTP detection.
    if matches!(protocol, DetectedProtocol::Http)
        && let Ok(text) = std::str::from_utf8(payload)
    {
        let first_line = text.lines().next().unwrap_or("");
        let parts: Vec<&str> = first_line.splitn(3, ' ').collect();
        if parts.len() < 3 || !parts[2].starts_with("HTTP/") {
            anomalies.push(ProtocolAnomaly {
                kind: AnomalyKind::MalformedHeader,
                detail: "HTTP request line missing version".to_string(),
            });
        }
    }

    anomalies
}

// ---------------------------------------------------------------------------
// DPI Engine
// ---------------------------------------------------------------------------

/// Deep packet inspection engine.
pub struct DpiEngine {
    known_bad_ja3: Vec<String>,
}

impl DpiEngine {
    /// Create a new DPI engine with a default set of known-bad JA3 hashes.
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
        if payload.starts_with(b"GET ")
            || payload.starts_with(b"POST ")
            || payload.starts_with(b"PUT ")
            || payload.starts_with(b"DELETE ")
            || payload.starts_with(b"HEAD ")
            || payload.starts_with(b"HTTP/")
        {
            return DetectedProtocol::Http;
        }

        // DNS (standard format: first 2 bytes = length for TCP, or directly for UDP)
        if dest_port == 53 && payload.len() > 12 {
            return DetectedProtocol::Dns;
        }

        // SMTP
        if payload.starts_with(b"220 ")
            || payload.starts_with(b"EHLO ")
            || payload.starts_with(b"HELO ")
        {
            return DetectedProtocol::Smtp;
        }

        // BitTorrent
        if payload.len() > 20 && payload[0] == 19 && &payload[1..20] == b"BitTorrent protocol" {
            return DetectedProtocol::BitTorrent;
        }

        // WireGuard (first byte is message type 1-4, next 3 are reserved zeros)
        if payload.len() >= 4
            && payload[0] >= 1
            && payload[0] <= 4
            && payload[1] == 0
            && payload[2] == 0
            && payload[3] == 0
            && dest_port == 51820
        {
            return DetectedProtocol::Wireguard;
        }

        // OpenVPN (starts with 0x38 or 0x40 on port 1194)
        if dest_port == 1194 && payload.len() > 2 {
            return DetectedProtocol::OpenVpn;
        }

        // Tor (TLS on port 9001 or 9030)
        if (dest_port == 9001 || dest_port == 9030)
            && payload.len() > 5
            && payload[0] == 0x16
            && payload[1] == 0x03
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

    /// Extract JA3 fingerprint from a TLS ClientHello.
    ///
    /// Performs real TLS parsing to compute the standard JA3 hash (MD5 of the
    /// canonical JA3 string). Falls back to a blake3-based hash if the
    /// ClientHello cannot be fully parsed but the record header is valid.
    ///
    /// Returns `None` if the payload is not a TLS record.
    pub fn extract_ja3(&self, payload: &[u8]) -> Option<String> {
        // Must at least have a TLS record header.
        if payload.len() < 6 || payload[0] != 0x16 || payload[1] != 0x03 {
            return None;
        }

        // Try real ClientHello parsing.
        if let Some(parsed) = parse_client_hello(payload) {
            let (_ja3_string, ja3_hash) = compute_ja3(&parsed);
            return Some(ja3_hash);
        }

        // Fallback: hash the raw bytes for a best-effort fingerprint.
        let hash = blake3::hash(&payload[..payload.len().min(512)]);
        let bytes: &[u8; 32] = hash.as_bytes();
        // Safe: we know bytes is 32 long, slicing first 16 always succeeds.
        let arr: [u8; 16] = [
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
        ];
        Some(format!("{:032x}", u128::from_le_bytes(arr)))
    }

    /// Extract the SNI hostname from a TLS ClientHello.
    ///
    /// Returns `None` if the payload is not a valid ClientHello or contains no SNI.
    pub fn extract_sni(&self, payload: &[u8]) -> Option<String> {
        parse_client_hello(payload).and_then(|p| p.sni)
    }

    /// Extract the list of cipher suites from a TLS ClientHello.
    pub fn extract_cipher_suites(&self, payload: &[u8]) -> Vec<u16> {
        parse_client_hello(payload)
            .map(|p| p.cipher_suites)
            .unwrap_or_default()
    }

    /// Parse an HTTP request from the payload.
    pub fn parse_http(&self, payload: &[u8]) -> Option<HttpRequestInfo> {
        parse_http_request(payload)
    }

    /// Parse a DNS query from the payload.
    pub fn parse_dns(&self, payload: &[u8]) -> Option<DnsQueryInfo> {
        parse_dns_query(payload)
    }

    /// Check if a JA3 hash is known-bad.
    pub fn is_suspicious_ja3(&self, ja3: &str) -> bool {
        self.known_bad_ja3.contains(&ja3.to_string())
    }

    /// Full packet inspection.
    ///
    /// Combines protocol detection, TLS fingerprinting, HTTP analysis, DNS
    /// analysis, and anomaly detection into a single [`InspectionResult`].
    pub fn inspect(&self, payload: &[u8], dest_port: u16) -> InspectionResult {
        let protocol = self.detect_protocol(payload, dest_port);

        // TLS fingerprinting.
        let (tls_fp, sni, cipher_suites) =
            if matches!(protocol, DetectedProtocol::Https | DetectedProtocol::Tor) {
                let fp = self.extract_ja3(payload);
                let sni = self.extract_sni(payload);
                let cs = self.extract_cipher_suites(payload);
                (fp, sni, cs)
            } else {
                (None, None, Vec::new())
            };

        // HTTP analysis.
        let http_info = if protocol == DetectedProtocol::Http {
            self.parse_http(payload)
        } else {
            None
        };

        // DNS analysis.
        let dns_info = if protocol == DetectedProtocol::Dns {
            self.parse_dns(payload)
        } else {
            None
        };

        // Anomaly detection.
        let anomalies = detect_anomalies(payload, dest_port, protocol);

        // Determine suspicion.
        let ja3_suspicious = tls_fp.as_ref().is_some_and(|fp| self.is_suspicious_ja3(fp));
        let http_suspicious = http_info
            .as_ref()
            .is_some_and(|h| !h.threat_indicators.is_empty());
        let dns_suspicious = dns_info
            .as_ref()
            .is_some_and(|d| !d.tunneling_indicators.is_empty());
        let anomaly_suspicious = !anomalies.is_empty();

        let suspicious = ja3_suspicious || http_suspicious || dns_suspicious || anomaly_suspicious;

        // Build description.
        let description = if ja3_suspicious {
            format!("Suspicious TLS fingerprint detected on port {dest_port}")
        } else if http_suspicious {
            let indicators = &http_info.as_ref().map(|h| h.threat_indicators.join(", ")).unwrap_or_default();
            format!("HTTP threat indicators on port {dest_port}: {indicators}")
        } else if dns_suspicious {
            let indicators = &dns_info.as_ref().map(|d| d.tunneling_indicators.join(", ")).unwrap_or_default();
            format!("DNS tunneling indicators: {indicators}")
        } else if anomaly_suspicious {
            let details: Vec<_> = anomalies.iter().map(|a| a.detail.clone()).collect();
            format!("Protocol anomalies: {}", details.join(", "))
        } else {
            format!("{:?} traffic on port {dest_port}", protocol)
        };

        InspectionResult {
            protocol,
            tls_fingerprint: tls_fp,
            suspicious,
            description,
            confidence: if protocol == DetectedProtocol::Unknown {
                0.2
            } else {
                0.9
            },
            sni,
            cipher_suites,
            http_info,
            dns_info,
            anomalies,
        }
    }
}

impl Default for DpiEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Existing tests (preserved)
    // -----------------------------------------------------------------------

    #[test]
    fn test_detect_http() {
        let dpi = DpiEngine::new();
        assert_eq!(
            dpi.detect_protocol(b"GET / HTTP/1.1\r\n", 80),
            DetectedProtocol::Http
        );
        assert_eq!(
            dpi.detect_protocol(b"POST /api HTTP/1.1\r\n", 80),
            DetectedProtocol::Http
        );
    }

    #[test]
    fn test_detect_tls() {
        let dpi = DpiEngine::new();
        let client_hello = [0x16, 0x03, 0x01, 0x00, 0x05, 0x01];
        assert_eq!(
            dpi.detect_protocol(&client_hello, 443),
            DetectedProtocol::Https
        );
    }

    #[test]
    fn test_detect_ssh() {
        let dpi = DpiEngine::new();
        assert_eq!(
            dpi.detect_protocol(b"SSH-2.0-OpenSSH_8.9\r\n", 22),
            DetectedProtocol::Ssh
        );
    }

    #[test]
    fn test_detect_dns() {
        let dpi = DpiEngine::new();
        let dns_query = [0x00; 20]; // Minimal DNS-like payload
        assert_eq!(
            dpi.detect_protocol(&dns_query, 53),
            DetectedProtocol::Dns
        );
    }

    #[test]
    fn test_detect_smtp() {
        let dpi = DpiEngine::new();
        assert_eq!(
            dpi.detect_protocol(b"220 mail.example.com ESMTP", 25),
            DetectedProtocol::Smtp
        );
    }

    #[test]
    fn test_port_fallback() {
        let dpi = DpiEngine::new();
        assert_eq!(
            dpi.detect_protocol(&[0x00], 443),
            DetectedProtocol::Https
        );
        assert_eq!(
            dpi.detect_protocol(&[0x00], 22),
            DetectedProtocol::Ssh
        );
    }

    #[test]
    fn test_unknown_protocol() {
        let dpi = DpiEngine::new();
        assert_eq!(
            dpi.detect_protocol(&[0xAB, 0xCD], 12345),
            DetectedProtocol::Unknown
        );
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

    // -----------------------------------------------------------------------
    // New tests: TLS ClientHello parsing, SNI, JA3
    // -----------------------------------------------------------------------

    /// Build a minimal but structurally valid TLS ClientHello.
    fn build_client_hello(sni: &str) -> Vec<u8> {
        // We build a real TLS ClientHello with:
        //   - TLS 1.2 (0x0303)
        //   - 2 cipher suites: TLS_AES_128_GCM_SHA256 (0x1301), TLS_AES_256_GCM_SHA384 (0x1302)
        //   - Extensions: SNI (0x0000), supported_groups (0x000a), ec_point_formats (0x000b)
        //   - Supported groups: x25519 (0x001d), secp256r1 (0x0017)
        //   - EC point formats: uncompressed (0x00)

        let mut hello_body = Vec::new();

        // client_version: TLS 1.2
        hello_body.extend_from_slice(&[0x03, 0x03]);

        // random: 32 bytes of zeros
        hello_body.extend_from_slice(&[0u8; 32]);

        // session_id length: 0
        hello_body.push(0x00);

        // cipher suites: 4 bytes (2 suites)
        hello_body.extend_from_slice(&[0x00, 0x04]); // length
        hello_body.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
        hello_body.extend_from_slice(&[0x13, 0x02]); // TLS_AES_256_GCM_SHA384

        // compression methods: 1 byte, null
        hello_body.push(0x01);
        hello_body.push(0x00);

        // --- Extensions ---
        let mut extensions = Vec::new();

        // SNI extension (type 0x0000)
        {
            let name_bytes = sni.as_bytes();
            let mut sni_data = Vec::new();
            // SNI list length = 1 (type) + 2 (name length) + name
            let sni_list_len = 3 + name_bytes.len();
            sni_data.extend_from_slice(&(sni_list_len as u16).to_be_bytes());
            sni_data.push(0x00); // host_name type
            sni_data.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
            sni_data.extend_from_slice(name_bytes);

            extensions.extend_from_slice(&[0x00, 0x00]); // extension type
            extensions.extend_from_slice(&(sni_data.len() as u16).to_be_bytes());
            extensions.extend_from_slice(&sni_data);
        }

        // Supported Groups extension (type 0x000a)
        {
            let mut groups_data = Vec::new();
            groups_data.extend_from_slice(&[0x00, 0x04]); // groups list length = 4
            groups_data.extend_from_slice(&[0x00, 0x1d]); // x25519
            groups_data.extend_from_slice(&[0x00, 0x17]); // secp256r1

            extensions.extend_from_slice(&[0x00, 0x0a]); // extension type
            extensions.extend_from_slice(&(groups_data.len() as u16).to_be_bytes());
            extensions.extend_from_slice(&groups_data);
        }

        // EC Point Formats extension (type 0x000b)
        {
            let mut ecpf_data = Vec::new();
            ecpf_data.push(0x01); // formats length = 1
            ecpf_data.push(0x00); // uncompressed

            extensions.extend_from_slice(&[0x00, 0x0b]); // extension type
            extensions.extend_from_slice(&(ecpf_data.len() as u16).to_be_bytes());
            extensions.extend_from_slice(&ecpf_data);
        }

        // Extensions total length
        hello_body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        hello_body.extend_from_slice(&extensions);

        // --- Handshake header ---
        let mut handshake = Vec::new();
        handshake.push(0x01); // ClientHello
        // 3-byte length
        let hl = hello_body.len() as u32;
        handshake.push((hl >> 16) as u8);
        handshake.push((hl >> 8) as u8);
        handshake.push(hl as u8);
        handshake.extend_from_slice(&hello_body);

        // --- TLS record header ---
        let mut record = Vec::new();
        record.push(0x16); // Handshake
        record.extend_from_slice(&[0x03, 0x01]); // TLS 1.0 record version (common)
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);

        record
    }

    #[test]
    fn test_tls_sni_extraction() {
        let dpi = DpiEngine::new();
        let payload = build_client_hello("example.com");
        let sni = dpi.extract_sni(&payload);
        assert_eq!(sni.as_deref(), Some("example.com"));
    }

    #[test]
    fn test_tls_cipher_suite_extraction() {
        let dpi = DpiEngine::new();
        let payload = build_client_hello("test.org");
        let cs = dpi.extract_cipher_suites(&payload);
        assert_eq!(cs, vec![0x1301, 0x1302]);
    }

    #[test]
    fn test_tls_ja3_deterministic() {
        let dpi = DpiEngine::new();
        let payload = build_client_hello("example.com");
        let ja3_1 = dpi.extract_ja3(&payload);
        let ja3_2 = dpi.extract_ja3(&payload);
        assert!(ja3_1.is_some());
        assert_eq!(ja3_1, ja3_2, "JA3 must be deterministic");
        // JA3 hash is 32 hex chars.
        assert_eq!(ja3_1.as_ref().map(|s| s.len()), Some(32));
    }

    #[test]
    fn test_tls_inspect_populates_sni_and_ciphers() {
        let dpi = DpiEngine::new();
        let payload = build_client_hello("secure.example.org");
        let result = dpi.inspect(&payload, 443);
        assert_eq!(result.protocol, DetectedProtocol::Https);
        assert_eq!(result.sni.as_deref(), Some("secure.example.org"));
        assert!(!result.cipher_suites.is_empty());
        assert!(result.tls_fingerprint.is_some());
    }

    // -----------------------------------------------------------------------
    // New tests: HTTP analysis
    // -----------------------------------------------------------------------

    #[test]
    fn test_http_suspicious_path_detection() {
        let dpi = DpiEngine::new();
        let payload = b"GET /wp-admin/admin-ajax.php HTTP/1.1\r\nHost: victim.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n";
        let info = dpi.parse_http(payload).expect("should parse HTTP");
        assert_eq!(info.method, "GET");
        assert_eq!(info.host.as_deref(), Some("victim.com"));
        assert!(
            info.threat_indicators.iter().any(|i| i.contains("wp-admin")),
            "should flag /wp-admin as suspicious"
        );
    }

    #[test]
    fn test_http_sqli_detection() {
        let dpi = DpiEngine::new();
        let payload = b"GET /search?q=1'%20or%20'1'='1 HTTP/1.1\r\nHost: target.com\r\n\r\n";
        let info = dpi.parse_http(payload).expect("should parse HTTP");
        assert!(
            info.threat_indicators.iter().any(|i| i.starts_with("sqli:")),
            "should detect SQL injection: {:?}",
            info.threat_indicators
        );
    }

    #[test]
    fn test_http_cmdi_detection() {
        let dpi = DpiEngine::new();
        let payload = b"GET /api/ping?host=127.0.0.1;cat%20/etc/passwd HTTP/1.1\r\nHost: target.com\r\n\r\n";
        let info = dpi.parse_http(payload).expect("should parse HTTP");
        assert!(
            info.threat_indicators.iter().any(|i| i.starts_with("cmdi:")),
            "should detect command injection: {:?}",
            info.threat_indicators
        );
    }

    #[test]
    fn test_http_clean_request_no_threats() {
        let dpi = DpiEngine::new();
        let payload = b"GET /index.html HTTP/1.1\r\nHost: safe.com\r\nUser-Agent: curl/7.88\r\n\r\n";
        let info = dpi.parse_http(payload).expect("should parse HTTP");
        assert_eq!(info.method, "GET");
        assert_eq!(info.path, "/index.html");
        assert!(
            info.threat_indicators.is_empty(),
            "clean request should have no threats: {:?}",
            info.threat_indicators
        );
    }

    // -----------------------------------------------------------------------
    // New tests: DNS parsing
    // -----------------------------------------------------------------------

    /// Build a minimal DNS query for a given domain name and query type.
    fn build_dns_query(domain: &str, qtype: u16) -> Vec<u8> {
        let mut pkt = Vec::new();

        // Header: transaction ID
        pkt.extend_from_slice(&[0xAB, 0xCD]);
        // Flags: standard query (QR=0, OPCODE=0, RD=1)
        pkt.extend_from_slice(&[0x01, 0x00]);
        // QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
        pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

        // Question: encode domain name in wire format.
        for label in domain.split('.') {
            pkt.push(label.len() as u8);
            pkt.extend_from_slice(label.as_bytes());
        }
        pkt.push(0x00); // root label

        // QTYPE
        pkt.extend_from_slice(&qtype.to_be_bytes());
        // QCLASS = IN (1)
        pkt.extend_from_slice(&[0x00, 0x01]);

        pkt
    }

    #[test]
    fn test_dns_query_name_parsing() {
        let dpi = DpiEngine::new();
        let payload = build_dns_query("example.com", 1); // A record
        let info = dpi.parse_dns(&payload).expect("should parse DNS query");
        assert_eq!(info.query_name, "example.com");
        assert_eq!(info.query_type, 1);
        assert_eq!(info.query_class, 1);
        assert!(
            info.tunneling_indicators.is_empty(),
            "normal query should have no tunneling indicators"
        );
    }

    #[test]
    fn test_dns_tunneling_detection() {
        let dpi = DpiEngine::new();
        // Simulate a tunneling query: long random-looking subdomain + TXT type.
        let tunnel_domain =
            "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Q.x2k9m.data.evil-tunnel.com";
        let payload = build_dns_query(tunnel_domain, 16); // TXT
        let info = dpi.parse_dns(&payload).expect("should parse DNS query");
        assert_eq!(info.query_name, tunnel_domain);
        assert!(
            info.tunneling_indicators.iter().any(|i| i.contains("long_label")),
            "should detect long label: {:?}",
            info.tunneling_indicators
        );
        assert!(
            info.tunneling_indicators.iter().any(|i| i == "txt_query"),
            "should flag TXT query: {:?}",
            info.tunneling_indicators
        );
    }

    // -----------------------------------------------------------------------
    // New tests: Protocol anomaly detection
    // -----------------------------------------------------------------------

    #[test]
    fn test_port_protocol_mismatch_ssh_on_80() {
        let dpi = DpiEngine::new();
        // SSH banner on port 80 (HTTP port).
        let result = dpi.inspect(b"SSH-2.0-OpenSSH_8.9\r\n", 80);
        assert_eq!(result.protocol, DetectedProtocol::Ssh);
        assert!(result.suspicious, "SSH on port 80 should be suspicious");
        assert!(
            result.anomalies.iter().any(|a| a.kind == AnomalyKind::PortProtocolMismatch),
            "should report PortProtocolMismatch anomaly"
        );
    }

    #[test]
    fn test_oversized_dns_query_anomaly() {
        let dpi = DpiEngine::new();
        // Build a huge DNS query payload (> 512 bytes).
        let mut huge_dns = build_dns_query("normal.com", 1);
        huge_dns.resize(600, 0x00); // pad to 600 bytes
        let result = dpi.inspect(&huge_dns, 53);
        assert_eq!(result.protocol, DetectedProtocol::Dns);
        assert!(
            result.anomalies.iter().any(|a| a.kind == AnomalyKind::OversizedDnsQuery),
            "should flag oversized DNS query"
        );
    }

    #[test]
    fn test_http_on_ssh_port_anomaly() {
        let dpi = DpiEngine::new();
        let result = dpi.inspect(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n", 22);
        assert_eq!(result.protocol, DetectedProtocol::Http);
        assert!(
            result.anomalies.iter().any(|a| a.kind == AnomalyKind::PortProtocolMismatch),
            "HTTP on port 22 should flag mismatch"
        );
    }

    #[test]
    fn test_malformed_http_missing_version() {
        let dpi = DpiEngine::new();
        // HTTP-like request without version string.
        let result = dpi.inspect(b"GET /path\r\n\r\n", 80);
        assert_eq!(result.protocol, DetectedProtocol::Http);
        assert!(
            result.anomalies.iter().any(|a| a.kind == AnomalyKind::MalformedHeader),
            "should detect malformed HTTP header: {:?}",
            result.anomalies
        );
    }
}
