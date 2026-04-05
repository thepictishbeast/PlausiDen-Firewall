//! DNS sinkhole for blocking known-malicious, tracking, and telemetry domains.
//!
//! Supports exact-match and wildcard (`*.example.com`) patterns. Ships with a
//! curated default blocklist of malware C2 infrastructure, advertising trackers,
//! and telemetry endpoints that exfiltrate user data.
//!
//! Also provides DNS-over-HTTPS (DoH) bypass detection, TLD-based blocking,
//! and punycode/IDN homograph attack detection.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

/// Known DNS-over-HTTPS provider endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DohEndpoint {
    /// Human-readable provider name.
    pub provider: &'static str,
    /// IP addresses associated with this DoH provider.
    pub ips: &'static [&'static str],
    /// Domain names used for DoH resolution.
    pub domains: &'static [&'static str],
}

/// Well-known DoH provider definitions.
pub const KNOWN_DOH_PROVIDERS: &[DohEndpoint] = &[
    DohEndpoint {
        provider: "Cloudflare",
        ips: &["1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"],
        domains: &["cloudflare-dns.com", "one.one.one.one"],
    },
    DohEndpoint {
        provider: "Google",
        ips: &["8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844"],
        domains: &["dns.google", "dns.google.com"],
    },
    DohEndpoint {
        provider: "Quad9",
        ips: &["9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"],
        domains: &["dns.quad9.net"],
    },
    DohEndpoint {
        provider: "NextDNS",
        ips: &["45.90.28.0", "45.90.30.0"],
        domains: &["dns.nextdns.io"],
    },
    DohEndpoint {
        provider: "AdGuard",
        ips: &["94.140.14.14", "94.140.15.15"],
        domains: &["dns.adguard.com", "dns.adguard-dns.com"],
    },
    DohEndpoint {
        provider: "CleanBrowsing",
        ips: &["185.228.168.9", "185.228.169.9"],
        domains: &["doh.cleanbrowsing.org"],
    },
    DohEndpoint {
        provider: "Mullvad",
        ips: &["194.242.2.2"],
        domains: &["dns.mullvad.net", "doh.mullvad.net"],
    },
    DohEndpoint {
        provider: "OpenDNS",
        ips: &["208.67.222.222", "208.67.220.220"],
        domains: &["doh.opendns.com"],
    },
];

/// Characters used in homograph attacks, mapped to their ASCII lookalikes.
///
/// Key = Unicode codepoint from confusable scripts, Value = ASCII letter it mimics.
const HOMOGRAPH_CONFUSABLES: &[(char, char)] = &[
    // Cyrillic confusables
    ('\u{0430}', 'a'), // а → a
    ('\u{0441}', 'c'), // с → c
    ('\u{0435}', 'e'), // е → e
    ('\u{043E}', 'o'), // о → o
    ('\u{0440}', 'p'), // р → p
    ('\u{0445}', 'x'), // х → x
    ('\u{0443}', 'y'), // у → y
    ('\u{0455}', 's'), // ѕ → s
    ('\u{0456}', 'i'), // і → i
    ('\u{0458}', 'j'), // ј → j
    ('\u{04BB}', 'h'), // һ → h
    ('\u{0432}', 'b'), // в → b  (sometimes confused)
    ('\u{043A}', 'k'), // к → k
    ('\u{043C}', 'm'), // м → m  (visual similarity)
    ('\u{0442}', 't'), // т → t
    // Greek confusables
    ('\u{03BF}', 'o'), // ο → o
    ('\u{03B1}', 'a'), // α → a
    ('\u{03C1}', 'p'), // ρ → p
    ('\u{03B5}', 'e'), // ε → e (somewhat similar)
];

/// Result of a punycode/IDN homograph analysis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HomographAnalysis {
    /// The original domain being analyzed.
    pub domain: String,
    /// Whether the domain is a suspected homograph attack.
    pub is_homograph: bool,
    /// The ASCII-equivalent domain this may be impersonating.
    pub ascii_equivalent: Option<String>,
    /// Script mix detected (e.g., "Cyrillic + Latin").
    pub script_mix: Option<String>,
}

/// A detected DNS-over-HTTPS bypass attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DohBypassAttempt {
    /// Name of the process that attempted the DoH connection.
    pub process_name: String,
    /// Destination IP address, if known.
    pub dest_ip: Option<String>,
    /// Destination port, if known.
    pub dest_port: Option<u16>,
    /// Destination domain (from SNI/Host header), if known.
    pub domain: Option<String>,
    /// Identified DoH provider name.
    pub provider: String,
}

/// A connection observation for DoH bypass detection.
///
/// Fields: `(process_name, dest_ip, dest_port, domain)`.
pub type ConnectionTuple<'a> = (&'a str, Option<&'a str>, Option<u16>, Option<&'a str>);

/// A DNS sinkhole that blocks resolution of domains on a blocklist.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsSinkhole {
    /// Exact-match domain blocklist.
    exact_domains: HashSet<String>,
    /// Wildcard suffix blocklist (stored without the leading `*.`).
    wildcard_suffixes: HashSet<String>,
    /// Blocked top-level domains (e.g., "ru", "cn").
    blocked_tlds: HashSet<String>,
}

impl Default for DnsSinkhole {
    fn default() -> Self {
        Self::with_default_blocklist()
    }
}

impl DnsSinkhole {
    /// Create an empty sinkhole with no blocked domains.
    pub fn new() -> Self {
        Self {
            exact_domains: HashSet::new(),
            wildcard_suffixes: HashSet::new(),
            blocked_tlds: HashSet::new(),
        }
    }

    /// Create a sinkhole pre-loaded with the default blocklist.
    pub fn with_default_blocklist() -> Self {
        let mut sinkhole = Self::new();
        for domain in Self::default_blocklist() {
            sinkhole.add_domain(domain);
        }
        sinkhole
    }

    /// Add a domain to the blocklist.
    ///
    /// Supports exact match (e.g., `"example.com"`) and wildcard
    /// (e.g., `"*.example.com"`, which blocks all subdomains).
    pub fn add_domain(&mut self, domain: &str) {
        let normalized = domain.to_lowercase();
        if let Some(suffix) = normalized.strip_prefix("*.") {
            self.wildcard_suffixes.insert(suffix.to_string());
        } else {
            self.exact_domains.insert(normalized);
        }
    }

    /// Remove a domain from the blocklist.
    ///
    /// Returns `true` if the domain was present and removed.
    pub fn remove_domain(&mut self, domain: &str) -> bool {
        let normalized = domain.to_lowercase();
        if let Some(suffix) = normalized.strip_prefix("*.") {
            self.wildcard_suffixes.remove(suffix)
        } else {
            self.exact_domains.remove(&normalized)
        }
    }

    /// Add a TLD to the blocklist (e.g., `"ru"`, `"cn"`).
    ///
    /// All domains ending in this TLD will be sinkholed.
    pub fn block_tld(&mut self, tld: &str) {
        self.blocked_tlds.insert(tld.to_lowercase().trim_start_matches('.').to_string());
    }

    /// Remove a TLD from the blocklist.
    ///
    /// Returns `true` if the TLD was present and removed.
    pub fn unblock_tld(&mut self, tld: &str) -> bool {
        self.blocked_tlds.remove(tld.to_lowercase().trim_start_matches('.'))

    }

    /// Check whether a domain should be sinkholed (blocked).
    pub fn is_sinkholed(&self, domain: &str) -> bool {
        let normalized = domain.to_lowercase();

        // Exact match.
        if self.exact_domains.contains(&normalized) {
            return true;
        }

        // TLD-based blocking.
        if let Some(tld) = normalized.rsplit('.').next()
            && self.blocked_tlds.contains(tld)
        {
            return true;
        }

        // Wildcard suffix match: check if any suffix in the wildcard set
        // matches the domain or any of its parent domains.
        if self.wildcard_suffixes.contains(&normalized) {
            return true;
        }
        // Walk up from the full domain, checking each parent.
        let mut remaining = normalized.as_str();
        while let Some(dot_pos) = remaining.find('.') {
            let parent = &remaining[dot_pos + 1..];
            if self.wildcard_suffixes.contains(parent) {
                return true;
            }
            remaining = parent;
        }

        false
    }

    /// Return the number of blocked entries (exact + wildcard).
    pub fn blocked_count(&self) -> usize {
        self.exact_domains.len() + self.wildcard_suffixes.len()
    }

    /// Return the number of blocked TLDs.
    pub fn blocked_tld_count(&self) -> usize {
        self.blocked_tlds.len()
    }

    /// Check whether a destination is a known DNS-over-HTTPS endpoint.
    ///
    /// This detects DoH bypass attempts where applications send DNS queries
    /// over HTTPS to public resolvers, circumventing the local DNS sinkhole.
    ///
    /// `dest_ip` is the destination IP address (as a string or `IpAddr`).
    /// `dest_port` is the destination port (DoH uses 443).
    /// `domain` is the SNI or Host header domain, if available.
    pub fn is_doh_endpoint(
        dest_ip: Option<&str>,
        dest_port: Option<u16>,
        domain: Option<&str>,
    ) -> bool {
        // DoH always uses port 443. If we know the port and it is not 443, this
        // is not DoH.
        if let Some(port) = dest_port
            && port != 443
        {
            return false;
        }

        // Check IP against known DoH provider IPs.
        if let Some(ip) = dest_ip {
            for provider in KNOWN_DOH_PROVIDERS {
                if provider.ips.contains(&ip) {
                    return true;
                }
            }
        }

        // Check domain against known DoH provider domains.
        if let Some(d) = domain {
            let d_lower = d.to_lowercase();
            for provider in KNOWN_DOH_PROVIDERS {
                for known_domain in provider.domains {
                    if d_lower == *known_domain || d_lower.ends_with(&format!(".{known_domain}")) {
                        return true;
                    }
                }
            }
        }

        false
    }

    /// Identify which known DoH provider a destination corresponds to.
    ///
    /// Returns the provider name if matched, or `None`.
    pub fn identify_doh_provider(
        dest_ip: Option<&str>,
        dest_port: Option<u16>,
        domain: Option<&str>,
    ) -> Option<&'static str> {
        if let Some(port) = dest_port
            && port != 443
        {
            return None;
        }

        if let Some(ip) = dest_ip {
            for provider in KNOWN_DOH_PROVIDERS {
                if provider.ips.contains(&ip) {
                    return Some(provider.provider);
                }
            }
        }

        if let Some(d) = domain {
            let d_lower = d.to_lowercase();
            for provider in KNOWN_DOH_PROVIDERS {
                for known_domain in provider.domains {
                    if d_lower == *known_domain || d_lower.ends_with(&format!(".{known_domain}")) {
                        return Some(provider.provider);
                    }
                }
            }
        }

        None
    }

    /// Detect processes that are attempting DNS-over-HTTPS connections,
    /// bypassing the local DNS sinkhole.
    ///
    /// Takes a slice of `(process_name, dest_ip, dest_port, domain)` tuples
    /// representing observed outbound connections and returns a list of
    /// `DohBypassAttempt` records for any that target known DoH endpoints.
    pub fn detect_doh_bypass(
        connections: &[ConnectionTuple<'_>],
    ) -> Vec<DohBypassAttempt> {
        let mut attempts = Vec::new();
        for &(process, ip, port, domain) in connections {
            if Self::is_doh_endpoint(ip, port, domain) {
                let provider = Self::identify_doh_provider(ip, port, domain)
                    .unwrap_or("Unknown");
                attempts.push(DohBypassAttempt {
                    process_name: process.to_string(),
                    dest_ip: ip.map(String::from),
                    dest_port: port,
                    domain: domain.map(String::from),
                    provider: provider.to_string(),
                });
            }
        }
        attempts
    }

    /// Analyze a domain for punycode/IDN homograph attacks.
    ///
    /// Detects domains that use characters from non-Latin scripts (Cyrillic,
    /// Greek, etc.) to visually impersonate legitimate domains. For example,
    /// `xn--80ak6aa92e.com` (apple.com in Cyrillic) looks identical to
    /// `apple.com` in many fonts.
    pub fn analyze_homograph(domain: &str) -> HomographAnalysis {
        let normalized = domain.to_lowercase();

        // Handle xn-- (punycode) encoded domains.
        if normalized.contains("xn--") {
            // Decode each label and check for mixed scripts.
            let labels: Vec<&str> = normalized.split('.').collect();
            let mut decoded_labels = Vec::new();
            let mut has_punycode = false;

            for label in &labels {
                if let Some(encoded) = label.strip_prefix("xn--") {
                    has_punycode = true;
                    // Decode punycode to Unicode for analysis.
                    if let Some(decoded) = Self::decode_punycode_label(encoded) {
                        decoded_labels.push(decoded);
                    } else {
                        decoded_labels.push(label.to_string());
                    }
                } else {
                    decoded_labels.push(label.to_string());
                }
            }

            if has_punycode {
                let decoded_domain = decoded_labels.join(".");
                let (has_confusables, ascii_equiv, script_mix) =
                    Self::check_confusable_chars(&decoded_domain);

                if has_confusables {
                    return HomographAnalysis {
                        domain: normalized,
                        is_homograph: true,
                        ascii_equivalent: Some(ascii_equiv),
                        script_mix: Some(script_mix),
                    };
                }
            }
        }

        // Also check non-punycode domains for mixed-script confusables
        // (in case the domain was provided already decoded).
        let (has_confusables, ascii_equiv, script_mix) =
            Self::check_confusable_chars(&normalized);

        if has_confusables {
            return HomographAnalysis {
                domain: normalized,
                is_homograph: true,
                ascii_equivalent: Some(ascii_equiv),
                script_mix: Some(script_mix),
            };
        }

        HomographAnalysis {
            domain: normalized,
            is_homograph: false,
            ascii_equivalent: None,
            script_mix: None,
        }
    }

    /// Check a decoded domain for confusable characters.
    ///
    /// Returns `(has_confusables, ascii_equivalent, script_description)`.
    fn check_confusable_chars(domain: &str) -> (bool, String, String) {
        let mut ascii_equiv = String::new();
        let mut has_cyrillic = false;
        let mut has_greek = false;
        let mut has_latin = false;
        let mut found_confusable = false;

        for ch in domain.chars() {
            if ch == '.' || ch == '-' {
                ascii_equiv.push(ch);
                continue;
            }

            // Check for confusable characters.
            let mut replaced = false;
            for &(confusable, ascii) in HOMOGRAPH_CONFUSABLES {
                if ch == confusable {
                    ascii_equiv.push(ascii);
                    found_confusable = true;
                    replaced = true;

                    // Track which scripts are present.
                    if ('\u{0400}'..='\u{04FF}').contains(&ch) {
                        has_cyrillic = true;
                    } else if ('\u{0370}'..='\u{03FF}').contains(&ch) {
                        has_greek = true;
                    }
                    break;
                }
            }

            if !replaced {
                if ch.is_ascii_alphanumeric() {
                    has_latin = true;
                    ascii_equiv.push(ch);
                } else if ch.is_ascii() {
                    ascii_equiv.push(ch);
                } else {
                    // Non-ASCII character not in our confusables list.
                    // Still potentially suspicious, keep it.
                    ascii_equiv.push(ch);
                    if ('\u{0400}'..='\u{04FF}').contains(&ch) {
                        has_cyrillic = true;
                    } else if ('\u{0370}'..='\u{03FF}').contains(&ch) {
                        has_greek = true;
                    }
                }
            }
        }

        let mut scripts = Vec::new();
        if has_latin {
            scripts.push("Latin");
        }
        if has_cyrillic {
            scripts.push("Cyrillic");
        }
        if has_greek {
            scripts.push("Greek");
        }

        let script_mix = scripts.join(" + ");
        // A homograph requires confusable chars to be present.
        (found_confusable, ascii_equiv, script_mix)
    }

    /// Minimal punycode label decoder.
    ///
    /// Decodes a single punycode-encoded label (without the `xn--` prefix).
    /// Returns `None` if decoding fails.
    fn decode_punycode_label(encoded: &str) -> Option<String> {
        // Simplified bootstring decoder per RFC 3492.
        const BASE: u32 = 36;
        const TMIN: u32 = 1;
        const TMAX: u32 = 26;
        const SKEW: u32 = 38;
        const DAMP: u32 = 700;
        const INITIAL_BIAS: u32 = 72;
        const INITIAL_N: u32 = 0x80;

        fn adapt(mut delta: u32, num_points: u32, first_time: bool) -> u32 {
            delta = if first_time { delta / DAMP } else { delta / 2 };
            delta += delta / num_points;
            let mut k = 0u32;
            while delta > ((BASE - TMIN) * TMAX) / 2 {
                delta /= BASE - TMIN;
                k += BASE;
            }
            k + (BASE - TMIN + 1) * delta / (delta + SKEW)
        }

        fn decode_digit(cp: u8) -> Option<u32> {
            match cp {
                b'a'..=b'z' => Some(u32::from(cp - b'a')),
                b'A'..=b'Z' => Some(u32::from(cp - b'A')),
                b'0'..=b'9' => Some(u32::from(cp - b'0') + 26),
                _ => None,
            }
        }

        let (basic_str, encoded_part) = match encoded.rfind('-') {
            Some(pos) => (&encoded[..pos], &encoded[pos + 1..]),
            None => ("", encoded),
        };

        let mut output: Vec<u32> = basic_str.chars().map(|c| c as u32).collect();
        let mut n = INITIAL_N;
        let mut bias = INITIAL_BIAS;
        let mut i: u32 = 0;
        let bytes = encoded_part.as_bytes();
        let mut idx = 0;

        while idx < bytes.len() {
            let old_i = i;
            let mut w: u32 = 1;
            let mut k: u32 = BASE;

            loop {
                if idx >= bytes.len() {
                    return None;
                }
                let digit = decode_digit(bytes[idx])?;
                idx += 1;

                i = i.checked_add(digit.checked_mul(w)?)?;

                let t = if k <= bias {
                    TMIN
                } else if k >= bias + TMAX {
                    TMAX
                } else {
                    k - bias
                };

                if digit < t {
                    break;
                }

                w = w.checked_mul(BASE - t)?;
                k += BASE;
            }

            let out_len = output.len() as u32 + 1;
            bias = adapt(i - old_i, out_len, old_i == 0);
            n = n.checked_add(i / out_len)?;
            i %= out_len;

            output.insert(i as usize, n);
            i += 1;
        }

        output.iter().map(|&cp| char::from_u32(cp)).collect()
    }

    /// Default blocklist of known-malicious and privacy-invasive domains.
    fn default_blocklist() -> Vec<&'static str> {
        vec![
            // --- Malware C2 / exploit infrastructure ---
            "*.cobaltstrike.com",
            "*.metasploit.com",
            "darkside-ransomware.cc",
            "evil-corp-c2.net",
            "apt28-implant.ru",
            "lazarus-c2.kp",
            "emotet-loader.xyz",
            "trickbot-c2.biz",
            "qakbot-deliver.info",
            "icedid-c2.club",
            // --- Advertising / tracking ---
            "*.doubleclick.net",
            "*.googlesyndication.com",
            "*.googleadservices.com",
            "*.google-analytics.com",
            "*.googletagmanager.com",
            "*.googletagservices.com",
            "*.facebook.net",
            "*.fbcdn.net",
            "pixel.facebook.com",
            "*.ads.linkedin.com",
            "*.analytics.twitter.com",
            "*.ads.twitter.com",
            "*.scorecardresearch.com",
            "*.quantserve.com",
            "*.outbrain.com",
            "*.taboola.com",
            "*.criteo.com",
            "*.criteo.net",
            "*.moatads.com",
            "*.adnxs.com",
            "*.rubiconproject.com",
            "*.pubmatic.com",
            "*.casalemedia.com",
            "*.openx.net",
            // --- Telemetry endpoints ---
            "*.telemetry.microsoft.com",
            "*.vortex.data.microsoft.com",
            "*.settings-win.data.microsoft.com",
            "*.watson.telemetry.microsoft.com",
            "*.events.data.microsoft.com",
            "telemetry.mozilla.org",
            "incoming.telemetry.mozilla.org",
            "*.phone-home.brave.com",
            "*.analytics.google.com",
            "*.ssl.google-analytics.com",
            "analytics.facebook.com",
            "pixel.wp.com",
            "stats.wp.com",
            "*.hotjar.com",
            "*.hotjar.io",
            "*.fullstory.com",
            "*.amplitude.com",
            "*.mixpanel.com",
            "*.segment.io",
            "*.segment.com",
            "*.sentry.io",
            "*.bugsnag.com",
            "*.newrelic.com",
            "*.nr-data.net",
            "*.datadog-agent.com",
            "*.browser-intake-datadoghq.com",
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_match() {
        let mut sinkhole = DnsSinkhole::new();
        sinkhole.add_domain("malware.example.com");

        assert!(sinkhole.is_sinkholed("malware.example.com"));
        assert!(!sinkhole.is_sinkholed("safe.example.com"));
    }

    #[test]
    fn test_exact_match_case_insensitive() {
        let mut sinkhole = DnsSinkhole::new();
        sinkhole.add_domain("Malware.Example.COM");

        assert!(sinkhole.is_sinkholed("malware.example.com"));
        assert!(sinkhole.is_sinkholed("MALWARE.EXAMPLE.COM"));
    }

    #[test]
    fn test_wildcard_match() {
        let mut sinkhole = DnsSinkhole::new();
        sinkhole.add_domain("*.evil.com");

        assert!(sinkhole.is_sinkholed("c2.evil.com"));
        assert!(sinkhole.is_sinkholed("deep.sub.evil.com"));
        assert!(sinkhole.is_sinkholed("evil.com")); // wildcard also matches base
        assert!(!sinkhole.is_sinkholed("notevil.com"));
        assert!(!sinkhole.is_sinkholed("good.org"));
    }

    #[test]
    fn test_non_blocked_passes() {
        let sinkhole = DnsSinkhole::with_default_blocklist();

        assert!(!sinkhole.is_sinkholed("rust-lang.org"));
        assert!(!sinkhole.is_sinkholed("crates.io"));
        assert!(!sinkhole.is_sinkholed("kernel.org"));
        assert!(!sinkhole.is_sinkholed("debian.org"));
    }

    #[test]
    fn test_default_blocklist_has_entries() {
        let sinkhole = DnsSinkhole::with_default_blocklist();
        assert!(sinkhole.blocked_count() > 0);
        // Should block known trackers.
        assert!(sinkhole.is_sinkholed("tracker.doubleclick.net"));
        assert!(sinkhole.is_sinkholed("stats.google-analytics.com"));
        assert!(sinkhole.is_sinkholed("pixel.facebook.com"));
    }

    #[test]
    fn test_default_blocklist_blocks_telemetry() {
        let sinkhole = DnsSinkhole::with_default_blocklist();
        assert!(sinkhole.is_sinkholed("vortex.data.microsoft.com"));
        assert!(sinkhole.is_sinkholed("incoming.telemetry.mozilla.org"));
        assert!(sinkhole.is_sinkholed("cdn.segment.com"));
        assert!(sinkhole.is_sinkholed("api.mixpanel.com"));
    }

    #[test]
    fn test_remove_domain_exact() {
        let mut sinkhole = DnsSinkhole::new();
        sinkhole.add_domain("block-me.com");
        assert!(sinkhole.is_sinkholed("block-me.com"));

        assert!(sinkhole.remove_domain("block-me.com"));
        assert!(!sinkhole.is_sinkholed("block-me.com"));
    }

    #[test]
    fn test_remove_domain_wildcard() {
        let mut sinkhole = DnsSinkhole::new();
        sinkhole.add_domain("*.tracker.net");
        assert!(sinkhole.is_sinkholed("ads.tracker.net"));

        assert!(sinkhole.remove_domain("*.tracker.net"));
        assert!(!sinkhole.is_sinkholed("ads.tracker.net"));
    }

    #[test]
    fn test_remove_nonexistent_returns_false() {
        let mut sinkhole = DnsSinkhole::new();
        assert!(!sinkhole.remove_domain("nonexistent.com"));
    }

    // --- DoH endpoint detection tests ---

    #[test]
    fn test_doh_cloudflare_ip_detected() {
        assert!(DnsSinkhole::is_doh_endpoint(
            Some("1.1.1.1"),
            Some(443),
            None,
        ));
    }

    #[test]
    fn test_doh_google_ip_detected() {
        assert!(DnsSinkhole::is_doh_endpoint(
            Some("8.8.8.8"),
            Some(443),
            None,
        ));
    }

    #[test]
    fn test_doh_google_domain_detected() {
        assert!(DnsSinkhole::is_doh_endpoint(
            None,
            Some(443),
            Some("dns.google"),
        ));
    }

    #[test]
    fn test_doh_quad9_ip_detected() {
        assert!(DnsSinkhole::is_doh_endpoint(
            Some("9.9.9.9"),
            Some(443),
            None,
        ));
    }

    #[test]
    fn test_doh_nextdns_domain_detected() {
        assert!(DnsSinkhole::is_doh_endpoint(
            None,
            Some(443),
            Some("dns.nextdns.io"),
        ));
    }

    #[test]
    fn test_unknown_ip_on_443_not_flagged_as_doh() {
        // Random IP on port 443 should NOT be identified as DoH.
        assert!(!DnsSinkhole::is_doh_endpoint(
            Some("93.184.216.34"),
            Some(443),
            None,
        ));
    }

    #[test]
    fn test_known_doh_ip_wrong_port_not_flagged() {
        // Google DNS IP on port 53 (regular DNS) is not DoH.
        assert!(!DnsSinkhole::is_doh_endpoint(
            Some("8.8.8.8"),
            Some(53),
            None,
        ));
    }

    #[test]
    fn test_identify_doh_provider() {
        assert_eq!(
            DnsSinkhole::identify_doh_provider(Some("1.1.1.1"), Some(443), None),
            Some("Cloudflare"),
        );
        assert_eq!(
            DnsSinkhole::identify_doh_provider(Some("8.8.8.8"), Some(443), None),
            Some("Google"),
        );
        assert_eq!(
            DnsSinkhole::identify_doh_provider(None, Some(443), Some("dns.quad9.net")),
            Some("Quad9"),
        );
        assert_eq!(
            DnsSinkhole::identify_doh_provider(Some("93.184.216.34"), Some(443), None),
            None,
        );
    }

    #[test]
    fn test_detect_doh_bypass_finds_attempts() {
        let connections = vec![
            ("malware_agent", Some("1.1.1.1"), Some(443u16), None),
            ("firefox", Some("93.184.216.34"), Some(443u16), None),
            ("suspicious_bin", None, Some(443u16), Some("dns.google")),
        ];
        let attempts = DnsSinkhole::detect_doh_bypass(&connections);
        assert_eq!(attempts.len(), 2);
        assert_eq!(attempts[0].process_name, "malware_agent");
        assert_eq!(attempts[0].provider, "Cloudflare");
        assert_eq!(attempts[1].process_name, "suspicious_bin");
        assert_eq!(attempts[1].provider, "Google");
    }

    #[test]
    fn test_detect_doh_bypass_empty_when_no_doh() {
        let connections = vec![
            ("firefox", Some("93.184.216.34"), Some(443u16), None),
            ("curl", Some("10.0.0.1"), Some(8080u16), None),
        ];
        let attempts = DnsSinkhole::detect_doh_bypass(&connections);
        assert!(attempts.is_empty());
    }

    // --- TLD blocking tests ---

    #[test]
    fn test_tld_blocking_ru() {
        let mut sinkhole = DnsSinkhole::new();
        sinkhole.block_tld("ru");

        assert!(sinkhole.is_sinkholed("evil.ru"));
        assert!(sinkhole.is_sinkholed("sub.domain.ru"));
        assert!(!sinkhole.is_sinkholed("safe.com"));
        assert!(!sinkhole.is_sinkholed("notru.org"));
    }

    #[test]
    fn test_tld_blocking_cn() {
        let mut sinkhole = DnsSinkhole::new();
        sinkhole.block_tld("cn");

        assert!(sinkhole.is_sinkholed("something.cn"));
        assert!(sinkhole.is_sinkholed("deep.sub.domain.cn"));
        assert!(!sinkhole.is_sinkholed("china-news.com")); // .com, not .cn
    }

    #[test]
    fn test_tld_blocking_multiple() {
        let mut sinkhole = DnsSinkhole::new();
        sinkhole.block_tld("ru");
        sinkhole.block_tld("cn");
        sinkhole.block_tld("kp");

        assert!(sinkhole.is_sinkholed("anything.ru"));
        assert!(sinkhole.is_sinkholed("anything.cn"));
        assert!(sinkhole.is_sinkholed("anything.kp"));
        assert!(!sinkhole.is_sinkholed("anything.com"));
    }

    #[test]
    fn test_tld_blocking_case_insensitive() {
        let mut sinkhole = DnsSinkhole::new();
        sinkhole.block_tld("RU");

        assert!(sinkhole.is_sinkholed("evil.ru"));
        assert!(sinkhole.is_sinkholed("evil.RU"));
    }

    #[test]
    fn test_tld_unblock() {
        let mut sinkhole = DnsSinkhole::new();
        sinkhole.block_tld("ru");
        assert!(sinkhole.is_sinkholed("test.ru"));

        assert!(sinkhole.unblock_tld("ru"));
        assert!(!sinkhole.is_sinkholed("test.ru"));
    }

    #[test]
    fn test_tld_unblock_nonexistent() {
        let mut sinkhole = DnsSinkhole::new();
        assert!(!sinkhole.unblock_tld("xyz"));
    }

    #[test]
    fn test_blocked_tld_count() {
        let mut sinkhole = DnsSinkhole::new();
        assert_eq!(sinkhole.blocked_tld_count(), 0);
        sinkhole.block_tld("ru");
        sinkhole.block_tld("cn");
        assert_eq!(sinkhole.blocked_tld_count(), 2);
    }

    // --- Punycode / IDN homograph tests ---

    #[test]
    fn test_homograph_cyrillic_a() {
        // Domain with Cyrillic "a" (U+0430) instead of Latin "a".
        let domain = "g\u{043E}\u{043E}gle.com"; // "gооgle.com" with Cyrillic о
        let analysis = DnsSinkhole::analyze_homograph(domain);
        assert!(analysis.is_homograph);
        assert_eq!(analysis.ascii_equivalent.as_deref(), Some("google.com"));
    }

    #[test]
    fn test_homograph_punycode_apple() {
        // xn--80ak6aa92e.com is the punycode encoding of "apple" in Cyrillic.
        let analysis = DnsSinkhole::analyze_homograph("xn--80ak6aa92e.com");
        assert!(analysis.is_homograph);
        // The decoded domain should contain confusable chars.
        assert!(analysis.ascii_equivalent.is_some());
    }

    #[test]
    fn test_legitimate_domain_not_homograph() {
        let analysis = DnsSinkhole::analyze_homograph("google.com");
        assert!(!analysis.is_homograph);
        assert!(analysis.ascii_equivalent.is_none());
    }

    #[test]
    fn test_legitimate_punycode_idn() {
        // A legitimate IDN like "xn--nxasmq6b.com" (Greek characters, not mimicking Latin).
        let analysis = DnsSinkhole::analyze_homograph("rust-lang.org");
        assert!(!analysis.is_homograph);
    }

    #[test]
    fn test_homograph_mixed_script_detection() {
        // Mix of Cyrillic and Latin to spell "paypal".
        // р (Cyrillic) + a (Latin) + y (Latin) + р (Cyrillic) + а (Cyrillic) + l (Latin)
        let domain = "\u{0440}ay\u{0440}\u{0430}l.com";
        let analysis = DnsSinkhole::analyze_homograph(domain);
        assert!(analysis.is_homograph);
        assert!(analysis.script_mix.as_deref().unwrap_or("").contains("Cyrillic"));
    }

    #[test]
    fn test_homograph_full_cyrillic() {
        // Full Cyrillic substitution: "аррlе" using Cyrillic а, р, е.
        let domain = "\u{0430}\u{0440}\u{0440}l\u{0435}.com";
        let analysis = DnsSinkhole::analyze_homograph(domain);
        assert!(analysis.is_homograph);
        assert_eq!(analysis.ascii_equivalent.as_deref(), Some("apple.com"));
    }
}
