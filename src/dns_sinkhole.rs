//! DNS sinkhole for blocking known-malicious, tracking, and telemetry domains.
//!
//! Supports exact-match and wildcard (`*.example.com`) patterns. Ships with a
//! curated default blocklist of malware C2 infrastructure, advertising trackers,
//! and telemetry endpoints that exfiltrate user data.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

/// A DNS sinkhole that blocks resolution of domains on a blocklist.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsSinkhole {
    /// Exact-match domain blocklist.
    exact_domains: HashSet<String>,
    /// Wildcard suffix blocklist (stored without the leading `*.`).
    wildcard_suffixes: HashSet<String>,
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

    /// Check whether a domain should be sinkholed (blocked).
    pub fn is_sinkholed(&self, domain: &str) -> bool {
        let normalized = domain.to_lowercase();

        // Exact match.
        if self.exact_domains.contains(&normalized) {
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
}
