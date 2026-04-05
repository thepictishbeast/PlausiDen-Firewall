//! Application fingerprinting — identify apps by their network behavior.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppFingerprint {
    pub app_name: String,
    pub typical_ports: Vec<u16>,
    pub typical_domains: Vec<String>,
    pub typical_user_agents: Vec<String>,
    pub tls_ja3_hashes: Vec<String>,
}

pub struct AppIdentifier {
    fingerprints: Vec<AppFingerprint>,
}

impl AppIdentifier {
    pub fn new() -> Self {
        Self { fingerprints: vec![
            AppFingerprint { app_name: "Chrome".into(), typical_ports: vec![80, 443], typical_domains: vec!["clients1.google.com".into(), "update.googleapis.com".into()], typical_user_agents: vec!["Chrome/".into()], tls_ja3_hashes: vec!["72a589da586844d7f0818ce684948eea".into()] },
            AppFingerprint { app_name: "Firefox".into(), typical_ports: vec![80, 443], typical_domains: vec!["detectportal.firefox.com".into(), "firefox.settings.services.mozilla.com".into()], typical_user_agents: vec!["Firefox/".into()], tls_ja3_hashes: vec![] },
            AppFingerprint { app_name: "Steam".into(), typical_ports: vec![27015, 27036, 443], typical_domains: vec!["steamcommunity.com".into(), "steampowered.com".into()], typical_user_agents: vec!["Valve/Steam".into()], tls_ja3_hashes: vec![] },
            AppFingerprint { app_name: "Discord".into(), typical_ports: vec![443], typical_domains: vec!["discord.com".into(), "discordapp.com".into(), "gateway.discord.gg".into()], typical_user_agents: vec!["Discord".into()], tls_ja3_hashes: vec![] },
            AppFingerprint { app_name: "Spotify".into(), typical_ports: vec![443, 4070], typical_domains: vec!["spclient.wg.spotify.com".into(), "audio-ak-spotify-com".into()], typical_user_agents: vec!["Spotify".into()], tls_ja3_hashes: vec![] },
        ]}
    }

    pub fn identify_by_domain(&self, domain: &str) -> Option<&str> {
        for fp in &self.fingerprints {
            if fp.typical_domains.iter().any(|d| domain.contains(d) || d.contains(domain)) {
                return Some(&fp.app_name);
            }
        }
        None
    }

    pub fn identify_by_ua(&self, user_agent: &str) -> Option<&str> {
        for fp in &self.fingerprints {
            if fp.typical_user_agents.iter().any(|ua| user_agent.contains(ua)) {
                return Some(&fp.app_name);
            }
        }
        None
    }

    pub fn identify_by_port(&self, port: u16) -> Vec<&str> {
        self.fingerprints.iter().filter(|fp| fp.typical_ports.contains(&port)).map(|fp| fp.app_name.as_str()).collect()
    }

    pub fn add_fingerprint(&mut self, fp: AppFingerprint) { self.fingerprints.push(fp); }
    pub fn fingerprint_count(&self) -> usize { self.fingerprints.len() }
}

impl Default for AppIdentifier { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identify_by_domain() {
        let id = AppIdentifier::new();
        assert_eq!(id.identify_by_domain("steamcommunity.com"), Some("Steam"));
        assert_eq!(id.identify_by_domain("unknown.com"), None);
    }

    #[test]
    fn test_identify_by_ua() {
        let id = AppIdentifier::new();
        assert_eq!(id.identify_by_ua("Mozilla/5.0 Chrome/120"), Some("Chrome"));
        assert_eq!(id.identify_by_ua("curl/7.88"), None);
    }

    #[test]
    fn test_identify_by_port() {
        let id = AppIdentifier::new();
        let steam = id.identify_by_port(27015);
        assert!(steam.contains(&"Steam"));
    }

    #[test]
    fn test_custom_fingerprint() {
        let mut id = AppIdentifier::new();
        id.add_fingerprint(AppFingerprint { app_name: "CustomApp".into(), typical_ports: vec![9999], typical_domains: vec!["custom.app".into()], typical_user_agents: vec![], tls_ja3_hashes: vec![] });
        assert_eq!(id.identify_by_domain("custom.app"), Some("CustomApp"));
    }
}
