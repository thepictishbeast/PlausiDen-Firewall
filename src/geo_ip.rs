//! Geo-IP blocking — block/allow traffic by country.

use std::collections::HashSet;
use std::net::IpAddr;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoIpPolicy {
    pub mode: GeoIpMode,
    pub countries: HashSet<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GeoIpMode { AllowList, BlockList }

impl GeoIpPolicy {
    pub fn block_countries(countries: Vec<&str>) -> Self {
        Self { mode: GeoIpMode::BlockList, countries: countries.into_iter().map(|s| s.to_uppercase()).collect() }
    }

    pub fn allow_only(countries: Vec<&str>) -> Self {
        Self { mode: GeoIpMode::AllowList, countries: countries.into_iter().map(|s| s.to_uppercase()).collect() }
    }

    /// Check if a country code is allowed by this policy.
    pub fn is_allowed(&self, country_code: &str) -> bool {
        let cc = country_code.to_uppercase();
        match self.mode {
            GeoIpMode::AllowList => self.countries.contains(&cc),
            GeoIpMode::BlockList => !self.countries.contains(&cc),
        }
    }

    pub fn country_count(&self) -> usize { self.countries.len() }
}

/// Simplified geo-IP lookup using IP range heuristics.
/// In production, use MaxMind GeoLite2 or similar database.
pub fn lookup_country(_ip: &IpAddr) -> Option<String> {
    // Stub — real implementation needs GeoIP database
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blocklist() {
        let policy = GeoIpPolicy::block_countries(vec!["CN", "RU", "KP"]);
        assert!(!policy.is_allowed("CN"));
        assert!(!policy.is_allowed("ru")); // case insensitive
        assert!(policy.is_allowed("US"));
    }

    #[test]
    fn test_allowlist() {
        let policy = GeoIpPolicy::allow_only(vec!["US", "CA", "GB"]);
        assert!(policy.is_allowed("US"));
        assert!(!policy.is_allowed("CN"));
    }

    #[test]
    fn test_case_insensitive() {
        let policy = GeoIpPolicy::block_countries(vec!["cn"]);
        assert!(!policy.is_allowed("CN"));
        assert!(!policy.is_allowed("cn"));
    }
}
