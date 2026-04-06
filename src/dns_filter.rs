//! DNS category filter — block domains by category.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Domain category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DomainCategory {
    Ads,
    Malware,
    Phishing,
    Adult,
    Gambling,
    Social,
    Tracker,
    Cryptominer,
    Cdn,
    News,
    Shopping,
    Other,
}

/// DNS category filter.
pub struct DnsCategoryFilter {
    /// Map: category → domain set
    by_category: HashMap<DomainCategory, HashSet<String>>,
    /// Blocked categories.
    blocked: HashSet<DomainCategory>,
}

impl DnsCategoryFilter {
    pub fn new() -> Self {
        let mut filter = Self {
            by_category: HashMap::new(),
            blocked: HashSet::new(),
        };
        // Default: block ads, malware, phishing, trackers, cryptominers.
        filter.block(DomainCategory::Ads);
        filter.block(DomainCategory::Malware);
        filter.block(DomainCategory::Phishing);
        filter.block(DomainCategory::Tracker);
        filter.block(DomainCategory::Cryptominer);
        filter
    }

    /// Add a domain to a category.
    pub fn add_domain(&mut self, domain: &str, category: DomainCategory) {
        self.by_category.entry(category).or_default().insert(domain.to_lowercase());
    }

    /// Block a category.
    pub fn block(&mut self, category: DomainCategory) {
        self.blocked.insert(category);
    }

    /// Unblock a category.
    pub fn unblock(&mut self, category: DomainCategory) {
        self.blocked.remove(&category);
    }

    /// Check if a domain is blocked.
    pub fn is_blocked(&self, domain: &str) -> bool {
        let lower = domain.to_lowercase();
        for category in &self.blocked {
            if let Some(domains) = self.by_category.get(category) {
                if domains.contains(&lower) { return true; }
                // Wildcard subdomain match.
                for pattern in domains {
                    if let Some(base) = pattern.strip_prefix("*.") {
                        if lower.ends_with(&format!(".{base}")) || lower == base {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    /// Get the category of a domain.
    pub fn get_category(&self, domain: &str) -> Option<DomainCategory> {
        let lower = domain.to_lowercase();
        for (category, domains) in &self.by_category {
            if domains.contains(&lower) {
                return Some(*category);
            }
        }
        None
    }

    /// Total domains in a category.
    pub fn count_in_category(&self, category: DomainCategory) -> usize {
        self.by_category.get(&category).map(|s| s.len()).unwrap_or(0)
    }

    /// Total domains.
    pub fn total_domains(&self) -> usize {
        self.by_category.values().map(|s| s.len()).sum()
    }

    /// Whether a category is blocked.
    pub fn is_category_blocked(&self, category: DomainCategory) -> bool {
        self.blocked.contains(&category)
    }

    pub fn blocked_categories(&self) -> Vec<DomainCategory> {
        self.blocked.iter().copied().collect()
    }
}

impl Default for DnsCategoryFilter {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_blocks_ads() {
        let filter = DnsCategoryFilter::new();
        assert!(filter.is_category_blocked(DomainCategory::Ads));
    }

    #[test]
    fn test_block_specific_domain() {
        let mut filter = DnsCategoryFilter::new();
        filter.add_domain("doubleclick.net", DomainCategory::Ads);
        assert!(filter.is_blocked("doubleclick.net"));
    }

    #[test]
    fn test_not_blocked() {
        let filter = DnsCategoryFilter::new();
        assert!(!filter.is_blocked("google.com"));
    }

    #[test]
    fn test_wildcard_subdomain() {
        let mut filter = DnsCategoryFilter::new();
        filter.add_domain("*.tracker.com", DomainCategory::Tracker);
        assert!(filter.is_blocked("a.tracker.com"));
        assert!(filter.is_blocked("tracker.com"));
        assert!(!filter.is_blocked("notatracker.com"));
    }

    #[test]
    fn test_unblock_category() {
        let mut filter = DnsCategoryFilter::new();
        filter.add_domain("ads.example.com", DomainCategory::Ads);
        assert!(filter.is_blocked("ads.example.com"));
        filter.unblock(DomainCategory::Ads);
        assert!(!filter.is_blocked("ads.example.com"));
    }

    #[test]
    fn test_get_category() {
        let mut filter = DnsCategoryFilter::new();
        filter.add_domain("malware.com", DomainCategory::Malware);
        assert_eq!(filter.get_category("malware.com"), Some(DomainCategory::Malware));
        assert_eq!(filter.get_category("google.com"), None);
    }

    #[test]
    fn test_count_in_category() {
        let mut filter = DnsCategoryFilter::new();
        filter.add_domain("a.com", DomainCategory::Ads);
        filter.add_domain("b.com", DomainCategory::Ads);
        filter.add_domain("c.com", DomainCategory::Malware);
        assert_eq!(filter.count_in_category(DomainCategory::Ads), 2);
        assert_eq!(filter.count_in_category(DomainCategory::Malware), 1);
    }

    #[test]
    fn test_blocked_categories() {
        let filter = DnsCategoryFilter::new();
        let blocked = filter.blocked_categories();
        assert!(blocked.len() >= 5);
    }

    #[test]
    fn test_total_domains() {
        let mut filter = DnsCategoryFilter::new();
        filter.add_domain("a.com", DomainCategory::Ads);
        filter.add_domain("b.com", DomainCategory::Malware);
        assert_eq!(filter.total_domains(), 2);
    }
}
