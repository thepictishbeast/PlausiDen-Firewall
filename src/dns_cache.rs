//! DNS cache — local DNS query cache with TTL.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A cached DNS entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsEntry {
    pub domain: String,
    pub answers: Vec<String>,
    pub ttl_secs: u32,
    pub cached_at: DateTime<Utc>,
    pub hits: u64,
}

impl DnsEntry {
    pub fn is_expired(&self) -> bool {
        let elapsed = (Utc::now() - self.cached_at).num_seconds();
        elapsed >= self.ttl_secs as i64
    }

    pub fn age_secs(&self) -> i64 {
        (Utc::now() - self.cached_at).num_seconds()
    }
}

/// DNS cache with LRU eviction.
pub struct DnsCache {
    entries: HashMap<String, DnsEntry>,
    max_entries: usize,
    /// Total cache hits.
    hits: u64,
    /// Total cache misses.
    misses: u64,
}

impl DnsCache {
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: HashMap::new(),
            max_entries,
            hits: 0,
            misses: 0,
        }
    }

    /// Get a cached entry.
    pub fn get(&mut self, domain: &str) -> Option<Vec<String>> {
        if let Some(entry) = self.entries.get_mut(domain) {
            if !entry.is_expired() {
                entry.hits += 1;
                self.hits += 1;
                return Some(entry.answers.clone());
            }
        }
        self.misses += 1;
        None
    }

    /// Store a DNS response in the cache.
    pub fn put(&mut self, domain: &str, answers: Vec<String>, ttl_secs: u32) {
        // Evict oldest if at capacity.
        if self.entries.len() >= self.max_entries && !self.entries.contains_key(domain) {
            if let Some(oldest_key) = self.entries.iter()
                .min_by_key(|(_, e)| e.cached_at)
                .map(|(k, _)| k.clone())
            {
                self.entries.remove(&oldest_key);
            }
        }

        self.entries.insert(domain.into(), DnsEntry {
            domain: domain.into(),
            answers,
            ttl_secs,
            cached_at: Utc::now(),
            hits: 0,
        });
    }

    /// Remove an entry.
    pub fn remove(&mut self, domain: &str) -> bool {
        self.entries.remove(domain).is_some()
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Purge expired entries.
    pub fn purge_expired(&mut self) -> usize {
        let before = self.entries.len();
        self.entries.retain(|_, e| !e.is_expired());
        before - self.entries.len()
    }

    /// Get cache hit rate.
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 { return 0.0; }
        self.hits as f64 / total as f64
    }

    pub fn entry_count(&self) -> usize { self.entries.len() }
    pub fn hits(&self) -> u64 { self.hits }
    pub fn misses(&self) -> u64 { self.misses }
}

impl Default for DnsCache {
    fn default() -> Self { Self::new(10_000) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_put_and_get() {
        let mut cache = DnsCache::default();
        cache.put("example.com", vec!["1.2.3.4".into()], 300);
        assert_eq!(cache.get("example.com"), Some(vec!["1.2.3.4".into()]));
    }

    #[test]
    fn test_miss() {
        let mut cache = DnsCache::default();
        assert_eq!(cache.get("notcached.com"), None);
        assert_eq!(cache.misses(), 1);
    }

    #[test]
    fn test_hit_count() {
        let mut cache = DnsCache::default();
        cache.put("example.com", vec!["1.2.3.4".into()], 300);
        for _ in 0..5 {
            cache.get("example.com");
        }
        assert_eq!(cache.hits(), 5);
    }

    #[test]
    fn test_remove() {
        let mut cache = DnsCache::default();
        cache.put("example.com", vec!["1.2.3.4".into()], 300);
        assert!(cache.remove("example.com"));
        assert_eq!(cache.get("example.com"), None);
    }

    #[test]
    fn test_clear() {
        let mut cache = DnsCache::default();
        cache.put("a.com", vec!["1".into()], 300);
        cache.put("b.com", vec!["2".into()], 300);
        cache.clear();
        assert_eq!(cache.entry_count(), 0);
    }

    #[test]
    fn test_eviction() {
        let mut cache = DnsCache::new(3);
        cache.put("a.com", vec!["1".into()], 300);
        std::thread::sleep(std::time::Duration::from_millis(10));
        cache.put("b.com", vec!["2".into()], 300);
        std::thread::sleep(std::time::Duration::from_millis(10));
        cache.put("c.com", vec!["3".into()], 300);
        std::thread::sleep(std::time::Duration::from_millis(10));
        cache.put("d.com", vec!["4".into()], 300);
        assert_eq!(cache.entry_count(), 3);
        // Oldest (a.com) should be evicted.
    }

    #[test]
    fn test_purge_expired() {
        let mut cache = DnsCache::default();
        cache.put("expired.com", vec!["1".into()], 0); // Immediate expiry.
        cache.put("fresh.com", vec!["2".into()], 3600);
        std::thread::sleep(std::time::Duration::from_millis(10));
        let purged = cache.purge_expired();
        assert!(purged >= 1);
    }

    #[test]
    fn test_hit_rate() {
        let mut cache = DnsCache::default();
        cache.put("a.com", vec!["1".into()], 300);
        cache.get("a.com");
        cache.get("a.com");
        cache.get("missing.com");
        let rate = cache.hit_rate();
        assert!((rate - 2.0/3.0).abs() < 0.01);
    }
}
