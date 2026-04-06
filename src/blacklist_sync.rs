//! Blacklist sync — periodically refresh threat intelligence feeds.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A blacklist source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlacklistSource {
    pub name: String,
    pub url: String,
    pub source_type: SourceType,
    pub refresh_interval_secs: i64,
    pub last_updated: Option<DateTime<Utc>>,
    pub entry_count: usize,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SourceType {
    IpList,
    DomainList,
    HashList,
    UrlList,
    Mixed,
}

/// Sync state for a source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncState {
    Idle,
    Pending,
    InProgress,
    Failed { error: String },
    Updated { count: usize },
}

/// Blacklist sync manager.
pub struct BlacklistSync {
    sources: HashMap<String, BlacklistSource>,
    states: HashMap<String, SyncState>,
}

impl BlacklistSync {
    pub fn new() -> Self {
        Self {
            sources: HashMap::new(),
            states: HashMap::new(),
        }
    }

    /// Add a blacklist source.
    pub fn add_source(&mut self, source: BlacklistSource) {
        self.states.insert(source.name.clone(), SyncState::Idle);
        self.sources.insert(source.name.clone(), source);
    }

    /// Get sources due for refresh.
    pub fn due_for_refresh(&self) -> Vec<&BlacklistSource> {
        let now = Utc::now();
        self.sources.values()
            .filter(|s| s.enabled)
            .filter(|s| {
                s.last_updated
                    .map(|t| (now - t).num_seconds() > s.refresh_interval_secs)
                    .unwrap_or(true)
            })
            .collect()
    }

    /// Mark a source as starting sync.
    pub fn mark_pending(&mut self, name: &str) {
        self.states.insert(name.into(), SyncState::Pending);
    }

    /// Mark a source as updated.
    pub fn mark_updated(&mut self, name: &str, entry_count: usize) {
        if let Some(s) = self.sources.get_mut(name) {
            s.last_updated = Some(Utc::now());
            s.entry_count = entry_count;
        }
        self.states.insert(name.into(), SyncState::Updated { count: entry_count });
    }

    /// Mark a source as failed.
    pub fn mark_failed(&mut self, name: &str, error: &str) {
        self.states.insert(name.into(), SyncState::Failed { error: error.into() });
    }

    /// Get current state of a source.
    pub fn get_state(&self, name: &str) -> Option<&SyncState> {
        self.states.get(name)
    }

    /// Enable/disable a source.
    pub fn set_enabled(&mut self, name: &str, enabled: bool) -> bool {
        if let Some(s) = self.sources.get_mut(name) {
            s.enabled = enabled;
            true
        } else {
            false
        }
    }

    /// Get total entries across all sources.
    pub fn total_entries(&self) -> usize {
        self.sources.values().map(|s| s.entry_count).sum()
    }

    /// Get sources by type.
    pub fn by_type(&self, source_type: &SourceType) -> Vec<&BlacklistSource> {
        self.sources.values().filter(|s| &s.source_type == source_type).collect()
    }

    pub fn source_count(&self) -> usize { self.sources.len() }
}

impl Default for BlacklistSync {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_source(name: &str, source_type: SourceType) -> BlacklistSource {
        BlacklistSource {
            name: name.into(),
            url: format!("https://example.com/{name}"),
            source_type,
            refresh_interval_secs: 3600,
            last_updated: None,
            entry_count: 0,
            enabled: true,
        }
    }

    #[test]
    fn test_add_source() {
        let mut sync = BlacklistSync::new();
        sync.add_source(make_source("malware-ip", SourceType::IpList));
        assert_eq!(sync.source_count(), 1);
    }

    #[test]
    fn test_due_for_refresh_initial() {
        let mut sync = BlacklistSync::new();
        sync.add_source(make_source("test", SourceType::IpList));
        // Never updated — should be due.
        assert_eq!(sync.due_for_refresh().len(), 1);
    }

    #[test]
    fn test_not_due_after_update() {
        let mut sync = BlacklistSync::new();
        sync.add_source(make_source("test", SourceType::IpList));
        sync.mark_updated("test", 100);
        assert_eq!(sync.due_for_refresh().len(), 0);
    }

    #[test]
    fn test_mark_failed() {
        let mut sync = BlacklistSync::new();
        sync.add_source(make_source("test", SourceType::IpList));
        sync.mark_failed("test", "connection timeout");
        match sync.get_state("test") {
            Some(SyncState::Failed { error }) => assert!(error.contains("timeout")),
            _ => panic!("Expected Failed state"),
        }
    }

    #[test]
    fn test_total_entries() {
        let mut sync = BlacklistSync::new();
        sync.add_source(make_source("a", SourceType::IpList));
        sync.add_source(make_source("b", SourceType::DomainList));
        sync.mark_updated("a", 1000);
        sync.mark_updated("b", 500);
        assert_eq!(sync.total_entries(), 1500);
    }

    #[test]
    fn test_disable_source() {
        let mut sync = BlacklistSync::new();
        sync.add_source(make_source("test", SourceType::IpList));
        sync.set_enabled("test", false);
        assert_eq!(sync.due_for_refresh().len(), 0);
    }

    #[test]
    fn test_by_type() {
        let mut sync = BlacklistSync::new();
        sync.add_source(make_source("ip1", SourceType::IpList));
        sync.add_source(make_source("ip2", SourceType::IpList));
        sync.add_source(make_source("dom", SourceType::DomainList));
        assert_eq!(sync.by_type(&SourceType::IpList).len(), 2);
        assert_eq!(sync.by_type(&SourceType::DomainList).len(), 1);
    }

    #[test]
    fn test_state_transitions() {
        let mut sync = BlacklistSync::new();
        sync.add_source(make_source("test", SourceType::IpList));
        assert_eq!(sync.get_state("test"), Some(&SyncState::Idle));
        sync.mark_pending("test");
        assert_eq!(sync.get_state("test"), Some(&SyncState::Pending));
        sync.mark_updated("test", 50);
        match sync.get_state("test") {
            Some(SyncState::Updated { count }) => assert_eq!(*count, 50),
            _ => panic!("Expected Updated"),
        }
    }
}
