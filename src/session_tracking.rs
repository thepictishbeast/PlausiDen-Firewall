//! Session tracking — group related connections into application sessions.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSession {
    pub session_id: u64,
    pub app_name: String,
    pub start_time: DateTime<Utc>,
    pub last_activity: DateTime<Utc>,
    pub connections: u32,
    pub bytes_total: u64,
    pub destinations: Vec<String>,
    pub active: bool,
}

pub struct SessionTracker {
    sessions: HashMap<u64, NetworkSession>,
    next_id: u64,
    timeout_secs: i64,
}

impl SessionTracker {
    pub fn new(timeout_secs: i64) -> Self { Self { sessions: HashMap::new(), next_id: 1, timeout_secs } }

    pub fn start_session(&mut self, app: &str) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        let now = Utc::now();
        self.sessions.insert(id, NetworkSession { session_id: id, app_name: app.into(), start_time: now, last_activity: now, connections: 0, bytes_total: 0, destinations: Vec::new(), active: true });
        id
    }

    pub fn record_activity(&mut self, session_id: u64, dest: &str, bytes: u64) {
        if let Some(s) = self.sessions.get_mut(&session_id) {
            s.last_activity = Utc::now();
            s.connections += 1;
            s.bytes_total += bytes;
            if !s.destinations.contains(&dest.to_string()) { s.destinations.push(dest.into()); }
        }
    }

    pub fn expire_stale(&mut self) -> usize {
        let cutoff = Utc::now() - Duration::seconds(self.timeout_secs);
        let mut expired = 0;
        for s in self.sessions.values_mut() {
            if s.active && s.last_activity < cutoff { s.active = false; expired += 1; }
        }
        expired
    }

    pub fn active_sessions(&self) -> Vec<&NetworkSession> { self.sessions.values().filter(|s| s.active).collect() }
    pub fn session_count(&self) -> usize { self.sessions.len() }
    pub fn active_count(&self) -> usize { self.sessions.values().filter(|s| s.active).count() }
}

impl Default for SessionTracker { fn default() -> Self { Self::new(300) } }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_start_and_record() {
        let mut tracker = SessionTracker::new(300);
        let id = tracker.start_session("firefox");
        tracker.record_activity(id, "google.com", 5000);
        tracker.record_activity(id, "github.com", 3000);
        let sessions = tracker.active_sessions();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].connections, 2);
        assert_eq!(sessions[0].destinations.len(), 2);
    }

    #[test]
    fn test_expire() {
        let mut tracker = SessionTracker::new(1); // 1 second timeout
        let id = tracker.start_session("app");
        // Manually set last_activity to past
        tracker.sessions.get_mut(&id).unwrap().last_activity = Utc::now() - Duration::seconds(5);
        let expired = tracker.expire_stale();
        assert_eq!(expired, 1);
        assert_eq!(tracker.active_count(), 0);
    }

    #[test]
    fn test_multiple_sessions() {
        let mut tracker = SessionTracker::new(300);
        tracker.start_session("chrome");
        tracker.start_session("firefox");
        tracker.start_session("curl");
        assert_eq!(tracker.active_count(), 3);
    }
}
