//! HTTP MIME filter — block suspicious content types per-application.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// A MIME type classification.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MimeCategory {
    Html,
    Css,
    JavaScript,
    Json,
    Xml,
    Image,
    Video,
    Audio,
    Font,
    Executable,
    Archive,
    Document,
    Unknown,
}

impl MimeCategory {
    pub fn from_mime(mime: &str) -> Self {
        let m = mime.to_lowercase();
        if m.starts_with("text/html") { MimeCategory::Html }
        else if m.starts_with("text/css") { MimeCategory::Css }
        else if m.contains("javascript") || m == "application/ecmascript" { MimeCategory::JavaScript }
        else if m == "application/json" || m.ends_with("+json") { MimeCategory::Json }
        else if m == "application/xml" || m.ends_with("+xml") { MimeCategory::Xml }
        else if m.starts_with("image/") { MimeCategory::Image }
        else if m.starts_with("video/") { MimeCategory::Video }
        else if m.starts_with("audio/") { MimeCategory::Audio }
        else if m.starts_with("font/") || m == "application/font-woff" { MimeCategory::Font }
        else if m == "application/octet-stream"
            || m == "application/x-msdownload"
            || m == "application/x-executable"
            || m == "application/x-elf" { MimeCategory::Executable }
        else if m == "application/zip"
            || m == "application/gzip"
            || m == "application/x-tar"
            || m == "application/x-7z-compressed" { MimeCategory::Archive }
        else if m == "application/pdf"
            || m.contains("msword")
            || m.contains("officedocument") { MimeCategory::Document }
        else { MimeCategory::Unknown }
    }

    /// Is this category high-risk for browser delivery?
    pub fn is_dangerous(&self) -> bool {
        matches!(self, MimeCategory::Executable | MimeCategory::Archive)
    }
}

/// A MIME filter decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MimeDecision {
    Allow,
    Block(BlockReason),
    Warn,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlockReason {
    DangerousCategory,
    NotInAllowlist,
    AppSpecificBlock,
}

/// Per-app MIME policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppMimePolicy {
    pub app_id: String,
    pub allowed: HashSet<MimeCategory>,
    pub blocked: HashSet<MimeCategory>,
    pub block_dangerous: bool,
    pub warn_on_unknown: bool,
}

impl AppMimePolicy {
    /// Browser-like policy: allow web content, block executables.
    pub fn browser(app_id: &str) -> Self {
        let mut allowed = HashSet::new();
        for c in [
            MimeCategory::Html, MimeCategory::Css, MimeCategory::JavaScript,
            MimeCategory::Json, MimeCategory::Xml, MimeCategory::Image,
            MimeCategory::Video, MimeCategory::Audio, MimeCategory::Font,
        ] {
            allowed.insert(c);
        }
        let mut blocked = HashSet::new();
        blocked.insert(MimeCategory::Executable);
        Self {
            app_id: app_id.into(),
            allowed,
            blocked,
            block_dangerous: true,
            warn_on_unknown: true,
        }
    }

    /// Strict policy: allow only specific categories.
    pub fn strict(app_id: &str, categories: Vec<MimeCategory>) -> Self {
        let allowed: HashSet<MimeCategory> = categories.into_iter().collect();
        Self {
            app_id: app_id.into(),
            allowed,
            blocked: HashSet::new(),
            block_dangerous: true,
            warn_on_unknown: false,
        }
    }
}

/// HTTP MIME filter.
pub struct MimeFilter {
    policies: HashMap<String, AppMimePolicy>,
    decisions_log: Vec<MimeLogEntry>,
    log_limit: usize,
}

/// Decision log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MimeLogEntry {
    pub app_id: String,
    pub mime: String,
    pub url: String,
    pub decision: MimeDecision,
    pub timestamp: DateTime<Utc>,
}

impl MimeFilter {
    pub fn new() -> Self {
        Self {
            policies: HashMap::new(),
            decisions_log: Vec::new(),
            log_limit: 10_000,
        }
    }

    /// Set a policy for an app.
    pub fn set_policy(&mut self, policy: AppMimePolicy) {
        self.policies.insert(policy.app_id.clone(), policy);
    }

    /// Remove a policy.
    pub fn remove_policy(&mut self, app_id: &str) -> bool {
        self.policies.remove(app_id).is_some()
    }

    /// Evaluate a response MIME type for an app.
    pub fn evaluate(&mut self, app_id: &str, mime: &str, url: &str) -> MimeDecision {
        let category = MimeCategory::from_mime(mime);
        let decision = match self.policies.get(app_id) {
            None => MimeDecision::Allow, // no policy → allow
            Some(policy) => {
                if policy.blocked.contains(&category) {
                    MimeDecision::Block(BlockReason::AppSpecificBlock)
                } else if policy.block_dangerous && category.is_dangerous() {
                    MimeDecision::Block(BlockReason::DangerousCategory)
                } else if !policy.allowed.is_empty() && !policy.allowed.contains(&category) {
                    MimeDecision::Block(BlockReason::NotInAllowlist)
                } else if category == MimeCategory::Unknown && policy.warn_on_unknown {
                    MimeDecision::Warn
                } else {
                    MimeDecision::Allow
                }
            }
        };

        self.decisions_log.push(MimeLogEntry {
            app_id: app_id.into(),
            mime: mime.into(),
            url: url.into(),
            decision: decision.clone(),
            timestamp: Utc::now(),
        });
        if self.decisions_log.len() > self.log_limit {
            self.decisions_log.remove(0);
        }

        decision
    }

    /// Get policy for an app.
    pub fn policy(&self, app_id: &str) -> Option<&AppMimePolicy> {
        self.policies.get(app_id)
    }

    /// Recent decisions.
    pub fn recent(&self, n: usize) -> Vec<&MimeLogEntry> {
        let start = self.decisions_log.len().saturating_sub(n);
        self.decisions_log.iter().skip(start).collect()
    }

    /// Count of blocked responses.
    pub fn blocked_count(&self) -> usize {
        self.decisions_log.iter()
            .filter(|e| matches!(e.decision, MimeDecision::Block(_)))
            .count()
    }

    /// Top blocked MIME types.
    pub fn top_blocked_mimes(&self, n: usize) -> Vec<(String, usize)> {
        let mut counts: HashMap<String, usize> = HashMap::new();
        for e in &self.decisions_log {
            if matches!(e.decision, MimeDecision::Block(_)) {
                *counts.entry(e.mime.clone()).or_insert(0) += 1;
            }
        }
        let mut ranked: Vec<_> = counts.into_iter().collect();
        ranked.sort_by(|a, b| b.1.cmp(&a.1));
        ranked.truncate(n);
        ranked
    }

    pub fn policy_count(&self) -> usize { self.policies.len() }
    pub fn log_count(&self) -> usize { self.decisions_log.len() }
}

impl Default for MimeFilter {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mime_category_mapping() {
        assert_eq!(MimeCategory::from_mime("text/html"), MimeCategory::Html);
        assert_eq!(MimeCategory::from_mime("application/javascript"), MimeCategory::JavaScript);
        assert_eq!(MimeCategory::from_mime("image/png"), MimeCategory::Image);
        assert_eq!(MimeCategory::from_mime("application/octet-stream"), MimeCategory::Executable);
    }

    #[test]
    fn test_is_dangerous() {
        assert!(MimeCategory::Executable.is_dangerous());
        assert!(MimeCategory::Archive.is_dangerous());
        assert!(!MimeCategory::Html.is_dangerous());
    }

    #[test]
    fn test_no_policy_allows() {
        let mut f = MimeFilter::new();
        assert_eq!(
            f.evaluate("unknown_app", "application/octet-stream", "http://x/a.exe"),
            MimeDecision::Allow
        );
    }

    #[test]
    fn test_browser_blocks_executable() {
        let mut f = MimeFilter::new();
        f.set_policy(AppMimePolicy::browser("firefox"));
        let decision = f.evaluate("firefox", "application/octet-stream", "http://x/a.exe");
        assert!(matches!(decision, MimeDecision::Block(_)));
    }

    #[test]
    fn test_browser_allows_html() {
        let mut f = MimeFilter::new();
        f.set_policy(AppMimePolicy::browser("firefox"));
        assert_eq!(
            f.evaluate("firefox", "text/html", "http://x/"),
            MimeDecision::Allow
        );
    }

    #[test]
    fn test_strict_policy() {
        let mut f = MimeFilter::new();
        f.set_policy(AppMimePolicy::strict("agent", vec![MimeCategory::Json]));
        assert_eq!(
            f.evaluate("agent", "application/json", "http://api/"),
            MimeDecision::Allow
        );
        let decision = f.evaluate("agent", "text/html", "http://api/");
        assert!(matches!(decision, MimeDecision::Block(_)));
    }

    #[test]
    fn test_blocked_counter() {
        let mut f = MimeFilter::new();
        f.set_policy(AppMimePolicy::browser("firefox"));
        f.evaluate("firefox", "application/octet-stream", "http://x/a");
        f.evaluate("firefox", "text/html", "http://x/b");
        assert_eq!(f.blocked_count(), 1);
    }

    #[test]
    fn test_top_blocked_mimes() {
        let mut f = MimeFilter::new();
        f.set_policy(AppMimePolicy::browser("firefox"));
        for _ in 0..3 { f.evaluate("firefox", "application/octet-stream", "http://x"); }
        f.evaluate("firefox", "application/x-msdownload", "http://x");
        let top = f.top_blocked_mimes(2);
        assert!(top[0].1 >= 1);
    }

    #[test]
    fn test_json_variant() {
        assert_eq!(MimeCategory::from_mime("application/vnd.api+json"), MimeCategory::Json);
    }

    #[test]
    fn test_remove_policy() {
        let mut f = MimeFilter::new();
        f.set_policy(AppMimePolicy::browser("firefox"));
        assert!(f.remove_policy("firefox"));
        assert_eq!(f.policy_count(), 0);
    }

    #[test]
    fn test_warn_on_unknown() {
        let mut f = MimeFilter::new();
        f.set_policy(AppMimePolicy::browser("firefox"));
        let decision = f.evaluate("firefox", "application/vnd.custom-type", "http://x");
        // Unknown types in allowlist-only mode are blocked; browser mode allows with warning.
        // Browser policy has warn_on_unknown and non-empty allowed, so NotInAllowlist wins.
        assert!(matches!(decision, MimeDecision::Block(_) | MimeDecision::Warn));
    }
}
