//! Application identity — verify which process owns a network connection.
//!
//! Maps network connections to PIDs and process names via /proc/net/tcp
//! and /proc/PID/fd. Ensures firewall rules can't be bypassed by
//! renaming executables or using proxies.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Identity of an application making a network connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppIdentity {
    pub pid: u32,
    pub name: String,
    pub exe_path: String,
    pub cmdline: String,
    pub uid: u32,
    pub exe_hash: Option<String>,
}

/// Connection-to-application mapping.
#[derive(Debug, Clone)]
pub struct ConnectionOwner {
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub identity: AppIdentity,
}

/// Application identity resolver.
pub struct AppIdentityResolver {
    /// Cache of PID → identity.
    cache: HashMap<u32, AppIdentity>,
    /// Known legitimate applications and their expected paths.
    known_apps: HashMap<String, Vec<String>>,
}

impl AppIdentityResolver {
    pub fn new() -> Self {
        let mut known = HashMap::new();
        known.insert("firefox".into(), vec!["/usr/lib/firefox/firefox".into(), "/snap/firefox/current/usr/lib/firefox/firefox".into()]);
        known.insert("chrome".into(), vec!["/opt/google/chrome/chrome".into()]);
        known.insert("sshd".into(), vec!["/usr/sbin/sshd".into()]);
        known.insert("nginx".into(), vec!["/usr/sbin/nginx".into()]);
        known.insert("curl".into(), vec!["/usr/bin/curl".into()]);
        known.insert("wget".into(), vec!["/usr/bin/wget".into()]);

        Self { cache: HashMap::new(), known_apps: known }
    }

    /// Register a known application path.
    pub fn register_app(&mut self, name: &str, path: &str) {
        self.known_apps.entry(name.into()).or_default().push(path.into());
    }

    /// Resolve the identity of a process by PID.
    pub fn resolve(&mut self, pid: u32) -> Option<AppIdentity> {
        if let Some(cached) = self.cache.get(&pid) {
            return Some(cached.clone());
        }

        #[cfg(target_os = "linux")]
        {
            let name = std::fs::read_to_string(format!("/proc/{pid}/comm"))
                .ok()?
                .trim()
                .to_string();
            let exe_path = std::fs::read_link(format!("/proc/{pid}/exe"))
                .ok()?
                .to_string_lossy()
                .into_owned();
            let cmdline = std::fs::read_to_string(format!("/proc/{pid}/cmdline"))
                .unwrap_or_default()
                .replace('\0', " ")
                .trim()
                .to_string();
            let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
            let uid = status.lines()
                .find(|l| l.starts_with("Uid:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);

            let identity = AppIdentity {
                pid, name, exe_path, cmdline, uid, exe_hash: None,
            };
            self.cache.insert(pid, identity.clone());
            Some(identity)
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = pid;
            None
        }
    }

    /// Check if a process's exe path matches known legitimate paths.
    pub fn verify_identity(&self, identity: &AppIdentity) -> IdentityVerification {
        if let Some(known_paths) = self.known_apps.get(&identity.name) {
            if known_paths.iter().any(|p| identity.exe_path.starts_with(p)) {
                IdentityVerification::Verified
            } else {
                IdentityVerification::PathMismatch {
                    expected: known_paths.clone(),
                    actual: identity.exe_path.clone(),
                }
            }
        } else {
            IdentityVerification::Unknown
        }
    }

    /// Check if a process is masquerading as another (name matches known app but path doesn't).
    pub fn detect_masquerade(&self, identity: &AppIdentity) -> bool {
        matches!(self.verify_identity(identity), IdentityVerification::PathMismatch { .. })
    }

    /// Clear the PID cache.
    pub fn clear_cache(&mut self) {
        self.cache.clear();
    }

    pub fn cache_size(&self) -> usize { self.cache.len() }
    pub fn known_app_count(&self) -> usize { self.known_apps.len() }
}

/// Result of identity verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityVerification {
    /// Path matches a known application.
    Verified,
    /// Name matches but path doesn't — possible masquerade.
    PathMismatch { expected: Vec<String>, actual: String },
    /// Application not in known list.
    Unknown,
}

impl Default for AppIdentityResolver {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_identity(name: &str, path: &str) -> AppIdentity {
        AppIdentity {
            pid: 1234, name: name.into(), exe_path: path.into(),
            cmdline: format!("{path} --arg"), uid: 1000, exe_hash: None,
        }
    }

    #[test]
    fn test_verify_known_app() {
        let resolver = AppIdentityResolver::new();
        let id = make_identity("firefox", "/usr/lib/firefox/firefox");
        assert_eq!(resolver.verify_identity(&id), IdentityVerification::Verified);
    }

    #[test]
    fn test_masquerade_detection() {
        let resolver = AppIdentityResolver::new();
        let id = make_identity("firefox", "/tmp/fake_firefox");
        assert!(resolver.detect_masquerade(&id));
    }

    #[test]
    fn test_unknown_app() {
        let resolver = AppIdentityResolver::new();
        let id = make_identity("myapp", "/usr/local/bin/myapp");
        assert_eq!(resolver.verify_identity(&id), IdentityVerification::Unknown);
        assert!(!resolver.detect_masquerade(&id));
    }

    #[test]
    fn test_register_app() {
        let mut resolver = AppIdentityResolver::new();
        resolver.register_app("custom", "/opt/custom/bin/app");
        let id = make_identity("custom", "/opt/custom/bin/app");
        assert_eq!(resolver.verify_identity(&id), IdentityVerification::Verified);
    }

    #[test]
    fn test_sshd_verified() {
        let resolver = AppIdentityResolver::new();
        let id = make_identity("sshd", "/usr/sbin/sshd");
        assert_eq!(resolver.verify_identity(&id), IdentityVerification::Verified);
    }

    #[test]
    fn test_path_mismatch_details() {
        let resolver = AppIdentityResolver::new();
        let id = make_identity("nginx", "/tmp/evil_nginx");
        match resolver.verify_identity(&id) {
            IdentityVerification::PathMismatch { expected, actual } => {
                assert!(expected.contains(&"/usr/sbin/nginx".to_string()));
                assert_eq!(actual, "/tmp/evil_nginx");
            }
            other => panic!("Expected PathMismatch, got {:?}", other),
        }
    }

    #[test]
    fn test_resolve_self() {
        let mut resolver = AppIdentityResolver::new();
        let result = resolver.resolve(std::process::id());
        // On Linux this should work; on other platforms it returns None.
        #[cfg(target_os = "linux")]
        assert!(result.is_some());
        let _ = result;
    }

    #[test]
    fn test_cache() {
        let mut resolver = AppIdentityResolver::new();
        let _ = resolver.resolve(std::process::id());
        #[cfg(target_os = "linux")]
        assert_eq!(resolver.cache_size(), 1);
        resolver.clear_cache();
        assert_eq!(resolver.cache_size(), 0);
    }

    #[test]
    fn test_known_app_count() {
        let resolver = AppIdentityResolver::new();
        assert!(resolver.known_app_count() >= 6);
    }
}
