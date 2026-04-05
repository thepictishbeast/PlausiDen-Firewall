//! Per-application egress filtering with default-deny semantics.
//!
//! Each application must be explicitly granted permission to communicate with
//! specific destinations. Unknown applications are denied all outbound traffic.

use std::collections::HashMap;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors from egress filter operations.
#[derive(Debug, Error)]
pub enum EgressError {
    /// The specified application was not found in the filter.
    #[error("application not found: {0}")]
    ApplicationNotFound(String),
}

/// Identifies an application for egress control.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AppIdentifier {
    /// Match by process name (e.g., `"firefox"`).
    ProcessName(String),
    /// Match by full binary path (e.g., `"/usr/bin/firefox"`).
    BinaryPath(String),
}

impl AppIdentifier {
    /// Check whether a given process name or binary path matches this identifier.
    pub fn matches(&self, process_name: Option<&str>, binary_path: Option<&str>) -> bool {
        match self {
            Self::ProcessName(name) => process_name.is_some_and(|pn| pn == name),
            Self::BinaryPath(path) => binary_path.is_some_and(|bp| bp == path),
        }
    }
}

/// A permitted egress destination for an application.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EgressDestination {
    /// Destination IP address. `None` means any IP.
    pub ip: Option<IpAddr>,
    /// Destination port. `None` means any port.
    pub port: Option<u16>,
    /// Destination domain pattern. `None` means any domain.
    pub domain: Option<String>,
}

impl EgressDestination {
    /// Check whether the given traffic parameters match this destination.
    pub fn matches(&self, dest_ip: Option<IpAddr>, dest_port: Option<u16>, domain: Option<&str>) -> bool {
        if let Some(ref allowed_ip) = self.ip {
            match dest_ip {
                Some(ref actual_ip) if actual_ip != allowed_ip => return false,
                None => return false,
                _ => {}
            }
        }

        if let Some(allowed_port) = self.port {
            match dest_port {
                Some(actual_port) if actual_port != allowed_port => return false,
                None => return false,
                _ => {}
            }
        }

        if let Some(ref allowed_domain) = self.domain {
            match domain {
                Some(actual_domain) if actual_domain != allowed_domain => return false,
                None => return false,
                _ => {}
            }
        }

        true
    }
}

/// An application's egress policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppEgressPolicy {
    /// The application identifier.
    pub app: AppIdentifier,
    /// Permitted destinations. If empty, all egress is denied for this app.
    pub allowed_destinations: Vec<EgressDestination>,
}

/// Egress filter with default-deny: only explicitly permitted application+destination
/// combinations are allowed through.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EgressFilter {
    /// Per-application egress policies.
    policies: HashMap<AppIdentifier, AppEgressPolicy>,
}

impl Default for EgressFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl EgressFilter {
    /// Create a new egress filter with no policies (all egress denied).
    pub fn new() -> Self {
        Self {
            policies: HashMap::new(),
        }
    }

    /// Add or replace an egress policy for an application.
    pub fn set_policy(&mut self, policy: AppEgressPolicy) {
        self.policies.insert(policy.app.clone(), policy);
    }

    /// Remove the egress policy for an application.
    ///
    /// # Errors
    ///
    /// Returns `EgressError::ApplicationNotFound` if no policy exists.
    pub fn remove_policy(&mut self, app: &AppIdentifier) -> Result<(), EgressError> {
        if self.policies.remove(app).is_some() {
            Ok(())
        } else {
            let name = match app {
                AppIdentifier::ProcessName(n) => n.clone(),
                AppIdentifier::BinaryPath(p) => p.clone(),
            };
            Err(EgressError::ApplicationNotFound(name))
        }
    }

    /// Check whether the specified application is allowed to send traffic to the
    /// given destination.
    ///
    /// Returns `true` only if a policy exists for the application **and** at least
    /// one of its allowed destinations matches the traffic. Otherwise returns `false`
    /// (default deny).
    pub fn is_allowed(
        &self,
        process_name: Option<&str>,
        binary_path: Option<&str>,
        dest_ip: Option<IpAddr>,
        dest_port: Option<u16>,
        domain: Option<&str>,
    ) -> bool {
        for policy in self.policies.values() {
            if !policy.app.matches(process_name, binary_path) {
                continue;
            }
            for dest in &policy.allowed_destinations {
                if dest.matches(dest_ip, dest_port, domain) {
                    return true;
                }
            }
            // Policy exists but no destination matched — deny.
            return false;
        }
        // No policy found — default deny.
        false
    }

    /// Return the number of configured application policies.
    pub fn policy_count(&self) -> usize {
        self.policies.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_unknown_app_denied() {
        let filter = EgressFilter::new();
        assert!(!filter.is_allowed(
            Some("unknown_app"),
            None,
            Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
            Some(443),
            None,
        ));
    }

    #[test]
    fn test_app_allowed_to_permitted_destination() {
        let mut filter = EgressFilter::new();
        filter.set_policy(AppEgressPolicy {
            app: AppIdentifier::ProcessName("firefox".to_string()),
            allowed_destinations: vec![EgressDestination {
                ip: None,
                port: Some(443),
                domain: None,
            }],
        });

        assert!(filter.is_allowed(
            Some("firefox"),
            None,
            Some(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))),
            Some(443),
            None,
        ));
    }

    #[test]
    fn test_app_denied_non_permitted_destination() {
        let mut filter = EgressFilter::new();
        filter.set_policy(AppEgressPolicy {
            app: AppIdentifier::ProcessName("firefox".to_string()),
            allowed_destinations: vec![EgressDestination {
                ip: None,
                port: Some(443),
                domain: None,
            }],
        });

        // Port 80 is not in the allow list.
        assert!(!filter.is_allowed(
            Some("firefox"),
            None,
            Some(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))),
            Some(80),
            None,
        ));
    }

    #[test]
    fn test_binary_path_identification() {
        let mut filter = EgressFilter::new();
        filter.set_policy(AppEgressPolicy {
            app: AppIdentifier::BinaryPath("/usr/bin/curl".to_string()),
            allowed_destinations: vec![EgressDestination {
                ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
                port: Some(8080),
                domain: None,
            }],
        });

        assert!(filter.is_allowed(
            None,
            Some("/usr/bin/curl"),
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            Some(8080),
            None,
        ));

        // Different binary path.
        assert!(!filter.is_allowed(
            None,
            Some("/usr/bin/wget"),
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            Some(8080),
            None,
        ));
    }

    #[test]
    fn test_domain_based_egress() {
        let mut filter = EgressFilter::new();
        filter.set_policy(AppEgressPolicy {
            app: AppIdentifier::ProcessName("apt".to_string()),
            allowed_destinations: vec![EgressDestination {
                ip: None,
                port: None,
                domain: Some("deb.debian.org".to_string()),
            }],
        });

        assert!(filter.is_allowed(
            Some("apt"),
            None,
            None,
            None,
            Some("deb.debian.org"),
        ));

        assert!(!filter.is_allowed(
            Some("apt"),
            None,
            None,
            None,
            Some("evil.com"),
        ));
    }

    #[test]
    fn test_multiple_destinations() {
        let mut filter = EgressFilter::new();
        filter.set_policy(AppEgressPolicy {
            app: AppIdentifier::ProcessName("ssh".to_string()),
            allowed_destinations: vec![
                EgressDestination {
                    ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
                    port: Some(22),
                    domain: None,
                },
                EgressDestination {
                    ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
                    port: Some(22),
                    domain: None,
                },
            ],
        });

        assert!(filter.is_allowed(
            Some("ssh"),
            None,
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            Some(22),
            None,
        ));
        assert!(filter.is_allowed(
            Some("ssh"),
            None,
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
            Some(22),
            None,
        ));
        assert!(!filter.is_allowed(
            Some("ssh"),
            None,
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3))),
            Some(22),
            None,
        ));
    }

    #[test]
    fn test_remove_policy() {
        let mut filter = EgressFilter::new();
        let app = AppIdentifier::ProcessName("test".to_string());
        filter.set_policy(AppEgressPolicy {
            app: app.clone(),
            allowed_destinations: vec![],
        });
        assert_eq!(filter.policy_count(), 1);

        filter.remove_policy(&app).unwrap();
        assert_eq!(filter.policy_count(), 0);
    }

    #[test]
    fn test_remove_nonexistent_policy_errors() {
        let mut filter = EgressFilter::new();
        let app = AppIdentifier::ProcessName("ghost".to_string());
        let result = filter.remove_policy(&app);
        assert!(result.is_err());
    }

    #[test]
    fn test_app_with_empty_destinations_denied() {
        let mut filter = EgressFilter::new();
        filter.set_policy(AppEgressPolicy {
            app: AppIdentifier::ProcessName("locked-down".to_string()),
            allowed_destinations: vec![],
        });

        // Policy exists but no destinations — all traffic denied.
        assert!(!filter.is_allowed(
            Some("locked-down"),
            None,
            Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
            Some(443),
            None,
        ));
    }
}
