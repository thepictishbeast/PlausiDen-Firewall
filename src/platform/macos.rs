//! macOS firewall backend using pf and Network Extension.
//!
//! Uses the BSD packet filter (pf) for kernel-level filtering and the
//! Network Extension framework for application-level control.
//!
//! **Status:** Scaffold — implementation planned.

/// macOS firewall backend.
///
/// # Future implementation
///
/// - Generate pf.conf rules from `RuleSet`
/// - Use `pfctl` for atomic rule updates
/// - Integrate with Network Extension for per-app filtering
/// - Support macOS system extensions for kernel-level hooks
#[derive(Debug, Default)]
pub struct MacosBackend {
    _private: (),
}

impl MacosBackend {
    /// Create a new macOS backend.
    pub fn new() -> Self {
        Self { _private: () }
    }
}
