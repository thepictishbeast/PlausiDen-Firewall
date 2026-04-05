//! Linux firewall backend using eBPF and nftables.
//!
//! Primary platform. Uses eBPF for high-performance kernel-level filtering
//! and nftables for stateful connection tracking and NAT.
//!
//! **Status:** Scaffold — implementation planned.

/// Linux firewall backend.
///
/// # Future implementation
///
/// - Initialize eBPF programs and attach to interfaces
/// - Configure nftables base chains
/// - Translate `RuleSet` into both eBPF maps and nftables rules
/// - Monitor `/proc/net` for connection state
/// - Integrate with cgroup v2 for per-application filtering
#[derive(Debug, Default)]
pub struct LinuxBackend {
    _private: (),
}

impl LinuxBackend {
    /// Create a new Linux backend.
    pub fn new() -> Self {
        Self { _private: () }
    }
}
