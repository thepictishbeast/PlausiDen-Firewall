//! nftables backend for translating firewall rules into kernel netfilter rules.
//!
//! Generates nftables rulesets and applies them via the `nft` command or
//! libnftables bindings. Manages tables, chains, and sets for the PlausiDen
//! firewall.
//!
//! **Status:** Scaffold — implementation planned.

/// nftables table family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TableFamily {
    /// IPv4 (ip).
    Inet4,
    /// IPv6 (ip6).
    Inet6,
    /// Dual-stack (inet).
    Inet,
}

/// nftables chain type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainType {
    /// Filter chain — accept or drop packets.
    Filter,
    /// NAT chain — network address translation.
    Nat,
    /// Route chain — reroute packets.
    Route,
}

/// nftables backend engine.
///
/// # Future implementation
///
/// - Generate nftables rulesets from `RuleSet`
/// - Apply atomically via `nft -f`
/// - Manage named sets for IP blocklists
/// - Support connection tracking (conntrack) for stateful filtering
/// - Integrate with DNS sinkhole for dynamic IP sets
#[derive(Debug, Default)]
pub struct NftablesBackend {
    _private: (),
}

impl NftablesBackend {
    /// Create a new nftables backend.
    pub fn new() -> Self {
        Self { _private: () }
    }
}
