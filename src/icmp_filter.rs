//! ICMP filter — control ICMP message types and rate limiting.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// ICMP message type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IcmpType {
    EchoRequest,
    EchoReply,
    DestinationUnreachable,
    SourceQuench,
    Redirect,
    TimeExceeded,
    ParameterProblem,
    Timestamp,
    AddressMask,
    RouterAdvert,
    RouterSolicit,
    Other(u8),
}

impl IcmpType {
    pub fn from_code(code: u8) -> Self {
        match code {
            0 => IcmpType::EchoReply,
            3 => IcmpType::DestinationUnreachable,
            4 => IcmpType::SourceQuench,
            5 => IcmpType::Redirect,
            8 => IcmpType::EchoRequest,
            9 => IcmpType::RouterAdvert,
            10 => IcmpType::RouterSolicit,
            11 => IcmpType::TimeExceeded,
            12 => IcmpType::ParameterProblem,
            13 | 14 => IcmpType::Timestamp,
            17 | 18 => IcmpType::AddressMask,
            other => IcmpType::Other(other),
        }
    }
}

/// ICMP filter policy.
pub struct IcmpFilter {
    /// Allowed message types (whitelist).
    allowed_types: HashSet<IcmpType>,
    /// Block all types not in allowed_types.
    default_deny: bool,
    /// Per-type counters.
    counters: std::collections::HashMap<IcmpType, u64>,
    /// Drop counters.
    drops: std::collections::HashMap<IcmpType, u64>,
}

impl IcmpFilter {
    pub fn new() -> Self {
        Self {
            allowed_types: Self::safe_default_allowed(),
            default_deny: true,
            counters: Default::default(),
            drops: Default::default(),
        }
    }

    /// Reasonable default — allow basic ICMP, block info disclosure types.
    fn safe_default_allowed() -> HashSet<IcmpType> {
        HashSet::from([
            IcmpType::EchoRequest,
            IcmpType::EchoReply,
            IcmpType::DestinationUnreachable,
            IcmpType::TimeExceeded,
            IcmpType::ParameterProblem,
        ])
    }

    /// Allow a specific ICMP type.
    pub fn allow(&mut self, icmp_type: IcmpType) {
        self.allowed_types.insert(icmp_type);
    }

    /// Block a specific ICMP type.
    pub fn block(&mut self, icmp_type: IcmpType) {
        self.allowed_types.remove(&icmp_type);
    }

    /// Process an incoming ICMP packet, returning whether to allow it.
    pub fn check(&mut self, icmp_type: IcmpType) -> bool {
        let allowed = if self.default_deny {
            self.allowed_types.contains(&icmp_type)
        } else {
            !self.allowed_types.contains(&icmp_type)
        };

        if allowed {
            *self.counters.entry(icmp_type).or_default() += 1;
        } else {
            *self.drops.entry(icmp_type).or_default() += 1;
        }

        allowed
    }

    /// Total packets allowed.
    pub fn total_allowed(&self) -> u64 {
        self.counters.values().sum()
    }

    /// Total packets dropped.
    pub fn total_dropped(&self) -> u64 {
        self.drops.values().sum()
    }

    /// Get per-type stats.
    pub fn type_stats(&self) -> Vec<(IcmpType, u64, u64)> {
        let mut all_types: HashSet<IcmpType> = self.counters.keys().copied().collect();
        all_types.extend(self.drops.keys().copied());
        all_types.into_iter()
            .map(|t| (t, *self.counters.get(&t).unwrap_or(&0), *self.drops.get(&t).unwrap_or(&0)))
            .collect()
    }

    /// Apply paranoid policy — block all but echo reply.
    pub fn apply_paranoid(&mut self) {
        self.allowed_types.clear();
        self.allowed_types.insert(IcmpType::EchoReply);
    }

    /// Apply standard policy.
    pub fn apply_standard(&mut self) {
        self.allowed_types = Self::safe_default_allowed();
    }
}

impl Default for IcmpFilter {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_allows_echo() {
        let mut filter = IcmpFilter::new();
        assert!(filter.check(IcmpType::EchoRequest));
        assert!(filter.check(IcmpType::EchoReply));
    }

    #[test]
    fn test_default_blocks_redirect() {
        let mut filter = IcmpFilter::new();
        assert!(!filter.check(IcmpType::Redirect));
        assert_eq!(filter.total_dropped(), 1);
    }

    #[test]
    fn test_block_echo_request() {
        let mut filter = IcmpFilter::new();
        filter.block(IcmpType::EchoRequest);
        assert!(!filter.check(IcmpType::EchoRequest));
    }

    #[test]
    fn test_allow_redirect() {
        let mut filter = IcmpFilter::new();
        filter.allow(IcmpType::Redirect);
        assert!(filter.check(IcmpType::Redirect));
    }

    #[test]
    fn test_paranoid_mode() {
        let mut filter = IcmpFilter::new();
        filter.apply_paranoid();
        assert!(filter.check(IcmpType::EchoReply));
        assert!(!filter.check(IcmpType::EchoRequest));
    }

    #[test]
    fn test_from_code() {
        assert_eq!(IcmpType::from_code(8), IcmpType::EchoRequest);
        assert_eq!(IcmpType::from_code(0), IcmpType::EchoReply);
        assert_eq!(IcmpType::from_code(3), IcmpType::DestinationUnreachable);
    }

    #[test]
    fn test_stats() {
        let mut filter = IcmpFilter::new();
        filter.check(IcmpType::EchoRequest);
        filter.check(IcmpType::EchoRequest);
        filter.check(IcmpType::Redirect); // Dropped.
        assert_eq!(filter.total_allowed(), 2);
        assert_eq!(filter.total_dropped(), 1);
    }

    #[test]
    fn test_type_stats() {
        let mut filter = IcmpFilter::new();
        filter.check(IcmpType::EchoRequest);
        filter.check(IcmpType::Redirect);
        let stats = filter.type_stats();
        assert!(!stats.is_empty());
    }
}
