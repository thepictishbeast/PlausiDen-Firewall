//! PlausiDen Firewall — Application-aware firewall with DPI, egress filtering, DNS sinkholing.
//!
//! Designed for state-level adversary threat models. Linux-first via eBPF/nftables,
//! with cross-platform support planned.

pub mod bandwidth;
pub mod conntrack;
pub mod dns_sinkhole;
pub mod doh_monitor;
pub mod dpi;
pub mod ebpf;
pub mod egress;
pub mod monitor;
pub mod nftables;
pub mod platform;
pub mod rules;
pub mod stats;
