//! PlausiDen Firewall — Application-aware firewall with DPI, egress filtering, DNS sinkholing.
//!
//! Designed for state-level adversary threat models. Linux-first via eBPF/nftables,
//! with cross-platform support planned.

pub mod dns_sinkhole;
pub mod dpi;
pub mod ebpf;
pub mod egress;
pub mod nftables;
pub mod platform;
pub mod rules;
