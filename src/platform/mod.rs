//! Platform-specific firewall backends.
//!
//! Each platform module implements the native packet filtering API:
//! - Linux: eBPF + nftables
//! - macOS: pf (packet filter) + Network Extension
//! - Windows: WFP (Windows Filtering Platform)

pub mod linux;
pub mod macos;
pub mod windows;
