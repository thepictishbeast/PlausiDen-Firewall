//! PlausiDen Firewall — Application-aware firewall with DPI, egress filtering, DNS sinkholing.
//!
//! Designed for state-level adversary threat models. Linux-first via eBPF/nftables,
//! with cross-platform support planned.

pub mod bandwidth;
pub mod anomaly_detector;
pub mod app_fingerprint;
pub mod application_identity;
pub mod connection_limit;
pub mod conntrack;
pub mod dns_sinkhole;
pub mod dns_tunnel;
pub mod doh_monitor;
pub mod dpi;
pub mod ebpf;
pub mod egress;
pub mod monitor;
pub mod nftables;
pub mod platform;
pub mod rules;
pub mod stats;
pub mod session_tracking;
pub mod ssl_inspection;
pub mod threat_intel;
pub mod traffic_shaper;
pub mod geo_block;
pub mod geo_ip;
pub mod ip_reputation;
pub mod packet_log;
pub mod port_knock;
pub mod protocol_filter;
