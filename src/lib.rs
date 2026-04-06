//! PlausiDen Firewall — Application-aware firewall with DPI, egress filtering, DNS sinkholing.
//!
//! Designed for state-level adversary threat models. Linux-first via eBPF/nftables,
//! with cross-platform support planned.

pub mod bandwidth;
pub mod blacklist_sync;
pub mod anomaly_detector;
pub mod app_fingerprint;
pub mod application_identity;
pub mod arp_monitor;
pub mod connection_limit;
pub mod conntrack;
pub mod dns_cache;
pub mod dns_filter;
pub mod dns_query_log;
pub mod dns_over_https;
pub mod dns_pinning;
pub mod dns_sinkhole;
pub mod dns_tunnel;
pub mod doh_monitor;
pub mod dpi;
pub mod ebpf;
pub mod egress;
pub mod monitor;
pub mod network_zones;
pub mod nftables;
pub mod nftables_state;
pub mod platform;
pub mod route_table;
pub mod rules;
pub mod stats;
pub mod session_hijack;
pub mod session_tracking;
pub mod ssl_inspection;
pub mod syn_flood;
pub mod tcp_reset;
pub mod threat_intel;
pub mod traffic_shaper;
pub mod geo_block;
pub mod geo_routing;
pub mod geo_ip;
pub mod http_mime_filter;
pub mod icmp_filter;
pub mod icmp_rate_limit;
pub mod ip_reputation;
pub mod ipv6_filter;
pub mod packet_log;
pub mod payload_inspector;
pub mod port_knock;
pub mod port_scan_detector;
pub mod protocol_anomaly;
pub mod protocol_filter;
pub mod proxy_detect;
pub mod qos_classifier;
pub mod whitelist;
