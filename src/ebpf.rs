//! eBPF integration for kernel-level packet filtering.
//!
//! Defines the interface for loading and managing eBPF programs.
//! Actual eBPF loading requires root and kernel support — this module
//! provides the data structures and configuration that userspace manages.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttachPoint { Xdp, TcIngress, TcEgress }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EbpfAction { Pass, Drop, Redirect }

/// A rule entry for the eBPF hash map.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BpfMapEntry {
    pub key: BpfMapKey,
    pub action: EbpfAction,
    pub packet_count: u64,
    pub byte_count: u64,
}

/// Key for the BPF hash map — matches packet 5-tuple.
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct BpfMapKey {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
}

/// eBPF program configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EbpfConfig {
    pub program_path: Option<PathBuf>,
    pub attach_point: AttachPoint,
    pub interface: String,
    pub map_capacity: u32,
}

impl Default for EbpfConfig {
    fn default() -> Self {
        Self {
            program_path: None,
            attach_point: AttachPoint::TcIngress,
            interface: "eth0".into(),
            map_capacity: 65536,
        }
    }
}

/// eBPF engine — manages program loading and map updates.
pub struct EbpfEngine {
    config: EbpfConfig,
    rules: HashMap<BpfMapKey, EbpfAction>,
    loaded: bool,
}

impl EbpfEngine {
    pub fn new(config: EbpfConfig) -> Self {
        Self { config, rules: HashMap::new(), loaded: false }
    }

    /// Add a rule to the BPF map.
    pub fn add_rule(&mut self, key: BpfMapKey, action: EbpfAction) {
        self.rules.insert(key, action);
    }

    /// Remove a rule from the BPF map.
    pub fn remove_rule(&mut self, key: &BpfMapKey) -> bool {
        self.rules.remove(key).is_some()
    }

    /// Get all rules.
    pub fn rules(&self) -> &HashMap<BpfMapKey, EbpfAction> {
        &self.rules
    }

    /// Number of rules loaded.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Simulate packet evaluation (for testing without actual eBPF).
    pub fn evaluate_packet(&self, key: &BpfMapKey) -> EbpfAction {
        self.rules.get(key).copied().unwrap_or(EbpfAction::Pass)
    }

    /// Convert an IPv4 address string to u32.
    pub fn ip_to_u32(ip: &str) -> Option<u32> {
        let parts: Vec<u8> = ip.split('.').filter_map(|s| s.parse().ok()).collect();
        if parts.len() == 4 {
            Some((parts[0] as u32) << 24 | (parts[1] as u32) << 16 | (parts[2] as u32) << 8 | parts[3] as u32)
        } else {
            None
        }
    }

    /// Check if the engine would be ready to load (has config + rules).
    pub fn ready_to_load(&self) -> bool {
        self.config.program_path.is_some() && !self.rules.is_empty()
    }

    /// Simulate loading (actual loading requires root + eBPF support).
    pub fn simulate_load(&mut self) -> Result<(), String> {
        if self.rules.is_empty() {
            return Err("no rules to load".into());
        }
        if self.rules.len() > self.config.map_capacity as usize {
            return Err(format!("too many rules: {} > {}", self.rules.len(), self.config.map_capacity));
        }
        self.loaded = true;
        Ok(())
    }

    pub fn is_loaded(&self) -> bool { self.loaded }
}

impl Default for EbpfEngine {
    fn default() -> Self { Self::new(EbpfConfig::default()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key(dst_port: u16) -> BpfMapKey {
        BpfMapKey { src_ip: 0, dst_ip: EbpfEngine::ip_to_u32("93.184.216.34").unwrap(), src_port: 0, dst_port, protocol: 6 }
    }

    #[test]
    fn test_add_and_evaluate() {
        let mut engine = EbpfEngine::default();
        let key = test_key(443);
        engine.add_rule(key.clone(), EbpfAction::Drop);
        assert_eq!(engine.evaluate_packet(&key), EbpfAction::Drop);
    }

    #[test]
    fn test_default_pass() {
        let engine = EbpfEngine::default();
        assert_eq!(engine.evaluate_packet(&test_key(80)), EbpfAction::Pass);
    }

    #[test]
    fn test_remove_rule() {
        let mut engine = EbpfEngine::default();
        let key = test_key(22);
        engine.add_rule(key.clone(), EbpfAction::Drop);
        assert!(engine.remove_rule(&key));
        assert_eq!(engine.evaluate_packet(&key), EbpfAction::Pass);
    }

    #[test]
    fn test_ip_to_u32() {
        assert_eq!(EbpfEngine::ip_to_u32("192.168.1.1"), Some(0xC0A80101));
        assert_eq!(EbpfEngine::ip_to_u32("10.0.0.1"), Some(0x0A000001));
        assert_eq!(EbpfEngine::ip_to_u32("invalid"), None);
    }

    #[test]
    fn test_simulate_load() {
        let mut engine = EbpfEngine::default();
        assert!(engine.simulate_load().is_err()); // No rules
        engine.add_rule(test_key(443), EbpfAction::Drop);
        assert!(engine.simulate_load().is_ok());
        assert!(engine.is_loaded());
    }

    #[test]
    fn test_capacity_limit() {
        let mut engine = EbpfEngine::new(EbpfConfig { map_capacity: 2, ..Default::default() });
        engine.add_rule(test_key(80), EbpfAction::Pass);
        engine.add_rule(test_key(443), EbpfAction::Pass);
        engine.add_rule(test_key(22), EbpfAction::Drop);
        assert!(engine.simulate_load().is_err());
    }
}
