//! eBPF integration for kernel-level packet filtering.
//!
//! Uses eBPF programs attached to TC (traffic control) and XDP (eXpress Data Path)
//! hooks for high-performance, in-kernel packet processing. Communicates with
//! userspace via BPF maps for dynamic rule updates.
//!
//! **Status:** Scaffold — implementation planned.

/// eBPF program attachment point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachPoint {
    /// XDP (eXpress Data Path) — earliest hook, before the kernel network stack.
    Xdp,
    /// TC ingress — traffic control on incoming packets.
    TcIngress,
    /// TC egress — traffic control on outgoing packets.
    TcEgress,
}

/// eBPF-backed firewall engine.
///
/// # Future implementation
///
/// - Load compiled eBPF programs from ELF objects
/// - Attach to network interfaces at XDP/TC hooks
/// - Populate BPF hash maps with firewall rules
/// - Receive events from eBPF ring buffer for logging
/// - Support CO-RE (Compile Once, Run Everywhere) via BTF
#[derive(Debug, Default)]
pub struct EbpfEngine {
    _private: (),
}

impl EbpfEngine {
    /// Create a new eBPF engine.
    pub fn new() -> Self {
        Self { _private: () }
    }
}
