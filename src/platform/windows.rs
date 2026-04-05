//! Windows firewall backend using WFP (Windows Filtering Platform).
//!
//! Uses the Windows Filtering Platform API for kernel-level packet inspection
//! and filtering. Supports per-application rules via WFP application ID conditions.
//!
//! **Status:** Scaffold — implementation planned.

/// Windows firewall backend.
///
/// # Future implementation
///
/// - Initialize WFP engine via `FwpmEngineOpen`
/// - Add sublayers and filters for PlausiDen rules
/// - Use WFP callout drivers for DPI
/// - Map `AppIdentifier::BinaryPath` to WFP application IDs
/// - Support Windows service SIDs for service-level filtering
#[derive(Debug, Default)]
pub struct WindowsBackend {
    _private: (),
}

impl WindowsBackend {
    /// Create a new Windows backend.
    pub fn new() -> Self {
        Self { _private: () }
    }
}
