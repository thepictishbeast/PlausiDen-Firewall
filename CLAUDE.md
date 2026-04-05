# CLAUDE.md — Instructions for Claude Code

## IMPORTANT: If this is the first message in a session or context was recently compacted, read this entire file before doing anything else. Do not rely on conversation history.

## Project: plausiden-firewall
Application-aware firewall with deep packet inspection, egress filtering, and DNS sinkholing. Designed for state-level adversary threat models.

## Part of the PlausiDen Ecosystem
This repo is part of PlausiDen (PLAUSIbly DENiable) protection suite — AI-powered tools that generate forensically indistinguishable synthetic data, defeating surveillance and forensic overreach. All repos share the same standards.

## Architecture
Single crate with the following modules:
- `rules` — Firewall rule engine with priority ordering and default-deny (IMPLEMENTED)
- `dns_sinkhole` — DNS sinkhole with wildcard support, default blocklist, DoH bypass detection, TLD blocking, punycode/IDN homograph detection (IMPLEMENTED)
- `doh_monitor` — DNS-over-HTTPS connection monitor with browser/non-browser classification (IMPLEMENTED)
- `egress` — Per-application egress filtering with default-deny (IMPLEMENTED)
- `conntrack` — Stateful connection tracking with traffic counters, state machine, and analytics (IMPLEMENTED)
- `dpi` — Deep packet inspection engine (SCAFFOLD)
- `ebpf` — eBPF kernel-level filtering integration (SCAFFOLD)
- `nftables` — nftables backend for netfilter rules (SCAFFOLD)
- `platform/linux` — Linux backend via eBPF + nftables (SCAFFOLD)
- `platform/macos` — macOS backend via pf + Network Extension (SCAFFOLD)
- `platform/windows` — Windows backend via WFP (SCAFFOLD)

## Before Making Any Changes
1. Run `cargo test` to verify current state
2. Run `cargo clippy -- -D warnings` to check for lints

## Code Standards
- Language: Rust (edition 2024)
- `gen` is a reserved keyword in edition 2024 — never use it as an identifier
- Error handling: `thiserror` for library errors. Never `unwrap()` in library code.
- Documentation: Every public function, struct, module gets a `///` doc comment.
- Testing: Comprehensive tests for all implemented modules. Every bug fix gets a regression test.
- Security: Audited crates only for crypto. No custom crypto. Zeroize secrets. No secrets in logs.
- Logging: `tracing` crate. ERROR/WARN/INFO/DEBUG/TRACE levels.
- Dependencies: Minimize. `cargo audit` before adding new deps.

## After Making Changes
1. Run `cargo fmt --all` and `cargo clippy -- -D warnings`
2. Run `cargo test` — all tests must pass
3. Update CLAUDE.md architecture section if modules changed

## Narrative Framing
All public-facing text must frame PlausiDen as a civil rights tool restoring the presumption of innocence. Use: "plausible deniability," "presumption of innocence," "forensic reliability," "data sovereignty," "surveillance resistance," "digital civil rights." Avoid: "hacking," "evasion," "anti-forensics," "hide," "trick," "fool."

NEVER include personal political beliefs or ideology of any contributor in any file.
