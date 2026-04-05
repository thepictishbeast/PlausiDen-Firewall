# PlausiDen Firewall

Application-aware firewall with deep packet inspection, egress filtering, and DNS sinkholing. Part of the PlausiDen ecosystem.

## Threat Model

Assumes state-level adversaries with the capability to intercept, analyze, and correlate network traffic. Every connection that leaves your machine is a potential data exfiltration vector.

## Features

- **Rule Engine** — Priority-ordered rules with default-deny semantics. Supports IP, port range, protocol, application, and domain matching.
- **DNS Sinkhole** — Blocks resolution of malware C2, tracking, and telemetry domains. Supports exact and wildcard patterns. Ships with a curated default blocklist.
- **Egress Filtering** — Per-application outbound control. Each application must be explicitly granted network access to specific destinations.
- **Deep Packet Inspection** *(planned)* — Protocol detection, TLS fingerprinting, payload signature matching.
- **eBPF Integration** *(planned)* — Kernel-level packet filtering via XDP and TC hooks.
- **nftables Backend** *(planned)* — Stateful connection tracking and NAT via netfilter.

## Platform Support

- **Linux** — Primary platform (eBPF + nftables)
- **macOS** — Planned (pf + Network Extension)
- **Windows** — Planned (WFP)

## Building

```sh
cargo build
cargo test
```

## License

BSL-1.1
