//! Integration tests exercising multiple PlausiDen Firewall modules together.
//!
//! Each test combines two or more modules to verify end-to-end behavior that
//! unit tests within individual modules cannot cover.

use std::net::{IpAddr, Ipv4Addr};

use plausiden_firewall::conntrack::{ConnectionKey, ConnectionTracker, Direction, TcpState};
use plausiden_firewall::dns_sinkhole::DnsSinkhole;
use plausiden_firewall::doh_monitor::{DohMonitor, ObservedConnection};
use plausiden_firewall::dpi::{DetectedProtocol, DpiEngine};
use plausiden_firewall::ebpf::{BpfMapKey, EbpfAction, EbpfConfig, EbpfEngine};
use plausiden_firewall::egress::{AppEgressPolicy, AppIdentifier, EgressDestination, EgressFilter};
use plausiden_firewall::nftables::{NftablesBackend, TableFamily};
use plausiden_firewall::platform::linux::LinuxBackend;
use plausiden_firewall::platform::macos::MacosBackend;
use plausiden_firewall::platform::windows::WindowsBackend;
use plausiden_firewall::rules::{FirewallRule, Protocol, RuleAction, RuleMatch, RuleSet};

/// Helper: create a firewall rule with the given parameters.
fn make_rule(
    name: &str,
    priority: u32,
    action: RuleAction,
    rule_match: RuleMatch,
) -> FirewallRule {
    FirewallRule {
        id: uuid::Uuid::new_v4(),
        name: name.to_string(),
        priority,
        rule_match,
        action,
        enabled: true,
    }
}

// ---------------------------------------------------------------------------
// 1. Full pipeline: create rules -> generate nftables -> verify script
// ---------------------------------------------------------------------------

#[test]
fn test_full_pipeline_rules_to_nftables_script() {
    // Build a realistic rule set.
    let mut rules = RuleSet::new();

    rules
        .add_rule(make_rule(
            "allow-dns",
            10,
            RuleAction::Allow,
            RuleMatch {
                dest_port_range: Some((53, 53)),
                protocol: Some(Protocol::Udp),
                ..Default::default()
            },
        ))
        .unwrap();

    rules
        .add_rule(make_rule(
            "allow-https-trusted",
            20,
            RuleAction::Allow,
            RuleMatch {
                dest_ip: Some(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))),
                dest_port_range: Some((443, 443)),
                protocol: Some(Protocol::Tcp),
                ..Default::default()
            },
        ))
        .unwrap();

    rules
        .add_rule(make_rule(
            "deny-ssh-outbound",
            30,
            RuleAction::Deny,
            RuleMatch {
                dest_port_range: Some((22, 22)),
                protocol: Some(Protocol::Tcp),
                ..Default::default()
            },
        ))
        .unwrap();

    rules
        .add_rule(make_rule(
            "log-inbound-http",
            40,
            RuleAction::Log,
            RuleMatch {
                source_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0))),
                dest_port_range: Some((80, 80)),
                ..Default::default()
            },
        ))
        .unwrap();

    // Generate the nftables script.
    let backend = NftablesBackend::new("plausiden", TableFamily::Inet);
    let nft = backend.generate_ruleset(&rules);
    let script = nft.to_script();

    // The script must contain boilerplate plus our rules.
    assert!(script.contains("flush table inet plausiden"));
    assert!(script.contains("policy drop"));
    assert!(script.contains("ct state established,related accept"));
    assert!(script.contains("iif lo accept"));

    // Each of the four rules should produce an nft command.
    assert!(script.contains("53"));
    assert!(script.contains("93.184.216.34"));
    assert!(script.contains("443"));
    assert!(script.contains("22"));
    assert!(script.contains("accept")); // allow rules
    assert!(script.contains("drop")); // deny rules
    assert!(script.contains("log")); // log rule

    // At least 4 user rules plus the boilerplate rules.
    assert!(nft.rule_count() >= 4 + 4);

    // Verify rule evaluation still works for the same rule set.
    let action = rules.evaluate(
        None,
        None,
        None,
        Some(53),
        Some(Protocol::Udp),
        None,
        None,
    );
    assert_eq!(action, RuleAction::Allow);

    let action = rules.evaluate(
        None,
        None,
        None,
        Some(22),
        Some(Protocol::Tcp),
        None,
        None,
    );
    assert_eq!(action, RuleAction::Deny);
}

// ---------------------------------------------------------------------------
// 2. DNS sinkhole + egress filter: blocked domain also denied at egress
// ---------------------------------------------------------------------------

#[test]
fn test_dns_sinkhole_plus_egress_filter() {
    // Set up sinkhole with a malicious domain and its known IP.
    let mut sinkhole = DnsSinkhole::new();
    sinkhole.add_domain("malware-c2.evil.org");
    sinkhole.add_domain("*.evil.org");

    // The "resolved" IP of malware-c2.evil.org in our scenario.
    let malware_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 42));

    // Sinkhole correctly blocks the domain.
    assert!(sinkhole.is_sinkholed("malware-c2.evil.org"));
    assert!(sinkhole.is_sinkholed("other.evil.org"));
    assert!(!sinkhole.is_sinkholed("safe-site.com"));

    // Set up egress filter: only allow firefox to reach safe destinations.
    let mut egress = EgressFilter::new();
    egress.set_policy(AppEgressPolicy {
        app: AppIdentifier::ProcessName("firefox".to_string()),
        allowed_destinations: vec![
            EgressDestination {
                ip: Some(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))),
                port: Some(443),
                domain: None,
            },
        ],
    });

    // Firefox can reach the allowed IP.
    assert!(egress.is_allowed(
        Some("firefox"),
        None,
        Some(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))),
        Some(443),
        None,
    ));

    // Firefox cannot reach the malware IP (not in allowed list).
    assert!(!egress.is_allowed(
        Some("firefox"),
        None,
        Some(malware_ip),
        Some(443),
        None,
    ));

    // Unknown app cannot reach anything (default deny).
    assert!(!egress.is_allowed(
        Some("malware_agent"),
        None,
        Some(malware_ip),
        Some(443),
        None,
    ));

    // Combined check: if the domain is sinkholed AND the IP is denied at egress,
    // neither layer allows the connection.
    let domain = "malware-c2.evil.org";
    let domain_blocked = sinkhole.is_sinkholed(domain);
    let egress_blocked = !egress.is_allowed(
        Some("malware_agent"),
        None,
        Some(malware_ip),
        Some(443),
        None,
    );
    assert!(domain_blocked && egress_blocked, "Both layers must block");
}

// ---------------------------------------------------------------------------
// 3. DPI + conntrack: inspect packet, track connection, verify transitions
// ---------------------------------------------------------------------------

#[test]
fn test_dpi_plus_conntrack_state_transitions() {
    let dpi = DpiEngine::new();
    let mut tracker = ConnectionTracker::new(1000);

    // Simulate an outbound TLS Client Hello.
    let client_hello: Vec<u8> = {
        let mut buf = vec![0x16, 0x03, 0x01, 0x00, 0x05, 0x01];
        buf.extend_from_slice(&[0u8; 50]); // pad to realistic size
        buf
    };

    // DPI detects HTTPS.
    let inspection = dpi.inspect(&client_hello, 443);
    assert_eq!(inspection.protocol, DetectedProtocol::Https);
    assert!(inspection.confidence > 0.5);

    // Track the outbound SYN/Client Hello.
    let conn = tracker
        .track_packet(
            "192.168.1.100",
            50000,
            "93.184.216.34",
            443,
            Protocol::Tcp,
            Direction::Outbound,
            client_hello.len() as u64,
        )
        .unwrap();
    assert_eq!(conn.state, TcpState::New);
    assert_eq!(conn.packets_sent, 1);

    // Simulate inbound SYN-ACK: state should transition to Established.
    let conn = tracker
        .track_packet(
            "192.168.1.100",
            50000,
            "93.184.216.34",
            443,
            Protocol::Tcp,
            Direction::Inbound,
            64,
        )
        .unwrap();
    assert_eq!(conn.state, TcpState::Established);
    assert_eq!(conn.packets_sent, 1);
    assert_eq!(conn.packets_received, 1);

    // Simulate more data exchange.
    tracker
        .track_packet(
            "192.168.1.100",
            50000,
            "93.184.216.34",
            443,
            Protocol::Tcp,
            Direction::Outbound,
            512,
        )
        .unwrap();
    tracker
        .track_packet(
            "192.168.1.100",
            50000,
            "93.184.216.34",
            443,
            Protocol::Tcp,
            Direction::Inbound,
            2048,
        )
        .unwrap();

    // Verify accumulated counters.
    let key = ConnectionKey {
        src_ip: "192.168.1.100".to_string(),
        src_port: 50000,
        dst_ip: "93.184.216.34".to_string(),
        dst_port: 443,
        protocol: Protocol::Tcp,
    };
    let final_state = tracker.get_connection(&key).unwrap();
    assert_eq!(final_state.state, TcpState::Established);
    assert_eq!(final_state.packets_sent, 2);
    assert_eq!(final_state.packets_received, 2);
    assert_eq!(
        final_state.bytes_sent,
        client_hello.len() as u64 + 512
    );
    assert_eq!(final_state.bytes_received, 64 + 2048);

    // Manually transition to close.
    assert!(tracker.set_state(&key, TcpState::TimeWait));
    assert_eq!(
        tracker.get_connection(&key).unwrap().state,
        TcpState::TimeWait
    );
    assert!(tracker.set_state(&key, TcpState::Closed));
    assert_eq!(
        tracker.get_connection(&key).unwrap().state,
        TcpState::Closed
    );
}

// ---------------------------------------------------------------------------
// 4. eBPF + rules: add rules to both engines, verify consistent behavior
// ---------------------------------------------------------------------------

#[test]
fn test_ebpf_plus_rules_consistent_decisions() {
    // Set up the standard rule engine.
    let mut rules = RuleSet::new();
    let target_ip = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));

    rules
        .add_rule(make_rule(
            "allow-https-trusted",
            10,
            RuleAction::Allow,
            RuleMatch {
                dest_ip: Some(target_ip),
                dest_port_range: Some((443, 443)),
                protocol: Some(Protocol::Tcp),
                ..Default::default()
            },
        ))
        .unwrap();

    rules
        .add_rule(make_rule(
            "deny-ssh-all",
            20,
            RuleAction::Deny,
            RuleMatch {
                dest_port_range: Some((22, 22)),
                protocol: Some(Protocol::Tcp),
                ..Default::default()
            },
        ))
        .unwrap();

    // Set up eBPF engine with matching rules.
    let mut ebpf = EbpfEngine::new(EbpfConfig::default());

    let https_key = BpfMapKey {
        src_ip: 0,
        dst_ip: EbpfEngine::ip_to_u32("93.184.216.34").unwrap(),
        src_port: 0,
        dst_port: 443,
        protocol: 6, // TCP
    };
    ebpf.add_rule(https_key.clone(), EbpfAction::Pass);

    let ssh_key = BpfMapKey {
        src_ip: 0,
        dst_ip: 0,
        src_port: 0,
        dst_port: 22,
        protocol: 6,
    };
    ebpf.add_rule(ssh_key.clone(), EbpfAction::Drop);

    // Verify both engines agree on HTTPS to trusted IP.
    let rule_action = rules.evaluate(
        None,
        None,
        Some(target_ip),
        Some(443),
        Some(Protocol::Tcp),
        None,
        None,
    );
    let ebpf_action = ebpf.evaluate_packet(&https_key);
    assert_eq!(rule_action, RuleAction::Allow);
    assert_eq!(ebpf_action, EbpfAction::Pass);

    // Verify both engines agree on SSH block.
    let rule_action = rules.evaluate(
        None,
        None,
        Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
        Some(22),
        Some(Protocol::Tcp),
        None,
        None,
    );
    let ebpf_action = ebpf.evaluate_packet(&ssh_key);
    assert_eq!(rule_action, RuleAction::Deny);
    assert_eq!(ebpf_action, EbpfAction::Drop);

    // Verify both default to block/pass for unknown traffic.
    let unknown_key = BpfMapKey {
        src_ip: 0,
        dst_ip: EbpfEngine::ip_to_u32("1.2.3.4").unwrap(),
        src_port: 0,
        dst_port: 9999,
        protocol: 6,
    };
    let rule_action = rules.evaluate(
        None,
        None,
        Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))),
        Some(9999),
        Some(Protocol::Tcp),
        None,
        None,
    );
    // RuleSet defaults to Deny, eBPF defaults to Pass (no rule = pass through).
    // In production the eBPF layer would cooperate with userspace for final deny;
    // here we verify we can simulate loading successfully when rules exist.
    assert_eq!(rule_action, RuleAction::Deny);
    assert_eq!(ebpf.evaluate_packet(&unknown_key), EbpfAction::Pass);

    // Simulate loading: should succeed because rules exist.
    assert!(ebpf.simulate_load().is_ok());
    assert!(ebpf.is_loaded());
    assert_eq!(ebpf.rule_count(), 2);
}

// ---------------------------------------------------------------------------
// 5. DoH detection + sinkhole: detect bypass, verify sinkhole catches domain
// ---------------------------------------------------------------------------

#[test]
fn test_doh_detection_plus_sinkhole_coverage() {
    let monitor = DohMonitor::new();
    let sinkhole = DnsSinkhole::with_default_blocklist();

    // Simulate a malware process connecting to Cloudflare DoH (1.1.1.1:443).
    let connections = vec![
        ObservedConnection {
            process_name: "malware_agent".to_string(),
            binary_path: Some("/tmp/.hidden/malware".to_string()),
            dest_ip: Some("1.1.1.1".to_string()),
            dest_port: Some(443),
            domain: None,
        },
        // Also test a process using a DoH domain.
        ObservedConnection {
            process_name: "exfil_tool".to_string(),
            binary_path: None,
            dest_ip: None,
            dest_port: Some(443),
            domain: Some("dns.google".to_string()),
        },
    ];

    let alerts = monitor.analyze_connections(&connections);
    assert_eq!(alerts.len(), 2);

    // Both should be critical (non-browser processes).
    for alert in &alerts {
        assert_eq!(
            alert.severity,
            plausiden_firewall::doh_monitor::DohAlertSeverity::Critical
        );
    }

    assert_eq!(alerts[0].provider, "Cloudflare");
    assert_eq!(alerts[1].provider, "Google");

    // Verify that the DoH provider domains themselves are detectable by the sinkhole
    // if we add them. The default blocklist does not include DoH providers (they are
    // legitimate services), but an admin could add them.
    let mut custom_sinkhole = DnsSinkhole::new();
    custom_sinkhole.add_domain("cloudflare-dns.com");
    custom_sinkhole.add_domain("dns.google");
    custom_sinkhole.add_domain("dns.google.com");
    custom_sinkhole.add_domain("*.dns.nextdns.io");

    assert!(custom_sinkhole.is_sinkholed("cloudflare-dns.com"));
    assert!(custom_sinkhole.is_sinkholed("dns.google"));
    assert!(custom_sinkhole.is_sinkholed("dns.google.com"));
    assert!(custom_sinkhole.is_sinkholed("abc123.dns.nextdns.io"));

    // Verify the DoH bypass detection API agrees these are DoH endpoints.
    assert!(DnsSinkhole::is_doh_endpoint(
        Some("1.1.1.1"),
        Some(443),
        None,
    ));
    assert!(DnsSinkhole::is_doh_endpoint(
        None,
        Some(443),
        Some("dns.google"),
    ));

    // Legitimate traffic should not trigger either system.
    let safe_connections = vec![ObservedConnection {
        process_name: "curl".to_string(),
        binary_path: None,
        dest_ip: Some("93.184.216.34".to_string()),
        dest_port: Some(443),
        domain: Some("example.com".to_string()),
    }];
    let safe_alerts = monitor.analyze_connections(&safe_connections);
    assert!(safe_alerts.is_empty());
    assert!(!sinkhole.is_sinkholed("example.com"));
}

// ---------------------------------------------------------------------------
// 6. Rate limiting scenario: 100 connections, verify tracker counts
// ---------------------------------------------------------------------------

#[test]
fn test_rate_limiting_100_connections() {
    let mut tracker = ConnectionTracker::new(200);

    // Simulate 100 unique outbound connections from the same source.
    for i in 0..100u16 {
        tracker
            .track_packet(
                "192.168.1.100",
                40000 + i,
                "10.0.0.1",
                443,
                Protocol::Tcp,
                Direction::Outbound,
                64,
            )
            .unwrap();
    }

    assert_eq!(tracker.active_connections(), 100);

    // All connections are in New state.
    let new_conns = tracker.connections_by_state(TcpState::New);
    assert_eq!(new_conns.len(), 100);

    // Connection rate over a 60-second window should reflect all 100.
    let rate = tracker.connection_rate(60);
    let expected_rate = 100.0 / 60.0;
    assert!(
        (rate - expected_rate).abs() < 0.1,
        "Rate {rate} should be close to {expected_rate}"
    );

    // Establish half of them by sending inbound replies.
    for i in 0..50u16 {
        tracker
            .track_packet(
                "192.168.1.100",
                40000 + i,
                "10.0.0.1",
                443,
                Protocol::Tcp,
                Direction::Inbound,
                128,
            )
            .unwrap();
    }

    let new_conns = tracker.connections_by_state(TcpState::New);
    let established_conns = tracker.connections_by_state(TcpState::Established);
    assert_eq!(new_conns.len(), 50);
    assert_eq!(established_conns.len(), 50);
    assert_eq!(tracker.active_connections(), 100);

    // Top talkers: the 50 established connections each have 64+128=192 bytes,
    // the other 50 only have 64 bytes outbound.
    let top = tracker.top_talkers(5);
    assert_eq!(top.len(), 5);
    for entry in &top {
        let total = entry.1.bytes_sent + entry.1.bytes_received;
        assert_eq!(total, 192, "Top talkers should all be established connections");
    }

    // Verify an individual connection's counters.
    let key = ConnectionKey {
        src_ip: "192.168.1.100".to_string(),
        src_port: 40025, // one of the established ones
        dst_ip: "10.0.0.1".to_string(),
        dst_port: 443,
        protocol: Protocol::Tcp,
    };
    let conn = tracker.get_connection(&key).unwrap();
    assert_eq!(conn.state, TcpState::Established);
    assert_eq!(conn.bytes_sent, 64);
    assert_eq!(conn.bytes_received, 128);
    assert_eq!(conn.packets_sent, 1);
    assert_eq!(conn.packets_received, 1);
}

// ---------------------------------------------------------------------------
// 7. Full Linux backend: apply rules, verify nftables + domain blocking
// ---------------------------------------------------------------------------

#[test]
fn test_full_linux_backend() {
    let mut backend = LinuxBackend::new();

    // Build rules.
    let mut rules = RuleSet::new();
    rules
        .add_rule(make_rule(
            "allow-https",
            10,
            RuleAction::Allow,
            RuleMatch {
                dest_ip: Some(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))),
                dest_port_range: Some((443, 443)),
                protocol: Some(Protocol::Tcp),
                ..Default::default()
            },
        ))
        .unwrap();
    rules
        .add_rule(make_rule(
            "deny-telnet",
            20,
            RuleAction::Deny,
            RuleMatch {
                dest_port_range: Some((23, 23)),
                ..Default::default()
            },
        ))
        .unwrap();

    backend.apply_rules(rules);
    backend.activate();

    // Verify nftables script.
    let script = backend.generate_nftables_script();
    assert!(script.contains("93.184.216.34"));
    assert!(script.contains("443"));
    assert!(script.contains("accept"));
    assert!(script.contains("23"));
    assert!(script.contains("drop"));
    assert!(script.contains("flush table"));

    // Block domains via sinkhole.
    backend.block_domain("evil.com");
    backend.block_domain("*.malware.net");
    assert!(backend.is_domain_blocked("evil.com"));
    assert!(backend.is_domain_blocked("c2.malware.net"));
    assert!(!backend.is_domain_blocked("safe.org"));

    // Verify status.
    let status = backend.status();
    assert!(backend.is_active());
    assert!(!status.ebpf_loaded);
    assert!(status.dns_sinkhole_active);
    assert_eq!(status.rules_count, 2);
    // Default blocklist + 2 custom domains.
    assert!(status.blocked_domains > 2);

    // Deactivate and verify.
    backend.deactivate();
    assert!(!backend.is_active());
}

// ---------------------------------------------------------------------------
// 8. Cross-platform: same rules -> nftables + pf.conf + WFP
// ---------------------------------------------------------------------------

#[test]
fn test_cross_platform_rule_generation() {
    // Build a common rule set.
    let mut rules = RuleSet::new();

    rules
        .add_rule(make_rule(
            "allow-https-trusted",
            10,
            RuleAction::Allow,
            RuleMatch {
                dest_ip: Some(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))),
                dest_port_range: Some((443, 443)),
                protocol: Some(Protocol::Tcp),
                ..Default::default()
            },
        ))
        .unwrap();

    rules
        .add_rule(make_rule(
            "deny-telnet",
            20,
            RuleAction::Deny,
            RuleMatch {
                dest_port_range: Some((23, 23)),
                ..Default::default()
            },
        ))
        .unwrap();

    rules
        .add_rule(make_rule(
            "log-inbound-scanner",
            30,
            RuleAction::Log,
            RuleMatch {
                source_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 99))),
                ..Default::default()
            },
        ))
        .unwrap();

    // --- nftables (Linux) ---
    let nft_backend = NftablesBackend::new("plausiden", TableFamily::Inet);
    let nft = nft_backend.generate_ruleset(&rules);
    let nft_script = nft.to_script();

    assert!(nft_script.contains("inet plausiden"));
    assert!(nft_script.contains("93.184.216.34"));
    assert!(nft_script.contains("accept"));
    assert!(nft_script.contains("23"));
    assert!(nft_script.contains("drop"));
    assert!(nft_script.contains("log"));
    assert!(nft_script.contains("10.0.0.99"));

    // --- pf.conf (macOS) ---
    let pf_backend = MacosBackend::default();
    let pf_conf = pf_backend.generate_pf_conf(&rules);

    assert!(pf_conf.contains("block all"));
    assert!(pf_conf.contains("set skip on lo0"));
    assert!(pf_conf.contains("93.184.216.34"));
    assert!(pf_conf.contains("pass"));
    assert!(pf_conf.contains("443"));
    assert!(pf_conf.contains("block")); // deny rule
    assert!(pf_conf.contains("23"));
    assert!(pf_conf.contains("10.0.0.99"));

    // --- WFP (Windows) ---
    let wfp_backend = WindowsBackend::new();
    let filters = wfp_backend.generate_filters(&rules);

    // Should have default block + allow + deny (Log may not be supported, but
    // the backend skips unsupported actions gracefully).
    assert!(filters.len() >= 3); // default-block + allow + deny

    // Generate PowerShell for the filters.
    let ps = wfp_backend.generate_powershell(&filters);
    assert!(ps.contains("New-NetFirewallRule"));
    assert!(ps.contains("Allow"));
    assert!(ps.contains("Block"));

    // All three backends produce non-empty output from the same rules.
    assert!(!nft_script.is_empty());
    assert!(!pf_conf.is_empty());
    assert!(!filters.is_empty());
    assert!(!ps.is_empty());
}
