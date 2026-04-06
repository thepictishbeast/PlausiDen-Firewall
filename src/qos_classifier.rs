//! QoS classifier — classify traffic into priority classes for shaping.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Traffic priority class.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TrafficClass {
    Interactive,   // SSH, VoIP, real-time games
    Latency,       // web, API calls
    Streaming,     // video, music
    Bulk,          // downloads, backups
    Background,    // updates, sync
    Unclassified,
}

impl TrafficClass {
    /// DSCP value for this class (0-63).
    pub fn dscp(&self) -> u8 {
        match self {
            TrafficClass::Interactive => 46,   // EF
            TrafficClass::Latency => 34,       // AF41
            TrafficClass::Streaming => 26,     // AF31
            TrafficClass::Bulk => 8,           // CS1
            TrafficClass::Background => 0,     // BE
            TrafficClass::Unclassified => 0,
        }
    }

    /// Priority weight for scheduling.
    pub fn priority(&self) -> u8 {
        match self {
            TrafficClass::Interactive => 100,
            TrafficClass::Latency => 80,
            TrafficClass::Streaming => 50,
            TrafficClass::Bulk => 20,
            TrafficClass::Background => 10,
            TrafficClass::Unclassified => 30,
        }
    }
}

/// A classification rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassRule {
    pub id: String,
    pub matcher: Matcher,
    pub class: TrafficClass,
    pub priority: i32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Matcher {
    Port(u16),
    PortRange(u16, u16),
    Protocol(String),
    AppName(String),
    DestinationCidr { network: String, prefix: u8 },
    Dscp(u8),
}

/// Traffic flow to be classified.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Flow {
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: String,
    pub app_name: Option<String>,
    pub dst_ip: Option<String>,
    pub dscp: u8,
}

/// QoS classifier.
pub struct QosClassifier {
    rules: Vec<ClassRule>,
    default_class: TrafficClass,
    stats: HashMap<TrafficClass, u64>,
}

impl QosClassifier {
    pub fn new() -> Self {
        let mut c = Self {
            rules: Vec::new(),
            default_class: TrafficClass::Unclassified,
            stats: HashMap::new(),
        };
        c.load_defaults();
        c
    }

    fn load_defaults(&mut self) {
        // SSH, DNS → Interactive.
        self.add_rule(ClassRule {
            id: "ssh".into(),
            matcher: Matcher::Port(22),
            class: TrafficClass::Interactive,
            priority: 100,
        });
        self.add_rule(ClassRule {
            id: "dns".into(),
            matcher: Matcher::Port(53),
            class: TrafficClass::Interactive,
            priority: 100,
        });
        // HTTPS, HTTP → Latency.
        self.add_rule(ClassRule {
            id: "https".into(),
            matcher: Matcher::Port(443),
            class: TrafficClass::Latency,
            priority: 80,
        });
        self.add_rule(ClassRule {
            id: "http".into(),
            matcher: Matcher::Port(80),
            class: TrafficClass::Latency,
            priority: 80,
        });
        // SMTP, IMAP, POP3 → Background.
        self.add_rule(ClassRule {
            id: "smtp".into(),
            matcher: Matcher::PortRange(25, 25),
            class: TrafficClass::Background,
            priority: 30,
        });
        self.add_rule(ClassRule {
            id: "imap".into(),
            matcher: Matcher::Port(993),
            class: TrafficClass::Background,
            priority: 30,
        });
    }

    /// Add a classification rule.
    pub fn add_rule(&mut self, rule: ClassRule) {
        self.rules.push(rule);
        self.rules.sort_by(|a, b| b.priority.cmp(&a.priority));
    }

    /// Remove a rule.
    pub fn remove_rule(&mut self, id: &str) -> bool {
        let before = self.rules.len();
        self.rules.retain(|r| r.id != id);
        self.rules.len() != before
    }

    /// Classify a flow.
    pub fn classify(&mut self, flow: &Flow) -> TrafficClass {
        for rule in &self.rules {
            if self.matches(flow, &rule.matcher) {
                let class = rule.class.clone();
                *self.stats.entry(class.clone()).or_insert(0) += 1;
                return class;
            }
        }
        let class = self.default_class.clone();
        *self.stats.entry(class.clone()).or_insert(0) += 1;
        class
    }

    fn matches(&self, flow: &Flow, matcher: &Matcher) -> bool {
        match matcher {
            Matcher::Port(p) => flow.dst_port == *p || flow.src_port == *p,
            Matcher::PortRange(start, end) => {
                (flow.dst_port >= *start && flow.dst_port <= *end)
                    || (flow.src_port >= *start && flow.src_port <= *end)
            }
            Matcher::Protocol(p) => flow.protocol.eq_ignore_ascii_case(p),
            Matcher::AppName(name) => flow.app_name.as_deref() == Some(name),
            Matcher::DestinationCidr { network, prefix: _ } => {
                flow.dst_ip.as_deref().map(|ip| ip.starts_with(network)).unwrap_or(false)
            }
            Matcher::Dscp(d) => flow.dscp == *d,
        }
    }

    /// Classification statistics.
    pub fn stats(&self) -> &HashMap<TrafficClass, u64> {
        &self.stats
    }

    /// Total classifications performed.
    pub fn total_classified(&self) -> u64 {
        self.stats.values().sum()
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

impl Default for QosClassifier {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flow(src: u16, dst: u16, protocol: &str) -> Flow {
        Flow {
            src_port: src,
            dst_port: dst,
            protocol: protocol.into(),
            app_name: None,
            dst_ip: None,
            dscp: 0,
        }
    }

    #[test]
    fn test_default_rules_loaded() {
        let c = QosClassifier::new();
        assert!(c.rule_count() >= 5);
    }

    #[test]
    fn test_classify_ssh() {
        let mut c = QosClassifier::new();
        let class = c.classify(&flow(12345, 22, "tcp"));
        assert_eq!(class, TrafficClass::Interactive);
    }

    #[test]
    fn test_classify_https() {
        let mut c = QosClassifier::new();
        let class = c.classify(&flow(12345, 443, "tcp"));
        assert_eq!(class, TrafficClass::Latency);
    }

    #[test]
    fn test_classify_unclassified() {
        let mut c = QosClassifier::new();
        let class = c.classify(&flow(12345, 9999, "tcp"));
        assert_eq!(class, TrafficClass::Unclassified);
    }

    #[test]
    fn test_dscp_values() {
        assert_eq!(TrafficClass::Interactive.dscp(), 46);
        assert_eq!(TrafficClass::Background.dscp(), 0);
    }

    #[test]
    fn test_priority_order() {
        assert!(TrafficClass::Interactive.priority() > TrafficClass::Latency.priority());
        assert!(TrafficClass::Latency.priority() > TrafficClass::Bulk.priority());
    }

    #[test]
    fn test_stats_tracking() {
        let mut c = QosClassifier::new();
        c.classify(&flow(12345, 22, "tcp"));
        c.classify(&flow(12345, 443, "tcp"));
        c.classify(&flow(12345, 443, "tcp"));
        assert_eq!(*c.stats().get(&TrafficClass::Interactive).unwrap(), 1);
        assert_eq!(*c.stats().get(&TrafficClass::Latency).unwrap(), 2);
    }

    #[test]
    fn test_remove_rule() {
        let mut c = QosClassifier::new();
        assert!(c.remove_rule("ssh"));
    }

    #[test]
    fn test_custom_rule_priority() {
        let mut c = QosClassifier::new();
        c.add_rule(ClassRule {
            id: "custom".into(),
            matcher: Matcher::Port(443),
            class: TrafficClass::Bulk, // override default Latency for port 443
            priority: 200,
        });
        assert_eq!(c.classify(&flow(12345, 443, "tcp")), TrafficClass::Bulk);
    }

    #[test]
    fn test_total_classified() {
        let mut c = QosClassifier::new();
        c.classify(&flow(12345, 22, "tcp"));
        c.classify(&flow(12345, 443, "tcp"));
        assert_eq!(c.total_classified(), 2);
    }
}
