//! DNS query log — bounded history of resolved queries for forensic review.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;

/// A single logged DNS query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsQuery {
    pub timestamp: DateTime<Utc>,
    pub client: IpAddr,
    pub domain: String,
    pub qtype: QueryType,
    pub response: QueryResponse,
    pub latency_ms: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum QueryType {
    A,
    Aaaa,
    Cname,
    Mx,
    Txt,
    Ns,
    Ptr,
    Srv,
    Any,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum QueryResponse {
    Resolved(Vec<IpAddr>),
    Nxdomain,
    Timeout,
    Refused,
    Blocked, // sinkholed
    Servfail,
}

/// DNS query log with bounded ring buffer semantics.
pub struct DnsQueryLog {
    entries: VecDeque<DnsQuery>,
    capacity: usize,
}

impl DnsQueryLog {
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    /// Record a query. Oldest entries evicted when at capacity.
    pub fn record(&mut self, query: DnsQuery) {
        if self.entries.len() == self.capacity {
            self.entries.pop_front();
        }
        self.entries.push_back(query);
    }

    /// Recent queries (newest last).
    pub fn recent(&self, n: usize) -> Vec<&DnsQuery> {
        let start = self.entries.len().saturating_sub(n);
        self.entries.iter().skip(start).collect()
    }

    /// All queries for a specific domain (substring match).
    pub fn for_domain(&self, domain: &str) -> Vec<&DnsQuery> {
        let needle = domain.to_lowercase();
        self.entries.iter()
            .filter(|q| q.domain.to_lowercase().contains(&needle))
            .collect()
    }

    /// All queries from a given client IP.
    pub fn for_client(&self, client: &IpAddr) -> Vec<&DnsQuery> {
        self.entries.iter().filter(|q| &q.client == client).collect()
    }

    /// All blocked (sinkholed) queries.
    pub fn blocked(&self) -> Vec<&DnsQuery> {
        self.entries.iter()
            .filter(|q| matches!(q.response, QueryResponse::Blocked))
            .collect()
    }

    /// Top N most-queried domains by count.
    pub fn top_domains(&self, n: usize) -> Vec<(String, usize)> {
        let mut counts: HashMap<String, usize> = HashMap::new();
        for q in &self.entries {
            *counts.entry(q.domain.to_lowercase()).or_insert(0) += 1;
        }
        let mut ranked: Vec<_> = counts.into_iter().collect();
        ranked.sort_by(|a, b| b.1.cmp(&a.1));
        ranked.truncate(n);
        ranked
    }

    /// Top clients by query count.
    pub fn top_clients(&self, n: usize) -> Vec<(IpAddr, usize)> {
        let mut counts: HashMap<IpAddr, usize> = HashMap::new();
        for q in &self.entries {
            *counts.entry(q.client).or_insert(0) += 1;
        }
        let mut ranked: Vec<_> = counts.into_iter().collect();
        ranked.sort_by(|a, b| b.1.cmp(&a.1));
        ranked.truncate(n);
        ranked
    }

    /// Unique domains queried.
    pub fn unique_domains(&self) -> usize {
        let mut set = std::collections::HashSet::new();
        for q in &self.entries {
            set.insert(q.domain.to_lowercase());
        }
        set.len()
    }

    /// Average latency in milliseconds across all successful queries.
    pub fn avg_latency(&self) -> Option<f64> {
        let successful: Vec<u32> = self.entries.iter()
            .filter(|q| matches!(q.response, QueryResponse::Resolved(_)))
            .map(|q| q.latency_ms)
            .collect();
        if successful.is_empty() {
            None
        } else {
            Some(successful.iter().sum::<u32>() as f64 / successful.len() as f64)
        }
    }

    /// Block rate: fraction of queries that were sinkholed.
    pub fn block_rate(&self) -> f64 {
        if self.entries.is_empty() {
            return 0.0;
        }
        let blocked = self.entries.iter()
            .filter(|q| matches!(q.response, QueryResponse::Blocked))
            .count();
        blocked as f64 / self.entries.len() as f64
    }

    pub fn len(&self) -> usize { self.entries.len() }
    pub fn is_empty(&self) -> bool { self.entries.is_empty() }
    pub fn capacity(&self) -> usize { self.capacity }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_query(client: &str, domain: &str, response: QueryResponse) -> DnsQuery {
        DnsQuery {
            timestamp: Utc::now(),
            client: client.parse().unwrap(),
            domain: domain.into(),
            qtype: QueryType::A,
            response,
            latency_ms: 12,
        }
    }

    #[test]
    fn test_record_and_recent() {
        let mut log = DnsQueryLog::new(10);
        log.record(mk_query("10.0.0.1", "example.com", QueryResponse::Resolved(vec![])));
        assert_eq!(log.len(), 1);
        assert_eq!(log.recent(5).len(), 1);
    }

    #[test]
    fn test_capacity_eviction() {
        let mut log = DnsQueryLog::new(3);
        for i in 0..5 {
            log.record(mk_query("10.0.0.1", &format!("a{}.com", i), QueryResponse::Nxdomain));
        }
        assert_eq!(log.len(), 3);
        let recent: Vec<_> = log.recent(3).iter().map(|q| q.domain.clone()).collect();
        assert_eq!(recent, vec!["a2.com", "a3.com", "a4.com"]);
    }

    #[test]
    fn test_for_domain() {
        let mut log = DnsQueryLog::new(10);
        log.record(mk_query("10.0.0.1", "mail.example.com", QueryResponse::Resolved(vec![])));
        log.record(mk_query("10.0.0.1", "example.com", QueryResponse::Resolved(vec![])));
        log.record(mk_query("10.0.0.1", "other.org", QueryResponse::Resolved(vec![])));
        assert_eq!(log.for_domain("example.com").len(), 2);
    }

    #[test]
    fn test_for_client() {
        let mut log = DnsQueryLog::new(10);
        log.record(mk_query("10.0.0.1", "a.com", QueryResponse::Nxdomain));
        log.record(mk_query("10.0.0.2", "a.com", QueryResponse::Nxdomain));
        log.record(mk_query("10.0.0.1", "b.com", QueryResponse::Nxdomain));
        assert_eq!(log.for_client(&"10.0.0.1".parse().unwrap()).len(), 2);
    }

    #[test]
    fn test_blocked() {
        let mut log = DnsQueryLog::new(10);
        log.record(mk_query("10.0.0.1", "ads.example.com", QueryResponse::Blocked));
        log.record(mk_query("10.0.0.1", "ok.com", QueryResponse::Resolved(vec![])));
        log.record(mk_query("10.0.0.1", "tracker.io", QueryResponse::Blocked));
        assert_eq!(log.blocked().len(), 2);
    }

    #[test]
    fn test_top_domains() {
        let mut log = DnsQueryLog::new(20);
        for _ in 0..5 { log.record(mk_query("10.0.0.1", "popular.com", QueryResponse::Nxdomain)); }
        for _ in 0..2 { log.record(mk_query("10.0.0.1", "rare.com", QueryResponse::Nxdomain)); }
        let top = log.top_domains(5);
        assert_eq!(top[0], ("popular.com".to_string(), 5));
        assert_eq!(top[1], ("rare.com".to_string(), 2));
    }

    #[test]
    fn test_top_clients() {
        let mut log = DnsQueryLog::new(20);
        for _ in 0..3 { log.record(mk_query("10.0.0.1", "a.com", QueryResponse::Nxdomain)); }
        for _ in 0..1 { log.record(mk_query("10.0.0.2", "a.com", QueryResponse::Nxdomain)); }
        let top = log.top_clients(2);
        assert_eq!(top[0].1, 3);
    }

    #[test]
    fn test_unique_domains() {
        let mut log = DnsQueryLog::new(10);
        log.record(mk_query("10.0.0.1", "a.com", QueryResponse::Nxdomain));
        log.record(mk_query("10.0.0.1", "a.com", QueryResponse::Nxdomain));
        log.record(mk_query("10.0.0.1", "b.com", QueryResponse::Nxdomain));
        assert_eq!(log.unique_domains(), 2);
    }

    #[test]
    fn test_block_rate() {
        let mut log = DnsQueryLog::new(10);
        log.record(mk_query("10.0.0.1", "a.com", QueryResponse::Blocked));
        log.record(mk_query("10.0.0.1", "b.com", QueryResponse::Resolved(vec![])));
        assert_eq!(log.block_rate(), 0.5);
    }

    #[test]
    fn test_avg_latency() {
        let mut log = DnsQueryLog::new(10);
        let mut q1 = mk_query("10.0.0.1", "a.com", QueryResponse::Resolved(vec![]));
        q1.latency_ms = 10;
        let mut q2 = mk_query("10.0.0.1", "b.com", QueryResponse::Resolved(vec![]));
        q2.latency_ms = 30;
        log.record(q1);
        log.record(q2);
        assert_eq!(log.avg_latency(), Some(20.0));
    }
}
