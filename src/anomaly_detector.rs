//! Network anomaly detection — statistical baseline deviation alerting.
//!
//! Learns normal traffic patterns and alerts on deviations using
//! exponentially weighted moving averages (EWMA) and Z-score thresholds.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A metric being tracked for anomalies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricBaseline {
    pub name: String,
    /// EWMA of the metric value.
    pub mean: f64,
    /// EWMA of squared deviation (for variance).
    pub variance: f64,
    /// Number of samples incorporated.
    pub sample_count: u64,
    /// Smoothing factor for EWMA (0.0-1.0, lower = more smoothing).
    pub alpha: f64,
    /// Z-score threshold for anomaly detection.
    pub threshold: f64,
    /// Last observed value.
    pub last_value: f64,
    /// Last update time.
    pub last_updated: DateTime<Utc>,
}

impl MetricBaseline {
    pub fn new(name: &str, alpha: f64, threshold: f64) -> Self {
        Self {
            name: name.to_string(),
            mean: 0.0,
            variance: 0.0,
            sample_count: 0,
            alpha: alpha.clamp(0.01, 1.0),
            threshold,
            last_value: 0.0,
            last_updated: Utc::now(),
        }
    }

    /// Update the baseline with a new observation.
    /// Returns the z-score of this value against the *pre-update* baseline.
    pub fn observe(&mut self, value: f64) -> f64 {
        self.sample_count += 1;
        self.last_value = value;
        self.last_updated = Utc::now();

        if self.sample_count == 1 {
            self.mean = value;
            self.variance = 0.0;
            return 0.0;
        }

        // Compute z-score BEFORE updating baseline.
        let pre_z = self.z_score(value);

        let diff = value - self.mean;
        self.mean += self.alpha * diff;
        self.variance = (1.0 - self.alpha) * (self.variance + self.alpha * diff * diff);

        pre_z
    }

    /// Standard deviation of the metric.
    pub fn stddev(&self) -> f64 {
        self.variance.sqrt()
    }

    /// Z-score of a given value relative to the baseline.
    pub fn z_score(&self, value: f64) -> f64 {
        let sd = self.stddev();
        if sd < f64::EPSILON { return 0.0; }
        (value - self.mean).abs() / sd
    }

    /// Check if a specific value would be anomalous against current baseline.
    pub fn check_value(&self, value: f64) -> bool {
        self.sample_count >= 10 && self.z_score(value) > self.threshold
    }
}

/// An anomaly alert.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyAlert {
    pub metric_name: String,
    pub observed_value: f64,
    pub baseline_mean: f64,
    pub z_score: f64,
    pub timestamp: DateTime<Utc>,
}

/// Tracks multiple metrics for anomaly detection.
pub struct AnomalyDetector {
    metrics: HashMap<String, MetricBaseline>,
    alerts: Vec<AnomalyAlert>,
    max_alerts: usize,
}

impl AnomalyDetector {
    pub fn new() -> Self {
        Self {
            metrics: HashMap::new(),
            alerts: Vec::new(),
            max_alerts: 1000,
        }
    }

    /// Register a metric for tracking.
    pub fn register_metric(&mut self, name: &str, alpha: f64, threshold: f64) {
        self.metrics.insert(name.to_string(), MetricBaseline::new(name, alpha, threshold));
    }

    /// Register default network metrics.
    pub fn register_defaults(&mut self) {
        self.register_metric("bytes_per_second", 0.1, 3.0);
        self.register_metric("packets_per_second", 0.1, 3.0);
        self.register_metric("connections_per_minute", 0.05, 3.0);
        self.register_metric("dns_queries_per_minute", 0.1, 2.5);
        self.register_metric("avg_packet_size", 0.1, 3.0);
        self.register_metric("unique_destinations", 0.05, 3.0);
        self.register_metric("error_rate", 0.1, 2.5);
    }

    /// Record a metric observation and check for anomalies.
    pub fn observe(&mut self, metric_name: &str, value: f64) -> Option<AnomalyAlert> {
        let baseline = match self.metrics.get_mut(metric_name) {
            Some(b) => b,
            None => return None,
        };

        let was_trained = baseline.sample_count >= 10;
        let pre_z = baseline.observe(value);

        if was_trained && pre_z > baseline.threshold {
            let alert = AnomalyAlert {
                metric_name: metric_name.to_string(),
                observed_value: value,
                baseline_mean: baseline.mean,
                z_score: baseline.z_score(value),
                timestamp: Utc::now(),
            };
            self.alerts.push(alert.clone());
            if self.alerts.len() > self.max_alerts {
                self.alerts.remove(0);
            }
            return Some(alert);
        }

        None
    }

    /// Get all recent alerts.
    pub fn alerts(&self) -> &[AnomalyAlert] {
        &self.alerts
    }

    /// Get the baseline for a metric.
    pub fn get_baseline(&self, name: &str) -> Option<&MetricBaseline> {
        self.metrics.get(name)
    }

    /// Number of tracked metrics.
    pub fn metric_count(&self) -> usize {
        self.metrics.len()
    }

    /// Number of metrics where the last value exceeds the threshold.
    pub fn anomalous_count(&self) -> usize {
        self.metrics.values().filter(|m| m.check_value(m.last_value)).count()
    }

    /// Get all metrics where the last value exceeds the threshold.
    pub fn anomalous_metrics(&self) -> Vec<&MetricBaseline> {
        self.metrics.values().filter(|m| m.check_value(m.last_value)).collect()
    }
}

impl Default for AnomalyDetector {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_baseline_learning() {
        let mut b = MetricBaseline::new("test", 0.1, 3.0);
        for i in 0..100 {
            b.observe(50.0 + (i % 5) as f64);
        }
        // Mean should be close to 52 (avg of 50,51,52,53,54).
        assert!((b.mean - 52.0).abs() < 2.0);
        assert!(b.stddev() > 0.0);
    }

    #[test]
    fn test_anomaly_detection() {
        let mut b = MetricBaseline::new("test", 0.1, 3.0);
        // Train with values that have some variance.
        for i in 0..50 {
            b.observe(50.0 + (i % 3) as f64);
        }
        // Spike to 500 — pre-update z-score should be high.
        let z = b.observe(500.0);
        assert!(z > 3.0, "z-score should exceed threshold: got {z}");
    }

    #[test]
    fn test_no_anomaly_normal() {
        let mut b = MetricBaseline::new("test", 0.1, 3.0);
        for i in 0..50 {
            b.observe(50.0 + (i % 3) as f64);
        }
        let z = b.observe(52.0);
        assert!(z < 3.0, "small deviation shouldn't be anomalous: z={z}");
    }

    #[test]
    fn test_insufficient_samples() {
        let mut b = MetricBaseline::new("test", 0.1, 3.0);
        for _ in 0..5 {
            b.observe(50.0);
        }
        // Even a big spike shouldn't alert with few samples.
        assert!(!b.check_value(500.0));
    }

    #[test]
    fn test_detector_observe() {
        let mut det = AnomalyDetector::new();
        det.register_metric("bps", 0.1, 3.0);

        // Train with some variance.
        for i in 0..50 {
            det.observe("bps", 1000.0 + (i % 5) as f64 * 10.0);
        }

        // Anomaly.
        let alert = det.observe("bps", 100_000.0);
        assert!(alert.is_some());
        assert_eq!(det.alerts().len(), 1);
    }

    #[test]
    fn test_defaults() {
        let mut det = AnomalyDetector::new();
        det.register_defaults();
        assert!(det.metric_count() >= 7);
    }

    #[test]
    fn test_unknown_metric() {
        let mut det = AnomalyDetector::new();
        let result = det.observe("nonexistent", 100.0);
        assert!(result.is_none());
    }

    #[test]
    fn test_z_score_zero_variance() {
        let mut b = MetricBaseline::new("test", 0.1, 3.0);
        b.observe(50.0); // Only one sample — variance is 0.
        assert_eq!(b.z_score(100.0), 0.0); // Can't compute z-score with zero stddev.
    }

    #[test]
    fn test_anomalous_metrics_list() {
        let mut det = AnomalyDetector::new();
        det.register_metric("a", 0.1, 3.0);
        det.register_metric("b", 0.1, 3.0);

        for i in 0..50 {
            det.observe("a", 100.0 + (i % 4) as f64);
            det.observe("b", 100.0 + (i % 4) as f64);
        }
        // Spike on 'a' only — should generate alert.
        let alert = det.observe("a", 10_000.0);
        assert!(alert.is_some(), "spike should trigger alert");
        assert_eq!(det.alerts().len(), 1);
    }
}
