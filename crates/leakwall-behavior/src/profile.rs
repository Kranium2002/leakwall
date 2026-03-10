use std::collections::HashMap;
use std::time::Instant;

use crate::{Anomaly, AnomalyKind, Severity};

/// Tracks request statistics for a single destination host.
pub struct DestinationStats {
    pub first_seen: Instant,
    pub request_count: u64,
    pub total_bytes: u64,
    pub avg_request_size: f64,
    pub max_request_size: usize,
}

/// Maintains a behavioral profile of all destinations seen during a session.
/// Detects anomalies such as new destinations appearing late in a session
/// and sudden volume spikes.
pub struct DestinationProfile {
    pub baseline: HashMap<String, DestinationStats>,
    pub session_start: Instant,
    pub total_requests: u64,
}

impl DestinationProfile {
    pub fn new() -> Self {
        Self {
            baseline: HashMap::new(),
            session_start: Instant::now(),
            total_requests: 0,
        }
    }

    /// Record a request to `host` with `body_size` bytes and return any
    /// anomalies detected.
    pub fn check(&mut self, host: &str, body_size: usize) -> Vec<Anomaly> {
        self.total_requests += 1;
        let mut anomalies = Vec::new();

        let is_new = !self.baseline.contains_key(host);

        // Update or insert destination stats
        let stats = self
            .baseline
            .entry(host.to_owned())
            .or_insert_with(|| DestinationStats {
                first_seen: Instant::now(),
                request_count: 0,
                total_bytes: 0,
                avg_request_size: 0.0,
                max_request_size: 0,
            });

        // Check for volume spike BEFORE updating the average so the comparison
        // uses the historical average. Only meaningful when we have prior data.
        if stats.request_count > 0 {
            let threshold = stats.avg_request_size * 3.0;
            let min_absolute = 10 * 1024; // 10 KB
            if body_size as f64 > threshold && body_size > min_absolute {
                anomalies.push(Anomaly {
                    kind: AnomalyKind::VolumeSpike,
                    severity: Severity::Medium,
                    detail: format!(
                        "request to {} is {} bytes (avg {:.0})",
                        host, body_size, stats.avg_request_size
                    ),
                });
            }
        }

        // Update rolling stats
        stats.request_count += 1;
        stats.total_bytes += body_size as u64;
        stats.avg_request_size = stats.total_bytes as f64 / stats.request_count as f64;
        if body_size > stats.max_request_size {
            stats.max_request_size = body_size;
        }

        // Detect new destination after warmup period
        if is_new && self.total_requests > 10 {
            anomalies.push(Anomaly {
                kind: AnomalyKind::NewDestination,
                severity: Severity::Low,
                detail: format!(
                    "new destination {} first seen after {} requests",
                    host, self.total_requests
                ),
            });
        }

        anomalies
    }
}

impl Default for DestinationProfile {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_destination_not_flagged_during_warmup() {
        let mut profile = DestinationProfile::new();
        for i in 0..10 {
            let host = format!("host-{}.example.com", i);
            let anomalies = profile.check(&host, 100);
            assert!(
                anomalies
                    .iter()
                    .all(|a| a.kind != AnomalyKind::NewDestination),
                "should not flag new destinations during warmup"
            );
        }
    }

    #[test]
    fn new_destination_flagged_after_warmup() {
        let mut profile = DestinationProfile::new();
        // Build up 11 requests to a known host
        for _ in 0..11 {
            profile.check("api.openai.com", 100);
        }
        // Now a new host should trigger NewDestination
        let anomalies = profile.check("evil.example.com", 100);
        assert!(
            anomalies
                .iter()
                .any(|a| a.kind == AnomalyKind::NewDestination),
            "should flag new destination after warmup"
        );
    }

    #[test]
    fn volume_spike_detected() {
        let mut profile = DestinationProfile::new();
        // Establish baseline with small requests
        for _ in 0..5 {
            profile.check("api.openai.com", 500);
        }
        // Send a large request (>3x avg AND >10KB)
        let anomalies = profile.check("api.openai.com", 50_000);
        assert!(
            anomalies.iter().any(|a| a.kind == AnomalyKind::VolumeSpike),
            "should detect volume spike"
        );
    }

    #[test]
    fn no_volume_spike_for_small_requests() {
        let mut profile = DestinationProfile::new();
        // Establish baseline with small requests
        for _ in 0..5 {
            profile.check("api.openai.com", 100);
        }
        // 3x of 100 = 300, but 5000 < 10KB absolute minimum
        let anomalies = profile.check("api.openai.com", 5000);
        assert!(
            anomalies.iter().all(|a| a.kind != AnomalyKind::VolumeSpike),
            "should not flag volume spike below 10KB"
        );
    }

    #[test]
    fn stats_are_tracked_correctly() {
        let mut profile = DestinationProfile::new();
        profile.check("api.openai.com", 100);
        profile.check("api.openai.com", 200);
        profile.check("api.openai.com", 300);

        let stats = profile.baseline.get("api.openai.com").unwrap();
        assert_eq!(stats.request_count, 3);
        assert_eq!(stats.total_bytes, 600);
        assert!((stats.avg_request_size - 200.0).abs() < f64::EPSILON);
        assert_eq!(stats.max_request_size, 300);
    }
}
