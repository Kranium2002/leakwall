use std::collections::HashMap;
use std::time::{Duration, Instant};

use tracing::{debug, info};

/// Desktop notification sender with per-event-type rate limiting.
pub struct Notifier {
    last_notified: HashMap<String, Instant>,
    rate_limit: Duration,
    enabled: bool,
}

impl Notifier {
    /// Create a new Notifier.
    /// If `enabled` is false, notifications are logged but not sent.
    pub fn new(enabled: bool) -> Self {
        Self {
            last_notified: HashMap::new(),
            rate_limit: Duration::from_secs(300), // 5 minutes
            enabled,
        }
    }

    /// Send a desktop notification.
    ///
    /// Non-critical notifications are rate-limited to one per
    /// event_type per 5-minute window. Critical notifications
    /// bypass the rate limit.
    pub fn send(&mut self, event_type: &str, title: &str, body: &str, critical: bool) {
        if !critical {
            if let Some(last) = self.last_notified.get(event_type) {
                if last.elapsed() < self.rate_limit {
                    debug!(event_type, "notification suppressed by rate limit");
                    return;
                }
            }
        }

        self.last_notified
            .insert(event_type.to_owned(), Instant::now());

        if !self.enabled {
            info!(
                event_type,
                title, body, "notification disabled, logged only"
            );
            return;
        }

        info!(event_type, title, "sending desktop notification");

        #[cfg(not(test))]
        {
            let result = notify_rust::Notification::new()
                .summary(title)
                .body(body)
                .appname("LeakWall")
                .show();

            if let Err(e) = result {
                debug!(
                    error = %e,
                    "failed to send desktop notification"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_notifier_rate_limiting() {
        let mut notifier = Notifier::new(false);

        // First call should go through (updates last_notified)
        notifier.send("test_event", "Title", "Body", false);
        assert!(notifier.last_notified.contains_key("test_event"));
        let first_time = *notifier.last_notified.get("test_event").unwrap();

        // Second call within rate limit window should be suppressed
        // (last_notified timestamp should NOT be updated)
        notifier.send("test_event", "Title 2", "Body 2", false);
        let second_time = *notifier.last_notified.get("test_event").unwrap();
        assert_eq!(first_time, second_time);
    }

    #[test]
    fn test_notifier_critical_bypasses_rate_limit() {
        let mut notifier = Notifier::new(false);

        // First non-critical call
        notifier.send("test_event", "Title", "Body", false);
        let first_time = *notifier.last_notified.get("test_event").unwrap();

        // Tiny sleep so Instant changes
        std::thread::sleep(Duration::from_millis(1));

        // Critical call should bypass rate limit and update
        // timestamp
        notifier.send("test_event", "Critical!", "Body", true);
        let after_critical = *notifier.last_notified.get("test_event").unwrap();
        assert!(after_critical > first_time);
    }

    #[test]
    fn test_notifier_different_event_types_independent() {
        let mut notifier = Notifier::new(false);

        notifier.send("event_a", "Title A", "Body A", false);
        notifier.send("event_b", "Title B", "Body B", false);

        assert!(notifier.last_notified.contains_key("event_a"));
        assert!(notifier.last_notified.contains_key("event_b"));
    }
}
