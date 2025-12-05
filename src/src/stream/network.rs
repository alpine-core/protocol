//! Network condition detection helpers for ALPINE streaming.
//!
//! Phase 3.1 introduces deterministic metrics for packet loss, late frames, and
//! jitter so we can reason about what the network is doing without changing
//! runtime behavior yet. Each session gets its own `NetworkConditions` tracker,
//! and the metrics snapshot exposes `loss_ratio`, `late_frame_rate`, and
//! `jitter_ms` derived from observed arrival timelines.

/// Snapshot of the observed network metrics for a single session.
#[derive(Debug, Clone, Copy)]
pub struct NetworkMetrics {
    /// Fraction of expected frames that never arrived, in `[0, 1]`.
    pub loss_ratio: f64,
    /// Fraction of observed frames that missed their delivery deadline.
    pub late_frame_rate: f64,
    /// Average jitter in milliseconds between consecutive arrivals.
    pub jitter_ms: Option<f64>,
}

/// Determines the network conditions for an ALPINE streaming session.
pub struct NetworkConditions {
    last_sequence: Option<u64>,
    total_expected: u64,
    observed_frames: u64,
    lost_frames: u64,
    late_frames: u64,
    last_arrival: Option<u64>,
    last_interval: Option<u64>,
    total_jitter_ns: u128,
    jitter_samples: u64,
    max_loss_gap: u64,
}

impl NetworkConditions {
    /// Creates a fresh tracker.
    pub fn new() -> Self {
        Self {
            last_sequence: None,
            total_expected: 0,
            observed_frames: 0,
            lost_frames: 0,
            late_frames: 0,
            last_arrival: None,
            last_interval: None,
            total_jitter_ns: 0,
            jitter_samples: 0,
            max_loss_gap: 0,
        }
    }

    /// Records an observed frame arrival.
    ///
    /// The stream encodes `sequence`, `arrival_us`, and the caller-supplied
    /// `deadline_us` so we can independently reason about lateness, loss, and
    /// jitter. All calculations are deterministic and rely solely on these
    /// inputs.
    pub fn record_frame(&mut self, sequence: u64, arrival_us: u64, deadline_us: u64) {
        if let Some(last_seq) = self.last_sequence {
            if sequence <= last_seq {
                // Out-of-order or duplicate frames do not affect the metrics.
                return;
            }
            let delta = sequence - last_seq;
            self.total_expected = self.total_expected.saturating_add(delta);
            if delta > 1 {
                self.lost_frames = self.lost_frames.saturating_add(delta - 1);
                self.max_loss_gap = self.max_loss_gap.max(delta - 1);
            }
        } else {
            self.total_expected = self.total_expected.saturating_add(1);
        }

        self.last_sequence = Some(sequence);
        self.observed_frames = self.observed_frames.saturating_add(1);

        if arrival_us > deadline_us {
            self.late_frames = self.late_frames.saturating_add(1);
        }

        if let Some(last) = self.last_arrival {
            let interval = arrival_us.saturating_sub(last);
            if let Some(prev_interval) = self.last_interval {
                let jitter = if interval > prev_interval {
                    interval - prev_interval
                } else {
                    prev_interval - interval
                };
                self.total_jitter_ns = self.total_jitter_ns.saturating_add(jitter as u128);
                self.jitter_samples = self.jitter_samples.saturating_add(1);
            }
            self.last_interval = Some(interval);
        }
        self.last_arrival = Some(arrival_us);
    }

    /// Returns the latest metrics snapshot.
    pub fn metrics(&self) -> NetworkMetrics {
        let total_expected = self.total_expected.max(self.observed_frames);
        let loss_ratio = if total_expected == 0 {
            0.0
        } else {
            self.lost_frames as f64 / total_expected as f64
        };

        let late_frame_rate = if self.observed_frames == 0 {
            0.0
        } else {
            self.late_frames as f64 / self.observed_frames as f64
        };

        let jitter_ms = if self.jitter_samples == 0 {
            None
        } else {
            Some(self.total_jitter_ns as f64 / self.jitter_samples as f64 / 1000.0)
        };

        NetworkMetrics {
            loss_ratio,
            late_frame_rate,
            jitter_ms,
        }
    }

    /// Returns the largest sequence gap observed for burst detection.
    pub fn max_loss_gap(&self) -> u64 {
        self.max_loss_gap
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loss_ratio_accounts_for_missing_sequences() {
        let mut net = NetworkConditions::new();
        net.record_frame(1, 0, 1);
        net.record_frame(2, 1_000, 2_000);
        net.record_frame(4, 3_000, 4_000);
        let metrics = net.metrics();
        assert!((metrics.loss_ratio - (1.0 / 4.0)).abs() < f64::EPSILON);
    }

    #[test]
    fn late_frame_rate_counts_deadlines() {
        let mut net = NetworkConditions::new();
        net.record_frame(1, 0, 0);
        net.record_frame(2, 5_000, 3_000);
        net.record_frame(3, 6_000, 6_000);
        let metrics = net.metrics();
        assert!((metrics.late_frame_rate - (1.0 / 3.0)).abs() < f64::EPSILON);
    }

    #[test]
    fn jitter_ms_average() {
        let mut net = NetworkConditions::new();
        net.record_frame(1, 0, 0);
        net.record_frame(2, 1_000, 2_000);
        net.record_frame(3, 2_500, 4_000);
        net.record_frame(4, 3_900, 5_000);
        let metrics = net.metrics();
        // intervals: 1000, 1500, 1400 -> diffs: 500, 100 -> avg = 300 µs => 0.3 ms
        assert_eq!(metrics.jitter_ms, Some(0.3));
    }
}
