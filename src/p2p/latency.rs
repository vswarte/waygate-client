use std::time::{Duration, Instant};

const PROBE_INTERVAL: Duration = Duration::from_secs(2);

pub type LatencySequence = u8; 

/// Tracks latency for a particular p2p connection. This is done by sending a ping and awaiting a
/// pong, then taking the duration and dividing it in two. This measuring is crude and later down
/// the line I want to expose steamworks's connection info API, but this seems a more concrete
/// statistic as well.
pub struct LatencyTracker {
    /// Last latency probe sequence. We'll need to manually track it since the unreliable
    /// transmission might be passing things out of order.
    sequence: LatencySequence,

    /// When we last sent out a latency probe.
    sent_at: Option<Instant>,

    /// Last measured latency. The total time from forming the probe to the pong handling.
    last_measured: Option<Duration>,
}

impl LatencyTracker {
    pub fn new() -> Self {
        Self {
            sequence: 0,
            sent_at: None,
            last_measured: None,
        }
    }

    /// Yields true if enough time has passed since the last probe and we need to send out another
    /// one.
    pub fn should_send_probe(&self) -> bool {
        // Disable until I build the stats RPC
        return false;

        match self.sent_at {
            Some(sent_at) => Instant::now()
                .duration_since(sent_at) > PROBE_INTERVAL,

            None => true,
        }
    }

    /// Starts timing a probe and returns the sequence for the probe.
    pub fn start_probe(&mut self) -> LatencySequence {
        self.sent_at = Some(Instant::now());
        self.sequence.wrapping_add(1)
    }

    /// Ends timing for a probe.
    pub fn end_probe(&mut self, sequence: LatencySequence) {
        // We weren't expecting a pong since we never sent a ping.
        let Some(sent_at) = self.sent_at.as_ref() else {
            return;
        };

        // Received unexpected sequence number.
        if sequence != self.sequence {
            return;
        }

        let time = Instant::now().duration_since(*sent_at);
        self.last_measured = Some(time);
    }
}

#[cfg(test)]
mod test {
    use std::time::Duration;
    use std::thread::sleep;

    use super::LatencyTracker;

    #[test]
    fn measures_duration_between_probe_events() {
        let mut tracker = LatencyTracker::new();

        let sequence = tracker.start_probe();
        sleep(Duration::from_millis(100));
        tracker.end_probe(sequence);

        let last_measured = tracker.last_measured().unwrap();
        assert!(last_measured.as_millis() >= 99 && last_measured.as_millis() <= 110);
    }

    #[test]
    fn ignores_out_of_order_probe_events() {
        let mut tracker = LatencyTracker::new();

        let sequence_stale = tracker.start_probe();
        let sequence = tracker.start_probe();
        sleep(Duration::from_millis(100));
        tracker.end_probe(sequence);
        sleep(Duration::from_millis(100));
        dbg!(&tracker.sent_at);
        tracker.end_probe(sequence_stale);

        let last_measured = tracker.last_measured().unwrap();
        assert!(last_measured.as_millis() >= 99 && last_measured.as_millis() <= 110);
    }
}
