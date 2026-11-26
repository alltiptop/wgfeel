use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClockError {
    Overflow,
}

impl std::fmt::Display for ClockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("manual clock overflow")
    }
}

impl std::error::Error for ClockError {}

/// A manually advanced timeline for unit tests, independent of subprocess timeouts.
#[derive(Debug, Default)]
pub struct ManualClock {
    now: Duration,
}

impl ManualClock {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn now(&self) -> Duration {
        self.now
    }

    pub fn advance(&mut self, duration: Duration) -> Result<(), ClockError> {
        self.now = self.now.checked_add(duration).ok_or(ClockError::Overflow)?;
        Ok(())
    }

    pub fn deadline_after(&self, duration: Duration) -> Result<Deadline, ClockError> {
        self.now
            .checked_add(duration)
            .map(Deadline)
            .ok_or(ClockError::Overflow)
    }
}

/// A deadline on the logical timeline of the clock that created it.
#[derive(Debug, Clone, Copy)]
pub struct Deadline(Duration);

impl Deadline {
    pub fn is_elapsed(&self, clock: &ManualClock) -> bool {
        clock.now >= self.0
    }
}
