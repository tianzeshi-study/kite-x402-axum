#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

pub struct CircuitBreaker {
    state: CircuitState,
    failure_threshold: u32,
    failure_count: u32,
}

impl CircuitBreaker {
    pub fn new(failure_threshold: u32) -> Self {
        Self {
            state: CircuitState::Closed,
            failure_threshold,
            failure_count: 0,
        }
    }

    pub fn state(&self) -> CircuitState {
        self.state
    }

    pub fn record_success(&mut self) {
        self.failure_count = 0;
        self.state = CircuitState::Closed;
    }

    pub fn record_failure(&mut self) {
        self.failure_count += 1;
        if self.failure_count >= self.failure_threshold {
            self.state = CircuitState::Open;
        }
    }
}
