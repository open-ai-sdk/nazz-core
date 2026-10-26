//! Trusted host time budgets. No client can disable the watchdog.
use crate::RuntimeError;
use std::time::Duration;

#[derive(Debug, Clone, Copy)]
pub struct ExecutionPolicy {
    pub slice: Duration,
    pub lease: Duration,
    pub model: Duration,
    pub tool: Duration,
}
impl Default for ExecutionPolicy {
    fn default() -> Self {
        Self {
            slice: Duration::from_secs(240),
            lease: Duration::from_secs(300),
            model: Duration::from_secs(60),
            tool: Duration::from_secs(60),
        }
    }
}
impl ExecutionPolicy {
    pub fn validate(self) -> Result<Self, RuntimeError> {
        if [self.slice, self.lease, self.model, self.tool]
            .iter()
            .any(Duration::is_zero)
            || self.slice > Duration::from_secs(3600)
            || self.lease > Duration::from_secs(7200)
            || self.lease <= self.slice
            || self.model > self.slice
            || self.tool > self.slice
        {
            return Err(RuntimeError::Format("execution time budget refused".into()));
        }
        Ok(self)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn watchdog_cannot_be_disabled_or_outlive_lease() {
        assert!(ExecutionPolicy::default().validate().is_ok());
        for policy in [
            ExecutionPolicy {
                slice: Duration::ZERO,
                ..Default::default()
            },
            ExecutionPolicy {
                lease: Duration::from_secs(200),
                ..Default::default()
            },
            ExecutionPolicy {
                tool: Duration::from_secs(241),
                ..Default::default()
            },
        ] {
            assert!(policy.validate().is_err());
        }
    }
}
