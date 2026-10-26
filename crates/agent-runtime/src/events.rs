//! Bounded, non-authoritative model deltas. Dropping a subscriber never stops a job.
//! Hosts create one bus per authorized attempt; durable replay comes from Store.
use agent_core::AttemptId;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

use crate::RuntimeError;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelDelta {
    pub attempt_id: AttemptId,
    pub generation: u64,
    pub text: String,
}

pub struct LiveEvents {
    attempt_id: AttemptId,
    generation: u64,
    sender: broadcast::Sender<ModelDelta>,
}
impl LiveEvents {
    pub fn new(
        attempt_id: AttemptId,
        generation: u64,
        capacity: usize,
    ) -> Result<Self, RuntimeError> {
        if generation == 0 || !(1..=1024).contains(&capacity) {
            return Err(RuntimeError::StaleAuthority);
        }
        let (sender, _) = broadcast::channel(capacity);
        Ok(Self {
            attempt_id,
            generation,
            sender,
        })
    }
    pub fn subscribe(&self) -> broadcast::Receiver<ModelDelta> {
        self.sender.subscribe()
    }
    pub fn publish_delta(&self, text: String) -> Result<(), RuntimeError> {
        if text.len() > 64 * 1024 {
            return Err(RuntimeError::Format("delta exceeds bound".into()));
        }
        let _ = self.sender.send(ModelDelta {
            attempt_id: self.attempt_id.clone(),
            generation: self.generation,
            text,
        });
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn slow_or_disconnected_subscriber_does_not_cancel_producer() {
        let bus = LiveEvents::new(AttemptId::new("a"), 1, 1).unwrap();
        let mut slow = bus.subscribe();
        bus.publish_delta("first".into()).unwrap();
        bus.publish_delta("second".into()).unwrap();
        assert!(matches!(
            slow.recv().await,
            Err(broadcast::error::RecvError::Lagged(1))
        ));
        assert_eq!(slow.recv().await.unwrap().text, "second");
        drop(slow);
        bus.publish_delta("no listeners".into()).unwrap();
        let mut reconnected = bus.subscribe();
        assert!(matches!(
            reconnected.try_recv(),
            Err(broadcast::error::TryRecvError::Empty)
        ));
        bus.publish_delta("fresh".into()).unwrap();
        assert_eq!(reconnected.recv().await.unwrap().text, "fresh");
        assert!(bus.publish_delta("x".repeat(65537)).is_err());
    }
}
