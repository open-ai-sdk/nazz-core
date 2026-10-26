//! Neutral dispatch and outbox protocol values.

use nazz_core::{AttemptId, RequestId};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DispatchPhase {
    Pending,
    Claimed,
    Started,
    EffectPersisted,
    Reported,
    Acked,
    Held,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DispatchIntent {
    pub intent_id: String,
    pub request_id: RequestId,
    pub attempt_id: AttemptId,
    pub body_digest: String,
    pub parameters: Value,
    pub phase: DispatchPhase,
    pub cursor: i64,
    pub fence: String,
    pub holder: String,
    pub generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PollOutcome {
    Empty,
    Execute(DispatchIntent),
    FeedReceipt {
        intent: DispatchIntent,
        result: Value,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DispatchView {
    pub intent_id: String,
    pub request_id: RequestId,
    pub attempt_id: AttemptId,
    pub phase: DispatchPhase,
    pub cursor: i64,
    pub body_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeSnapshot {
    pub cursor: i64,
    pub views: Vec<DispatchView>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DispatchEvent {
    pub cursor: i64,
    pub intent_id: String,
    pub attempt_id: AttemptId,
    pub kind: String,
    pub body: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ReconcileReport {
    pub acked: Vec<AttemptId>,
    pub held: Vec<AttemptId>,
    pub cancelled: Vec<AttemptId>,
}
