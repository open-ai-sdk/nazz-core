//! Host-neutral persistence ports for durable agent execution.
//!
//! This crate contains contracts and protocol values only. A host owns its
//! database, transaction boundaries, migrations, artifacts, and local journal.

use std::future::Future;
use std::time::Duration;

use agent_core::{
    AccountReference, ActorGrant, AdmissionReceipt, AttemptExecutionBinding, AttemptId,
    AttemptStatus, EffectClaim, EffectId, EffectState, ExecutionSelection, RequestId, ScopeError,
    StopReceipt, TracedEffectIdentity,
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

pub mod conformance;
pub mod dispatch;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error(transparent)]
    Scope(#[from] ScopeError),
    #[error("digest mismatch for request {0}")]
    DigestMismatch(String),
    #[error("stale generation")]
    StaleGeneration,
    #[error("lease held by the active owner")]
    LeaseHeld,
    #[error("approval is not bound to this actor, scope, args, and tool revision")]
    ApprovalMissing,
    #[error("stop receipt rejected: observed_stop is false")]
    StopNotObserved,
    #[error("attempt is already terminal")]
    TerminalAttempt,
    #[error("lifecycle transition conflicts with the committed state")]
    LifecycleConflict,
    #[error("stop receipt does not match the immutable receipt")]
    StopMismatch,
    #[error("needs_reconcile hold: unresolved effects block generation advance")]
    NeedsReconcileHold,
    #[error("legacy attempt has no authentic execution context")]
    ContextUnbound,
    #[error(transparent)]
    Context(#[from] agent_core::ContextError),
    #[error("credential material is not a queue payload")]
    CredentialInPayload,
    #[error("checkpoint format version {0} is refused; pinned version is {1}")]
    CheckpointFormat(u64, u64),
    #[error("checkpoint step {0} already holds different committed state")]
    CheckpointConflict(i64),
    #[error("storage backend: {0}")]
    Backend(String),
    #[error("io: {0}")]
    Io(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttemptRow {
    pub attempt_id: AttemptId,
    pub request_id: RequestId,
    pub generation: u64,
    pub status: AttemptStatus,
    pub result: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimOutcome {
    Fresh,
    Receipt(EffectClaim),
    InDoubt(EffectClaim),
}

/// Identity and authority bound by an exclusive durable effect claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectBinding {
    pub claim: EffectClaim,
    pub scope: String,
    pub tool_revision: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExclusiveClaim {
    Fresh(EffectBinding),
    KnownReceipt(EffectBinding),
    Existing(EffectBinding),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TracedClaim {
    Fresh(EffectBinding),
    KnownReceipt(EffectBinding),
    Unknown(EffectBinding),
    Unresolved,
}

/// `Blocked` means the callback did not run. `Attempted` means it was entered,
/// so the remote outcome is unknown and must not be retried blindly.
#[derive(Debug)]
pub enum EffectLaunch<T> {
    Blocked(StorageError),
    Ready(T),
    Attempted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchSettlement {
    Receipt,
    Unknown,
}

/// Checkpoint serialization format read and written by this runtime.
pub const CHECKPOINT_FORMAT_VERSION: u64 = 2;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CheckpointRecord {
    pub attempt_id: AttemptId,
    pub generation: u64,
    pub step: i64,
    pub format_version: u64,
    pub payload: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CommittedEvent {
    pub cursor: i64,
    pub attempt_id: String,
    pub body: Value,
}

/// Opaque context returned only after a storage adapter verifies the persisted
/// context, current grant revisions, generation, and live lease.
///
/// This type deliberately has no serde implementation. A host adapter may call
/// [`VerifiedExecutionContext::mint_trusted`] only after performing those live
/// checks in its own storage transaction. Callers must never construct it from
/// an API request, checkpoint, or serialized worker state.
#[derive(Debug, Clone)]
pub struct VerifiedExecutionContext {
    binding: AttemptExecutionBinding,
    generation: u64,
    holder: String,
}

impl VerifiedExecutionContext {
    /// Mint a runtime capability after the adapter has completed authoritative
    /// live verification of the binding, grant revisions, and lease.
    pub fn mint_trusted(
        binding: AttemptExecutionBinding,
        generation: u64,
        holder: impl Into<String>,
    ) -> Self {
        Self {
            binding,
            generation,
            holder: holder.into(),
        }
    }

    pub fn binding(&self) -> &AttemptExecutionBinding {
        &self.binding
    }
    pub fn capsule(&self) -> &agent_core::ContextCapsule {
        &self.binding.capsule
    }
    pub fn attempt_id(&self) -> &AttemptId {
        &self.binding.attempt_id
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn holder(&self) -> &str {
        &self.holder
    }
    pub fn account(&self) -> &AccountReference {
        &self.binding.account
    }
}

/// Durable attempt, lifecycle, checkpoint, authority, effect, and dispatch
/// operations required by the shared runtime. Implementations must preserve
/// each operation's atomicity and fencing semantics; the trait does not expose
/// SQL, connection pools, transactions, or schema management.
#[async_trait]
pub trait ExecutionStore: Send + Sync {
    async fn publish_grant(&self, grant: &ActorGrant) -> Result<(), StorageError>;

    async fn revoke_grant(&self, grant: &ActorGrant) -> Result<(), StorageError>;

    async fn admit(
        &self,
        grant: &ActorGrant,
        request_id: &RequestId,
        payload: &Value,
        selection: Option<&ExecutionSelection>,
    ) -> Result<AdmissionReceipt, StorageError>;

    async fn read_attempt(
        &self,
        grant: &ActorGrant,
        attempt_id: &AttemptId,
    ) -> Result<Option<AttemptRow>, StorageError>;

    async fn claim_lease(
        &self,
        grant: &ActorGrant,
        attempt_id: &AttemptId,
        generation: u64,
        holder: &str,
        ttl: Duration,
    ) -> Result<(), StorageError>;

    async fn release_lease(
        &self,
        grant: &ActorGrant,
        attempt_id: &AttemptId,
        generation: u64,
        holder: &str,
    ) -> Result<(), StorageError>;

    #[expect(
        clippy::too_many_arguments,
        reason = "Keep the host storage contract explicit and compatible."
    )]
    async fn put_checkpoint(
        &self,
        grant: &ActorGrant,
        attempt_id: &AttemptId,
        generation: u64,
        holder: &str,
        step: i64,
        format_version: u64,
        payload: &Value,
    ) -> Result<(), StorageError>;

    async fn read_checkpoint(
        &self,
        grant: &ActorGrant,
        attempt_id: &AttemptId,
        generation: u64,
        step: i64,
    ) -> Result<Option<CheckpointRecord>, StorageError>;

    async fn read_checkpoints(
        &self,
        grant: &ActorGrant,
        attempt_id: &AttemptId,
        generation: u64,
        after_step: i64,
    ) -> Result<Vec<CheckpointRecord>, StorageError>;

    #[expect(
        clippy::too_many_arguments,
        reason = "Keep the host storage contract explicit and compatible."
    )]
    async fn bind_approval(
        &self,
        grant: &ActorGrant,
        attempt_id: &AttemptId,
        generation: u64,
        holder: &str,
        scope: &str,
        tool_revision: &str,
        args_digest: &str,
    ) -> Result<(), StorageError>;

    #[expect(
        clippy::too_many_arguments,
        reason = "Keep the host storage contract explicit and compatible."
    )]
    async fn assert_effect_authority(
        &self,
        grant: &ActorGrant,
        attempt_id: &AttemptId,
        generation: u64,
        holder: &str,
        scope: &str,
        tool_revision: &str,
        args_digest: &str,
    ) -> Result<(), StorageError>;

    async fn request_cancel(
        &self,
        grant: &ActorGrant,
        attempt_id: &AttemptId,
        generation: u64,
    ) -> Result<(), StorageError>;

    async fn commit_stop(
        &self,
        grant: &ActorGrant,
        receipt: &StopReceipt,
    ) -> Result<AttemptStatus, StorageError>;

    async fn read_stop(
        &self,
        grant: &ActorGrant,
        attempt_id: &AttemptId,
        generation: u64,
    ) -> Result<Option<StopReceipt>, StorageError>;

    async fn complete_attempt(
        &self,
        grant: &ActorGrant,
        attempt_id: &AttemptId,
        generation: u64,
        holder: &str,
        result: &Value,
    ) -> Result<(), StorageError>;

    /// Persist a caller-provided effect state, including an explicit receipt
    /// for legacy/import flows. This does not prove that this adapter launched
    /// the external operation; new launches use `with_effect_launch`.
    async fn record_effect(
        &self,
        grant: &ActorGrant,
        holder: &str,
        scope: &str,
        tool_revision: &str,
        claim: &EffectClaim,
    ) -> Result<(), StorageError>;

    async fn claim_effect_exclusive(
        &self,
        grant: &ActorGrant,
        holder: &str,
        scope: &str,
        tool_revision: &str,
        claim: &EffectClaim,
    ) -> Result<ExclusiveClaim, StorageError>;

    #[expect(
        clippy::too_many_arguments,
        reason = "Keep the host storage contract explicit and compatible."
    )]
    async fn claim_traced_effect(
        &self,
        grant: &ActorGrant,
        holder: &str,
        scope: &str,
        tool_revision: &str,
        attempt_id: &AttemptId,
        generation: u64,
        tool_name: &str,
        traced: &TracedEffectIdentity,
    ) -> Result<TracedClaim, StorageError>;

    /// Atomically recheck and fence the live grant, attempt, lease, approval,
    /// verified context, and effect claim; persist `started` before calling
    /// `launch`; and serialize this permit with cancellation/stop. The permit
    /// must be held only up to `deadline`. A callback timeout or error returns
    /// `Attempted`, never permission to launch the same external effect again.
    #[expect(
        clippy::too_many_arguments,
        reason = "Keep the host storage contract explicit and compatible."
    )]
    async fn with_effect_launch<T, F, Fut>(
        &self,
        grant: &ActorGrant,
        holder: &str,
        scope: &str,
        tool_revision: &str,
        claim: &EffectClaim,
        deadline: Duration,
        launch: F,
    ) -> Result<EffectLaunch<T>, StorageError>
    where
        T: Send,
        F: FnOnce() -> Fut + Send,
        Fut: Future<Output = Result<T, ()>> + Send;

    /// Settle the matching launched effect as a receipt. Implementations must
    /// require the durable started marker committed by `with_effect_launch`;
    /// this method cannot import a receipt for an unstarted claim.
    async fn settle_launched_effect(
        &self,
        grant: &ActorGrant,
        holder: &str,
        scope: &str,
        tool_revision: &str,
        claim: &EffectClaim,
    ) -> Result<LaunchSettlement, StorageError>;

    async fn read_effect(
        &self,
        grant: &ActorGrant,
        effect_id: &EffectId,
    ) -> Result<Option<EffectClaim>, StorageError>;

    async fn read_attempt_context(
        &self,
        grant: &ActorGrant,
        attempt: &AttemptId,
    ) -> Result<Option<AttemptExecutionBinding>, StorageError>;

    async fn resolve_execution_context(
        &self,
        grant: &ActorGrant,
        attempt: &AttemptId,
        generation: u64,
        holder: &str,
    ) -> Result<VerifiedExecutionContext, StorageError>;

    async fn read_account_use(
        &self,
        grant: &ActorGrant,
        attempt: &AttemptId,
    ) -> Result<AccountReference, StorageError>;

    #[expect(
        clippy::too_many_arguments,
        reason = "Keep the host storage contract explicit and compatible."
    )]
    async fn suspend_before_launch(
        &self,
        grant: &ActorGrant,
        attempt: &AttemptId,
        generation: u64,
        holder: &str,
        step: i64,
        checkpoint: &Value,
        wait_key: &str,
    ) -> Result<String, StorageError>;

    async fn suspended_is_quiescent(
        &self,
        grant: &ActorGrant,
        attempt: &AttemptId,
        generation: u64,
    ) -> Result<bool, StorageError>;

    async fn resume_suspended(
        &self,
        grant: &ActorGrant,
        attempt: &AttemptId,
        generation: u64,
        wait_key: &str,
        checkpoint_digest: &str,
    ) -> Result<(), StorageError>;

    async fn reconcile_dispatch(
        &self,
        grant: &ActorGrant,
    ) -> Result<dispatch::ReconcileReport, StorageError>;

    async fn scope_snapshot(
        &self,
        grant: &ActorGrant,
    ) -> Result<dispatch::ScopeSnapshot, StorageError>;

    async fn read_dispatch_events(
        &self,
        grant: &ActorGrant,
        after: i64,
    ) -> Result<Vec<dispatch::DispatchEvent>, StorageError>;

    async fn poll_checkpoint_dispatch(
        &self,
        grant: &ActorGrant,
        holder: &str,
        host_fence: &str,
        ttl: Duration,
    ) -> Result<dispatch::PollOutcome, StorageError>;

    async fn mark_dispatch_started(
        &self,
        grant: &ActorGrant,
        attempt_id: &AttemptId,
        generation: u64,
        holder: &str,
        host_fence: &str,
    ) -> Result<i64, StorageError>;

    async fn note_dispatch_effect(
        &self,
        grant: &ActorGrant,
        attempt_id: &AttemptId,
        generation: u64,
        holder: &str,
        host_fence: &str,
        effect_id: &EffectId,
    ) -> Result<i64, StorageError>;

    async fn report_checkpoint_dispatch(
        &self,
        grant: &ActorGrant,
        attempt_id: &AttemptId,
        generation: u64,
        holder: &str,
        host_fence: &str,
        result: &Value,
    ) -> Result<i64, StorageError>;

    async fn report_agent_dispatch(
        &self,
        grant: &ActorGrant,
        attempt_id: &AttemptId,
        generation: u64,
        holder: &str,
        host_fence: &str,
        result: &Value,
    ) -> Result<i64, StorageError>;

    async fn ack_dispatch(
        &self,
        grant: &ActorGrant,
        attempt_id: &AttemptId,
        generation: u64,
        holder: &str,
        host_fence: &str,
    ) -> Result<i64, StorageError>;
}

/// Scoped durable artifact association. The host owns object bytes and keys;
/// these operations only bind an artifact to a verified execution attempt.
#[async_trait]
pub trait ArtifactStore: Send + Sync {
    async fn put_artifact(
        &self,
        grant: &ActorGrant,
        artifact_id: &str,
        attempt_id: &AttemptId,
        object_key: &str,
    ) -> Result<(), StorageError>;

    async fn read_artifact(
        &self,
        grant: &ActorGrant,
        artifact_id: &str,
    ) -> Result<Option<String>, StorageError>;

    async fn read_artifact_reference(
        &self,
        grant: &ActorGrant,
        artifact_id: &str,
    ) -> Result<Option<(AttemptId, String)>, StorageError>;
}

/// Scoped event log. Cursor allocation and host-specific transaction rules
/// remain owned by each storage adapter.
#[async_trait]
pub trait EventStore: Send + Sync {
    async fn append_event(
        &self,
        grant: &ActorGrant,
        attempt_id: &AttemptId,
        body: &Value,
    ) -> Result<i64, StorageError>;

    async fn read_events(&self, grant: &ActorGrant, after: i64)
    -> Result<Vec<Value>, StorageError>;

    async fn read_event_page(
        &self,
        grant: &ActorGrant,
        after: i64,
        limit: usize,
    ) -> Result<Vec<CommittedEvent>, StorageError>;
}

/// Worker-local journal port. It is a launch hint, never the durable authority
/// for whether a side effect ran; `ExecutionStore` owns that authority.
#[async_trait]
pub trait EffectJournal: Send + Sync {
    async fn claim_exclusive(&self, claim: &EffectClaim) -> Result<ClaimOutcome, StorageError>;
    async fn replace(&self, claim: &EffectClaim) -> Result<(), StorageError>;
    async fn release_unstarted(&self, effect_id: &EffectId) -> Result<(), StorageError>;
    async fn get(&self, effect_id: &EffectId) -> Result<Option<EffectClaim>, StorageError>;
    async fn seed_receipt(&self, claim: &EffectClaim) -> Result<(), StorageError>;
}

/// Claim through the journal before executing a side effect. Only a newly
/// created journal row enters the callback; receipts are returned as-is and
/// unresolved claims require reconciliation.
pub async fn claim_before_effect<J, T, F, Fut>(
    journal: &J,
    claim: EffectClaim,
    effect: F,
) -> Result<ClaimOutcome, StorageError>
where
    J: EffectJournal,
    T: Into<Value>,
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<T, ()>>,
{
    match journal.claim_exclusive(&claim).await? {
        ClaimOutcome::Fresh => match effect().await {
            Ok(receipt) => {
                let mut settled = claim.clone();
                settled.state = EffectState::Receipt;
                settled.receipt = Some(receipt.into());
                journal.replace(&settled).await?;
                Ok(ClaimOutcome::Receipt(settled))
            }
            Err(()) => {
                let mut unresolved = claim;
                unresolved.state = EffectState::NeedsReconcile;
                journal.replace(&unresolved).await?;
                Ok(ClaimOutcome::InDoubt(unresolved))
            }
        },
        outcome => Ok(outcome),
    }
}

/// Drop the raw trigger columns and recover any token the caller explicitly
/// proposed as an argument before it could be persisted in durable metadata.
pub fn scrub_credentials(text: &str, values: &[String]) -> String {
    let mut out = text.to_string();
    for secret in values.iter().filter(|s| s.len() >= 8) {
        if out.contains(secret.as_str()) {
            out = out.replace(secret.as_str(), "[redacted]");
        }
    }
    out
}
