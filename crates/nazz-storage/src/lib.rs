//! Host-neutral persistence ports for durable agent execution.
//!
//! This crate contains contracts and protocol values only. A host owns its
//! database, transaction boundaries, migrations, artifacts, and local journal.

use std::future::Future;
use std::time::Duration;

use async_trait::async_trait;
use nazz_core::{
    AccountReference, ActorGrant, ActorId, AdmissionReceipt, AttemptExecutionBinding, AttemptId,
    AttemptStatus, EffectClaim, EffectId, EffectState, ExecutionSelection, RequestId, ScopeError,
    StopReceipt, TenantId, TracedEffectIdentity, WorkspaceId,
};
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

    #[error("reconciliation candidate is not a durable-started unresolved effect")]
    InvalidReconciliationCandidate,
    #[error("reconciliation evidence is missing or incomplete")]
    ReconciliationEvidenceMissing,
    #[error("reconciliation conflicts with the persisted binding or ledger revision")]
    ReconciliationConflict,
    #[error("the original effect lease is still live")]
    ReconciliationLeaseActive,
    #[error("legacy attempt has no authentic execution context")]
    ContextUnbound,
    #[error(transparent)]
    Context(#[from] nazz_core::ContextError),
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

/// Exact immutable identity read from the host ledger before evidence review.
/// The host must compare every field again inside the reconciliation transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectReconciliationBinding {
    pub tenant_id: TenantId,
    pub workspace_id: WorkspaceId,
    pub actor_id: ActorId,
    pub grant_revision: u64,
    pub attempt_id: AttemptId,
    pub effect_id: EffectId,
    pub generation: u64,
    pub holder: String,
    pub tool_name: String,
    pub args_digest: String,
    pub scope: String,
    pub tool_revision: String,
    pub ledger_revision: u64,
    pub durable_started: bool,
    pub state: EffectState,
}

/// Reference to an immutable record already persisted by the host evidence
/// ledger. `digest` and `provenance` are rechecked atomically with promotion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectReconciliationEvidence {
    pub evidence_id: String,
    pub digest: String,
    pub provenance: String,
}

/// Verified outcome associated with reconciliation evidence. A proven
/// no-start carries the exact negative result transparently through the
/// existing receipt path; its proof kind is recorded separately here.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EffectReconciliationResult {
    Receipt { value: Value },
    ProvenNotStarted { value: Value },
}

impl EffectReconciliationResult {
    /// Exact value stored in the existing effect receipt field.
    pub fn receipt_value(&self) -> Value {
        match self {
            Self::Receipt { value } | Self::ProvenNotStarted { value } => value.clone(),
        }
    }
}

/// Host-minted capability; deliberately not serializable. Only a host verifier
/// with a current, non-revoked principal may call `mint_trusted`, after verifying
/// persisted evidence for this exact scope and binding. The store rechecks the
/// principal's grant, evidence, and CAS revision inside the atomic transaction.
#[derive(Debug, Clone)]
pub struct VerifiedEffectReconciliation {
    principal: ActorGrant,
    binding: EffectReconciliationBinding,
    evidence: EffectReconciliationEvidence,
    result: EffectReconciliationResult,
}

impl VerifiedEffectReconciliation {
    pub fn mint_trusted(
        principal: ActorGrant,
        binding: EffectReconciliationBinding,
        evidence: EffectReconciliationEvidence,
        result: EffectReconciliationResult,
    ) -> Result<Self, StorageError> {
        if principal.revoked
            || principal.tenant_id != binding.tenant_id
            || principal.workspace_id != binding.workspace_id
            || binding.state != EffectState::NeedsReconcile
            || !binding.durable_started
            || binding.grant_revision == 0
            || binding.ledger_revision == 0
            || binding.actor_id.as_str().is_empty()
            || binding.holder.is_empty()
            || binding.tool_name.is_empty()
            || binding.args_digest.is_empty()
            || binding.scope.is_empty()
            || binding.tool_revision.is_empty()
        {
            return Err(StorageError::InvalidReconciliationCandidate);
        }
        if evidence.evidence_id.is_empty()
            || evidence.digest.is_empty()
            || evidence.provenance.is_empty()
        {
            return Err(StorageError::ReconciliationEvidenceMissing);
        }
        Ok(Self {
            principal,
            binding,
            evidence,
            result,
        })
    }

    pub fn principal(&self) -> &ActorGrant {
        &self.principal
    }

    pub fn binding(&self) -> &EffectReconciliationBinding {
        &self.binding
    }

    pub fn evidence(&self) -> &EffectReconciliationEvidence {
        &self.evidence
    }

    pub fn result(&self) -> &EffectReconciliationResult {
        &self.result
    }
}

/// Immutable evidence/result association committed with the effect transition.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EffectReconciliationRecord {
    pub principal: ActorGrant,
    pub binding: EffectReconciliationBinding,
    pub evidence: EffectReconciliationEvidence,
    pub result: EffectReconciliationResult,
    pub committed_revision: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum EffectReconciliationOutcome {
    Applied(EffectReconciliationRecord),
    AlreadyApplied(EffectReconciliationRecord),
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
    pub fn capsule(&self) -> &nazz_core::ContextCapsule {
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

    /// Return the complete historical binding and current per-effect ledger
    /// revision used to verify evidence. This read does not lease or mutate the
    /// effect; the host must not substitute a caller-supplied holder or actor.
    async fn read_effect_reconciliation_binding(
        &self,
        principal: &ActorGrant,
        attempt_id: &AttemptId,
        effect_id: &EffectId,
    ) -> Result<Option<EffectReconciliationBinding>, StorageError>;
    /// Persist an immutable host-verified evidence association for later
    /// commit-time revalidation. Only a trusted verifier may pass this
    /// non-deserializable capability; this operation does not promote effects.
    async fn persist_verified_effect_reconciliation_evidence(
        &self,
        reconciliation: &VerifiedEffectReconciliation,
    ) -> Result<(), StorageError>;

    /// Atomically recheck the persisted evidence reference, its exact binding,
    /// proof digest, provenance, result, and the current non-revoked principal
    /// grant in the same transaction as the effect CAS. Require durable-started
    /// state, the expected ledger revision, and an expired/fenced original lease
    /// before appending the immutable record and promoting only that effect.
    /// Exact replay is idempotent; a different proof/result or stale revision is
    /// a conflict, never last-write-wins.
    ///
    /// This operation is history-only: it must not recreate a lease, advance
    /// generation, relaunch the effect, reopen cancellation/Stop/approval
    /// holds, or authorize work after grant revocation. It may release only the
    /// existing unknown-effect outbox hold when every unknown effect is
    /// resolved and no independent barrier remains.
    async fn reconcile_effect(
        &self,
        reconciliation: &VerifiedEffectReconciliation,
    ) -> Result<EffectReconciliationOutcome, StorageError>;

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
