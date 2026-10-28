//! Reusable, adapter-driven conformance checks for durable storage ports.

use nazz_core::{
    AccountReference, ActorGrant, ActorId, AgentId, AttemptId, EffectClaim, EffectId, EffectState,
    ExecutionSelection, RequestId, ScopeError, StopReceipt, TenantId, WorkspaceId,
    trace_effect_identity,
};
use serde_json::json;
use std::sync::atomic::{AtomicUsize, Ordering};
use thiserror::Error;

use crate::{
    ArtifactStore, ClaimOutcome, EffectJournal, EffectLaunch, EffectReconciliationEvidence,
    EffectReconciliationOutcome, EffectReconciliationResult, EventStore, ExecutionStore,
    StorageError, TracedClaim, VerifiedEffectReconciliation,
};

#[derive(Debug, Error)]
pub enum ConformanceError {
    #[error("storage operation failed: {0}")]
    Storage(#[from] StorageError),
    #[error("storage conformance failed: {0}")]
    Assertion(&'static str),
}

fn require(condition: bool, message: &'static str) -> Result<(), ConformanceError> {
    if condition {
        Ok(())
    } else {
        Err(ConformanceError::Assertion(message))
    }
}

fn is_hidden_optional<T>(result: Result<Option<T>, StorageError>) -> bool {
    matches!(
        result,
        Ok(None) | Err(StorageError::Scope(ScopeError::Denied))
    )
}

fn is_hidden_page<T>(result: Result<Vec<T>, StorageError>) -> bool {
    match result {
        Ok(records) => records.is_empty(),
        Err(StorageError::Scope(ScopeError::Denied)) => true,
        Err(_) => false,
    }
}

fn is_missing_attempt_mutation(result: Result<(), StorageError>) -> bool {
    matches!(
        result,
        Err(StorageError::Scope(ScopeError::Denied) | StorageError::StaleGeneration)
    )
}

fn owner(namespace: &str) -> ActorGrant {
    ActorGrant {
        tenant_id: TenantId::new(format!("storage-conformance/{namespace}")),
        workspace_id: WorkspaceId::new("port-contract"),
        actor_id: ActorId::new("owner"),
        revision: 1,
        revoked: false,
    }
}

fn selection(grant: &ActorGrant) -> ExecutionSelection {
    ExecutionSelection::new(
        grant,
        AgentId::new("storage-conformance-agent"),
        "Execute the scoped conformance task.".into(),
        "Use only operations explicitly granted by the host.".into(),
        AccountReference {
            account_ref: "storage-conformance-account".into(),
            provider: "local".into(),
            revision: 1,
        },
    )
}

struct UnknownEffectFixture<'a> {
    attempt_id: &'a AttemptId,
    holder: &'a str,
    scope: &'a str,
    revision: &'a str,
    tool_name: &'a str,
    call_id: &'a str,
    args: &'a serde_json::Value,
    lease_ttl: std::time::Duration,
}

async fn start_unknown_effect<S: ExecutionStore>(
    store: &S,
    grant: &ActorGrant,
    fixture: UnknownEffectFixture<'_>,
) -> Result<
    (
        nazz_core::TracedEffectIdentity,
        crate::EffectReconciliationBinding,
    ),
    ConformanceError,
> {
    store
        .claim_lease(
            grant,
            fixture.attempt_id,
            1,
            fixture.holder,
            fixture.lease_ttl,
        )
        .await?;
    let traced = trace_effect_identity(fixture.attempt_id, fixture.call_id, fixture.args);
    store
        .bind_approval(
            grant,
            fixture.attempt_id,
            1,
            fixture.holder,
            fixture.scope,
            fixture.revision,
            &traced.canonical.args_digest,
        )
        .await?;
    let fresh = match store
        .claim_traced_effect(
            grant,
            fixture.holder,
            fixture.scope,
            fixture.revision,
            fixture.attempt_id,
            1,
            fixture.tool_name,
            &traced,
        )
        .await?
    {
        TracedClaim::Fresh(binding) => binding,
        _ => {
            return Err(ConformanceError::Assertion(
                "reconciliation fixture did not claim a fresh effect",
            ));
        }
    };
    let launch = store
        .with_effect_launch(
            grant,
            fixture.holder,
            fixture.scope,
            fixture.revision,
            &fresh.claim,
            fixture.lease_ttl,
            || async { Err::<serde_json::Value, ()>(()) },
        )
        .await?;
    require(
        matches!(launch, EffectLaunch::Attempted),
        "reconciliation fixture did not persist a durable-started unknown",
    )?;
    let mut unknown = fresh.claim.clone();
    unknown.state = EffectState::NeedsReconcile;
    unknown.receipt = None;
    store
        .record_effect(
            grant,
            fixture.holder,
            fixture.scope,
            fixture.revision,
            &unknown,
        )
        .await?;
    let Some(binding) = store
        .read_effect_reconciliation_binding(grant, fixture.attempt_id, &fresh.claim.effect_id)
        .await?
    else {
        return Err(ConformanceError::Assertion(
            "durable-started effect has no reconciliation binding",
        ));
    };
    Ok((traced, binding))
}

/// Run the same contract against a host's isolated storage implementation.
/// The caller supplies a unique namespace per invocation and a disposable or
/// dedicated test store. The function writes test records into that namespace.
pub async fn run_storage_conformance<S, J>(
    store: &S,
    journal: &J,
    namespace: &str,
) -> Result<(), ConformanceError>
where
    S: ExecutionStore + ArtifactStore + EventStore,
    J: EffectJournal,
{
    let grant = owner(namespace);
    let foreign = ActorGrant {
        tenant_id: TenantId::new(format!("storage-conformance/{namespace}/foreign")),
        workspace_id: grant.workspace_id.clone(),
        actor_id: ActorId::new("foreign"),
        revision: 1,
        revoked: false,
    };
    let other_workspace = ActorGrant {
        tenant_id: grant.tenant_id.clone(),
        workspace_id: WorkspaceId::new("other-workspace"),
        actor_id: ActorId::new("workspace-peer"),
        revision: 1,
        revoked: false,
    };
    let unregistered = ActorGrant {
        tenant_id: TenantId::new(format!("storage-conformance/{namespace}/unregistered")),
        workspace_id: grant.workspace_id.clone(),
        actor_id: ActorId::new("unregistered"),
        revision: 1,
        revoked: false,
    };
    store.publish_grant(&grant).await?;
    store.publish_grant(&foreign).await?;
    store.publish_grant(&other_workspace).await?;

    let request = RequestId::new(format!("request/{namespace}"));
    let payload = json!({"kind":"conformance","namespace":namespace});
    let selected = selection(&grant);
    let admitted = store
        .admit(&grant, &request, &payload, Some(&selected))
        .await?;
    let repeated = store
        .admit(&grant, &request, &payload, Some(&selected))
        .await?;
    require(
        admitted == repeated,
        "same admission did not return the same receipt",
    )?;

    let changed = store
        .admit(
            &grant,
            &request,
            &json!({"kind":"changed","namespace":namespace}),
            Some(&selected),
        )
        .await;
    require(
        matches!(changed, Err(StorageError::DigestMismatch(_))),
        "changed request body did not refuse request-id reuse",
    )?;

    let unregistered_read = store
        .read_attempt(&unregistered, &admitted.attempt_id)
        .await;
    require(
        matches!(
            unregistered_read,
            Err(StorageError::Scope(ScopeError::Denied))
        ),
        "an unregistered grant authorized an attempt read",
    )?;
    require(
        is_hidden_optional(store.read_attempt(&foreign, &admitted.attempt_id).await),
        "a valid foreign tenant read the owner attempt",
    )?;
    require(
        is_hidden_optional(
            store
                .read_attempt(&other_workspace, &admitted.attempt_id)
                .await,
        ),
        "a valid same-tenant workspace peer read the owner attempt",
    )?;
    let Some(before_foreign_cancel) = store.read_attempt(&grant, &admitted.attempt_id).await?
    else {
        return Err(ConformanceError::Assertion(
            "admitted attempt disappeared before scope checks",
        ));
    };
    let foreign_cancel = store
        .request_cancel(
            &foreign,
            &admitted.attempt_id,
            before_foreign_cancel.generation,
        )
        .await;
    require(
        is_missing_attempt_mutation(foreign_cancel),
        "a valid foreign tenant changed the owner attempt",
    )?;
    let workspace_cancel = store
        .request_cancel(
            &other_workspace,
            &admitted.attempt_id,
            before_foreign_cancel.generation,
        )
        .await;
    require(
        is_missing_attempt_mutation(workspace_cancel),
        "a valid same-tenant workspace peer changed the owner attempt",
    )?;
    let Some(after_foreign_cancel) = store.read_attempt(&grant, &admitted.attempt_id).await? else {
        return Err(ConformanceError::Assertion(
            "foreign attempt mutation removed the owner attempt",
        ));
    };
    require(
        before_foreign_cancel.generation == after_foreign_cancel.generation
            && before_foreign_cancel.status == after_foreign_cancel.status
            && before_foreign_cancel.result == after_foreign_cancel.result,
        "a foreign attempt mutation changed the owner attempt state",
    )?;

    const HOLDER: &str = "conformance-holder-a";
    const OTHER_HOLDER: &str = "conformance-holder-b";
    let lease_ttl = std::time::Duration::from_secs(30);
    store
        .claim_lease(&grant, &admitted.attempt_id, 1, HOLDER, lease_ttl)
        .await?;
    let context = store
        .resolve_execution_context(&grant, &admitted.attempt_id, 1, HOLDER)
        .await?;
    require(
        context.attempt_id() == &admitted.attempt_id
            && context.generation() == 1
            && context.holder() == HOLDER,
        "verified context did not bind the live attempt and lease",
    )?;
    let competing = store
        .claim_lease(&grant, &admitted.attempt_id, 1, OTHER_HOLDER, lease_ttl)
        .await;
    require(
        matches!(competing, Err(StorageError::LeaseHeld)),
        "a second holder acquired a live lease",
    )?;
    store
        .release_lease(&grant, &admitted.attempt_id, 1, HOLDER)
        .await?;
    store
        .claim_lease(&grant, &admitted.attempt_id, 2, OTHER_HOLDER, lease_ttl)
        .await?;
    let stale = store
        .claim_lease(&grant, &admitted.attempt_id, 1, HOLDER, lease_ttl)
        .await;
    require(
        matches!(
            stale,
            Err(StorageError::StaleGeneration | StorageError::LeaseHeld)
        ),
        "stale generation reacquired a lease",
    )?;
    let current_lease = store
        .resolve_execution_context(&grant, &admitted.attempt_id, 2, OTHER_HOLDER)
        .await?;
    require(
        current_lease.holder() == OTHER_HOLDER,
        "stale lease acquisition changed the current holder",
    )?;
    let Some(current_attempt) = store.read_attempt(&grant, &admitted.attempt_id).await? else {
        return Err(ConformanceError::Assertion(
            "stale lease acquisition removed its attempt",
        ));
    };
    require(
        current_attempt.generation == 2,
        "stale lease acquisition advanced the current generation",
    )?;

    let checkpoint = json!({"contract":"immutable-step","namespace":namespace});
    store
        .put_checkpoint(
            &grant,
            &admitted.attempt_id,
            2,
            OTHER_HOLDER,
            1,
            crate::CHECKPOINT_FORMAT_VERSION,
            &checkpoint,
        )
        .await?;
    store
        .put_checkpoint(
            &grant,
            &admitted.attempt_id,
            2,
            OTHER_HOLDER,
            1,
            crate::CHECKPOINT_FORMAT_VERSION,
            &checkpoint,
        )
        .await?;
    let conflict = store
        .put_checkpoint(
            &grant,
            &admitted.attempt_id,
            2,
            OTHER_HOLDER,
            1,
            crate::CHECKPOINT_FORMAT_VERSION,
            &json!({"contract":"changed-step","namespace":namespace}),
        )
        .await;
    require(
        matches!(conflict, Err(StorageError::CheckpointConflict(1))),
        "checkpoint key accepted different committed payload",
    )?;

    let args = json!({"action":"single-launch","namespace":namespace});
    let traced = trace_effect_identity(&admitted.attempt_id, "conformance-call", &args);
    let digest = traced.canonical.args_digest.clone();
    const SCOPE: &str = "conformance:effect";
    const REVISION: &str = "conformance-revision-1";
    store
        .bind_approval(
            &grant,
            &admitted.attempt_id,
            2,
            OTHER_HOLDER,
            SCOPE,
            REVISION,
            &digest,
        )
        .await?;
    let first = store
        .claim_traced_effect(
            &grant,
            OTHER_HOLDER,
            SCOPE,
            REVISION,
            &admitted.attempt_id,
            2,
            "conformance_tool",
            &traced,
        )
        .await?;
    let fresh = match first {
        TracedClaim::Fresh(binding) => binding,
        _ => {
            return Err(ConformanceError::Assertion(
                "first effect claim was not fresh",
            ));
        }
    };
    let mut premature_receipt = fresh.claim.clone();
    premature_receipt.state = EffectState::Receipt;
    premature_receipt.receipt = Some(json!({"receipt":"must-not-settle-before-launch"}));
    require(
        matches!(
            store
                .settle_launched_effect(&grant, OTHER_HOLDER, SCOPE, REVISION, &premature_receipt,)
                .await,
            Err(StorageError::LifecycleConflict)
        ),
        "adapter settled a claimed effect before durable launch",
    )?;
    let Some(unlaunched) = store.read_effect(&grant, &fresh.claim.effect_id).await? else {
        return Err(ConformanceError::Assertion(
            "pre-launch settlement removed its effect claim",
        ));
    };
    require(
        unlaunched.state == EffectState::Claimed && unlaunched.receipt.is_none(),
        "pre-launch settlement changed the claimed effect",
    )?;

    let launches = AtomicUsize::new(0);
    let launch = store
        .with_effect_launch(
            &grant,
            OTHER_HOLDER,
            SCOPE,
            REVISION,
            &fresh.claim,
            lease_ttl,
            || {
                launches.fetch_add(1, Ordering::SeqCst);
                async { Ok(json!({"receipt":"persisted"})) }
            },
        )
        .await?;
    let receipt = match launch {
        EffectLaunch::Ready(receipt) => receipt,
        _ => {
            return Err(ConformanceError::Assertion(
                "valid fresh claim did not launch",
            ));
        }
    };
    let mut settled = fresh.claim.clone();
    settled.state = EffectState::Receipt;
    settled.receipt = Some(receipt);
    require(
        store
            .settle_launched_effect(&grant, OTHER_HOLDER, SCOPE, REVISION, &settled)
            .await?
            == crate::LaunchSettlement::Receipt,
        "successful effect was not durably settled as a receipt",
    )?;
    let replay = store
        .claim_traced_effect(
            &grant,
            OTHER_HOLDER,
            SCOPE,
            REVISION,
            &admitted.attempt_id,
            2,
            "conformance_tool",
            &traced,
        )
        .await?;
    require(
        matches!(replay, TracedClaim::KnownReceipt(_)),
        "replayed logical call did not return its stored receipt",
    )?;
    let blocked = store
        .with_effect_launch(
            &grant,
            OTHER_HOLDER,
            SCOPE,
            REVISION,
            &fresh.claim,
            lease_ttl,
            || {
                launches.fetch_add(1, Ordering::SeqCst);
                async { Ok(json!({"receipt":"duplicate"})) }
            },
        )
        .await?;
    require(
        matches!(blocked, EffectLaunch::Blocked(_)) && launches.load(Ordering::SeqCst) == 1,
        "a settled effect allowed a second launch",
    )?;
    require(
        is_hidden_optional(store.read_effect(&foreign, &fresh.claim.effect_id).await),
        "a valid foreign tenant read the owner effect",
    )?;
    require(
        is_hidden_optional(
            store
                .read_effect(&other_workspace, &fresh.claim.effect_id)
                .await,
        ),
        "a valid same-tenant workspace peer read the owner effect",
    )?;

    let reconcile_admission = store
        .admit(
            &grant,
            &RequestId::new(format!("reconcile-request/{namespace}")),
            &json!({"kind":"reconcile","namespace":namespace}),
            Some(&selected),
        )
        .await?;
    let reconcile_attempt = reconcile_admission.attempt_id;
    let reconcile_args = json!({"action":"reconcile-known-result","namespace":namespace});
    let (reconcile_trace, reconcile_binding) = start_unknown_effect(
        store,
        &grant,
        UnknownEffectFixture {
            attempt_id: &reconcile_attempt,
            holder: HOLDER,
            scope: SCOPE,
            revision: REVISION,
            tool_name: "conformance_tool",
            call_id: "reconcile-call",
            args: &reconcile_args,
            lease_ttl,
        },
    )
    .await?;
    require(
        reconcile_binding.tenant_id == grant.tenant_id
            && reconcile_binding.workspace_id == grant.workspace_id
            && reconcile_binding.actor_id == grant.actor_id
            && reconcile_binding.grant_revision == grant.revision
            && reconcile_binding.attempt_id == reconcile_attempt
            && reconcile_binding.effect_id == reconcile_trace.canonical.effect_id
            && reconcile_binding.generation == 1
            && reconcile_binding.holder == HOLDER
            && reconcile_binding.tool_name == "conformance_tool"
            && reconcile_binding.args_digest == reconcile_trace.canonical.args_digest
            && reconcile_binding.scope == SCOPE
            && reconcile_binding.tool_revision == REVISION
            && reconcile_binding.durable_started
            && reconcile_binding.state == EffectState::NeedsReconcile,
        "reconciliation binding lost original execution identity",
    )?;
    let reconcile_evidence = EffectReconciliationEvidence {
        evidence_id: format!("evidence/{namespace}/receipt"),
        digest: "27f557c509a6b490ba97d8c959b924f1660b97e95bb4f6cd027bdb14b3042e6a".into(),
        provenance: "storage-conformance:trusted-verifier-fixture".into(),
    };
    let reconcile_result = EffectReconciliationResult::Receipt {
        value: json!({"receipt":"reconciled-exact-result"}),
    };
    let verified_reconciliation = VerifiedEffectReconciliation::mint_trusted(
        grant.clone(),
        reconcile_binding.clone(),
        reconcile_evidence.clone(),
        reconcile_result.clone(),
    )?;
    let mut revoked_principal = grant.clone();
    revoked_principal.revoked = true;
    require(
        matches!(
            VerifiedEffectReconciliation::mint_trusted(
                revoked_principal,
                reconcile_binding.clone(),
                reconcile_evidence.clone(),
                reconcile_result.clone(),
            ),
            Err(StorageError::InvalidReconciliationCandidate)
        ),
        "a revoked principal minted a reconciliation capability",
    )?;
    store
        .persist_verified_effect_reconciliation_evidence(&verified_reconciliation)
        .await?;
    require(
        matches!(
            VerifiedEffectReconciliation::mint_trusted(
                foreign.clone(),
                reconcile_binding.clone(),
                reconcile_evidence.clone(),
                reconcile_result.clone(),
            ),
            Err(StorageError::InvalidReconciliationCandidate)
        ),
        "a foreign tenant minted a scoped reconciliation capability",
    )?;

    require(
        matches!(
            store.reconcile_effect(&verified_reconciliation).await,
            Err(StorageError::ReconciliationLeaseActive)
        ),
        "reconciliation stole an original live lease",
    )?;
    store
        .release_lease(&grant, &reconcile_attempt, 1, HOLDER)
        .await?;

    let mut wrong_digest_binding = reconcile_binding.clone();
    wrong_digest_binding.args_digest.push_str("-wrong");
    let wrong_digest = VerifiedEffectReconciliation::mint_trusted(
        grant.clone(),
        wrong_digest_binding,
        reconcile_evidence.clone(),
        reconcile_result.clone(),
    )?;
    require(
        matches!(
            store.reconcile_effect(&wrong_digest).await,
            Err(StorageError::ReconciliationConflict)
        ),
        "reconciliation accepted a different argument digest",
    )?;
    let mut wrong_session_binding = reconcile_binding.clone();
    wrong_session_binding.attempt_id = AttemptId::new(format!("wrong-attempt/{namespace}"));
    let wrong_session = VerifiedEffectReconciliation::mint_trusted(
        grant.clone(),
        wrong_session_binding,
        reconcile_evidence.clone(),
        reconcile_result.clone(),
    )?;
    require(
        matches!(
            store.reconcile_effect(&wrong_session).await,
            Err(StorageError::ReconciliationConflict)
        ),
        "reconciliation accepted a different attempt session",
    )?;
    let mut wrong_actor_binding = reconcile_binding.clone();
    wrong_actor_binding.actor_id = ActorId::new("different-original-actor");
    let wrong_actor = VerifiedEffectReconciliation::mint_trusted(
        grant.clone(),
        wrong_actor_binding,
        reconcile_evidence.clone(),
        reconcile_result.clone(),
    )?;
    require(
        matches!(
            store.reconcile_effect(&wrong_actor).await,
            Err(StorageError::ReconciliationConflict)
        ),
        "reconciliation accepted a different original actor",
    )?;
    let mut wrong_holder_binding = reconcile_binding.clone();
    wrong_holder_binding.holder.push_str("-wrong");
    let wrong_holder = VerifiedEffectReconciliation::mint_trusted(
        grant.clone(),
        wrong_holder_binding,
        reconcile_evidence.clone(),
        reconcile_result.clone(),
    )?;
    require(
        matches!(
            store.reconcile_effect(&wrong_holder).await,
            Err(StorageError::ReconciliationConflict)
        ),
        "reconciliation accepted a different original holder",
    )?;
    let mut wrong_generation_binding = reconcile_binding.clone();
    wrong_generation_binding.generation += 1;
    let wrong_generation = VerifiedEffectReconciliation::mint_trusted(
        grant.clone(),
        wrong_generation_binding,
        reconcile_evidence.clone(),
        reconcile_result.clone(),
    )?;
    require(
        matches!(
            store.reconcile_effect(&wrong_generation).await,
            Err(StorageError::ReconciliationConflict)
        ),
        "reconciliation accepted a different original generation",
    )?;
    let mut wrong_scope_binding = reconcile_binding.clone();
    wrong_scope_binding.scope.push_str("-wrong");
    let wrong_scope = VerifiedEffectReconciliation::mint_trusted(
        grant.clone(),
        wrong_scope_binding,
        reconcile_evidence.clone(),
        reconcile_result.clone(),
    )?;
    require(
        matches!(
            store.reconcile_effect(&wrong_scope).await,
            Err(StorageError::ReconciliationConflict)
        ),
        "reconciliation accepted a different effect scope",
    )?;
    let mut wrong_revision_binding = reconcile_binding.clone();
    wrong_revision_binding.tool_revision.push_str("-wrong");
    let wrong_revision = VerifiedEffectReconciliation::mint_trusted(
        grant.clone(),
        wrong_revision_binding,
        reconcile_evidence.clone(),
        reconcile_result.clone(),
    )?;
    require(
        matches!(
            store.reconcile_effect(&wrong_revision).await,
            Err(StorageError::ReconciliationConflict)
        ),
        "reconciliation accepted a different tool revision",
    )?;
    let mut wrong_grant_revision_binding = reconcile_binding.clone();
    wrong_grant_revision_binding.grant_revision += 1;
    let wrong_grant_revision = VerifiedEffectReconciliation::mint_trusted(
        grant.clone(),
        wrong_grant_revision_binding,
        reconcile_evidence.clone(),
        reconcile_result.clone(),
    )?;
    require(
        matches!(
            store.reconcile_effect(&wrong_grant_revision).await,
            Err(StorageError::ReconciliationConflict)
        ),
        "reconciliation accepted a different original grant revision",
    )?;
    let mut stale_ledger_binding = reconcile_binding.clone();
    stale_ledger_binding.ledger_revision += 1;
    let stale_ledger = VerifiedEffectReconciliation::mint_trusted(
        grant.clone(),
        stale_ledger_binding,
        reconcile_evidence.clone(),
        reconcile_result.clone(),
    )?;
    require(
        matches!(
            store.reconcile_effect(&stale_ledger).await,
            Err(StorageError::ReconciliationConflict)
        ),
        "reconciliation accepted a stale ledger revision",
    )?;
    let blocked_generation = store
        .claim_lease(&grant, &reconcile_attempt, 2, OTHER_HOLDER, lease_ttl)
        .await;
    require(
        matches!(
            blocked_generation,
            Err(StorageError::NeedsReconcileHold | StorageError::LeaseHeld)
        ),
        "unknown effect did not block generation advance before reconciliation",
    )?;
    let unpersisted_evidence = VerifiedEffectReconciliation::mint_trusted(
        grant.clone(),
        reconcile_binding.clone(),
        EffectReconciliationEvidence {
            evidence_id: format!("evidence/{namespace}/not-persisted"),
            digest: "5ef4f7d70e6208eeff711cc82b9064bf8b7a26e0c8ebf71fae056b79000a1b58".into(),
            provenance: "storage-conformance:unpersisted-fixture".into(),
        },
        reconcile_result.clone(),
    )?;
    require(
        matches!(
            store.reconcile_effect(&unpersisted_evidence).await,
            Err(StorageError::ReconciliationEvidenceMissing | StorageError::ReconciliationConflict)
        ),
        "reconciliation promoted an effect without persisted evidence",
    )?;
    let Some(still_unknown) = store
        .read_effect(&grant, &reconcile_binding.effect_id)
        .await?
    else {
        return Err(ConformanceError::Assertion(
            "missing evidence removed the unresolved effect",
        ));
    };
    require(
        still_unknown.state == EffectState::NeedsReconcile,
        "missing evidence changed the unresolved effect state",
    )?;
    let applied = store.reconcile_effect(&verified_reconciliation).await?;
    let committed = match applied {
        EffectReconciliationOutcome::Applied(record) => record,
        EffectReconciliationOutcome::AlreadyApplied(_) => {
            return Err(ConformanceError::Assertion(
                "first reconciliation was treated as a duplicate",
            ));
        }
    };
    require(
        committed.binding == reconcile_binding
            && committed.evidence == reconcile_evidence
            && committed.result == reconcile_result
            && committed.committed_revision > reconcile_binding.ledger_revision,
        "reconciliation did not atomically bind evidence, result, and ledger revision",
    )?;
    require(
        matches!(
            store.reconcile_effect(&verified_reconciliation).await?,
            EffectReconciliationOutcome::AlreadyApplied(record) if record == committed
        ),
        "identical reconciliation retry was not idempotent",
    )?;
    let conflicting_result = VerifiedEffectReconciliation::mint_trusted(
        grant.clone(),
        reconcile_binding.clone(),
        reconcile_evidence.clone(),
        EffectReconciliationResult::Receipt {
            value: json!({"receipt":"different-result"}),
        },
    )?;
    require(
        matches!(
            store.reconcile_effect(&conflicting_result).await,
            Err(StorageError::ReconciliationConflict)
        ),
        "same evidence and binding accepted a conflicting result",
    )?;
    let conflicting_evidence = VerifiedEffectReconciliation::mint_trusted(
        grant.clone(),
        reconcile_binding.clone(),
        EffectReconciliationEvidence {
            digest: "different-proof-digest".into(),
            ..reconcile_evidence.clone()
        },
        reconcile_result.clone(),
    )?;
    require(
        matches!(
            store.reconcile_effect(&conflicting_evidence).await,
            Err(StorageError::ReconciliationConflict)
        ),
        "same evidence identity accepted a changed proof digest",
    )?;
    let Some(reconciled_effect) = store
        .read_effect(&grant, &reconcile_binding.effect_id)
        .await?
    else {
        return Err(ConformanceError::Assertion(
            "reconciled effect disappeared from the ledger",
        ));
    };
    let exact_receipt = json!({"receipt":"reconciled-exact-result"});
    require(
        reconciled_effect.state == EffectState::Receipt
            && reconciled_effect.receipt == Some(exact_receipt.clone()),
        "reconciliation did not preserve the exact proven receipt",
    )?;
    store
        .claim_lease(&grant, &reconcile_attempt, 2, OTHER_HOLDER, lease_ttl)
        .await?;
    store
        .bind_approval(
            &grant,
            &reconcile_attempt,
            2,
            OTHER_HOLDER,
            SCOPE,
            REVISION,
            &reconcile_trace.canonical.args_digest,
        )
        .await?;
    let replayed_reconciliation = store
        .claim_traced_effect(
            &grant,
            OTHER_HOLDER,
            SCOPE,
            REVISION,
            &reconcile_attempt,
            2,
            "conformance_tool",
            &reconcile_trace,
        )
        .await?;
    require(
        matches!(
            replayed_reconciliation,
            TracedClaim::KnownReceipt(binding)
                if binding.claim.state == EffectState::Receipt
                    && binding.claim.receipt == Some(exact_receipt)
        ),
        "replacement generation did not replay the exact receipt",
    )?;

    let negative_admission = store
        .admit(
            &grant,
            &RequestId::new(format!("reconcile-negative-request/{namespace}")),
            &json!({"kind":"reconcile-negative","namespace":namespace}),
            Some(&selected),
        )
        .await?;
    let negative_attempt = negative_admission.attempt_id;
    let negative_args = json!({"action":"proven-absent","namespace":namespace});
    let (negative_trace, negative_binding) = start_unknown_effect(
        store,
        &grant,
        UnknownEffectFixture {
            attempt_id: &negative_attempt,
            holder: HOLDER,
            scope: SCOPE,
            revision: REVISION,
            tool_name: "conformance_tool",
            call_id: "negative-call",
            args: &negative_args,
            lease_ttl,
        },
    )
    .await?;
    let negative_evidence = EffectReconciliationEvidence {
        evidence_id: format!("evidence/{namespace}/proven-not-started"),
        digest: "27f557c509a6b490ba97d8c959b924f1660b97e95bb4f6cd027bdb14b3042e6a".into(),
        provenance: "storage-conformance:trusted-verifier-fixture".into(),
    };
    let native_error = json!({
        "code":"authoritative_absence",
        "request_id":format!("negative-call/{namespace}"),
        "message":"external record does not exist"
    });
    let negative_result = EffectReconciliationResult::ProvenNotStarted {
        value: native_error.clone(),
    };
    let verified_negative = VerifiedEffectReconciliation::mint_trusted(
        grant.clone(),
        negative_binding.clone(),
        negative_evidence,
        negative_result.clone(),
    )?;
    store
        .persist_verified_effect_reconciliation_evidence(&verified_negative)
        .await?;
    store
        .release_lease(&grant, &negative_attempt, 1, HOLDER)
        .await?;
    let negative_commit = store.reconcile_effect(&verified_negative).await?;
    require(
        matches!(
            negative_commit,
            EffectReconciliationOutcome::Applied(record) if record.result == negative_result
        ),
        "proven no-start was not committed as a typed negative",
    )?;
    let Some(negative_effect) = store
        .read_effect(&grant, &negative_binding.effect_id)
        .await?
    else {
        return Err(ConformanceError::Assertion(
            "proven-not-started effect disappeared from the ledger",
        ));
    };
    require(
        negative_effect.state == EffectState::Receipt
            && negative_effect.receipt == Some(negative_result.receipt_value()),
        "proven no-start did not persist as the exact typed negative receipt",
    )?;
    store
        .claim_lease(&grant, &negative_attempt, 2, OTHER_HOLDER, lease_ttl)
        .await?;
    store
        .bind_approval(
            &grant,
            &negative_attempt,
            2,
            OTHER_HOLDER,
            SCOPE,
            REVISION,
            &negative_trace.canonical.args_digest,
        )
        .await?;
    let negative_replay = store
        .claim_traced_effect(
            &grant,
            OTHER_HOLDER,
            SCOPE,
            REVISION,
            &negative_attempt,
            2,
            "conformance_tool",
            &negative_trace,
        )
        .await?;
    let negative_launches = AtomicUsize::new(0);
    let negative_launch = match negative_replay {
        TracedClaim::KnownReceipt(binding) => {
            require(
                binding.claim.state == EffectState::Receipt,
                "proven no-start did not preserve the known-receipt replay path",
            )?;
            let Some(receipt) = binding.claim.receipt.as_ref() else {
                return Err(ConformanceError::Assertion(
                    "proven no-start receipt was missing from the replay binding",
                ));
            };
            require(
                receipt == &native_error,
                "proven no-start replay did not preserve the exact native negative result",
            )?;
            store
                .with_effect_launch(
                    &grant,
                    OTHER_HOLDER,
                    SCOPE,
                    REVISION,
                    &binding.claim,
                    lease_ttl,
                    || {
                        negative_launches.fetch_add(1, Ordering::SeqCst);
                        async { Ok(json!({"receipt":"must-not-launch"})) }
                    },
                )
                .await?
        }
        _ => {
            return Err(ConformanceError::Assertion(
                "proven no-start did not replay as a known receipt",
            ));
        }
    };
    require(
        matches!(negative_launch, EffectLaunch::Blocked(_))
            && negative_launches.load(Ordering::SeqCst) == 0,
        "proven no-start was relaunched in the replacement generation",
    )?;

    let unstarted_admission = store
        .admit(
            &grant,
            &RequestId::new(format!("reconcile-unstarted-request/{namespace}")),
            &json!({"kind":"reconcile-unstarted","namespace":namespace}),
            Some(&selected),
        )
        .await?;
    let unstarted_attempt = unstarted_admission.attempt_id;
    store
        .claim_lease(&grant, &unstarted_attempt, 1, HOLDER, lease_ttl)
        .await?;
    let unstarted_args = json!({"action":"not-yet-started","namespace":namespace});
    let unstarted_trace =
        trace_effect_identity(&unstarted_attempt, "unstarted-call", &unstarted_args);
    store
        .bind_approval(
            &grant,
            &unstarted_attempt,
            1,
            HOLDER,
            SCOPE,
            REVISION,
            &unstarted_trace.canonical.args_digest,
        )
        .await?;
    let unstarted_claim = store
        .claim_traced_effect(
            &grant,
            HOLDER,
            SCOPE,
            REVISION,
            &unstarted_attempt,
            1,
            "conformance_tool",
            &unstarted_trace,
        )
        .await?;
    let unstarted_binding = match unstarted_claim {
        TracedClaim::Fresh(binding) => binding,
        _ => {
            return Err(ConformanceError::Assertion(
                "unstarted reconciliation fixture was not a fresh claim",
            ));
        }
    };
    let Some(unstarted_candidate) = store
        .read_effect_reconciliation_binding(
            &grant,
            &unstarted_attempt,
            &unstarted_binding.claim.effect_id,
        )
        .await?
    else {
        return Err(ConformanceError::Assertion(
            "unstarted claim has no reconciliation candidate",
        ));
    };
    require(
        !unstarted_candidate.durable_started && unstarted_candidate.state == EffectState::Claimed,
        "fresh claim incorrectly appeared durably started",
    )?;
    require(
        matches!(
            VerifiedEffectReconciliation::mint_trusted(
                grant.clone(),
                unstarted_candidate,
                reconcile_evidence,
                reconcile_result,
            ),
            Err(StorageError::InvalidReconciliationCandidate)
        ),
        "reconciliation accepted an unstarted effect",
    )?;
    store
        .release_lease(&grant, &unstarted_attempt, 1, HOLDER)
        .await?;

    let artifact_id = format!("artifact/{namespace}");
    let object_key = format!("objects/{namespace}");
    store
        .put_artifact(&grant, &artifact_id, &admitted.attempt_id, &object_key)
        .await?;
    require(
        store.read_artifact(&grant, &artifact_id).await? == Some(object_key.clone()),
        "artifact association was not readable in its scope",
    )?;
    require(
        is_hidden_optional(store.read_artifact(&foreign, &artifact_id).await),
        "a valid foreign tenant read the owner artifact",
    )?;
    require(
        is_hidden_optional(store.read_artifact(&other_workspace, &artifact_id).await),
        "a valid same-tenant workspace peer read the owner artifact",
    )?;
    require(
        is_hidden_optional(store.read_artifact_reference(&foreign, &artifact_id).await),
        "a valid foreign tenant read the owner artifact reference",
    )?;
    require(
        is_hidden_optional(
            store
                .read_artifact_reference(&other_workspace, &artifact_id)
                .await,
        ),
        "a valid same-tenant workspace peer read the owner artifact reference",
    )?;

    let event_cursor = store
        .append_event(
            &grant,
            &admitted.attempt_id,
            &json!({"event":"conformance","namespace":namespace}),
        )
        .await?;
    let page = store.read_event_page(&grant, event_cursor - 1, 1).await?;
    require(
        page.len() == 1
            && page[0].cursor == event_cursor
            && page[0].attempt_id == admitted.attempt_id.as_str()
            && page[0].body["namespace"] == namespace,
        "event page did not preserve cursor, scope, and body",
    )?;
    let foreign_events = store.read_event_page(&foreign, event_cursor - 1, 1).await;
    require(
        is_hidden_page(foreign_events),
        "a valid foreign tenant read the owner event page",
    )?;
    require(
        is_hidden_page(
            store
                .read_event_page(&other_workspace, event_cursor - 1, 1)
                .await,
        ),
        "a valid same-tenant workspace peer read the owner event page",
    )?;
    require(
        is_hidden_page(store.read_events(&foreign, event_cursor - 1).await),
        "a valid foreign tenant read the owner event log",
    )?;
    require(
        is_hidden_page(store.read_events(&other_workspace, event_cursor - 1).await),
        "a valid same-tenant workspace peer read the owner event log",
    )?;

    let stop_request = RequestId::new(format!("stop-request/{namespace}"));
    let stop_selection = selection(&grant);
    let stop_admission = store
        .admit(
            &grant,
            &stop_request,
            &json!({"kind":"unknown-effect-stop","namespace":namespace}),
            Some(&stop_selection),
        )
        .await?;
    let stop_attempt = stop_admission.attempt_id;
    let stop_args = json!({"action":"uncertain","namespace":namespace});
    let (_stop_trace, _stop_binding) = start_unknown_effect(
        store,
        &grant,
        UnknownEffectFixture {
            attempt_id: &stop_attempt,
            holder: HOLDER,
            scope: SCOPE,
            revision: REVISION,
            tool_name: "conformance_tool",
            call_id: "stop-call",
            args: &stop_args,
            lease_ttl,
        },
    )
    .await?;
    store.request_cancel(&grant, &stop_attempt, 1).await?;
    let stopped = store
        .commit_stop(
            &grant,
            &StopReceipt {
                attempt_id: stop_attempt.clone(),
                generation: 1,
                step: 0,
                owned_pids: Vec::new(),
                observed_stop: true,
                unknown_effects: Vec::new(),
            },
        )
        .await?;
    store
        .release_lease(&grant, &stop_attempt, 1, HOLDER)
        .await?;
    require(
        stopped == nazz_core::AttemptStatus::NeedsReconcile,
        "Stop settled an unknown launched effect as clean cancellation",
    )?;
    let held = store
        .claim_lease(&grant, &stop_attempt, 2, OTHER_HOLDER, lease_ttl)
        .await;
    require(
        matches!(
            held,
            Err(StorageError::LeaseHeld | StorageError::NeedsReconcileHold)
        ),
        "unknown effect did not block generation advance after Stop",
    )?;
    let Some(stopped_attempt) = store.read_attempt(&grant, &stop_attempt).await? else {
        return Err(ConformanceError::Assertion(
            "unknown effect hold removed its stopped attempt",
        ));
    };
    require(
        stopped_attempt.generation == 1
            && stopped_attempt.status == nazz_core::AttemptStatus::NeedsReconcile,
        "unknown effect hold advanced the stopped attempt",
    )?;
    let Some(stopped_binding) = store
        .read_effect_reconciliation_binding(&grant, &stop_attempt, &_stop_binding.effect_id)
        .await?
    else {
        return Err(ConformanceError::Assertion(
            "stopped unknown effect lost its reconciliation binding",
        ));
    };
    let stopped_evidence = EffectReconciliationEvidence {
        evidence_id: format!("evidence/{namespace}/stop-history"),
        digest: "46a8fc2d59965400362b346f8ee64e8eef7a591ea35ab0b716a9dcdd1e9713b2".into(),
        provenance: "storage-conformance:stopped-history".into(),
    };
    let stopped_result = EffectReconciliationResult::Receipt {
        value: json!({"receipt":"history-only-after-stop"}),
    };
    let stopped_reconciliation = VerifiedEffectReconciliation::mint_trusted(
        grant.clone(),
        stopped_binding.clone(),
        stopped_evidence,
        stopped_result,
    )?;
    store
        .persist_verified_effect_reconciliation_evidence(&stopped_reconciliation)
        .await?;
    require(
        matches!(
            store.reconcile_effect(&stopped_reconciliation).await?,
            EffectReconciliationOutcome::Applied(_)
        ),
        "Stop-blocked effect history was not reconciled",
    )?;
    let Some(stopped_after_reconcile) = store.read_attempt(&grant, &stop_attempt).await? else {
        return Err(ConformanceError::Assertion(
            "history reconciliation removed the stopped attempt",
        ));
    };
    require(
        stopped_after_reconcile.generation == 1
            && stopped_after_reconcile.status == nazz_core::AttemptStatus::NeedsReconcile,
        "history reconciliation reopened or advanced a stopped attempt",
    )?;
    require(
        store
            .claim_lease(&grant, &stop_attempt, 2, OTHER_HOLDER, lease_ttl)
            .await
            .is_err(),
        "history reconciliation reopened generation advance after Stop",
    )?;

    let revoked_reconciler = ActorGrant {
        tenant_id: grant.tenant_id.clone(),
        workspace_id: grant.workspace_id.clone(),
        actor_id: ActorId::new(format!("revoked-reconciler/{namespace}")),
        revision: 1,
        revoked: false,
    };
    store.publish_grant(&revoked_reconciler).await?;
    let revoked_reconcile_admission = store
        .admit(
            &grant,
            &RequestId::new(format!("revoked-reconcile-request/{namespace}")),
            &json!({"kind":"revoked-reconciler","namespace":namespace}),
            Some(&selected),
        )
        .await?;
    let revoked_reconcile_attempt = revoked_reconcile_admission.attempt_id;
    let (_, revoked_binding) = start_unknown_effect(
        store,
        &grant,
        UnknownEffectFixture {
            attempt_id: &revoked_reconcile_attempt,
            holder: HOLDER,
            scope: SCOPE,
            revision: REVISION,
            tool_name: "conformance_tool",
            call_id: "revoked-reconciler-call",
            args: &json!({"action":"verify-revoked-principal","namespace":namespace}),
            lease_ttl,
        },
    )
    .await?;
    let revoked_evidence = EffectReconciliationEvidence {
        evidence_id: format!("evidence/{namespace}/revoked-principal"),
        digest: "80672c3263a5be6a89c818744769b69285cc4821227cb20be9d05d204f09ed2f".into(),
        provenance: "storage-conformance:revoked-principal".into(),
    };
    let revoked_reconciliation = VerifiedEffectReconciliation::mint_trusted(
        revoked_reconciler.clone(),
        revoked_binding.clone(),
        revoked_evidence,
        EffectReconciliationResult::Receipt {
            value: json!({"receipt":"must-not-promote-after-revoke"}),
        },
    )?;
    store
        .persist_verified_effect_reconciliation_evidence(&revoked_reconciliation)
        .await?;
    store
        .release_lease(&grant, &revoked_reconcile_attempt, 1, HOLDER)
        .await?;
    store.revoke_grant(&revoked_reconciler).await?;
    require(
        matches!(
            store.reconcile_effect(&revoked_reconciliation).await,
            Err(StorageError::Scope(ScopeError::Denied))
        ),
        "reconciliation committed after its current principal was revoked",
    )?;
    let Some(revoked_effect) = store
        .read_effect(&grant, &revoked_binding.effect_id)
        .await?
    else {
        return Err(ConformanceError::Assertion(
            "revoked-principal reconciliation removed its effect",
        ));
    };
    require(
        revoked_effect.state == EffectState::NeedsReconcile,
        "revoked-principal reconciliation promoted the unresolved effect",
    )?;

    store.revoke_grant(&grant).await?;
    let revoked_read = store.read_attempt(&grant, &admitted.attempt_id).await;
    require(
        matches!(revoked_read, Err(StorageError::Scope(ScopeError::Denied))),
        "revoked grant continued to authorize reads",
    )?;

    run_journal_conformance(journal, namespace).await?;
    Ok(())
}

/// Verify journal claim/release/receipt behavior separately from durable store
/// authority. A journal pass must never be treated as permission to execute.
pub async fn run_journal_conformance<J: EffectJournal>(
    journal: &J,
    namespace: &str,
) -> Result<(), ConformanceError> {
    let claim = EffectClaim {
        effect_id: EffectId::new(format!("journal-{namespace}")),
        attempt_id: AttemptId::new(format!("journal-attempt/{namespace}")),
        generation: 1,
        tool_name: "conformance_tool".into(),
        args_digest: format!("journal-digest/{namespace}"),
        state: EffectState::Claimed,
        receipt: None,
    };
    require(
        journal.claim_exclusive(&claim).await? == ClaimOutcome::Fresh,
        "first journal claim was not fresh",
    )?;
    require(
        matches!(
            journal.claim_exclusive(&claim).await?,
            ClaimOutcome::InDoubt(_)
        ),
        "duplicate unstarted journal claim was not held in doubt",
    )?;
    journal.release_unstarted(&claim.effect_id).await?;
    require(
        journal.get(&claim.effect_id).await?.is_none(),
        "released unstarted journal claim remained present",
    )?;
    require(
        journal.claim_exclusive(&claim).await? == ClaimOutcome::Fresh,
        "released journal claim could not be reclaimed",
    )?;
    let mut receipt = claim.clone();
    receipt.state = EffectState::Receipt;
    receipt.receipt = Some(json!({"receipt":"durable"}));
    journal.replace(&receipt).await?;
    require(
        journal.get(&claim.effect_id).await? == Some(receipt.clone()),
        "journal receipt did not persist",
    )?;
    journal.seed_receipt(&receipt).await?;
    require(
        journal.get(&claim.effect_id).await? == Some(receipt),
        "seeding an existing journal receipt changed it",
    )?;
    Ok(())
}
