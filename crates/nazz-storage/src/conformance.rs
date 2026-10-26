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
    ArtifactStore, ClaimOutcome, EffectJournal, EffectLaunch, EventStore, ExecutionStore,
    StorageError, TracedClaim,
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
    store
        .claim_lease(&grant, &stop_attempt, 1, HOLDER, lease_ttl)
        .await?;
    let stop_args = json!({"action":"uncertain","namespace":namespace});
    let stop_trace = trace_effect_identity(&stop_attempt, "stop-call", &stop_args);
    store
        .bind_approval(
            &grant,
            &stop_attempt,
            1,
            HOLDER,
            SCOPE,
            REVISION,
            &stop_trace.canonical.args_digest,
        )
        .await?;
    let stop_claim = store
        .claim_traced_effect(
            &grant,
            HOLDER,
            SCOPE,
            REVISION,
            &stop_attempt,
            1,
            "conformance_tool",
            &stop_trace,
        )
        .await?;
    let stop_binding = match stop_claim {
        TracedClaim::Fresh(binding) => binding,
        _ => {
            return Err(ConformanceError::Assertion(
                "stop fixture effect was not fresh",
            ));
        }
    };
    let attempted = store
        .with_effect_launch(
            &grant,
            HOLDER,
            SCOPE,
            REVISION,
            &stop_binding.claim,
            lease_ttl,
            || async { Err::<serde_json::Value, ()>(()) },
        )
        .await?;
    require(
        matches!(attempted, EffectLaunch::Attempted),
        "failed launched effect was not held as attempted/unknown",
    )?;
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
