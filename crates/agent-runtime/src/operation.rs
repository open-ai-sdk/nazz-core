//! Durable host-operation boundary for business pipelines that already own
//! their stage ordering and validation.
//!
//! Each call is one externally visible operation (for example one provider
//! request). The host retains business orchestration; this driver owns the
//! durable effect claim, fenced launch, receipt settlement, and checkpoint.

use std::future::Future;
use std::time::Duration;

use agent_core::{ActorGrant, AttemptId, EffectState, trace_effect_identity};
use agent_storage::{
    CHECKPOINT_FORMAT_VERSION, CheckpointRecord, EffectLaunch, ExecutionStore, LaunchSettlement,
    TracedClaim,
};
use serde_json::{Value, json};

use crate::RuntimeError;

const OPERATION_CHECKPOINT_SCHEMA_VERSION: u64 = 1;

/// Core storage-backed operation driver bound to a live attempt lease.
/// Calls must be awaited serially. Each logical operation key is immutable
/// within an attempt and must identify one real external operation.
pub struct OperationDriver<'a, S> {
    store: &'a S,
    grant: &'a ActorGrant,
    attempt_id: AttemptId,
    generation: u64,
    holder: String,
    next_step: i64,
}

impl<'a, S> OperationDriver<'a, S>
where
    S: ExecutionStore,
{
    /// Resolve the attempt's persisted execution context before issuing any
    /// operation. The adapter verifies grant revisions and the live lease.
    pub async fn new(
        store: &'a S,
        grant: &'a ActorGrant,
        attempt_id: &AttemptId,
        generation: u64,
        holder: impl Into<String>,
    ) -> Result<Self, RuntimeError> {
        let holder = holder.into();
        store
            .resolve_execution_context(grant, attempt_id, generation, &holder)
            .await?;

        let mut next_step = 0_i64;
        for prior_generation in 1..=generation {
            for record in store
                .read_checkpoints(grant, attempt_id, prior_generation, -1)
                .await?
            {
                validate_checkpoint_version(&record)?;
                next_step = next_step.max(record.step.saturating_add(1));
            }
        }

        Ok(Self {
            store,
            grant,
            attempt_id: attempt_id.clone(),
            generation,
            holder,
            next_step,
        })
    }

    /// Execute one real side effect under the core effect authority.
    ///
    /// `operation_key` remains stable across recovery and changes only for a
    /// new logical call, such as a schema-validation retry. Arguments are
    /// persisted as a digest by the adapter. A callback error after launch is
    /// unknown and returns `NeedsReconcile`, so the operation is never replayed
    /// blindly.
    #[expect(
        clippy::too_many_arguments,
        reason = "Keep execution authority and tool inputs explicit."
    )]
    pub async fn execute<F, Fut>(
        &mut self,
        operation_key: &str,
        tool_name: &str,
        scope: &str,
        tool_revision: &str,
        args: &Value,
        deadline: Duration,
        launch: F,
    ) -> Result<Value, RuntimeError>
    where
        F: FnOnce() -> Fut + Send,
        Fut: Future<Output = Result<Value, ()>> + Send,
    {
        self.store
            .resolve_execution_context(self.grant, &self.attempt_id, self.generation, &self.holder)
            .await?;
        if operation_key.trim().is_empty()
            || tool_name.trim().is_empty()
            || scope.trim().is_empty()
            || tool_revision.trim().is_empty()
        {
            return Err(RuntimeError::StaleAuthority);
        }

        let traced = trace_effect_identity(&self.attempt_id, operation_key, args);
        if let Some(receipt) = self
            .checkpoint_receipt(
                operation_key,
                tool_name,
                scope,
                tool_revision,
                &traced.canonical.args_digest,
            )
            .await?
        {
            return Ok(receipt);
        }

        self.store
            .assert_effect_authority(
                self.grant,
                &self.attempt_id,
                self.generation,
                &self.holder,
                scope,
                tool_revision,
                &traced.canonical.args_digest,
            )
            .await?;

        let binding = match self
            .store
            .claim_traced_effect(
                self.grant,
                &self.holder,
                scope,
                tool_revision,
                &self.attempt_id,
                self.generation,
                tool_name,
                &traced,
            )
            .await?
        {
            TracedClaim::Fresh(binding) | TracedClaim::KnownReceipt(binding) => binding,
            TracedClaim::Unknown(_) | TracedClaim::Unresolved => {
                return Err(RuntimeError::NeedsReconcile);
            }
        };
        if binding.scope != scope
            || binding.tool_revision != tool_revision
            || !traced.contains_digest(&binding.claim.args_digest)
        {
            return Err(RuntimeError::StaleAuthority);
        }

        let receipt = match binding.claim.state {
            EffectState::Receipt => binding
                .claim
                .receipt
                .clone()
                .ok_or(RuntimeError::NeedsReconcile)?,
            EffectState::NeedsReconcile => return Err(RuntimeError::NeedsReconcile),
            EffectState::Claimed => match self
                .store
                .with_effect_launch(
                    self.grant,
                    &self.holder,
                    scope,
                    tool_revision,
                    &binding.claim,
                    deadline,
                    launch,
                )
                .await?
            {
                EffectLaunch::Ready(receipt) => {
                    let mut settled = binding.claim;
                    settled.state = EffectState::Receipt;
                    settled.receipt = Some(receipt.clone());
                    if self
                        .store
                        .settle_launched_effect(
                            self.grant,
                            &self.holder,
                            scope,
                            tool_revision,
                            &settled,
                        )
                        .await?
                        != LaunchSettlement::Receipt
                    {
                        return Err(RuntimeError::NeedsReconcile);
                    }
                    receipt
                }
                EffectLaunch::Blocked(error) => return Err(error.into()),
                EffectLaunch::Attempted => return Err(RuntimeError::NeedsReconcile),
            },
        };

        self.write_checkpoint(
            operation_key,
            tool_name,
            scope,
            tool_revision,
            &traced.canonical.args_digest,
            &receipt,
        )
        .await?;
        Ok(receipt)
    }

    async fn checkpoint_receipt(
        &self,
        operation_key: &str,
        tool_name: &str,
        scope: &str,
        tool_revision: &str,
        args_digest: &str,
    ) -> Result<Option<Value>, RuntimeError> {
        for generation in 1..=self.generation {
            for record in self
                .store
                .read_checkpoints(self.grant, &self.attempt_id, generation, -1)
                .await?
            {
                validate_checkpoint_version(&record)?;
                if record.payload.get("operation_key").and_then(Value::as_str)
                    != Some(operation_key)
                {
                    continue;
                }
                if record.payload.get("kind").and_then(Value::as_str) != Some("durable_operation")
                    || record.payload.get("schema_version").and_then(Value::as_u64)
                        != Some(OPERATION_CHECKPOINT_SCHEMA_VERSION)
                    || record.payload.get("tool_name").and_then(Value::as_str) != Some(tool_name)
                    || record.payload.get("scope").and_then(Value::as_str) != Some(scope)
                    || record.payload.get("tool_revision").and_then(Value::as_str)
                        != Some(tool_revision)
                    || record.payload.get("args_digest").and_then(Value::as_str)
                        != Some(args_digest)
                {
                    return Err(RuntimeError::StaleAuthority);
                }
                return record
                    .payload
                    .get("receipt")
                    .cloned()
                    .map(Some)
                    .ok_or(RuntimeError::NeedsReconcile);
            }
        }
        Ok(None)
    }

    async fn write_checkpoint(
        &mut self,
        operation_key: &str,
        tool_name: &str,
        scope: &str,
        tool_revision: &str,
        args_digest: &str,
        receipt: &Value,
    ) -> Result<(), RuntimeError> {
        let step = self.next_step;
        self.next_step = self
            .next_step
            .checked_add(1)
            .ok_or(RuntimeError::StaleAuthority)?;
        self.store
            .put_checkpoint(
                self.grant,
                &self.attempt_id,
                self.generation,
                &self.holder,
                step,
                CHECKPOINT_FORMAT_VERSION,
                &json!({
                    "kind": "durable_operation",
                    "schema_version": OPERATION_CHECKPOINT_SCHEMA_VERSION,
                    "operation_key": operation_key,
                    "tool_name": tool_name,
                    "scope": scope,
                    "tool_revision": tool_revision,
                    "args_digest": args_digest,
                    "receipt": receipt,
                }),
            )
            .await?;
        Ok(())
    }
}

fn validate_checkpoint_version(record: &CheckpointRecord) -> Result<(), RuntimeError> {
    if record.format_version != CHECKPOINT_FORMAT_VERSION {
        return Err(RuntimeError::Format(format!(
            "operation checkpoint format {} is unsupported; expected {}",
            record.format_version, CHECKPOINT_FORMAT_VERSION
        )));
    }
    Ok(())
}
