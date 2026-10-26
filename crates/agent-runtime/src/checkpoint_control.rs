//! Opt-in trusted rollout policy. Negotiation can remove, never add, the
//! compiled Rig capability. This is not a scheduler or a launch permission.
use std::time::Duration;

use agent_core::{ActorGrant, AttemptId, HARNESS_FORMAT};
use agent_storage::{
    CHECKPOINT_FORMAT_VERSION, CheckpointRecord, ExecutionStore, StorageError as StoreError,
};
use thiserror::Error;

use crate::{PINNED_RIG, PINNED_RUN_FORMAT, RigSession, RuntimeError, ToolRevision};

/// Trusted controller configuration, never derived from admission/tool input.
/// False drains this worker for existing pinned checkpoints; it does not
/// advertise a hypothetical newer serializer or change the write format.
#[derive(Debug, Clone, Copy)]
pub struct CheckpointPolicy {
    pub accept_pinned: bool,
}

#[derive(Debug, Error)]
pub enum CheckpointControlError {
    #[error("checkpoint capability excluded by rollout policy")]
    Excluded,
    #[error("checkpoint metadata is unsupported or malformed")]
    Unsupported,
    #[error("checkpoint changed after capability negotiation")]
    Drift,
    #[error("attempt has no checkpoint to negotiate")]
    Missing,
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Runtime(#[from] RuntimeError),
}

impl CheckpointPolicy {
    /// Inspect envelope/format scalars only, never deserialize an AgentRun.
    /// The tool revision is the driver's trusted approved revision. There is
    /// no caller-provided format/version allowlist that can expand support.
    pub fn check(
        &self,
        record: &CheckpointRecord,
        tool: &ToolRevision,
    ) -> Result<(), CheckpointControlError> {
        if !self.accept_pinned {
            return Err(CheckpointControlError::Excluded);
        }
        let value = &record.payload;
        if record.format_version != CHECKPOINT_FORMAT_VERSION
            || value["harness_format"].as_u64() != Some(u64::from(HARNESS_FORMAT))
            || value["rig_version"].as_str() != Some(PINNED_RIG)
            || value["rig_run_format"].as_u64() != Some(u64::from(PINNED_RUN_FORMAT))
            || value["run"]["format"].as_u64() != Some(u64::from(PINNED_RUN_FORMAT))
            || value["tool_revision"].as_str() != Some(tool.revision.as_str())
        {
            return Err(CheckpointControlError::Unsupported);
        }
        Ok(())
    }

    /// Refuse before lease/poll mutation. Reads use the persisted actor scope.
    /// A successful claim is NOT atomic with the earlier checkpoint read:
    /// callers must use restore_owned before driving the run. Store remains
    /// the authority for live lease exclusion and unknown-effect holds.
    #[expect(
        clippy::too_many_arguments,
        reason = "Keep execution authority and checkpoint inputs explicit."
    )]
    pub async fn claim(
        &self,
        store: &impl ExecutionStore,
        grant: &ActorGrant,
        attempt: &AttemptId,
        generation: u64,
        holder: &str,
        ttl: Duration,
        tool: &ToolRevision,
    ) -> Result<CheckpointRecord, CheckpointControlError> {
        let row = store
            .read_attempt(grant, attempt)
            .await?
            .ok_or(CheckpointControlError::Missing)?;
        let records = store
            .read_checkpoints(grant, attempt, row.generation, -1)
            .await?;
        let latest = records.last().ok_or(CheckpointControlError::Missing)?;
        for record in &records {
            self.check(record, tool)?;
        }
        let binding = store
            .read_attempt_context(grant, attempt)
            .await?
            .ok_or(StoreError::ContextUnbound)?;
        if binding.capsule.executor_actor_id != grant.actor_id {
            return Err(RuntimeError::StaleAuthority.into());
        }
        store
            .claim_lease(grant, attempt, generation, holder, ttl)
            .await?;
        Ok(latest.clone())
    }

    /// Revalidate the actual persisted boundary after the lease transition.
    /// Renewal establishes current ownership; exact row comparison catches
    /// pre-claim drift. A hold here may retain the acquired lease, but cannot
    /// deserialize or execute. Normal effect/publication fences still apply.
    #[expect(
        clippy::too_many_arguments,
        reason = "Keep execution authority and checkpoint inputs explicit."
    )]
    pub async fn restore_owned(
        &self,
        store: &impl ExecutionStore,
        grant: &ActorGrant,
        negotiated: &CheckpointRecord,
        generation: u64,
        holder: &str,
        ttl: Duration,
        tool: ToolRevision,
    ) -> Result<RigSession, CheckpointControlError> {
        self.check(negotiated, &tool)?;
        store
            .claim_lease(grant, &negotiated.attempt_id, generation, holder, ttl)
            .await?;
        let context = store
            .resolve_execution_context(grant, &negotiated.attempt_id, generation, holder)
            .await?;
        let current = store
            .read_checkpoint(
                grant,
                &negotiated.attempt_id,
                negotiated.generation,
                negotiated.step,
            )
            .await?
            .ok_or(CheckpointControlError::Drift)?;
        if current != *negotiated {
            return Err(CheckpointControlError::Drift);
        }
        // Also reject a newer source boundary committed between negotiation
        // and claim, rather than restoring the now-outdated step.
        let records = store
            .read_checkpoints(grant, &negotiated.attempt_id, negotiated.generation, -1)
            .await?;
        if records.last() != Some(&current) {
            return Err(CheckpointControlError::Drift);
        }
        self.check(&current, &tool)?;
        Ok(RigSession::restore(&current, &context, tool)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fixture() -> (CheckpointRecord, ToolRevision) {
        let tool = ToolRevision {
            revision: "approved-1".into(),
            name: "append".into(),
            description: "local file append".into(),
        };
        let attempt = AttemptId::new("policy-test");
        let session = RigSession::start_unbound("local", attempt.clone(), 1, tool.clone()).unwrap();
        (
            CheckpointRecord {
                attempt_id: attempt,
                generation: 1,
                step: 0,
                format_version: CHECKPOINT_FORMAT_VERSION,
                payload: serde_json::to_value(session.checkpoint().unwrap()).unwrap(),
            },
            tool,
        )
    }

    #[test]
    fn exact_compiled_tuple_is_supported() {
        let (row, tool) = fixture();
        CheckpointPolicy {
            accept_pinned: true,
        }
        .check(&row, &tool)
        .unwrap();
    }

    #[test]
    fn unknown_versions_and_unapproved_tool_are_refused() {
        let (row, tool) = fixture();
        for (field, value) in [
            ("rig_version", json!("unavailable-rig")),
            ("rig_run_format", json!(99)),
            ("harness_format", json!(99)),
            ("tool_revision", json!("unapproved")),
        ] {
            let mut changed = row.clone();
            changed.payload[field] = value;
            assert!(matches!(
                CheckpointPolicy {
                    accept_pinned: true
                }
                .check(&changed, &tool),
                Err(CheckpointControlError::Unsupported)
            ));
        }
        let mut changed = row.clone();
        changed.payload["run"]["format"] = json!(99);
        assert!(
            CheckpointPolicy {
                accept_pinned: true
            }
            .check(&changed, &tool)
            .is_err()
        );
        changed = row;
        changed.format_version = 99;
        assert!(
            CheckpointPolicy {
                accept_pinned: true
            }
            .check(&changed, &tool)
            .is_err()
        );
    }

    #[test]
    fn missing_or_malformed_metadata_never_reaches_deserialization() {
        let (row, tool) = fixture();
        for field in [
            "rig_version",
            "rig_run_format",
            "harness_format",
            "tool_revision",
            "run",
        ] {
            let mut changed = row.clone();
            changed.payload.as_object_mut().unwrap().remove(field);
            assert!(matches!(
                CheckpointPolicy {
                    accept_pinned: true
                }
                .check(&changed, &tool),
                Err(CheckpointControlError::Unsupported)
            ));
        }
    }

    #[test]
    fn negotiated_policy_can_only_narrow_compiled_support() {
        let (mut row, tool) = fixture();
        assert!(matches!(
            CheckpointPolicy {
                accept_pinned: false
            }
            .check(&row, &tool),
            Err(CheckpointControlError::Excluded)
        ));
        row.payload["rig_version"] = json!("not-compiled");
        assert!(matches!(
            CheckpointPolicy {
                accept_pinned: true
            }
            .check(&row, &tool),
            Err(CheckpointControlError::Unsupported)
        ));
    }
}
