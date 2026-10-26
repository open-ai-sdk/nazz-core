//! Materialized execution input. These records carry no permissions or secrets.
use crate::{ActorGrant, ActorId, AttemptId, TenantId, WorkspaceId, canonical_bytes};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{self, Write};
use thiserror::Error;

macro_rules! scoped_id {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
        pub struct $name(String);
        impl $name {
            pub fn new(value: impl Into<String>) -> Self {
                Self(value.into())
            }
            pub fn generate() -> Self {
                Self(uuid::Uuid::new_v4().to_string())
            }
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
    };
}
scoped_id!(AgentId);
scoped_id!(SessionId);
scoped_id!(TaskId);
scoped_id!(ContextRef);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextBounds {
    pub max_capsule_bytes: usize,
    pub max_items: usize,
    pub max_item_bytes: usize,
    pub max_model_input_bytes: usize,
}
impl Default for ContextBounds {
    fn default() -> Self {
        Self {
            max_capsule_bytes: 64 * 1024,
            max_items: 32,
            max_item_bytes: 16 * 1024,
            max_model_input_bytes: 1024 * 1024,
        }
    }
}
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ContextError {
    #[error("context policy contains an invalid bound or revision")]
    InvalidPolicy,
    #[error("context identity or association is invalid")]
    Identity,
    #[error("context exceeds {0} byte/item budget")]
    Budget(&'static str),
    #[error("context immutable revision conflicts")]
    Conflict,
}
impl ContextBounds {
    pub fn validate(&self) -> Result<(), ContextError> {
        if self.max_capsule_bytes == 0
            || self.max_items == 0
            || self.max_item_bytes == 0
            || self.max_model_input_bytes == 0
            || self.max_items.checked_mul(self.max_item_bytes).is_none()
            || [
                self.max_capsule_bytes,
                self.max_items,
                self.max_item_bytes,
                self.max_model_input_bytes,
            ]
            .iter()
            .any(|n| i64::try_from(*n).is_err())
        {
            return Err(ContextError::InvalidPolicy);
        }
        Ok(())
    }
}
/// Counts the exact compact serde JSON representation without a duplicate buffer.
/// The writer fails at the first over-limit chunk; it never truncates input.
pub fn serialized_input_bytes<T: Serialize>(
    value: &T,
    limit: usize,
) -> Result<usize, ContextError> {
    struct Counter {
        bytes: usize,
        limit: usize,
    }
    impl Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.bytes = self
                .bytes
                .checked_add(bytes.len())
                .filter(|n| *n <= self.limit)
                .ok_or_else(|| io::Error::other("input budget"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut count = Counter { bytes: 0, limit };
    serde_json::to_writer(&mut count, value)
        .map_err(|_| ContextError::Budget("serialized input"))?;
    Ok(count.bytes)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionRecord {
    pub tenant_id: TenantId,
    pub workspace_id: WorkspaceId,
    pub session_id: SessionId,
    pub agent_id: AgentId,
    pub owner_actor_id: ActorId,
    pub revision: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskRecord {
    pub tenant_id: TenantId,
    pub workspace_id: WorkspaceId,
    pub task_id: TaskId,
    pub session_id: SessionId,
    pub agent_id: AgentId,
    pub owner_actor_id: ActorId,
    pub target_actor_id: ActorId,
    pub revision: u64,
    pub expected_output: String,
    pub acceptance_criteria: String,
    pub thread_ref: Option<String>,
    pub report_destination: Option<String>,
    pub parent_task: Option<TaskId>,
    pub hop_count: u32,
    pub max_hops: u32,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextSource {
    Task,
    Project,
    PrivateMemory,
    SharedMemory,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextItem {
    pub kind: ContextSource,
    pub source_ref: String,
    pub source_revision: u64,
    pub owner_agent: Option<AgentId>,
    pub text: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountReference {
    pub account_ref: String,
    pub provider: String,
    pub revision: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextCapsule {
    pub tenant_id: TenantId,
    pub workspace_id: WorkspaceId,
    pub context_ref: ContextRef,
    pub revision: u64,
    pub agent_id: AgentId,
    pub session_id: SessionId,
    pub task_id: TaskId,
    pub admitted_actor_id: ActorId,
    pub executor_actor_id: ActorId,
    pub role_revision: String,
    pub preamble: String,
    pub instruction: String,
    pub expected_output: String,
    pub acceptance_criteria: String,
    pub items: Vec<ContextItem>,
    pub bounds: ContextBounds,
    pub policy_revision: String,
}
impl ContextCapsule {
    pub fn validate(&self) -> Result<(), ContextError> {
        self.bounds.validate()?;
        if self.revision == 0
            || self.revision > i64::MAX as u64
            || self.role_revision.is_empty()
            || self.policy_revision.is_empty()
            || self.instruction.trim().is_empty()
            || self.expected_output.is_empty()
            || self.acceptance_criteria.is_empty()
            || [
                self.tenant_id.as_str(),
                self.workspace_id.as_str(),
                self.context_ref.as_str(),
                self.agent_id.as_str(),
                self.session_id.as_str(),
                self.task_id.as_str(),
                self.admitted_actor_id.as_str(),
                self.executor_actor_id.as_str(),
            ]
            .contains(&"")
        {
            return Err(ContextError::Identity);
        }
        if self.items.len() > self.bounds.max_items {
            return Err(ContextError::Budget("items"));
        }
        for item in &self.items {
            if item.source_ref.is_empty()
                || item.source_revision == 0
                || item.source_revision > i64::MAX as u64
            {
                return Err(ContextError::Identity);
            }
            if item.text.len() > self.bounds.max_item_bytes {
                return Err(ContextError::Budget("item"));
            }
            if item.kind == ContextSource::PrivateMemory
                && item.owner_agent.as_ref() != Some(&self.agent_id)
            {
                return Err(ContextError::Identity);
            }
        }
        serialized_input_bytes(self, self.bounds.max_capsule_bytes)?;
        Ok(())
    }
    pub fn digest(&self) -> Result<String, ContextError> {
        let bytes = canonical_bytes(self).map_err(|_| ContextError::Identity)?;
        Ok(hex::encode(Sha256::digest(bytes)))
    }
    pub fn encoded(&self) -> Result<(String, String), ContextError> {
        let bytes = canonical_bytes(self).map_err(|_| ContextError::Identity)?;
        let digest = hex::encode(Sha256::digest(&bytes));
        Ok((
            String::from_utf8(bytes).map_err(|_| ContextError::Identity)?,
            digest,
        ))
    }
    /// Ordered materialized text; revisions are resolved before this boundary.
    pub fn prompt(&self) -> Result<String, ContextError> {
        const EXPECTED: &str = "\n\nExpected output: ";
        const ACCEPTANCE: &str = "\nAcceptance: ";
        let size = [
            self.instruction.len(),
            EXPECTED.len(),
            self.expected_output.len(),
            ACCEPTANCE.len(),
            self.acceptance_criteria.len(),
        ]
        .into_iter()
        .chain(self.items.iter().flat_map(|item| [2, item.text.len()]))
        .try_fold(0usize, usize::checked_add)
        .ok_or(ContextError::Budget("prompt"))?;
        let mut text = String::with_capacity(size);
        text.push_str(&self.instruction);
        text.push_str(EXPECTED);
        text.push_str(&self.expected_output);
        text.push_str(ACCEPTANCE);
        text.push_str(&self.acceptance_criteria);
        for item in &self.items {
            text.push_str("\n\n");
            text.push_str(&item.text);
        }
        Ok(text)
    }
}
/// Only trusted host code constructs a selection. It is not a wire command.
#[derive(Debug, Clone)]
pub struct ExecutionSelection {
    pub executor: ActorGrant,
    pub session: SessionRecord,
    pub task: TaskRecord,
    pub capsule: ContextCapsule,
    pub account: AccountReference,
}
impl ExecutionSelection {
    pub fn new(
        grant: &ActorGrant,
        agent: AgentId,
        instruction: String,
        preamble: String,
        account: AccountReference,
    ) -> Self {
        let session_id = SessionId::generate();
        let task_id = TaskId::generate();
        Self {
            executor: grant.clone(),
            session: SessionRecord {
                tenant_id: grant.tenant_id.clone(),
                workspace_id: grant.workspace_id.clone(),
                session_id: session_id.clone(),
                agent_id: agent.clone(),
                owner_actor_id: grant.actor_id.clone(),
                revision: 1,
            },
            task: TaskRecord {
                tenant_id: grant.tenant_id.clone(),
                workspace_id: grant.workspace_id.clone(),
                task_id: task_id.clone(),
                session_id: session_id.clone(),
                agent_id: agent.clone(),
                owner_actor_id: grant.actor_id.clone(),
                target_actor_id: grant.actor_id.clone(),
                revision: 1,
                expected_output: "durable result".into(),
                acceptance_criteria: "authoritative receipts and report".into(),
                thread_ref: None,
                report_destination: None,
                parent_task: None,
                hop_count: 0,
                max_hops: 1,
            },
            capsule: ContextCapsule {
                tenant_id: grant.tenant_id.clone(),
                workspace_id: grant.workspace_id.clone(),
                context_ref: ContextRef::generate(),
                revision: 1,
                agent_id: agent,
                session_id,
                task_id,
                admitted_actor_id: grant.actor_id.clone(),
                executor_actor_id: grant.actor_id.clone(),
                role_revision: "1".into(),
                preamble,
                instruction,
                items: Vec::new(),
                expected_output: "durable result".into(),
                acceptance_criteria: "authoritative receipts and report".into(),
                bounds: ContextBounds::default(),
                policy_revision: "1".into(),
            },
            account,
        }
    }
    pub fn validate(&self, grant: &ActorGrant) -> Result<(), ContextError> {
        self.capsule.validate()?;
        let c = &self.capsule;
        let s = &self.session;
        let t = &self.task;
        if c.tenant_id != grant.tenant_id
            || c.workspace_id != grant.workspace_id
            || c.admitted_actor_id != grant.actor_id
            || self.executor.revoked
            || !self.executor.covers(&grant.tenant_id, &grant.workspace_id)
            || c.executor_actor_id != self.executor.actor_id
            || s.tenant_id != c.tenant_id
            || s.workspace_id != c.workspace_id
            || t.tenant_id != c.tenant_id
            || t.workspace_id != c.workspace_id
            || s.session_id != c.session_id
            || t.session_id != c.session_id
            || t.task_id != c.task_id
            || s.agent_id != c.agent_id
            || t.agent_id != c.agent_id
            || s.owner_actor_id != c.admitted_actor_id
            || t.owner_actor_id != c.admitted_actor_id
            || t.target_actor_id != c.executor_actor_id
            || t.expected_output != c.expected_output
            || t.acceptance_criteria != c.acceptance_criteria
            || s.revision == 0
            || t.revision == 0
            || s.revision > i64::MAX as u64
            || t.revision > i64::MAX as u64
            || t.max_hops == 0
            || t.hop_count >= t.max_hops
            || self.account.revision == 0
            || self.account.revision > i64::MAX as u64
            || self.account.account_ref.is_empty()
            || self.account.provider.is_empty()
        {
            return Err(ContextError::Identity);
        }
        Ok(())
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttemptExecutionBinding {
    pub attempt_id: AttemptId,
    pub capsule: ContextCapsule,
    pub capsule_digest: String,
    pub grant_revision_at_admission: u64,
    pub executor_revision_at_admission: u64,
    pub account: AccountReference,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryRevision {
    pub tenant_id: TenantId,
    pub workspace_id: WorkspaceId,
    pub memory_ref: String,
    pub revision: u64,
    /// None means explicitly shared in this scope, never inferred from legacy rows.
    pub owner_agent: Option<AgentId>,
    pub writer_actor: ActorId,
    pub originating_attempt: AttemptId,
    pub text: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_utf8_serialized_bound_and_checked_arithmetic() {
        let text = "Việt 🐋";
        let bytes = serde_json::to_vec(text).unwrap();
        assert_eq!(
            serialized_input_bytes(&text, bytes.len()).unwrap(),
            bytes.len()
        );
        assert!(matches!(
            serialized_input_bytes(&text, bytes.len() - 1),
            Err(ContextError::Budget(_))
        ));
        let bounds = ContextBounds {
            max_items: usize::MAX,
            ..ContextBounds::default()
        };
        assert_eq!(bounds.validate(), Err(ContextError::InvalidPolicy));
        let bounds = ContextBounds {
            max_item_bytes: 0,
            ..ContextBounds::default()
        };
        assert_eq!(bounds.validate(), Err(ContextError::InvalidPolicy));
    }
}
