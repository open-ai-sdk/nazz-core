//! Drives pinned Rig `AgentRun` step boundaries.
//!
//! Pending tool calls are reconciled against the effect journal before any
//! result is fed back. This crate does not call `Agent::resume`, because that
//! API can execute pending tools before the host ledger is checked.

use std::collections::BTreeSet;
use std::future::Future;
use std::process::Stdio;

pub mod events;
mod http_broker;
pub mod operation;
pub mod policy;
pub mod tools;
pub use http_broker::{
    HTTP_TOOL_NAME, HTTP_TOOL_REVISION, HTTP_TOOL_SCOPE, HttpBrokerError, HttpToolBody,
    HttpToolOutcome, HttpToolRequest, exact_local_test_endpoint, execute_authorized_get,
    http_args_digest, http_effect_id, reconcile_http_tool,
};

pub mod checkpoint_control;
pub mod host_control;
pub mod provider;
pub mod worker;

use agent_core::{
    AttemptId, AttemptStatus, EffectState, HARNESS_FORMAT, Settlement, harness_format_of,
    settle_harness_format, trace_effect_identity,
};
use agent_storage::{
    CHECKPOINT_FORMAT_VERSION, CheckpointRecord, EffectJournal, EffectLaunch, ExecutionStore,
    LaunchSettlement, StorageError as StoreError, TracedClaim, VerifiedExecutionContext,
};
use rig::completion::{AssistantContent, ToolDefinition, Usage};
use rig::message::{
    AssistantMessage, CallId, ToolCall, ToolFunction, ToolName, ToolResultContent, UserContent,
};
use rig::run::{AgentRun, AgentRunStep, ModelTurn, ModelTurnOutcome, RUN_FORMAT};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

pub const PINNED_RIG: &str = "0.44.0";
pub const PINNED_RUN_FORMAT: u32 = RUN_FORMAT;

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("rig: {0}")]
    Rig(String),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("needs_reconcile")]
    NeedsReconcile,
    #[error("cancellation is already committed")]
    Cancelled,
    #[error("stale generation or approval")]
    StaleAuthority,
    #[error("checkpoint format refused: {0}")]
    Format(String),
    #[error("old worker holds checkpoint format {0}")]
    OldWorkerHolds(u32),
    /// Known credential material in tool metadata. The value is not included.
    #[error("credential material is not tool metadata")]
    CredentialInToolMetadata,
    #[error("io: {0}")]
    Io(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolRevision {
    pub revision: String,
    pub name: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarnessCheckpoint {
    pub harness_format: u32,
    pub rig_version: String,
    pub rig_run_format: u32,
    pub tool_revision: String,
    pub run: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_registry: Option<Value>,
}

pub struct RigSession {
    run: AgentRun,
    tool: ToolRevision,
    attempt_id: AttemptId,
    generation: u64,
    parameters: Option<Value>,
    registry: Option<tools::ToolRegistry>,
    tool_deadline: std::time::Duration,
    context_digest: Option<String>,
    preamble: Option<String>,
    max_model_input_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriveOutcome {
    AwaitingModel { turn: usize },
    Completed { output: String },
    NeedsReconcile,
}

/// Offline codec/advertisement inspection. Deliberately exposes no model,
/// tool, journal, Store, checkpoint-write or execution ports. It cannot be
/// converted into an executable `RigSession` without a Store context lookup.
pub struct RigInspection(RigSession);
impl RigInspection {
    pub fn new(prompt: &str, tool: ToolRevision) -> Result<Self, RuntimeError> {
        RigSession::start_unbound(prompt, AttemptId::new("codec-inspection"), 1, tool).map(Self)
    }
    pub fn restore(checkpoint: &Value, tool: ToolRevision) -> Result<Self, RuntimeError> {
        RigSession::restore_unbound(checkpoint, AttemptId::new("codec-inspection"), 1, tool)
            .map(Self)
    }
    pub fn checkpoint(&self) -> Result<HarnessCheckpoint, RuntimeError> {
        self.0.checkpoint()
    }
    pub fn serialized_run_contains_secret(&self, secret: &str) -> bool {
        self.0.serialized_run_contains_secret(secret)
    }
    pub fn accept_local_turn(&mut self, turn: ModelTurn) -> Result<ModelTurnOutcome, RuntimeError> {
        self.0.accept_local_turn(turn)
    }
}

impl RigSession {
    pub fn start(
        context: &VerifiedExecutionContext,
        tool: ToolRevision,
    ) -> Result<Self, RuntimeError> {
        Ok(Self {
            run: AgentRun::new(context.capsule().prompt().map_err(StoreError::from)?).max_turns(4),
            tool,
            attempt_id: context.attempt_id().clone(),
            generation: context.generation(),
            parameters: None,
            registry: None,
            tool_deadline: std::time::Duration::from_secs(60),
            context_digest: Some(context.binding().capsule_digest.clone()),
            preamble: Some(context.capsule().preamble.clone()),
            max_model_input_bytes: context.capsule().bounds.max_model_input_bytes,
        })
    }

    fn start_unbound(
        prompt: &str,
        attempt_id: AttemptId,
        generation: u64,
        tool: ToolRevision,
    ) -> Result<Self, RuntimeError> {
        let run = AgentRun::new(prompt).max_turns(4);
        Ok(Self {
            run,
            tool,
            attempt_id,
            generation,
            parameters: None,
            registry: None,
            tool_deadline: std::time::Duration::from_secs(60),
            context_digest: None,
            preamble: None,
            max_model_input_bytes: 0,
        })
    }

    pub fn start_with_tools(
        context: &VerifiedExecutionContext,
        registry: tools::ToolRegistry,
    ) -> Result<Self, RuntimeError> {
        registry.definitions()?;
        let mut session = Self::start(context, registry.binding_revision())?;
        session.registry = Some(registry);
        Ok(session)
    }

    pub fn restore_with_tools(
        record: &CheckpointRecord,
        context: &VerifiedExecutionContext,
        registry: tools::ToolRegistry,
    ) -> Result<Self, RuntimeError> {
        registry.definitions()?;
        if record.payload["harness_format"] != tools::TOOL_REGISTRY_FORMAT
            || record.payload["tool_registry"]
                != serde_json::to_value(&registry).map_err(|_| RuntimeError::StaleAuthority)?
            || record.payload["tool_revision"] != registry.digest()
            || record.payload["rig_version"] != PINNED_RIG
            || record.payload["rig_run_format"] != PINNED_RUN_FORMAT
        {
            return Err(RuntimeError::Format(
                "tool registry checkpoint mismatch".into(),
            ));
        }
        let mut legacy = record.clone();
        legacy.payload["harness_format"] = Value::from(HARNESS_FORMAT);
        let mut session = Self::restore(&legacy, context, registry.binding_revision())?;
        session.registry = Some(registry);
        Ok(session)
    }

    fn definitions(&self) -> Result<Vec<ToolDefinition>, RuntimeError> {
        if let Some(registry) = &self.registry {
            return registry.definitions();
        }
        let parameters = self
            .parameters
            .clone()
            .unwrap_or_else(advertised_parameters);
        if pending_metadata_has_credential(&self.tool, &parameters) {
            return Err(RuntimeError::CredentialInToolMetadata);
        }
        Ok(vec![ToolDefinition::new(
            ToolName::new(self.tool.name.clone()).map_err(|_| RuntimeError::StaleAuthority)?,
            self.tool.description.clone(),
            parameters,
        )])
    }

    /// JSON Schema checked and advertised with this revision.
    ///
    /// Absent keeps the historical path schema. Declaration names are not
    /// credential values; credential literals in the schema are still refused.
    pub fn with_parameters(mut self, parameters: Value) -> Self {
        self.parameters = Some(parameters);
        self
    }

    pub fn checkpoint(&self) -> Result<HarnessCheckpoint, RuntimeError> {
        reject_advertised_metadata(&self.run)?;
        let run =
            serde_json::to_value(&self.run).map_err(|err| RuntimeError::Rig(err.to_string()))?;
        Ok(HarnessCheckpoint {
            harness_format: if self.registry.is_some() {
                tools::TOOL_REGISTRY_FORMAT
            } else {
                HARNESS_FORMAT
            },
            rig_version: PINNED_RIG.to_string(),
            rig_run_format: RUN_FORMAT,
            tool_revision: self.tool.revision.clone(),
            tool_registry: self
                .registry
                .as_ref()
                .map(serde_json::to_value)
                .transpose()
                .map_err(|_| RuntimeError::StaleAuthority)?,
            run,
        })
    }

    pub fn restore(
        record: &CheckpointRecord,
        context: &VerifiedExecutionContext,
        tool: ToolRevision,
    ) -> Result<Self, RuntimeError> {
        if record.attempt_id != *context.attempt_id()
            || record.generation > context.generation()
            || record.format_version != CHECKPOINT_FORMAT_VERSION
        {
            return Err(RuntimeError::StaleAuthority);
        }
        let mut session = Self::restore_unbound(
            &record.payload,
            context.attempt_id().clone(),
            context.generation(),
            tool,
        )?;
        session.context_digest = Some(context.binding().capsule_digest.clone());
        session.preamble = Some(context.capsule().preamble.clone());
        session.max_model_input_bytes = context.capsule().bounds.max_model_input_bytes;
        Ok(session)
    }

    fn restore_unbound(
        checkpoint: &Value,
        attempt_id: AttemptId,
        generation: u64,
        tool: ToolRevision,
    ) -> Result<Self, RuntimeError> {
        let stored = harness_format_of(checkpoint)
            .ok_or(RuntimeError::Format("missing harness_format".into()))?;
        match settle_harness_format(stored, HARNESS_FORMAT)
            .map_err(|err| RuntimeError::Format(err.to_string()))?
        {
            Settlement::OldWorkerHolds => return Err(RuntimeError::OldWorkerHolds(stored)),
            Settlement::Migrated => {
                return Err(RuntimeError::Format(
                    "refusing invented v1 metadata migration; no persisted v1 payload schema"
                        .into(),
                ));
            }
            Settlement::Current => {}
        }
        if checkpoint
            .get("tool_revision")
            .and_then(|value| value.as_str())
            != Some(tool.revision.as_str())
        {
            return Err(RuntimeError::Format("tool revision mismatch".into()));
        }
        if checkpoint["rig_version"] != PINNED_RIG
            || checkpoint["rig_run_format"] != PINNED_RUN_FORMAT
        {
            return Err(RuntimeError::Format(
                "unsupported Rig checkpoint metadata".into(),
            ));
        }
        let run_value = checkpoint
            .get("run")
            .cloned()
            .ok_or(RuntimeError::Format("missing run".into()))?;
        let run: AgentRun = serde_json::from_value(run_value)
            .map_err(|err| RuntimeError::Format(err.to_string()))?;
        reject_advertised_metadata(&run)?;
        Ok(Self {
            run,
            tool,
            attempt_id,
            generation,
            parameters: None,
            registry: None,
            tool_deadline: std::time::Duration::from_secs(60),
            context_digest: None,
            preamble: None,
            max_model_input_bytes: 0,
        })
    }

    pub fn serialized_run_contains_secret(&self, secret: &str) -> bool {
        serde_json::to_string(&self.run)
            .unwrap_or_default()
            .contains(secret)
    }

    /// Feed a local model turn. This is a boundary fixture, not a live provider call.
    pub fn accept_local_turn(&mut self, turn: ModelTurn) -> Result<ModelTurnOutcome, RuntimeError> {
        let definitions = self.definitions()?;
        match self
            .run
            .next_step()
            .map_err(|err| RuntimeError::Rig(err.to_string()))?
        {
            AgentRunStep::CallModel {
                turn: index,
                prompt,
                history,
            } => {
                if self.context_digest.is_some() {
                    let mut spec = rig::run::spec::RunSpec::new();
                    spec.preamble = self.preamble.clone();
                    spec.max_tokens = Some(4096);
                    let prepared = rig::run::prepare::prepare_request(
                        &spec,
                        &rig::completion::ProviderCapabilities::default(),
                        &history,
                        definitions.clone(),
                        None,
                        None,
                    )
                    .map_err(|_| RuntimeError::Rig("local model input refused".into()))?;
                    let request = prepared.apply(rig::completion::CompletionRequest::new(prompt));
                    agent_core::serialized_input_bytes(&request, self.max_model_input_bytes)
                        .map_err(StoreError::from)?;
                }
                self.run.advertise_tools(index, definitions);
                self.run
                    .model_response(turn)
                    .map_err(|err| RuntimeError::Rig(err.to_string()))
            }
            other => Err(RuntimeError::Rig(format!(
                "expected CallModel, got {other:?}"
            ))),
        }
    }

    /// Move to the pending tool step and return call identity without executing.
    pub fn arm_pending_tools(&mut self) -> Result<Vec<(String, String, Value)>, RuntimeError> {
        match self
            .run
            .next_step()
            .map_err(|err| RuntimeError::Rig(err.to_string()))?
        {
            AgentRunStep::CallTools { calls } => Ok(calls
                .iter()
                .map(|call| {
                    (
                        call.tool_call.id.to_string(),
                        call.tool_call.function.name.as_str().to_string(),
                        call.tool_call.function.arguments_value(),
                    )
                })
                .collect()),
            other => Err(RuntimeError::Rig(format!(
                "expected CallTools, got {other:?}"
            ))),
        }
    }

    pub async fn reconcile_tools<S, J, F, Fut>(
        &mut self,
        journal: &J,
        store: &S,
        grant: &agent_core::ActorGrant,
        holder: &str,
        scope: &str,
        mut execute: F,
    ) -> Result<DriveOutcome, RuntimeError>
    where
        S: ExecutionStore,
        J: EffectJournal,
        F: FnMut(String, Value) -> Fut + Send,
        Fut: Future<Output = Result<String, RuntimeError>> + Send,
    {
        if self.generation == 0 {
            return Err(RuntimeError::StaleAuthority);
        }
        let calls = match self
            .run
            .next_step()
            .map_err(|err| RuntimeError::Rig(err.to_string()))?
        {
            AgentRunStep::CallTools { calls } => calls,
            AgentRunStep::Done(response) => {
                return Ok(DriveOutcome::Completed {
                    output: response.output(),
                });
            }
            AgentRunStep::CallModel { turn, .. } => {
                return Ok(DriveOutcome::AwaitingModel { turn });
            }
        };
        let mut results = Vec::new();
        for call in &calls {
            if call.preresolved_result.is_some() {
                continue;
            }
            if cancellation_committed(store, grant, &self.attempt_id).await? {
                return Err(RuntimeError::Cancelled);
            }
            let args = call.tool_call.function.arguments_value();
            let call_id = call.tool_call.id.to_string();
            let tool_name = call.tool_call.function.name.as_str();
            let (revision, scope) = if let Some(registry) = &self.registry {
                let tool = registry.get(tool_name)?;
                (tool.revision.as_str(), tool.scope.as_str())
            } else {
                if tool_name != self.tool.name {
                    return Err(RuntimeError::StaleAuthority);
                }
                (self.tool.revision.as_str(), scope)
            };
            let traced = trace_effect_identity(&self.attempt_id, &call_id, &args);
            // The local journal is not the authority. A second process with an
            // empty journal must not treat `record_effect`'s idempotent `Ok`
            // as permission to run the external effect again.
            let _journal_is_not_authority = journal;
            match store
                .claim_traced_effect(
                    grant,
                    holder,
                    scope,
                    revision,
                    &self.attempt_id,
                    self.generation,
                    tool_name,
                    &traced,
                )
                .await?
            {
                TracedClaim::KnownReceipt(binding) => {
                    if binding.scope != scope || binding.tool_revision != revision {
                        return Err(StoreError::LifecycleConflict.into());
                    }
                    let Some(text) = binding.claim.receipt.as_ref().and_then(Value::as_str) else {
                        return Err(RuntimeError::NeedsReconcile);
                    };
                    results.push((
                        call.tool_call.id.clone(),
                        call.tool_call.function.name.clone(),
                        text.to_string(),
                    ));
                    continue;
                }
                TracedClaim::Unknown(_) | TracedClaim::Unresolved => {
                    return Err(RuntimeError::NeedsReconcile);
                }
                TracedClaim::Fresh(binding) => {
                    if binding.scope != scope
                        || binding.tool_revision != revision
                        || !traced.contains_digest(&binding.claim.args_digest)
                    {
                        return Err(StoreError::LifecycleConflict.into());
                    }
                    let claim = binding.claim;
                    let launched = store
                        .with_effect_launch(
                            grant,
                            holder,
                            scope,
                            revision,
                            &claim,
                            self.tool_deadline,
                            || {
                                let pending = execute(tool_name.to_string(), args.clone());
                                async move { pending.await.map_err(|_| ()) }
                            },
                        )
                        .await?;
                    match launched {
                        EffectLaunch::Blocked(err) => {
                            if cancellation_committed(store, grant, &self.attempt_id).await? {
                                return Err(RuntimeError::Cancelled);
                            }
                            return Err(err.into());
                        }
                        EffectLaunch::Attempted => {
                            let mut blocked = claim;
                            blocked.state = EffectState::NeedsReconcile;
                            blocked.receipt = None;
                            let _ = store
                                .record_effect(grant, holder, scope, revision, &blocked)
                                .await;
                            return Err(RuntimeError::NeedsReconcile);
                        }
                        EffectLaunch::Ready(output) => {
                            let mut receipt = claim.clone();
                            receipt.state = EffectState::Receipt;
                            receipt.receipt = Some(Value::String(output.clone()));
                            match store
                                .settle_launched_effect(grant, holder, scope, revision, &receipt)
                                .await
                            {
                                Ok(LaunchSettlement::Receipt) => {
                                    results.push((
                                        call.tool_call.id.clone(),
                                        call.tool_call.function.name.clone(),
                                        output,
                                    ));
                                }
                                Ok(LaunchSettlement::Unknown) | Err(_) => {
                                    let mut blocked = claim;
                                    blocked.state = EffectState::NeedsReconcile;
                                    blocked.receipt = None;
                                    let _ = store
                                        .record_effect(grant, holder, scope, revision, &blocked)
                                        .await;
                                    return Err(RuntimeError::NeedsReconcile);
                                }
                            }
                        }
                    }
                }
            }
        }
        let tool_results = results
            .into_iter()
            .map(|(id, name, output)| {
                UserContent::tool_result(id, name, vec![ToolResultContent::text(output)])
            })
            .collect();
        self.run
            .tool_results(tool_results)
            .map_err(|err| RuntimeError::Rig(err.to_string()))?;
        Ok(DriveOutcome::AwaitingModel {
            turn: self.run.turn(),
        })
    }
}

/// Schema keywords whose object keys are declarations, not credential values.
const DECLARATION_MAPS: &[&str] = &[
    "properties",
    "patternProperties",
    "$defs",
    "definitions",
    "dependentSchemas",
];

/// Schema keywords whose strings name fields. They are not credential values.
const DECLARATION_NAME_LISTS: &[&str] = &["required"];

fn advertised_parameters() -> Value {
    serde_json::json!({"type": "object", "properties": {"path": {"type": "string"}}})
}

fn pending_metadata_has_credential(tool: &ToolRevision, parameters: &Value) -> bool {
    known_credential_text(&tool.name)
        || known_credential_text(&tool.description)
        || value_has_credential_material(parameters)
}

fn reject_advertised_metadata(run: &AgentRun) -> Result<(), RuntimeError> {
    let Some(tools) = run.advertised_tools() else {
        return Ok(());
    };
    if tools.definitions.iter().any(definition_has_credential) {
        return Err(RuntimeError::CredentialInToolMetadata);
    }
    Ok(())
}

fn definition_has_credential(definition: &ToolDefinition) -> bool {
    known_credential_text(definition.name.as_str())
        || known_credential_text(&definition.description)
        || value_has_credential_material(&definition.parameters)
}

/// Key-shaped text at a token boundary. Not every secret, and not `sk-` inside
/// an ordinary word such as `ask-` or `task-`.
fn known_credential_text(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    bounded_material(&lower, "sk-", sk_key_body)
        || bounded_material(&lower, "akia", aws_access_key_suffix)
        || bounded_phrase(&lower, "begin private")
        || bounded_phrase(&lower, "begin openssh")
}

fn token_boundary(text: &str, index: usize) -> bool {
    index == 0 || !text.as_bytes()[index - 1].is_ascii_alphanumeric()
}

fn bounded_phrase(text: &str, phrase: &str) -> bool {
    let mut from = 0;
    while let Some(pos) = text[from..].find(phrase) {
        let start = from + pos;
        if token_boundary(text, start) {
            return true;
        }
        from = start + phrase.len();
    }
    false
}

fn bounded_material(text: &str, marker: &str, material: fn(&str) -> bool) -> bool {
    let mut from = 0;
    while let Some(pos) = text[from..].find(marker) {
        let start = from + pos;
        if token_boundary(text, start) && material(&text[start + marker.len()..]) {
            return true;
        }
        from = start + marker.len();
    }
    false
}

/// `sk-` followed by a key body. A bare marker or a short tail is not material.
fn sk_key_body(body: &str) -> bool {
    let mut len = 0;
    let mut alnum = false;
    for byte in body.bytes() {
        if byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_' {
            len += 1;
            alnum |= byte.is_ascii_alphanumeric();
        } else {
            break;
        }
    }
    len >= 16 && alnum
}

/// AWS access-key id: `AKIA` plus 16 alphanumerics, not a longer word.
fn aws_access_key_suffix(body: &str) -> bool {
    let bytes = body.as_bytes();
    bytes.len() >= 16
        && bytes[..16].iter().all(|byte| byte.is_ascii_alphanumeric())
        && bytes
            .get(16)
            .is_none_or(|byte| !byte.is_ascii_alphanumeric())
}

fn value_has_credential_material(value: &Value) -> bool {
    match value {
        Value::String(text) => known_credential_text(text),
        Value::Array(items) => items.iter().any(value_has_credential_material),
        Value::Object(map) => object_has_credential(map),
        _ => false,
    }
}

fn object_has_credential(map: &serde_json::Map<String, Value>) -> bool {
    for (key, child) in map {
        if DECLARATION_MAPS.contains(&key.as_str()) {
            if declaration_map_has_credential(child) {
                return true;
            }
            continue;
        }
        if key == "dependentRequired" {
            if dependent_required_has_credential(child) {
                return true;
            }
            continue;
        }
        if DECLARATION_NAME_LISTS.contains(&key.as_str()) {
            if declaration_names_have_credential(child) {
                return true;
            }
            continue;
        }
        if known_credential_text(key) || value_has_credential_material(child) {
            return true;
        }
    }
    false
}

fn declaration_map_has_credential(value: &Value) -> bool {
    match value {
        Value::Object(map) => map.values().any(value_has_credential_material),
        other => value_has_credential_material(other),
    }
}

fn declaration_names_have_credential(value: &Value) -> bool {
    match value {
        Value::Array(items) => items.iter().any(|item| match item {
            Value::String(_) => false,
            other => value_has_credential_material(other),
        }),
        other => value_has_credential_material(other),
    }
}

fn dependent_required_has_credential(value: &Value) -> bool {
    match value {
        Value::Object(map) => map.values().any(declaration_names_have_credential),
        other => value_has_credential_material(other),
    }
}

async fn cancellation_committed(
    store: &impl ExecutionStore,
    grant: &agent_core::ActorGrant,
    attempt_id: &AttemptId,
) -> Result<bool, RuntimeError> {
    match store.read_attempt(grant, attempt_id).await? {
        Some(row)
            if matches!(
                row.status,
                AttemptStatus::CancelRequested
                    | AttemptStatus::Cancelled
                    | AttemptStatus::NeedsReconcile
            ) =>
        {
            Ok(true)
        }
        _ => Ok(false),
    }
}

pub fn local_tool_turn(call_id: &str, tool: &str, args: Value) -> Result<ModelTurn, RuntimeError> {
    let name = ToolName::new(tool.to_string()).map_err(|err| RuntimeError::Rig(err.to_string()))?;
    let function = ToolFunction::new(name, args);
    let content = AssistantContent::ToolCall(ToolCall::from_wire(call_id, function));
    let names = BTreeSet::from([tool.to_string()]);
    Ok(ModelTurn::new(
        AssistantMessage::default(),
        vec![content],
        Usage::default(),
        names.clone(),
        names,
        serde_json::json!({"source": "local-boundary-fixture"}),
    ))
}

pub fn local_text_turn(text: &str, tool: &str) -> ModelTurn {
    let names = BTreeSet::from([tool.to_string()]);
    ModelTurn::new(
        AssistantMessage::default(),
        vec![AssistantContent::text(text)],
        Usage::default(),
        names.clone(),
        names,
        serde_json::json!({"source": "local-boundary-fixture"}),
    )
}

pub fn refuse_foreign_rig_format(mut checkpoint: Value) -> Result<AgentRun, RuntimeError> {
    let run = checkpoint
        .get_mut("run")
        .ok_or(RuntimeError::Format("missing run".into()))?;
    run["format"] = Value::from(99);
    serde_json::from_value(run.clone()).map_err(|err| RuntimeError::Format(err.to_string()))
}

/// Compile-time pin of the image API. Not a live image generation call.
pub fn image_api_present() -> &'static str {
    let _request = std::any::type_name::<rig::image_generation::ImageGenerationRequest>();
    let _response = std::any::type_name::<rig::image_generation::ImageGenerationResponse>();
    "rig::image_generation"
}

pub struct OwnedGroup {
    child: std::process::Child,
    pub pgid: u32,
}

pub fn spawn_owned_group(program: &str, args: &[&str]) -> Result<OwnedGroup, RuntimeError> {
    use std::os::unix::process::CommandExt;
    let child = std::process::Command::new(program)
        .args(args)
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|err| RuntimeError::Io(err.to_string()))?;
    let pgid = child.id();
    Ok(OwnedGroup { child, pgid })
}

pub fn stop_owned_group(group: &mut OwnedGroup) -> Result<bool, RuntimeError> {
    let _ = std::process::Command::new("kill")
        .args(["-TERM", &format!("-{}", group.pgid)])
        .status();
    let _ = group.child.wait();
    let output = std::process::Command::new("ps")
        .args(["-p", &group.pgid.to_string(), "-o", "pid="])
        .output()
        .map_err(|err| RuntimeError::Io(err.to_string()))?;
    Ok(String::from_utf8_lossy(&output.stdout).trim().is_empty())
}

pub fn process_alive(pid: u32) -> bool {
    std::process::Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "pid="])
        .output()
        .map(|output| !String::from_utf8_lossy(&output.stdout).trim().is_empty())
        .unwrap_or(false)
}

pub fn call_id_display(id: &CallId) -> String {
    id.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_types_are_the_pinned_rig_api() {
        assert_eq!(image_api_present(), "rig::image_generation");
        assert_eq!(PINNED_RUN_FORMAT, 2);
    }

    #[test]
    fn foreign_run_format_is_refused_by_rig() {
        let session = RigSession::start_unbound(
            "hello",
            AttemptId::new("attempt"),
            1,
            ToolRevision {
                revision: "rev-1".into(),
                name: "write_file".into(),
                description: "write".into(),
            },
        )
        .unwrap();
        let checkpoint = serde_json::to_value(session.checkpoint().unwrap()).unwrap();
        let error = refuse_foreign_rig_format(checkpoint).unwrap_err();
        let RuntimeError::Format(message) = error else {
            panic!("format error");
        };
        assert!(
            message.contains("resume refused") || message.contains("format"),
            "{message}"
        );
    }

    fn tool(description: &str) -> ToolRevision {
        ToolRevision {
            revision: "rev-1".into(),
            name: "write_file".into(),
            description: description.into(),
        }
    }

    fn session(description: &str) -> RigSession {
        RigSession::start_unbound(
            "prompt-without-material",
            AttemptId::new("cred"),
            1,
            tool(description),
        )
        .expect("start")
    }

    fn snapshot(session: &RigSession) -> Value {
        serde_json::to_value(session.checkpoint().expect("checkpoint")).expect("json")
    }

    #[test]
    fn ordinary_description_is_advertised_unchanged() {
        let mut live = session("append a granted file");
        live.accept_local_turn(
            local_tool_turn(
                "call-meta",
                "write_file",
                serde_json::json!({"path": "meta.txt"}),
            )
            .expect("turn"),
        )
        .expect("advertise");
        let checkpoint = snapshot(&live);
        let text = checkpoint.to_string();
        assert!(text.contains("append a granted file"));
        assert_eq!(checkpoint["tool_revision"], "rev-1");
        assert!(checkpoint["run"]["turn_tools"]["definitions"][0]["description"].is_string());
        assert_eq!(
            checkpoint["run"]["turn_tools"]["definitions"][0]["parameters"]["properties"]["path"]["type"],
            "string"
        );
        assert!(
            checkpoint["run"]["turn_tools"]["definitions"][0]["parameters"]["properties"]
                .get("token")
                .is_none()
        );
        let mut prose = session("report the token count; does not read credentials");
        prose
            .accept_local_turn(
                local_tool_turn(
                    "call-prose",
                    "write_file",
                    serde_json::json!({"path": "note.txt"}),
                )
                .expect("turn"),
            )
            .expect("ordinary prose");
        assert!(snapshot(&prose).to_string().contains("token count"));
    }

    #[test]
    fn credential_metadata_is_rejected_before_run_mutation() {
        let shapes = [
            "sk-fixture-7c2e9a1b4d-not-a-real-key",
            "sk-ant-example-not-the-fixture",
            "AKIAIOSFODNN7EXAMPLE",
            "-----BEGIN PRIVATE KEY-----",
        ];
        for shape in shapes {
            let mut session = session(&format!("append a granted file {shape}"));
            let before = snapshot(&session);
            let err = session
                .accept_local_turn(
                    local_tool_turn(
                        "call-secret",
                        "write_file",
                        serde_json::json!({"path": "x"}),
                    )
                    .expect("turn"),
                )
                .expect_err("refusal");
            assert!(matches!(err, RuntimeError::CredentialInToolMetadata));
            let rendered = err.to_string();
            assert!(!rendered.contains(shape), "{rendered}");
            assert_eq!(snapshot(&session), before);
            assert!(!session.serialized_run_contains_secret(shape));
            assert!(!snapshot(&session).to_string().contains(shape));
            assert_eq!(session.tool.revision, "rev-1");
        }
    }

    #[test]
    fn prompt_material_is_not_censored() {
        let shape = "sk-fixture-7c2e9a1b4d-not-a-real-key";
        let session = RigSession::start_unbound(
            &format!("boundary {shape}"),
            AttemptId::new("detector"),
            1,
            tool("append a granted file"),
        )
        .expect("start");
        assert!(session.serialized_run_contains_secret(shape));
        assert!(snapshot(&session).to_string().contains(shape));
    }

    #[test]
    fn restore_rejects_secret_bearing_advertised_metadata() {
        let shape = "sk-fixture-7c2e9a1b4d-not-a-real-key";
        let mut clean = session("append a granted file");
        clean
            .accept_local_turn(
                local_tool_turn(
                    "call-clean",
                    "write_file",
                    serde_json::json!({"path": "ok.txt"}),
                )
                .expect("turn"),
            )
            .expect("advertise");
        let base = snapshot(&clean);
        let mut described = base.clone();
        described["run"]["turn_tools"]["definitions"][0]["description"] =
            serde_json::json!(format!("append a granted file {shape}"));
        let err = match RigSession::restore_unbound(
            &described,
            AttemptId::new("restore"),
            1,
            tool("append a granted file"),
        ) {
            Err(err) => err,
            Ok(_) => panic!("description restore accepted secret metadata"),
        };
        assert!(matches!(err, RuntimeError::CredentialInToolMetadata));
        assert!(!err.to_string().contains(shape));

        let mut nested = base.clone();
        nested["run"]["turn_tools"]["definitions"][0]["parameters"]["properties"]["path"]["description"] =
            serde_json::json!(shape);
        let err = match RigSession::restore_unbound(
            &nested,
            AttemptId::new("nested"),
            1,
            tool("append a granted file"),
        ) {
            Err(err) => err,
            Ok(_) => panic!("nested restore accepted secret metadata"),
        };
        assert!(matches!(err, RuntimeError::CredentialInToolMetadata));
        assert!(!err.to_string().contains(shape));

        let mut structural = base.clone();
        structural["run"]["turn_tools"]["definitions"][0]["parameters"]["api_key"] =
            serde_json::json!(shape);
        let err = match RigSession::restore_unbound(
            &structural,
            AttemptId::new("structural"),
            1,
            tool("append a granted file"),
        ) {
            Err(err) => err,
            Ok(_) => panic!("literal credential payload accepted"),
        };
        assert!(matches!(err, RuntimeError::CredentialInToolMetadata));
        assert!(!err.to_string().contains(shape));
    }

    const CANARY: &str = "sk-fixture-7c2e9a1b4d-not-a-real-key";

    fn field_schema() -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "token": {"type": "string", "description": "opaque-handle"},
                "api_key": {"type": "string"}
            },
            "required": ["token", "api_key"]
        })
    }

    fn advertised(session: &RigSession) -> Value {
        snapshot(session)["run"]["turn_tools"]["definitions"][0].clone()
    }

    #[test]
    fn ask_and_task_prose_and_names_stay_advertised() {
        let cases = [
            (
                "ask-operator",
                "ask-the operator to confirm the granted path",
            ),
            ("task-note", "task-prefixed note: append the granted file"),
            ("mask-writer", "mask-the granted path before append"),
            (
                "write_file",
                "document the marker as sk- without a key body",
            ),
        ];
        for (name, description) in cases {
            let mut live = RigSession::start_unbound(
                "prompt-without-material",
                AttemptId::new(name),
                1,
                ToolRevision {
                    revision: "rev-1".into(),
                    name: name.into(),
                    description: description.into(),
                },
            )
            .expect("start");
            live.accept_local_turn(
                local_tool_turn("call-prose", name, serde_json::json!({"path": "note.txt"}))
                    .expect("turn"),
            )
            .expect(description);
            let definition = advertised(&live);
            assert_eq!(definition["name"], name);
            assert_eq!(definition["description"], description);
            assert_eq!(snapshot(&live)["tool_revision"], "rev-1");
        }
    }

    #[test]
    fn schema_field_declarations_are_accepted_on_new_and_restore() {
        let mut live = session("append a granted file").with_parameters(field_schema());
        live.accept_local_turn(
            local_tool_turn(
                "call-schema",
                "write_file",
                serde_json::json!({"path": "a.txt"}),
            )
            .expect("turn"),
        )
        .expect("new path keeps token and api_key declarations");
        let definition = advertised(&live);
        assert_eq!(definition["description"], "append a granted file");
        assert_eq!(
            definition["parameters"]["properties"]["token"]["type"],
            "string"
        );
        assert_eq!(
            definition["parameters"]["properties"]["token"]["description"],
            "opaque-handle"
        );
        assert_eq!(
            definition["parameters"]["properties"]["api_key"]["type"],
            "string"
        );
        assert_eq!(
            definition["parameters"]["required"],
            serde_json::json!(["token", "api_key"])
        );

        let mut clean = session("append a granted file");
        clean
            .accept_local_turn(
                local_tool_turn(
                    "call-base",
                    "write_file",
                    serde_json::json!({"path": "b.txt"}),
                )
                .expect("turn"),
            )
            .expect("base");
        let mut stored = snapshot(&clean);
        stored["run"]["turn_tools"]["definitions"][0]["parameters"] = field_schema();
        let restored = RigSession::restore_unbound(
            &stored,
            AttemptId::new("restore-fields"),
            1,
            tool("append a granted file"),
        )
        .expect("restore keeps token and api_key declarations");
        let definition = advertised(&restored);
        assert_eq!(
            definition["parameters"]["properties"]["api_key"]["type"],
            "string"
        );
        assert_eq!(definition["description"], "append a granted file");
    }

    #[test]
    fn checkpoint_accepts_schema_field_names() {
        let mut session = session("append a granted file");
        session
            .accept_local_turn(
                local_tool_turn(
                    "call-ck",
                    "write_file",
                    serde_json::json!({"path": "c.txt"}),
                )
                .expect("turn"),
            )
            .expect("advertise");
        let mut raw = serde_json::to_value(&session.run).expect("run");
        raw["turn_tools"]["definitions"][0]["parameters"] = field_schema();
        session.run = serde_json::from_value(raw).expect("round trip");
        let saved = session
            .checkpoint()
            .expect("checkpoint keeps schema field names");
        assert_eq!(
            saved.run["turn_tools"]["definitions"][0]["parameters"]["properties"]["token"]["type"],
            "string"
        );
        assert!(!saved.run.to_string().contains(CANARY));
    }

    #[test]
    fn ordinary_api_key_value_is_not_a_credential() {
        let payload = serde_json::json!({"api_key": "ordinary-value", "token": "opaque-handle"});
        let mut live = session("append a granted file").with_parameters(payload.clone());
        live.accept_local_turn(
            local_tool_turn(
                "call-plain",
                "write_file",
                serde_json::json!({"path": "d.txt"}),
            )
            .expect("turn"),
        )
        .expect("new path keeps an ordinary literal");
        assert_eq!(advertised(&live)["parameters"]["api_key"], "ordinary-value");

        let mut clean = session("append a granted file");
        clean
            .accept_local_turn(
                local_tool_turn(
                    "call-base",
                    "write_file",
                    serde_json::json!({"path": "e.txt"}),
                )
                .expect("turn"),
            )
            .expect("base");
        let mut stored = snapshot(&clean);
        stored["run"]["turn_tools"]["definitions"][0]["parameters"] = payload;
        let restored = RigSession::restore_unbound(
            &stored,
            AttemptId::new("ordinary"),
            1,
            tool("append a granted file"),
        )
        .expect("restore keeps an ordinary literal");
        assert_eq!(
            advertised(&restored)["parameters"]["token"],
            "opaque-handle"
        );
        assert!(!restored.serialized_run_contains_secret(CANARY));
    }

    fn assert_refused_turn(parameters: Value, shape: &str) {
        let mut live = session("append a granted file").with_parameters(parameters);
        let before = snapshot(&live);
        let err = live
            .accept_local_turn(
                local_tool_turn(
                    "call-secret",
                    "write_file",
                    serde_json::json!({"path": "x"}),
                )
                .expect("turn"),
            )
            .expect_err("new path");
        assert!(matches!(err, RuntimeError::CredentialInToolMetadata));
        assert_eq!(err.to_string(), "credential material is not tool metadata");
        assert!(!err.to_string().contains(shape), "{shape}");
        assert_eq!(snapshot(&live), before);
        assert!(!live.serialized_run_contains_secret(shape));
        assert_eq!(live.tool.revision, "rev-1");
    }

    fn assert_restore_refuses(base: &Value, parameters: Value, shape: &str) {
        let mut stored = base.clone();
        stored["run"]["turn_tools"]["definitions"][0]["parameters"] = parameters;
        let owned = stored.clone();
        let err = match RigSession::restore_unbound(
            &stored,
            AttemptId::new("deny"),
            1,
            tool("append a granted file"),
        ) {
            Err(err) => err,
            Ok(_) => panic!("restore accepted credential metadata"),
        };
        assert!(matches!(err, RuntimeError::CredentialInToolMetadata));
        assert_eq!(err.to_string(), "credential material is not tool metadata");
        assert!(!err.to_string().contains(shape), "{shape}");
        assert_eq!(stored, owned);
    }

    #[test]
    fn nested_and_literal_credential_material_stays_refused() {
        let mut clean = session("append a granted file");
        clean
            .accept_local_turn(
                local_tool_turn(
                    "call-base",
                    "write_file",
                    serde_json::json!({"path": "ok.txt"}),
                )
                .expect("turn"),
            )
            .expect("base");
        let base = snapshot(&clean);
        let shapes = [
            CANARY,
            "sk-ant-example-not-the-fixture",
            "AKIAIOSFODNN7EXAMPLE",
            "-----BEGIN PRIVATE KEY-----",
            "-----BEGIN OPENSSH PRIVATE KEY-----",
        ];
        for shape in shapes {
            let described = serde_json::json!({
                "type": "object",
                "properties": {
                    "token": {"type": "string", "description": shape}
                }
            });
            let defaulted = serde_json::json!({
                "type": "object",
                "properties": {
                    "api_key": {"type": "string", "default": shape, "description": "opaque-handle"}
                }
            });
            let exemplified = serde_json::json!({
                "type": "object",
                "properties": {
                    "path": {"type": "string", "examples": [shape]}
                }
            });
            let nested_meta = serde_json::json!({
                "type": "object",
                "properties": {
                    "path": {"type": "string", "x-note": {"comment": shape}}
                }
            });
            let literal_field = serde_json::json!({
                "type": "object",
                "properties": {"token": shape}
            });
            let literal_payload = serde_json::json!({"api_key": shape, "token": "opaque-handle"});
            for parameters in [
                described,
                defaulted,
                exemplified,
                nested_meta,
                literal_field,
                literal_payload,
            ] {
                assert_refused_turn(parameters.clone(), shape);
                assert_restore_refuses(&base, parameters, shape);
            }
        }

        let mut contaminated = session("append a granted file");
        contaminated
            .accept_local_turn(
                local_tool_turn(
                    "call-ck",
                    "write_file",
                    serde_json::json!({"path": "ok.txt"}),
                )
                .expect("turn"),
            )
            .expect("advertise");
        let mut raw = serde_json::to_value(&contaminated.run).expect("run");
        raw["turn_tools"]["definitions"][0]["parameters"]["properties"]["token"] = serde_json::json!({
            "type": "string",
            "default": CANARY
        });
        contaminated.run = serde_json::from_value(raw).expect("round trip");
        let before = serde_json::to_value(&contaminated.run).expect("before");
        let err = contaminated.checkpoint().expect_err("checkpoint");
        assert!(matches!(err, RuntimeError::CredentialInToolMetadata));
        assert!(!err.to_string().contains(CANARY));
        assert_eq!(
            serde_json::to_value(&contaminated.run).expect("after"),
            before
        );
    }

    #[test]
    fn unmarked_opaque_text_is_not_a_credential() {
        let mut live = session("plain-opaque-value-9f3a");
        live.accept_local_turn(
            local_tool_turn(
                "call-opaque",
                "write_file",
                serde_json::json!({"path": "note.txt"}),
            )
            .expect("turn"),
        )
        .expect("unmarked opaque text");
        assert_eq!(advertised(&live)["description"], "plain-opaque-value-9f3a");
    }
}
