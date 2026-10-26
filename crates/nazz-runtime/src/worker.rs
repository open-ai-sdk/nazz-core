//! UI-independent scheduling of the existing Rig step driver and Store ports.
//! The host owns account resolution and tools; serialized state grants neither.

use nazz_core::{
    ActorGrant, AttemptId, AttemptStatus, EffectState, StopReceipt, trace_effect_identity,
};
use nazz_storage::dispatch::{DispatchIntent, DispatchPhase, PollOutcome};
use nazz_storage::{
    CHECKPOINT_FORMAT_VERSION, EffectJournal, EffectLaunch, ExecutionStore, LaunchSettlement,
    StorageError as StoreError, TracedClaim,
};
use rig::completion::CompletionRequest;
use rig::run::{AgentRunStep, ModelTurn, prepare::prepare_request, spec::RunSpec};
use serde_json::{Value, json};

use crate::provider::ProviderConfig;
use crate::{DriveOutcome, RigSession, RuntimeError, ToolRevision};
use crate::{policy::ExecutionPolicy, tools::ToolRegistry};

const MODEL_SCOPE: &str = "model:completion";
pub const ARTIFACT_TOOL: &str = "artifact_put";
pub const ARTIFACT_SCOPE: &str = "tool:artifact_put";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolAvailability {
    Ready,
    Unavailable { wait_key: String },
}

pub struct ModelExecution {
    pub turn: ModelTurn,
    /// Host/provider usage and opaque receipt, never credentials. A timeout has
    /// no settlement receipt; the host must reconcile possible billing.
    pub usage: Value,
    pub provider_receipt: Option<String>,
}

pub trait WorkerHost: Sync {
    /// Override for server-owned quota/model routing or streaming. The host may
    /// publish deltas on an attempt-scoped LiveEvents bus, but returns a complete
    /// turn only once. Subscriber disconnect is independent from this future.
    /// Key reservation/settlement by the supplied durable effect identity;
    /// never infer a refund from timeout. This callback must not access Store
    /// because the launch permit holds its transaction and authority locks.
    fn execute_model(
        &self,
        grant: &ActorGrant,
        account: &nazz_core::AccountReference,
        _effect: &nazz_core::EffectClaim,
        provider: &ProviderConfig,
        request: CompletionRequest,
        prepared: rig::run::prepare::PreparedRequest,
    ) -> impl Future<Output = Result<ModelExecution, RuntimeError>> + Send {
        async move {
            let secret = self.credential(account)?;
            let model = provider.model(grant, secret.clone())?;
            let response = model
                .call(request)
                .await
                .map_err(|_| RuntimeError::NeedsReconcile)?;
            let turn = ModelTurn::from_response(&response, &prepared);
            let usage =
                serde_json::to_value(response.usage).map_err(|_| RuntimeError::NeedsReconcile)?;
            let serialized =
                serde_json::to_string(&turn).map_err(|_| RuntimeError::NeedsReconcile)?;
            if serialized.contains(&secret) {
                return Err(RuntimeError::NeedsReconcile);
            }
            Ok(ModelExecution {
                turn,
                usage,
                provider_receipt: None,
            })
        }
    }

    /// Trusted host observation before any launch or claim. A later disconnect
    /// after launch is unknown and must reconcile, never park as unstarted.
    fn tool_availability(
        &self,
        _grant: &ActorGrant,
        _attempt: &AttemptId,
        _name: &str,
        _args: &Value,
    ) -> Result<ToolAvailability, RuntimeError> {
        Ok(ToolAvailability::Ready)
    }

    /// Resolve host credentials for this turn; never from durable parameters.
    fn credential(&self, account: &nazz_core::AccountReference) -> Result<String, RuntimeError>;
    /// Completion or drop must leave no locally executing work behind.
    /// Hosts that spawn children/tasks must join their teardown before returning;
    /// an unobserved remote outcome remains in the durable effect ledger.
    fn execute_tool(
        &self,
        grant: &ActorGrant,
        attempt: &AttemptId,
        name: String,
        args: Value,
    ) -> impl Future<Output = Result<String, RuntimeError>> + Send;
}

pub struct NativeWorker {
    pub holder: String,
    pub fence: String,
    pub provider: ProviderConfig,
    pub preamble: String,
    pub tool: ToolRevision,
    pub schema: Value,
    pub agent_id: nazz_core::AgentId,
}

impl NativeWorker {
    /// Process at most one durable admission, without a Hub/client connection.
    /// Returns false on an empty queue or another live owner's exclusion.
    pub async fn run_next(
        &self,
        store: &impl ExecutionStore,
        journal: &impl EffectJournal,
        grant: &ActorGrant,
        host: &impl WorkerHost,
    ) -> Result<bool, RuntimeError> {
        self.run_next_configured(
            store,
            journal,
            grant,
            host,
            None,
            ExecutionPolicy::default(),
        )
        .await
    }

    pub async fn run_next_configured(
        &self,
        store: &impl ExecutionStore,
        journal: &impl EffectJournal,
        grant: &ActorGrant,
        host: &impl WorkerHost,
        registry: Option<&ToolRegistry>,
        policy: ExecutionPolicy,
    ) -> Result<bool, RuntimeError> {
        let policy = policy.validate()?;
        if let Some(registry) = registry {
            registry.definitions()?;
        }
        store.reconcile_dispatch(grant).await?;
        let snapshot = store.scope_snapshot(grant).await?;
        for view in snapshot.views {
            // Inspect cancellation even when dispatch reconciliation has moved
            // the outbox to cancelled/held. Never attest another live owner's
            // execution stopped merely because its client or Hub detached.
            let Some(row) = store.read_attempt(grant, &view.attempt_id).await? else {
                continue;
            };
            if row.status == AttemptStatus::CancelRequested {
                if store
                    .suspended_is_quiescent(grant, &view.attempt_id, row.generation)
                    .await?
                {
                    self.stop_quiescent(store, grant, &view.attempt_id, row.generation)
                        .await?;
                    return Ok(true);
                }
                match store
                    .claim_lease(
                        grant,
                        &view.attempt_id,
                        row.generation,
                        &self.holder,
                        policy.lease,
                    )
                    .await
                {
                    Ok(()) => {
                        // A current-generation claim can only be a fresh queued
                        // admission or this execution owner; expired predecessor
                        // leases require advancement and deliberately stay held.
                        self.stop_quiescent(store, grant, &view.attempt_id, row.generation)
                            .await?;
                        return Ok(true);
                    }
                    Err(
                        StoreError::LeaseHeld
                        | StoreError::StaleGeneration
                        | StoreError::NeedsReconcileHold,
                    ) => continue,
                    Err(err) => return Err(err.into()),
                }
            }
            if !matches!(
                view.phase,
                DispatchPhase::Pending
                    | DispatchPhase::Claimed
                    | DispatchPhase::Started
                    | DispatchPhase::EffectPersisted
            ) {
                continue;
            }
            if !matches!(
                row.status,
                AttemptStatus::Queued | AttemptStatus::Running | AttemptStatus::AwaitingInput
            ) {
                continue;
            }
            let previous_generation = row.generation;
            let generation = match store
                .claim_lease(
                    grant,
                    &view.attempt_id,
                    row.generation,
                    &self.holder,
                    policy.lease,
                )
                .await
            {
                Ok(()) => row.generation,
                Err(StoreError::StaleGeneration) => {
                    match store
                        .claim_lease(
                            grant,
                            &view.attempt_id,
                            row.generation + 1,
                            &self.holder,
                            policy.lease,
                        )
                        .await
                    {
                        Ok(()) => row.generation + 1,
                        Err(StoreError::LeaseHeld | StoreError::NeedsReconcileHold) => {
                            return Ok(false);
                        }
                        Err(err) => return Err(err.into()),
                    }
                }
                Err(StoreError::LeaseHeld | StoreError::NeedsReconcileHold) => return Ok(false),
                Err(err) => return Err(err.into()),
            };
            let intent = match store
                .poll_checkpoint_dispatch(grant, &self.holder, &self.fence, policy.lease)
                .await?
            {
                PollOutcome::Execute(intent) if intent.attempt_id == view.attempt_id => intent,
                PollOutcome::Empty => return Ok(false),
                _ => return Err(RuntimeError::StaleAuthority),
            };
            let outcome = tokio::time::timeout(
                policy.slice,
                self.drive(
                    store,
                    journal,
                    grant,
                    host,
                    intent,
                    generation,
                    previous_generation,
                    registry,
                    policy,
                ),
            )
            .await
            .map_err(|_| RuntimeError::NeedsReconcile)
            .and_then(|result| result);
            // drive and every inline host/provider future have now returned or
            // been dropped. NativeWorker spawns no detached tasks/OS children.
            // A remote outcome may still be unknown: Store unions that ledger
            // into StopReceipt and settles needs_reconcile, never clean cancel.
            let row = store
                .read_attempt(grant, &view.attempt_id)
                .await?
                .ok_or(RuntimeError::StaleAuthority)?;
            if row.generation == generation && row.status == AttemptStatus::CancelRequested {
                self.stop_quiescent(store, grant, &view.attempt_id, generation)
                    .await?;
            } else {
                outcome?;
            }
            return Ok(true);
        }
        Ok(false)
    }

    /// Called only after this owner's local execution is quiescent, or after
    /// acquiring an unowned current-generation admission without executing it.
    async fn stop_quiescent(
        &self,
        store: &impl ExecutionStore,
        grant: &ActorGrant,
        attempt: &AttemptId,
        generation: u64,
    ) -> Result<(), RuntimeError> {
        let records = store
            .read_checkpoints(grant, attempt, generation, -1)
            .await?;
        let step = records.last().map_or(0, |record| record.step.max(0) as u64);
        let status = store
            .commit_stop(
                grant,
                &StopReceipt {
                    attempt_id: attempt.clone(),
                    generation,
                    step,
                    owned_pids: Vec::new(),
                    observed_stop: true,
                    unknown_effects: Vec::new(),
                },
            )
            .await?;
        eprintln!(
            "agent-stop: attempt={} generation={} status={status:?} local_quiescent=true",
            attempt.as_str(),
            generation
        );
        Ok(())
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "Keep execution authority and checkpoint inputs explicit."
    )]
    async fn drive(
        &self,
        store: &impl ExecutionStore,
        journal: &impl EffectJournal,
        grant: &ActorGrant,
        host: &impl WorkerHost,
        intent: DispatchIntent,
        generation: u64,
        previous_generation: u64,
        registry: Option<&ToolRegistry>,
        policy: ExecutionPolicy,
    ) -> Result<(), RuntimeError> {
        let attempt = &intent.attempt_id;
        let context = store
            .resolve_execution_context(grant, attempt, generation, &self.holder)
            .await?;
        if context.capsule().agent_id != self.agent_id
            || context.capsule().preamble != self.preamble
        {
            return Err(RuntimeError::StaleAuthority);
        }
        let account = store.read_account_use(grant, attempt).await?;
        if account != *context.account() || account.provider != self.provider.model {
            return Err(RuntimeError::StaleAuthority);
        }
        let mut binding = self.execution_binding();
        let model_revision = registry
            .map(ToolRegistry::digest)
            .unwrap_or_else(|| self.tool.revision.clone());
        if let Some(registry) = registry {
            binding["tool_registry"] = json!(registry);
        }
        let mut records = Vec::new();
        for prior in 1..=previous_generation {
            records.extend(store.read_checkpoints(grant, attempt, prior, -1).await?);
        }
        records.sort_by_key(|record| (record.step, record.generation));
        let mut steps: Vec<Value> = Vec::new();
        for record in &records {
            if let Some(effects) = record.payload.get("agent_effects") {
                for effect in effects.as_array().ok_or(RuntimeError::NeedsReconcile)? {
                    steps.push(json!({"step":record.step,"effect":effect}));
                }
            }
        }
        let mut step = records.last().map_or(0, |record| record.step + 1);
        let mut session = if let Some(last) = records.last() {
            if last.payload["execution_binding"] != binding {
                return Err(RuntimeError::StaleAuthority);
            }
            if let Some(registry) = registry {
                RigSession::restore_with_tools(last, &context, registry.clone())?
            } else {
                RigSession::restore(last, &context, self.tool.clone())?
                    .with_parameters(self.schema.clone())
            }
        } else {
            if let Some(registry) = registry {
                RigSession::start_with_tools(&context, registry.clone())?
            } else {
                RigSession::start(&context, self.tool.clone())?.with_parameters(self.schema.clone())
            }
        };
        session.tool_deadline = policy.tool;
        store
            .mark_dispatch_started(grant, attempt, generation, &self.holder, &self.fence)
            .await?;
        loop {
            // Renewal and current persisted status happen before every boundary;
            // a client detach has no state transition here.
            let row = store
                .read_attempt(grant, attempt)
                .await?
                .ok_or(RuntimeError::StaleAuthority)?;
            if row.status == AttemptStatus::CancelRequested
                || row.status == AttemptStatus::Cancelled
            {
                return Err(RuntimeError::Cancelled);
            }
            store
                .claim_lease(grant, attempt, generation, &self.holder, policy.lease)
                .await?;
            // Rig's AwaitingModel is not re-entrant: persist the resumable
            // pre-step state, then let the model effect receipt guard replay.
            self.save(store, grant, &session, step, &binding, &[], None)
                .await?;
            step += 1;
            let next = session
                .run
                .next_step()
                .map_err(|_| RuntimeError::Rig("Rig step refused".into()))?;
            match next {
                AgentRunStep::CallModel {
                    prompt,
                    history,
                    turn,
                } => {
                    let definitions = session.definitions()?;
                    let mut spec = RunSpec::new();
                    spec.preamble = session.preamble.clone();
                    spec.max_tokens = Some(4096);
                    let prepared = prepare_request(
                        &spec,
                        &self.provider.preparation_capabilities(grant)?,
                        &history,
                        definitions,
                        None,
                        None,
                    )
                    .map_err(|_| RuntimeError::Rig("model request refused".into()))?;
                    let request = prepared
                        .clone()
                        .apply(CompletionRequest::new(prompt.clone()));
                    nazz_core::serialized_input_bytes(&request, session.max_model_input_bytes)
                        .map_err(StoreError::from)?;
                    session.run.advertise_tools(turn, prepared.tools.clone());
                    let args = json!({"prepared":prepared,"prompt":prompt});
                    let traced =
                        trace_effect_identity(attempt, &format!("model-turn-{turn}"), &args);
                    store
                        .bind_approval(
                            grant,
                            attempt,
                            generation,
                            &self.holder,
                            MODEL_SCOPE,
                            &model_revision,
                            &traced.canonical.args_digest,
                        )
                        .await?;
                    let (response, effect) = match store
                        .claim_traced_effect(
                            grant,
                            &self.holder,
                            MODEL_SCOPE,
                            &model_revision,
                            attempt,
                            generation,
                            "native_model",
                            &traced,
                        )
                        .await?
                    {
                        TracedClaim::KnownReceipt(binding) => {
                            if binding.scope != MODEL_SCOPE
                                || binding.tool_revision != model_revision
                                || !traced.contains_digest(&binding.claim.args_digest)
                            {
                                return Err(RuntimeError::StaleAuthority);
                            }
                            let receipt = binding
                                .claim
                                .receipt
                                .as_ref()
                                .and_then(Value::as_str)
                                .ok_or(RuntimeError::NeedsReconcile)?;
                            let response = decode_model_receipt(receipt)?;
                            (
                                response,
                                effect_value(&binding.claim, &traced.call_id, &model_revision),
                            )
                        }
                        TracedClaim::Fresh(binding) => {
                            let launched = store
                                .with_effect_launch(
                                    grant,
                                    &self.holder,
                                    MODEL_SCOPE,
                                    &model_revision,
                                    &binding.claim,
                                    policy.model,
                                    || async {
                                        eprintln!(
                                            "agent-model: attempt={} generation={} turn={} step={} outcome=started",
                                            attempt.as_str(), generation, turn, step
                                        );
                                        let execution = host.execute_model(grant, context.account(), &binding.claim,
                                            &self.provider, request, prepared.clone()).await;
                                        eprintln!("agent-model: attempt={} generation={} turn={} step={} outcome={}",
                                            attempt.as_str(), generation, turn, step,
                                            if execution.is_ok() { "response" } else { "refused" });
                                        let execution = execution.map_err(|_| ())?;
                                        let serialized = serde_json::to_string(&execution.turn).map_err(|_| ())?;
                                        // Usage is a durable sidecar to the model receipt; settlement
                                        // belongs to the trusted host, keyed by this logical model call.
                                        Ok::<_, ()>(if registry.is_some() { serde_json::json!({"turn":serialized,
                                            "usage":execution.usage,"provider_receipt":execution.provider_receipt}).to_string() }
                                            else { serialized })

                                    },
                                )
                                .await?;
                            let text = match launched {
                                EffectLaunch::Ready(text) => text,
                                EffectLaunch::Blocked(err) => return Err(err.into()),
                                EffectLaunch::Attempted => {
                                    return Err(RuntimeError::NeedsReconcile);
                                }
                            };
                            let mut claim = binding.claim;
                            claim.state = EffectState::Receipt;
                            claim.receipt = Some(Value::String(text.clone()));
                            if store
                                .settle_launched_effect(
                                    grant,
                                    &self.holder,
                                    MODEL_SCOPE,
                                    &model_revision,
                                    &claim,
                                )
                                .await?
                                != LaunchSettlement::Receipt
                            {
                                return Err(RuntimeError::NeedsReconcile);
                            }
                            (
                                decode_model_receipt(&text)?,
                                effect_value(&claim, &traced.call_id, &model_revision),
                            )
                        }
                        _ => return Err(RuntimeError::NeedsReconcile),
                    };
                    session
                        .run
                        .model_response(response)
                        .map_err(|_| RuntimeError::Rig("model response refused".into()))?;
                    self.save(
                        store,
                        grant,
                        &session,
                        step,
                        &binding,
                        std::slice::from_ref(&effect),
                        None,
                    )
                    .await?;
                    steps.push(json!({"step":step,"effect":effect}));
                    step += 1;
                }
                AgentRunStep::CallTools { calls } => {
                    if calls.len() > 16 {
                        return Err(RuntimeError::Rig("tool batch exceeds host bound".into()));
                    }
                    self.save(store, grant, &session, step, &binding, &[], None)
                        .await?;
                    step += 1;
                    // Resolve every pending tool before the first effect in a batch.
                    // If any host resource is offline, release the worker durably.
                    for call in calls
                        .iter()
                        .filter(|call| call.preresolved_result.is_none())
                    {
                        let name = call.tool_call.function.name.as_str();
                        if let Some(registry) = registry {
                            registry.get(name)?;
                        } else if name != self.tool.name {
                            return Err(RuntimeError::StaleAuthority);
                        }
                        let trace = trace_effect_identity(
                            attempt,
                            &call.tool_call.id.to_string(),
                            &call.tool_call.function.arguments_value(),
                        );
                        let mut known = false;
                        for identity in trace.identities() {
                            if let Some(effect) =
                                store.read_effect(grant, &identity.effect_id).await?
                            {
                                if effect.state != EffectState::Receipt {
                                    return Err(RuntimeError::NeedsReconcile);
                                }
                                known = true;
                            }
                        }
                        if known {
                            continue;
                        } // Feed receipts even while the resource is offline.
                        if let ToolAvailability::Unavailable { wait_key } = host.tool_availability(
                            grant,
                            attempt,
                            name,
                            &call.tool_call.function.arguments_value(),
                        )? {
                            let mut checkpoint = serde_json::to_value(session.checkpoint()?)
                                .map_err(|_| RuntimeError::StaleAuthority)?;
                            checkpoint["execution_binding"] = binding.clone();
                            store
                                .suspend_before_launch(
                                    grant,
                                    attempt,
                                    generation,
                                    &self.holder,
                                    step,
                                    &checkpoint,
                                    &wait_key,
                                )
                                .await?;
                            return Ok(());
                        }
                    }
                    let mut traced = Vec::new();
                    for call in calls
                        .iter()
                        .filter(|call| call.preresolved_result.is_none())
                    {
                        let name = call.tool_call.function.name.as_str();
                        let (scope, revision) = if let Some(registry) = registry {
                            let tool = registry.get(name)?;
                            (tool.scope.as_str(), tool.revision.as_str())
                        } else {
                            (ARTIFACT_SCOPE, self.tool.revision.as_str())
                        };
                        if registry.is_none() {
                            artifact_bytes(&call.tool_call.function.arguments_value())?;
                        }
                        let identity = trace_effect_identity(
                            attempt,
                            &call.tool_call.id.to_string(),
                            &call.tool_call.function.arguments_value(),
                        );
                        store
                            .bind_approval(
                                grant,
                                attempt,
                                generation,
                                &self.holder,
                                scope,
                                revision,
                                &identity.canonical.args_digest,
                            )
                            .await?;
                        traced.push((identity, revision.to_string()));
                    }
                    let outcome = session
                        .reconcile_tools(
                            journal,
                            store,
                            grant,
                            &self.holder,
                            ARTIFACT_SCOPE,
                            |name, args| host.execute_tool(grant, attempt, name, args),
                        )
                        .await?;
                    if matches!(outcome, DriveOutcome::NeedsReconcile) {
                        return Err(RuntimeError::NeedsReconcile);
                    }
                    let mut effects = Vec::new();
                    for (trace, revision) in traced {
                        let claim = store
                            .read_effect(grant, &trace.canonical.effect_id)
                            .await?
                            .ok_or(RuntimeError::NeedsReconcile)?;
                        if claim.state != EffectState::Receipt {
                            return Err(RuntimeError::NeedsReconcile);
                        }
                        effects.push(effect_value(&claim, &trace.call_id, &revision));
                    }
                    self.save(store, grant, &session, step, &binding, &effects, None)
                        .await?;
                    steps.extend(
                        effects
                            .into_iter()
                            .map(|effect| json!({"step":step,"effect":effect})),
                    );
                    step += 1;
                }
                AgentRunStep::Done(response) => {
                    let artifacts = if let Some(registry) = registry {
                        let mut artifact_steps = Vec::new();
                        for step in &steps {
                            let id = step["effect"]["effect_id"]
                                .as_str()
                                .ok_or(RuntimeError::NeedsReconcile)?;
                            let claim = store
                                .read_effect(grant, &nazz_core::EffectId::new(id))
                                .await?
                                .ok_or(RuntimeError::NeedsReconcile)?;
                            if registry
                                .get(&claim.tool_name)
                                .is_ok_and(|tool| tool.artifact_output)
                            {
                                artifact_steps.push(step.clone());
                            }
                        }
                        artifacts_from_steps(&artifact_steps)?
                    } else {
                        artifacts_from_steps(&steps)?
                    };
                    let done = json!({"output":response.output(),"artifacts":artifacts});
                    self.save(store, grant, &session, step, &binding, &[], Some(&done))
                        .await?;
                    let result = json!({"output":done["output"],"steps":steps,"artifacts":done["artifacts"]});
                    store
                        .report_agent_dispatch(
                            grant,
                            attempt,
                            generation,
                            &self.holder,
                            &self.fence,
                            &result,
                        )
                        .await?;
                    store
                        .ack_dispatch(grant, attempt, generation, &self.holder, &self.fence)
                        .await?;
                    return Ok(());
                }
            }
        }
    }

    fn execution_binding(&self) -> Value {
        json!({"provider":self.provider.api,"model":self.provider.model,"base_url":self.provider.base_url,
            "endpoint":self.provider.endpoint,"preamble":self.preamble,"tool_revision":self.tool.revision,"schema":self.schema})
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "Keep execution authority and checkpoint inputs explicit."
    )]
    async fn save(
        &self,
        store: &impl ExecutionStore,
        grant: &ActorGrant,
        session: &RigSession,
        step: i64,
        binding: &Value,
        effects: &[Value],
        done: Option<&Value>,
    ) -> Result<(), RuntimeError> {
        let mut checkpoint = serde_json::to_value(session.checkpoint()?)
            .map_err(|_| RuntimeError::StaleAuthority)?;
        checkpoint["execution_binding"] = binding.clone();
        if !effects.is_empty() {
            checkpoint["agent_effects"] = json!(effects);
        }
        if let Some(done) = done {
            checkpoint["agent_done"] = done.clone();
        }
        store
            .put_checkpoint(
                grant,
                &session.attempt_id,
                session.generation,
                &self.holder,
                step,
                CHECKPOINT_FORMAT_VERSION,
                &checkpoint,
            )
            .await?;
        Ok(())
    }
}

fn effect_value(claim: &nazz_core::EffectClaim, call_id: &str, revision: &str) -> Value {
    json!({"effect_id":claim.effect_id,"call_id":call_id,"args_digest":claim.args_digest,
        "tool_revision":revision,"receipt":claim.receipt})
}

fn artifacts_from_steps(steps: &[Value]) -> Result<Vec<Value>, RuntimeError> {
    let mut artifacts = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for step in steps {
        let effect = &step["effect"];
        let text = effect["receipt"]
            .as_str()
            .ok_or(RuntimeError::NeedsReconcile)?;
        // General tools may return text. Artifact receipts remain validated
        // against their exact ledger entry by Store at final publication.
        let Ok(receipt) = serde_json::from_str::<Value>(text) else {
            continue;
        };
        if receipt.get("artifact_id").is_some()
            && seen.insert(receipt["artifact_id"].clone().to_string())
        {
            artifacts.push(
                json!({"effect_id":effect["effect_id"],"artifact_id":receipt["artifact_id"],
                "object_key":receipt["object_key"]}),
            );
        }
    }
    Ok(artifacts)
}

pub fn artifact_schema() -> Value {
    json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer","minimum":0,"maximum":255},"maxItems":8388608}},"required":["bytes"],"additionalProperties":false})
}

/// Validate the host's one bounded tool input before any external effect.
pub fn artifact_bytes(args: &Value) -> Result<Vec<u8>, RuntimeError> {
    let object = args.as_object().ok_or(RuntimeError::StaleAuthority)?;
    if object.len() != 1 {
        return Err(RuntimeError::StaleAuthority);
    }
    let bytes = args["bytes"]
        .as_array()
        .filter(|bytes| bytes.len() <= 8 * 1024 * 1024)
        .ok_or(RuntimeError::StaleAuthority)?;
    bytes
        .iter()
        .map(|byte| {
            byte.as_u64()
                .and_then(|n| u8::try_from(n).ok())
                .ok_or(RuntimeError::StaleAuthority)
        })
        .collect()
}

fn decode_model_receipt(text: &str) -> Result<ModelTurn, RuntimeError> {
    let value: Value = serde_json::from_str(text).map_err(|_| RuntimeError::NeedsReconcile)?;
    let turn = value.get("turn").and_then(Value::as_str).unwrap_or(text);
    serde_json::from_str(turn).map_err(|_| RuntimeError::NeedsReconcile)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn artifact_boundary_preserves_binary_bytes_and_refuses_authority_fields() {
        assert_eq!(
            artifact_bytes(&json!({"bytes":[0,255,13,10]})).unwrap(),
            [0, 255, 13, 10]
        );
        for bad in [
            json!({"bytes":[256]}),
            json!({"bytes":[-1]}),
            json!({"bytes":[1.5]}),
            json!({"bytes":[1],"object_key":"foreign"}),
            json!({"bytes":[1],"tenant_id":"foreign"}),
        ] {
            assert!(artifact_bytes(&bad).is_err());
        }
    }

    #[test]
    fn crash_before_model_response_restores_a_reenterable_boundary() {
        let tool = ToolRevision {
            revision: "r".into(),
            name: ARTIFACT_TOOL.into(),
            description: "artifact".into(),
        };
        let mut live =
            RigSession::start_unbound("prompt", AttemptId::new("attempt"), 1, tool.clone())
                .unwrap();
        let checkpoint = serde_json::to_value(live.checkpoint().unwrap()).unwrap();
        assert!(matches!(
            live.run.next_step().unwrap(),
            AgentRunStep::CallModel { turn: 1, .. }
        ));
        // A crash loses the in-memory pending state. Restoring the pre-step
        // checkpoint must reproduce the same logical turn, not skip/finalize it.
        let mut resumed =
            RigSession::restore_unbound(&checkpoint, AttemptId::new("attempt"), 2, tool).unwrap();
        assert!(matches!(
            resumed.run.next_step().unwrap(),
            AgentRunStep::CallModel { turn: 1, .. }
        ));
    }
}
