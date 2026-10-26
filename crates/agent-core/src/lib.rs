//! Host-neutral contracts for durable agent execution.
//!
//! Scope is resolved by the host into [`ActorGrant`]. Callers never promote a
//! client-supplied tenant id into authority.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;
mod canonical;
mod identity;
pub use canonical::{
    ExistingRequestDisposition, canonical_bytes, disposition_for_existing_request,
};
pub use identity::{
    EffectIdentity, LogicalCall, TracedEffectIdentity, ordered_object_bytes, trace_effect_identity,
    trace_effect_identity_from_json,
};
mod context;
pub use context::*;
mod host_bind;
pub use host_bind::{
    BindError, HostBindInput, PreparedHostBinding, RequestProjection, StoreReceiptCheck,
    UntrustedScope, VerifiedStoreReceipt, prepare_host_binding,
};

pub const HARNESS_FORMAT: u32 = 2;
pub const HARNESS_FORMAT_V1: u32 = 1;
/// Multi-tool runtime checkpoint envelope; canonical client wire stays format 2.
pub const TOOL_REGISTRY_FORMAT: u32 = 3;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TenantId(String);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WorkspaceId(String);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ActorId(String);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RequestId(String);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AttemptId(String);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EffectId(String);

impl TenantId {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl WorkspaceId {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl ActorId {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl RequestId {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl AttemptId {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
    pub fn generate() -> Self {
        Self(Uuid::new_v4().to_string())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl EffectId {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Immutable grant minted by the authenticated host. Not a client body field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActorGrant {
    pub tenant_id: TenantId,
    pub workspace_id: WorkspaceId,
    pub actor_id: ActorId,
    pub revision: u64,
    pub revoked: bool,
}

impl ActorGrant {
    pub fn covers(&self, tenant: &TenantId, workspace: &WorkspaceId) -> bool {
        !self.revoked && &self.tenant_id == tenant && &self.workspace_id == workspace
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ScopeError {
    #[error("grant revoked or does not cover the host-resolved scope")]
    Denied,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalRequest {
    pub request_id: RequestId,
    pub tenant_id: TenantId,
    pub workspace_id: WorkspaceId,
    pub actor_id: ActorId,
    pub kind: String,
    pub body: serde_json::Value,
}

impl CanonicalRequest {
    pub fn digest(&self) -> String {
        canonical::canonical_digest(self)
    }
}

/// Authority fields come from the authenticated grant. Payload is parameters only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalAdmission {
    pub tenant_id: TenantId,
    pub workspace_id: WorkspaceId,
    pub actor_id: ActorId,
    pub request_id: RequestId,
    pub payload: serde_json::Value,
}

impl CanonicalAdmission {
    pub fn from_grant(
        grant: &ActorGrant,
        request_id: RequestId,
        payload: serde_json::Value,
    ) -> Self {
        Self {
            tenant_id: grant.tenant_id.clone(),
            workspace_id: grant.workspace_id.clone(),
            actor_id: grant.actor_id.clone(),
            request_id,
            payload,
        }
    }
    pub fn digest(&self) -> String {
        canonical::canonical_digest(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionReceipt {
    pub request_id: RequestId,
    pub digest: String,
    pub attempt_id: AttemptId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptStatus {
    Queued,
    Running,
    AwaitingInput,
    Succeeded,
    CancelRequested,
    Cancelled,
    NeedsReconcile,
    Blocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectState {
    Claimed,
    Receipt,
    NeedsReconcile,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectClaim {
    pub effect_id: EffectId,
    pub attempt_id: AttemptId,
    pub generation: u64,
    pub tool_name: String,
    pub args_digest: String,
    pub state: EffectState,
    pub receipt: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialRoute {
    ApiKey,
    SiwcResponses,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderApi {
    OpenAiResponses,
    OpenAiChatCompletions,
    AnthropicMessages,
    CustomCompatible,
}

/// Exact host-scoped destination. Private/loopback/metadata require an owner
/// grant that names this scheme, host, and port. No blanket private bypass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointGrant {
    pub tenant_id: TenantId,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub route: CredentialRoute,
    pub allow_private: bool,
    /// Optional pinned peer. When set, every DNS answer must equal it.
    pub pinned_peer: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderDispatch {
    pub tenant_id: TenantId,
    pub api: ProviderApi,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub credential: CredentialRoute,
    pub resolved_peers: Vec<String>,
    pub redirect_count: u32,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BrokerDeny {
    #[error("endpoint is not an exact grant for this tenant")]
    UngrantedEndpoint,
    #[error("dispatch tenant does not match the endpoint grant")]
    TenantMismatch,
    #[error("private, loopback, link-local, or metadata destination denied")]
    PrivateDestination,
    #[error("resolved peer does not match the pinned grant")]
    Rebinding,
    #[error("redirects are denied")]
    Redirect,
    #[error("SIWC credential is only eligible for documented Responses requests")]
    SiwcRouteMismatch,
    #[error("custom endpoint cannot receive an unrelated provider credential")]
    CredentialRouteMismatch,
    #[error("resolver peer is not a canonical IP literal")]
    NoncanonicalPeer,
}
pub fn authorize_dispatch(
    grant: &EndpointGrant,
    request: &ProviderDispatch,
) -> Result<(), BrokerDeny> {
    if grant.tenant_id != request.tenant_id {
        return Err(BrokerDeny::TenantMismatch);
    }
    if grant.scheme != request.scheme || grant.host != request.host || grant.port != request.port {
        return Err(BrokerDeny::UngrantedEndpoint);
    }
    if request.redirect_count > 0 {
        return Err(BrokerDeny::Redirect);
    }
    if grant.route != request.credential {
        return Err(BrokerDeny::CredentialRouteMismatch);
    }
    if request.credential == CredentialRoute::SiwcResponses
        && request.api != ProviderApi::OpenAiResponses
    {
        return Err(BrokerDeny::SiwcRouteMismatch);
    }
    if request.resolved_peers.is_empty() && !exact_pinned_ip(grant) {
        return Err(BrokerDeny::Rebinding);
    }
    for peer in &request.resolved_peers {
        let Some(ip) = canonical_ip(peer) else {
            return Err(BrokerDeny::NoncanonicalPeer);
        };
        if let Some(pinned) = &grant.pinned_peer
            && peer != pinned
        {
            return Err(BrokerDeny::Rebinding);
        }
        if is_private_ip(&normalized_ip(ip)) && !private_peer_allowed(grant, peer) {
            return Err(BrokerDeny::PrivateDestination);
        }
    }
    if noncanonical_ip_literal(&request.host) {
        return Err(BrokerDeny::NoncanonicalPeer);
    }
    if is_private_or_metadata(&request.host) && !grant.allow_private {
        return Err(BrokerDeny::PrivateDestination);
    }
    Ok(())
}

fn exact_pinned_ip(grant: &EndpointGrant) -> bool {
    grant.pinned_peer.as_deref() == Some(grant.host.as_str()) && canonical_ip(&grant.host).is_some()
}

fn private_peer_allowed(grant: &EndpointGrant, peer: &str) -> bool {
    if !grant.allow_private {
        return false;
    }
    if peer == grant.host {
        return true;
    }
    match (canonical_ip(peer), canonical_ip(&grant.host)) {
        (Some(peer_ip), Some(host_ip)) => normalized_ip(peer_ip) == normalized_ip(host_ip),
        _ => false,
    }
}

fn canonical_ip(value: &str) -> Option<std::net::IpAddr> {
    if value.is_empty()
        || value.contains('%')
        || value.contains('/')
        || value.chars().any(|c| c.is_whitespace())
    {
        return None;
    }
    if value.contains('.') && !value.contains(':') {
        return canonical_v4(value).map(std::net::IpAddr::V4);
    }
    if value.contains(':') {
        let ip = value.parse::<std::net::Ipv6Addr>().ok()?;
        if let Some((_, tail)) = value.rsplit_once(':')
            && tail.contains('.')
            && canonical_v4(tail).is_none()
        {
            return None;
        }
        return Some(std::net::IpAddr::V6(ip));
    }
    None
}

fn canonical_v4(value: &str) -> Option<std::net::Ipv4Addr> {
    let mut parts = value.split('.');
    let mut octets = [0u8; 4];
    for octet in &mut octets {
        let part = parts.next()?;
        if !canonical_octet(part) {
            return None;
        }
        *octet = part.parse().ok()?;
    }
    if parts.next().is_some() {
        return None;
    }
    Some(std::net::Ipv4Addr::new(
        octets[0], octets[1], octets[2], octets[3],
    ))
}

fn canonical_octet(part: &str) -> bool {
    if part.is_empty() || part.len() > 3 || (part.len() > 1 && part.starts_with('0')) {
        return false;
    }
    part.bytes().all(|byte| byte.is_ascii_digit())
}

fn normalized_ip(ip: std::net::IpAddr) -> std::net::IpAddr {
    match ip {
        std::net::IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(std::net::IpAddr::V4)
            .unwrap_or(std::net::IpAddr::V6(v6)),
        other => other,
    }
}

fn noncanonical_ip_literal(value: &str) -> bool {
    let host = value.split('%').next().unwrap_or(value);
    if host.is_empty() || value.contains('%') {
        return value.contains('%');
    }
    let named = host.chars().any(|ch| ch.is_ascii_alphabetic()) && !host.contains(':');
    !named && canonical_ip(host).is_none()
}

fn is_private_ip(ip: &std::net::IpAddr) -> bool {
    match normalized_ip(*ip) {
        std::net::IpAddr::V4(ip) => {
            ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_unspecified()
                || ip.octets() == [169, 254, 169, 254]
        }
        std::net::IpAddr::V6(ip) => {
            ip.is_loopback()
                || ip.is_unspecified()
                || (ip.segments()[0] & 0xffc0) == 0xfe80
                || (ip.segments()[0] & 0xfe00) == 0xfc00
        }
    }
}

fn is_private_or_metadata(value: &str) -> bool {
    let host = value.split('%').next().unwrap_or(value);
    if host == "localhost" || host == "metadata.google.internal" {
        return true;
    }
    canonical_ip(host).is_some_and(|ip| is_private_ip(&ip))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StopReceipt {
    pub attempt_id: AttemptId,
    pub generation: u64,
    pub step: u64,
    pub owned_pids: Vec<u32>,
    pub observed_stop: bool,
    pub unknown_effects: Vec<EffectId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Settlement {
    Migrated,
    Current,
    OldWorkerHolds,
}

/// Read only the format integer. Unknown newer payloads are not guessed.
pub fn harness_format_of(value: &serde_json::Value) -> Option<u32> {
    value.get("harness_format")?.as_u64()?.try_into().ok()
}

pub fn settle_harness_format(stored: u32, worker_max: u32) -> Result<Settlement, &'static str> {
    if stored > worker_max {
        return Ok(Settlement::OldWorkerHolds);
    }
    if stored == HARNESS_FORMAT_V1 && worker_max >= HARNESS_FORMAT {
        return Ok(Settlement::Migrated);
    }
    if stored == worker_max {
        return Ok(Settlement::Current);
    }
    Err("unsupported harness format")
}

/// Stable args digest. Object keys are sorted. Struct field order is kept.
/// This does not follow `serde_json`'s `preserve_order` feature.
pub fn digest_json<T: Serialize>(value: &T) -> String {
    canonical::canonical_digest(value)
}

pub fn effect_id_for(attempt: &AttemptId, call_id: &str, args_digest: &str) -> EffectId {
    let raw = format!("{}|{call_id}|{args_digest}", attempt.as_str());
    EffectId::new(hex::encode(Sha256::digest(raw.as_bytes())))
}

pub fn settle_cancel(observed_stop: bool, unknown_effects: bool) -> AttemptStatus {
    if !observed_stop {
        return AttemptStatus::CancelRequested;
    }
    if unknown_effects {
        return AttemptStatus::NeedsReconcile;
    }
    AttemptStatus::Cancelled
}

/// SHA-256 of this file as compiled into the crate. Not a runtime disk read.
pub fn embedded_source_sha256() -> String {
    hex::encode(Sha256::digest(include_bytes!("lib.rs")))
}

pub fn wire_fixture() -> serde_json::Value {
    serde_json::json!({
        "source": "agent-core-serde",
        "source_files": [{"path": "crates/agent-core/src/lib.rs", "sha256": embedded_source_sha256()}],
        "harness_format": HARNESS_FORMAT,
        "events": sample_wire_events(),
        "newer_format_probe": {"harness_format": 9}
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireScope {
    pub harness_format: u32,
    pub event_id: String,
    pub cursor: u64,
    pub tenant_id: String,
    pub workspace_id: String,
    pub thread_id: String,
    pub task_id: String,
    pub attempt_id: String,
    pub ui_run_id: String,
    pub actor_id: String,
    pub agent_id: String,
    pub ui_terminal: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TextPhase {
    Start,
    Delta,
    End,
}

/// Client wire record. Field names match the settled TanStack decoder.
/// A newer `harness_format` is not interpreted as one of these variants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CanonicalEvent {
    Text {
        #[serde(flatten)]
        scope: WireScope,
        message_id: String,
        phase: TextPhase,
        delta: String,
    },
    Tool {
        #[serde(flatten)]
        scope: WireScope,
        effect_id: String,
        call_id: String,
        tool_name: String,
        args_digest: String,
        generation: u64,
        state: EffectState,
    },
    Artifact {
        #[serde(flatten)]
        scope: WireScope,
        artifact_id: String,
        object_key: String,
        media_type: String,
    },
    AwaitingInput {
        #[serde(flatten)]
        scope: WireScope,
        approval_id: String,
        effect_id: String,
        call_id: String,
        tool_name: String,
        args_digest: String,
        generation: u64,
    },
    Status {
        #[serde(flatten)]
        scope: WireScope,
        status: AttemptStatus,
    },
}

impl CanonicalEvent {
    pub fn harness_format(&self) -> u32 {
        match self {
            Self::Text { scope, .. }
            | Self::Tool { scope, .. }
            | Self::Artifact { scope, .. }
            | Self::AwaitingInput { scope, .. }
            | Self::Status { scope, .. } => scope.harness_format,
        }
    }
}

pub fn sample_wire_events() -> Vec<CanonicalEvent> {
    let scope = |event_id: &str, cursor: u64, terminal: bool| WireScope {
        harness_format: HARNESS_FORMAT,
        event_id: event_id.to_string(),
        cursor,
        tenant_id: "tenant-a".into(),
        workspace_id: "workspace-a".into(),
        thread_id: "thread-a".into(),
        task_id: "task-a".into(),
        attempt_id: "attempt-1".into(),
        ui_run_id: "ui-run-1".into(),
        actor_id: "actor-owner".into(),
        agent_id: "nana".into(),
        ui_terminal: terminal,
    };
    vec![
        CanonicalEvent::Text {
            scope: scope("evt-text", 1, false),
            message_id: "msg-1".into(),
            phase: TextPhase::Delta,
            delta: "café \"hi\"\n\t".into(),
        },
        CanonicalEvent::Tool {
            scope: scope("evt-tool", 2, false),
            effect_id: "effect-1".into(),
            call_id: "call-1".into(),
            tool_name: "read_file".into(),
            args_digest: "abc".into(),
            generation: 3,
            state: EffectState::Claimed,
        },
        CanonicalEvent::Artifact {
            scope: scope("evt-artifact", 3, false),
            artifact_id: "art-1".into(),
            object_key: "objects/a".into(),
            media_type: "text/plain".into(),
        },
        CanonicalEvent::AwaitingInput {
            scope: scope("evt-await", 4, false),
            approval_id: "apr-1".into(),
            effect_id: "effect-1".into(),
            call_id: "call-1".into(),
            tool_name: "read_file".into(),
            args_digest: "abc".into(),
            generation: 3,
        },
        CanonicalEvent::Status {
            scope: scope("evt-status", 5, true),
            status: AttemptStatus::Succeeded,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grant(
        route: CredentialRoute,
        host: &str,
        port: u16,
        private: bool,
        pin: Option<&str>,
    ) -> EndpointGrant {
        EndpointGrant {
            tenant_id: TenantId::new("tenant-a"),
            scheme: "https".into(),
            host: host.into(),
            port,
            route,
            allow_private: private,
            pinned_peer: pin.map(str::to_string),
        }
    }

    fn dispatch(
        api: ProviderApi,
        host: &str,
        port: u16,
        credential: CredentialRoute,
        peers: &[&str],
    ) -> ProviderDispatch {
        ProviderDispatch {
            tenant_id: TenantId::new("tenant-a"),
            api,
            scheme: "https".into(),
            host: host.into(),
            port,
            credential,
            resolved_peers: peers.iter().map(|peer| (*peer).to_string()).collect(),
            redirect_count: 0,
        }
    }

    #[test]
    fn siwc_allows_only_matching_responses_grant() {
        let grant = grant(
            CredentialRoute::SiwcResponses,
            "api.openai.com",
            443,
            false,
            Some("1.2.3.4"),
        );
        let ok = dispatch(
            ProviderApi::OpenAiResponses,
            "api.openai.com",
            443,
            CredentialRoute::SiwcResponses,
            &["1.2.3.4"],
        );
        assert!(authorize_dispatch(&grant, &ok).is_ok());
        let chat = dispatch(
            ProviderApi::OpenAiChatCompletions,
            "api.openai.com",
            443,
            CredentialRoute::SiwcResponses,
            &["1.2.3.4"],
        );
        assert_eq!(
            authorize_dispatch(&grant, &chat),
            Err(BrokerDeny::SiwcRouteMismatch)
        );
    }

    #[test]
    fn custom_endpoint_cannot_carry_siwc_and_rebinding_is_denied() {
        let grant = grant(
            CredentialRoute::ApiKey,
            "inference.example",
            443,
            false,
            Some("1.2.3.4"),
        );
        let custom = dispatch(
            ProviderApi::CustomCompatible,
            "inference.example",
            443,
            CredentialRoute::SiwcResponses,
            &["1.2.3.4"],
        );
        assert_eq!(
            authorize_dispatch(&grant, &custom),
            Err(BrokerDeny::CredentialRouteMismatch)
        );
        let rebound = dispatch(
            ProviderApi::OpenAiResponses,
            "inference.example",
            443,
            CredentialRoute::ApiKey,
            &["127.0.0.1"],
        );
        assert_eq!(
            authorize_dispatch(&grant, &rebound),
            Err(BrokerDeny::Rebinding)
        );
    }

    #[test]
    fn metadata_and_redirect_denied_without_exact_private_grant() {
        let metadata = grant(CredentialRoute::ApiKey, "169.254.169.254", 80, false, None);
        let meta = ProviderDispatch {
            tenant_id: TenantId::new("tenant-a"),
            api: ProviderApi::CustomCompatible,
            scheme: "https".into(),
            host: "169.254.169.254".into(),
            port: 80,
            credential: CredentialRoute::ApiKey,
            resolved_peers: vec!["169.254.169.254".into()],
            redirect_count: 0,
        };
        assert_eq!(
            authorize_dispatch(&metadata, &meta),
            Err(BrokerDeny::PrivateDestination)
        );
        let mut redirected = dispatch(
            ProviderApi::OpenAiResponses,
            "api.openai.com",
            443,
            CredentialRoute::ApiKey,
            &["1.2.3.4"],
        );
        redirected.redirect_count = 1;
        let public = grant(
            CredentialRoute::ApiKey,
            "api.openai.com",
            443,
            false,
            Some("1.2.3.4"),
        );
        assert_eq!(
            authorize_dispatch(&public, &redirected),
            Err(BrokerDeny::Redirect)
        );
    }

    #[test]
    fn empty_mapped_and_unrelated_private_peers_are_denied() {
        let pinned = grant(
            CredentialRoute::ApiKey,
            "api.openai.com",
            443,
            false,
            Some("1.2.3.4"),
        );
        let empty = dispatch(
            ProviderApi::OpenAiResponses,
            "api.openai.com",
            443,
            CredentialRoute::ApiKey,
            &[],
        );
        assert_eq!(
            authorize_dispatch(&pinned, &empty),
            Err(BrokerDeny::Rebinding)
        );
        let local = grant(
            CredentialRoute::ApiKey,
            "127.0.0.1",
            80,
            true,
            Some("127.0.0.1"),
        );
        let other_private = dispatch(
            ProviderApi::CustomCompatible,
            "127.0.0.1",
            80,
            CredentialRoute::ApiKey,
            &["169.254.169.254"],
        );
        assert_eq!(
            authorize_dispatch(&local, &other_private),
            Err(BrokerDeny::Rebinding)
        );
        let octal = dispatch(
            ProviderApi::CustomCompatible,
            "10.1.2.3",
            80,
            CredentialRoute::ApiKey,
            &["010.1.2.3"],
        );
        let public = grant(CredentialRoute::ApiKey, "10.1.2.3", 80, false, None);
        assert_eq!(
            authorize_dispatch(&public, &octal),
            Err(BrokerDeny::NoncanonicalPeer)
        );
    }

    #[test]
    fn noncanonical_resolver_peers_cannot_bypass_private_deny() {
        let open = grant(CredentialRoute::ApiKey, "example.com", 443, false, None);
        let blocked = [
            "2130706433",
            "0177.0.0.1",
            "017700000001",
            "0x7f000001",
            "0x7f.0.0.1",
            "127.0.0.01",
            "127.1",
            "127.0.1",
            "::ffff:0177.0.0.1",
            "127.0.0.1%lo",
            "",
        ];
        for peer in blocked {
            let request = dispatch(
                ProviderApi::CustomCompatible,
                "example.com",
                443,
                CredentialRoute::ApiKey,
                &[peer],
            );
            let result = authorize_dispatch(&open, &request);
            assert_eq!(
                result,
                Err(BrokerDeny::NoncanonicalPeer),
                "peer {peer} => {result:?}"
            );
        }
        let loopback = dispatch(
            ProviderApi::CustomCompatible,
            "example.com",
            443,
            CredentialRoute::ApiKey,
            &["127.0.0.1"],
        );
        assert_eq!(
            authorize_dispatch(&open, &loopback),
            Err(BrokerDeny::PrivateDestination)
        );
        let mapped = dispatch(
            ProviderApi::CustomCompatible,
            "example.com",
            443,
            CredentialRoute::ApiKey,
            &["::ffff:127.0.0.1"],
        );
        assert_eq!(
            authorize_dispatch(&open, &mapped),
            Err(BrokerDeny::PrivateDestination)
        );
        let metadata = dispatch(
            ProviderApi::CustomCompatible,
            "example.com",
            443,
            CredentialRoute::ApiKey,
            &["169.254.169.254"],
        );
        assert_eq!(
            authorize_dispatch(&open, &metadata),
            Err(BrokerDeny::PrivateDestination)
        );
        let public = dispatch(
            ProviderApi::CustomCompatible,
            "example.com",
            443,
            CredentialRoute::ApiKey,
            &["1.2.3.4"],
        );
        assert!(authorize_dispatch(&open, &public).is_ok());
        let pinned = grant(
            CredentialRoute::ApiKey,
            "api.openai.com",
            443,
            false,
            Some("1.2.3.4"),
        );
        let rebound = dispatch(
            ProviderApi::OpenAiResponses,
            "api.openai.com",
            443,
            CredentialRoute::ApiKey,
            &["::ffff:169.254.169.254"],
        );
        assert_eq!(
            authorize_dispatch(&pinned, &rebound),
            Err(BrokerDeny::Rebinding)
        );
    }

    #[test]
    fn newer_harness_format_is_held_not_guessed() {
        assert_eq!(
            settle_harness_format(3, HARNESS_FORMAT),
            Ok(Settlement::OldWorkerHolds)
        );
        assert_eq!(
            settle_harness_format(1, HARNESS_FORMAT),
            Ok(Settlement::Migrated)
        );
        let raw = serde_json::json!({"harness_format": 9, "mystery": {"secret": "nope"}});
        assert_eq!(harness_format_of(&raw), Some(9));
    }

    #[test]
    fn sample_wire_events_match_settled_client_fields() {
        let events = sample_wire_events();
        assert_eq!(events.len(), 5);
        let allowed = [
            "harness_format",
            "event_id",
            "cursor",
            "tenant_id",
            "workspace_id",
            "thread_id",
            "task_id",
            "attempt_id",
            "ui_run_id",
            "actor_id",
            "agent_id",
            "ui_terminal",
            "kind",
            "message_id",
            "phase",
            "delta",
            "effect_id",
            "call_id",
            "tool_name",
            "args_digest",
            "generation",
            "state",
            "artifact_id",
            "object_key",
            "media_type",
            "approval_id",
            "status",
        ];
        for event in &events {
            assert_eq!(event.harness_format(), HARNESS_FORMAT);
            let value = serde_json::to_value(event).expect("event");
            let object = value.as_object().expect("object");
            assert!(object.keys().all(|key| allowed.contains(&key.as_str())));
            assert_eq!(
                object.get("harness_format").and_then(|v| v.as_u64()),
                Some(HARNESS_FORMAT as u64)
            );
            assert!(object.get("kind").and_then(|v| v.as_str()).is_some());
        }
        let newer = serde_json::json!({"harness_format": 9, "kind": "text", "delta": "guessed"});
        assert_eq!(harness_format_of(&newer), Some(9));
        assert!(serde_json::from_value::<CanonicalEvent>(newer).is_err());
    }
}
