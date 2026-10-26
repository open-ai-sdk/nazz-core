// Trusted-side HTTP/1.1 tool boundary over `tokio::net`.
//
// This is not a provider TLS client. `https` is refused before any socket.
// Destination grants are checked with [`authorize_dispatch`] before connect.
// Only the insert winner of the host's exclusive effect claim may
// dial, and only while `ExecutionStore::with_effect_launch` still holds
// the grant, attempt, lease, and approval locks. A committed receipt whose
// stored scope and tool revision match this tool is fed again, including after
// generation failover. A claimed or unconfirmed effect is `needs_reconcile`
// and is not replayed. [`execute_authorized_get`] does not touch the ledger
// and is not a durable acceptance. Sandbox `NetworkGrant` stays `Deny`.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use sha2::{Digest, Sha256};

use nazz_core::{
    ActorGrant, AttemptId, BrokerDeny, EffectClaim, EffectId, EffectState, EndpointGrant,
    ProviderDispatch, TenantId, TracedEffectIdentity, authorize_dispatch, digest_json,
    effect_id_for, ordered_object_bytes, trace_effect_identity,
};
use nazz_storage::{
    EffectLaunch, ExecutionStore, LaunchSettlement, StorageError as StoreError, TracedClaim,
};
use serde_json::{Value, json};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

pub const HTTP_TOOL_NAME: &str = "http_get";
pub const HTTP_TOOL_SCOPE: &str = "tool:http_get";
pub const HTTP_TOOL_REVISION: &str = "http-1";

const MAX_PATH: usize = 256;
const MAX_STATUS_LINE: usize = 256;
const MAX_HEADERS: usize = 4096;
const MAX_BODY: usize = 65_536;
const MAX_DEADLINE: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpToolRequest {
    pub path: String,
    pub grant: EndpointGrant,
    pub dispatch: ProviderDispatch,
    pub deadline: Duration,
    pub redact: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpToolBody {
    pub status: u16,
    pub body: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpToolOutcome {
    Executed(HttpToolBody),
    Fed(HttpToolBody),
    NeedsReconcile,
}

#[derive(Debug, Error)]
pub enum HttpBrokerError {
    #[error("destination denied before connect: {0}")]
    Denied(BrokerDeny),
    #[error("request framing rejected")]
    Framing,
    #[error("https is not this broker; provider TLS is a separate boundary")]
    TlsSeam,
    #[error("redirect refused")]
    Redirect,
    #[error("connected peer does not match the authorized address")]
    Rebinding,
    #[error("connection deadline exceeded")]
    Deadline,
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("io")]
    Io,
}

/// Owner grant for one exact `127.0.0.1` listener. Not a production private bypass.
/// Grants with `allow_private = false` still fail [`authorize_dispatch`] before connect.
pub fn exact_local_test_endpoint(tenant: TenantId, port: u16) -> (EndpointGrant, ProviderDispatch) {
    let grant = EndpointGrant {
        tenant_id: tenant.clone(),
        scheme: "http".into(),
        host: "127.0.0.1".into(),
        port,
        route: nazz_core::CredentialRoute::ApiKey,
        allow_private: true,
        pinned_peer: Some("127.0.0.1".into()),
    };
    let dispatch = ProviderDispatch {
        tenant_id: tenant,
        api: nazz_core::ProviderApi::CustomCompatible,
        scheme: "http".into(),
        host: "127.0.0.1".into(),
        port,
        credential: nazz_core::CredentialRoute::ApiKey,
        resolved_peers: vec!["127.0.0.1".into()],
        redirect_count: 0,
    };
    (grant, dispatch)
}

pub fn http_args_digest(request: &HttpToolRequest) -> Result<String, HttpBrokerError> {
    validate_path(&request.path)?;
    Ok(digest_json(&json!({
        "method": "GET",
        "host": request.grant.host,
        "port": request.grant.port,
        "path": request.path,
    })))
}

fn http_traced_identity(
    attempt: &AttemptId,
    request: &HttpToolRequest,
) -> Result<TracedEffectIdentity, HttpBrokerError> {
    validate_path(&request.path)?;
    let args = json!({
        "method": "GET",
        "host": request.grant.host,
        "port": request.grant.port,
        "path": request.path,
    });
    let mut traced = trace_effect_identity(attempt, HTTP_TOOL_NAME, &args);
    // Effect ids stay `attempt|http_get|digest`. The tool name is not a unique
    // call, so the guard key is this request's canonical digest.
    let logical_key = format!("{HTTP_TOOL_NAME}:{}", traced.canonical.args_digest);
    traced = traced.with_logical_call_id(logical_key);
    let host = json!(request.grant.host.clone());
    let port = json!(request.grant.port);
    let path = json!(request.path.clone());
    let method = json!("GET");
    let insertion = ordered_object_bytes(&[
        ("method", &method),
        ("host", &host),
        ("port", &port),
        ("path", &path),
    ])
    .map_err(|_| HttpBrokerError::Framing)?;
    traced.include_digest(attempt, hex::encode(Sha256::digest(insertion)));
    Ok(traced)
}

pub fn http_effect_id(
    attempt: &AttemptId,
    request: &HttpToolRequest,
) -> Result<EffectId, HttpBrokerError> {
    Ok(effect_id_for(
        attempt,
        HTTP_TOOL_NAME,
        &http_args_digest(request)?,
    ))
}

/// One authorized GET. Not durable, not a ledger write, and not phase acceptance.
/// A successful return is one socket. Two calls are two sockets. Repeat callers
/// that must not re-execute use [`reconcile_http_tool`].
pub async fn execute_authorized_get(
    request: &HttpToolRequest,
) -> Result<HttpToolBody, HttpBrokerError> {
    let addr = authorized_socket(request)?;
    exchange(addr, request).await
}

pub async fn reconcile_http_tool<S: ExecutionStore>(
    store: &S,
    actor: &ActorGrant,
    holder: &str,
    attempt: &AttemptId,
    generation: u64,
    request: &HttpToolRequest,
) -> Result<HttpToolOutcome, HttpBrokerError> {
    let addr = authorized_socket(request)?;
    let traced = http_traced_identity(attempt, request)?;
    let claim = match store
        .claim_traced_effect(
            actor,
            holder,
            HTTP_TOOL_SCOPE,
            HTTP_TOOL_REVISION,
            attempt,
            generation,
            HTTP_TOOL_NAME,
            &traced,
        )
        .await?
    {
        TracedClaim::KnownReceipt(binding) => {
            if binding.scope != HTTP_TOOL_SCOPE || binding.tool_revision != HTTP_TOOL_REVISION {
                return Err(StoreError::LifecycleConflict.into());
            }
            return feed_existing(attempt, &traced, &binding.claim);
        }
        TracedClaim::Unknown(_) | TracedClaim::Unresolved => {
            return Ok(HttpToolOutcome::NeedsReconcile);
        }
        TracedClaim::Fresh(binding) => {
            if binding.scope != HTTP_TOOL_SCOPE
                || binding.tool_revision != HTTP_TOOL_REVISION
                || !traced.contains_digest(&binding.claim.args_digest)
            {
                return Err(StoreError::LifecycleConflict.into());
            }
            binding.claim
        }
    };
    let deadline = request.deadline.min(MAX_DEADLINE);
    let launched = store
        .with_effect_launch(
            actor,
            holder,
            HTTP_TOOL_SCOPE,
            HTTP_TOOL_REVISION,
            &claim,
            deadline,
            {
                let owned = request.clone();
                move || async move { connect_and_send(addr, &owned).await.map_err(|_| ()) }
            },
        )
        .await?;
    match launched {
        EffectLaunch::Blocked(err) => Err(err.into()),
        EffectLaunch::Attempted => {
            mark_unknown(store, actor, holder, &claim).await;
            Ok(HttpToolOutcome::NeedsReconcile)
        }
        EffectLaunch::Ready(mut stream) => {
            match timeout(deadline, read_response(&mut stream)).await {
                Ok(Ok(body)) => {
                    let body = HttpToolBody {
                        status: body.status,
                        body: redact_text(&body.body, &request.redact),
                    };
                    let mut receipt = claim.clone();
                    receipt.state = EffectState::Receipt;
                    receipt.receipt = Some(receipt_value(&body));
                    match store
                        .settle_launched_effect(
                            actor,
                            holder,
                            HTTP_TOOL_SCOPE,
                            HTTP_TOOL_REVISION,
                            &receipt,
                        )
                        .await
                    {
                        Ok(LaunchSettlement::Receipt) => Ok(HttpToolOutcome::Executed(body)),
                        Ok(LaunchSettlement::Unknown) | Err(_) => {
                            mark_unknown(store, actor, holder, &claim).await;
                            Ok(HttpToolOutcome::NeedsReconcile)
                        }
                    }
                }
                Ok(Err(_)) | Err(_) => {
                    mark_unknown(store, actor, holder, &claim).await;
                    Ok(HttpToolOutcome::NeedsReconcile)
                }
            }
        }
    }
}

async fn mark_unknown<S: ExecutionStore>(
    store: &S,
    actor: &ActorGrant,
    holder: &str,
    claim: &EffectClaim,
) {
    let mut blocked = claim.clone();
    blocked.state = EffectState::NeedsReconcile;
    blocked.receipt = None;
    let _ = store
        .record_effect(actor, holder, HTTP_TOOL_SCOPE, HTTP_TOOL_REVISION, &blocked)
        .await;
}

fn feed_existing(
    attempt: &AttemptId,
    traced: &TracedEffectIdentity,
    existing: &EffectClaim,
) -> Result<HttpToolOutcome, HttpBrokerError> {
    if existing.attempt_id != *attempt
        || existing.tool_name != HTTP_TOOL_NAME
        || !traced.contains_digest(&existing.args_digest)
    {
        return Err(StoreError::LifecycleConflict.into());
    }
    match existing.state {
        EffectState::Receipt => {
            Ok(parse_fed(existing.receipt.as_ref()).unwrap_or(HttpToolOutcome::NeedsReconcile))
        }
        EffectState::Claimed | EffectState::NeedsReconcile => Ok(HttpToolOutcome::NeedsReconcile),
    }
}

fn parse_fed(receipt: Option<&Value>) -> Option<HttpToolOutcome> {
    let receipt = receipt?;
    let status = u16::try_from(receipt.get("status")?.as_u64()?).ok()?;
    let body = receipt.get("body")?.as_str()?.to_string();
    if !(200..300).contains(&status) && !(400..600).contains(&status) {
        return None;
    }
    Some(HttpToolOutcome::Fed(HttpToolBody { status, body }))
}

fn receipt_value(body: &HttpToolBody) -> Value {
    json!({"status": body.status, "body": body.body})
}

fn authorized_socket(request: &HttpToolRequest) -> Result<SocketAddr, HttpBrokerError> {
    if request.deadline.is_zero() {
        return Err(HttpBrokerError::Framing);
    }
    validate_path(&request.path)?;
    if request.grant.scheme == "https" || request.dispatch.scheme == "https" {
        return Err(HttpBrokerError::TlsSeam);
    }
    if request.grant.scheme != "http" || request.dispatch.scheme != "http" {
        return Err(HttpBrokerError::Framing);
    }
    authorize_dispatch(&request.grant, &request.dispatch).map_err(HttpBrokerError::Denied)?;
    let Some(pinned) = request.grant.pinned_peer.as_deref() else {
        return Err(HttpBrokerError::Rebinding);
    };
    if pinned != request.grant.host
        || request.dispatch.resolved_peers.len() != 1
        || request.dispatch.resolved_peers[0] != pinned
    {
        return Err(HttpBrokerError::Rebinding);
    }
    let ip: IpAddr = pinned.parse().map_err(|_| HttpBrokerError::Rebinding)?;
    Ok(SocketAddr::new(ip, request.grant.port))
}

fn validate_path(path: &str) -> Result<(), HttpBrokerError> {
    if path.is_empty() || path.len() > MAX_PATH || !path.starts_with('/') || path.starts_with("//")
    {
        return Err(HttpBrokerError::Framing);
    }
    if path.contains("..") || path.contains('\\') || path.contains("://") {
        return Err(HttpBrokerError::Framing);
    }
    if !path.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'~' | b'-')
    }) {
        return Err(HttpBrokerError::Framing);
    }
    Ok(())
}

async fn exchange(
    addr: SocketAddr,
    request: &HttpToolRequest,
) -> Result<HttpToolBody, HttpBrokerError> {
    let deadline = request.deadline.min(MAX_DEADLINE);
    match timeout(deadline, exchange_inner(addr, request)).await {
        Ok(result) => result,
        Err(_) => Err(HttpBrokerError::Deadline),
    }
}

async fn connect_and_send(
    addr: SocketAddr,
    request: &HttpToolRequest,
) -> Result<TcpStream, HttpBrokerError> {
    let mut stream = TcpStream::connect(addr)
        .await
        .map_err(|_| HttpBrokerError::Io)?;
    let peer = stream.peer_addr().map_err(|_| HttpBrokerError::Io)?;
    if peer.ip() != addr.ip() || peer.port() != addr.port() {
        return Err(HttpBrokerError::Rebinding);
    }
    let host = match addr.ip() {
        IpAddr::V4(ip) => format!("{ip}:{}", addr.port()),
        IpAddr::V6(ip) => format!("[{ip}]:{}", addr.port()),
    };
    let bytes = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nAccept: text/plain\r\n\r\n",
        path = request.path,
    );
    stream
        .write_all(bytes.as_bytes())
        .await
        .map_err(|_| HttpBrokerError::Io)?;
    stream.flush().await.map_err(|_| HttpBrokerError::Io)?;
    Ok(stream)
}

async fn exchange_inner(
    addr: SocketAddr,
    request: &HttpToolRequest,
) -> Result<HttpToolBody, HttpBrokerError> {
    let mut stream = connect_and_send(addr, request).await?;
    let body = read_response(&mut stream).await?;
    Ok(HttpToolBody {
        status: body.status,
        body: redact_text(&body.body, &request.redact),
    })
}

async fn read_response(stream: &mut TcpStream) -> Result<HttpToolBody, HttpBrokerError> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    let header_end = loop {
        if buf.len() > MAX_STATUS_LINE + MAX_HEADERS + 4 {
            return Err(HttpBrokerError::Framing);
        }
        let read = stream
            .read(&mut tmp)
            .await
            .map_err(|_| HttpBrokerError::Io)?;
        if read == 0 {
            return Err(HttpBrokerError::Framing);
        }
        buf.extend_from_slice(&tmp[..read]);
        if let Some(end) = find_header_end(&buf) {
            break end;
        }
    };
    if header_end > MAX_STATUS_LINE + MAX_HEADERS + 4 {
        return Err(HttpBrokerError::Framing);
    }
    let header_text = std::str::from_utf8(&buf[..header_end.saturating_sub(4)])
        .map_err(|_| HttpBrokerError::Framing)?;
    let mut lines = header_text.split("\r\n");
    let status_line = lines.next().ok_or(HttpBrokerError::Framing)?;
    if status_line.len() > MAX_STATUS_LINE {
        return Err(HttpBrokerError::Framing);
    }
    let status = parse_status(status_line)?;
    let mut content_length = None;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            return Err(HttpBrokerError::Framing);
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(HttpBrokerError::Framing);
        };
        if name.is_empty() || name.bytes().any(|byte| byte.is_ascii_whitespace()) {
            return Err(HttpBrokerError::Framing);
        }
        let name = name.to_ascii_lowercase();
        let value = value.trim();
        if name == "transfer-encoding" {
            return Err(HttpBrokerError::Framing);
        }
        if name == "content-length" {
            if content_length.is_some() {
                return Err(HttpBrokerError::Framing);
            }
            let len: u64 = value.parse().map_err(|_| HttpBrokerError::Framing)?;
            if len > MAX_BODY as u64 {
                return Err(HttpBrokerError::Framing);
            }
            content_length = Some(len as usize);
        }
    }
    let mut body = buf[header_end..].to_vec();
    match content_length {
        Some(len) => {
            if body.len() > len {
                return Err(HttpBrokerError::Framing);
            }
            while body.len() < len {
                let read = stream
                    .read(&mut tmp)
                    .await
                    .map_err(|_| HttpBrokerError::Io)?;
                if read == 0 {
                    return Err(HttpBrokerError::Framing);
                }
                if body.len() + read > len {
                    return Err(HttpBrokerError::Framing);
                }
                body.extend_from_slice(&tmp[..read]);
            }
        }
        None => {
            loop {
                if body.len() > MAX_BODY {
                    return Err(HttpBrokerError::Framing);
                }
                let read = stream
                    .read(&mut tmp)
                    .await
                    .map_err(|_| HttpBrokerError::Io)?;
                if read == 0 {
                    break;
                }
                body.extend_from_slice(&tmp[..read]);
            }
            if body.len() > MAX_BODY {
                return Err(HttpBrokerError::Framing);
            }
        }
    }
    let body = String::from_utf8(body).map_err(|_| HttpBrokerError::Framing)?;
    Ok(HttpToolBody { status, body })
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
}

fn parse_status(line: &str) -> Result<u16, HttpBrokerError> {
    let mut parts = line.split(' ');
    let version = parts.next().unwrap_or("");
    let code = parts.next().unwrap_or("");
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(HttpBrokerError::Framing);
    }
    if code.len() != 3 || !code.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(HttpBrokerError::Framing);
    }
    let status: u16 = code.parse().map_err(|_| HttpBrokerError::Framing)?;
    if (300..400).contains(&status) {
        return Err(HttpBrokerError::Redirect);
    }
    if !(200..300).contains(&status) && !(400..600).contains(&status) {
        return Err(HttpBrokerError::Framing);
    }
    Ok(status)
}

fn redact_text(body: &str, secrets: &[String]) -> String {
    let mut out = body.to_string();
    for secret in secrets {
        if secret.is_empty() {
            continue;
        }
        if out.contains(secret.as_str()) {
            out = out.replace(secret.as_str(), "[redacted]");
        }
    }
    out
}
