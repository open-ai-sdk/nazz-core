//! Prepare a typed canonical request from a host-passed grant and a client body.
//!
//! This is not store admission and not authentication. The [`ActorGrant`] is
//! whatever the host passed in. This module does not read `harness_grant_state`,
//! does not prove `revision` is current, and does not persist a registry.
//! Replay uniqueness and current authority remain `Store::admit`.
//!
//! Authority bytes are [`crate::canonical_bytes`] of [`CanonicalRequest`] and
//! [`CanonicalAdmission`]. Object keys are sorted. Envelope fields stay in
//! declaration order. The body fingerprint is the same helper over the payload
//! only. It is not [`AdmissionReceipt::digest`].

use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    ActorGrant, ActorId, AdmissionReceipt, AttemptId, CanonicalAdmission, CanonicalRequest,
    RequestId, TenantId, WorkspaceId,
};

/// `serde_json` default recursion limit. Deeper input is not a second format.
const SERDE_RECURSION_LIMIT: usize = 128;

/// Client-declared scope. Never copied into the canonical envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UntrustedScope {
    pub tenant_id: String,
    pub workspace_id: String,
    pub actor_id: String,
}

/// Input to [`prepare_host_binding`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostBindInput<'a> {
    /// Grant the host passed. Not a store-verified current authority.
    pub host_passed_grant: &'a ActorGrant,
    pub request_id: &'a RequestId,
    pub body: &'a str,
    pub client_scope: Option<&'a UntrustedScope>,
    /// Previous preparation the caller still holds. Not a durable registry.
    /// `None` is a new preparation, not a replay of a stored admission.
    pub caller_held: Option<&'a PreparedHostBinding>,
}

/// Typed preparation. Digests are private so a caller cannot relabel them
/// into an [`AdmissionReceipt`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedHostBinding {
    request_id: RequestId,
    tenant_id: TenantId,
    workspace_id: WorkspaceId,
    actor_id: ActorId,
    host_passed_revision: u64,
    kind: String,
    request_bytes: String,
    admission_bytes: String,
    body_fingerprint: String,
    request_projection_digest: String,
    admission_digest: String,
}

/// `CanonicalRequest::digest`. Not an [`AdmissionReceipt`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestProjection {
    digest: String,
}

impl RequestProjection {
    pub fn digest(&self) -> &str {
        &self.digest
    }
}

/// A store receipt that matched this preparation. No public constructor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedStoreReceipt {
    receipt: AdmissionReceipt,
    request_projection_digest: String,
    body_fingerprint: String,
}

impl VerifiedStoreReceipt {
    pub fn receipt(&self) -> &AdmissionReceipt {
        &self.receipt
    }

    pub fn request_projection_digest(&self) -> &str {
        &self.request_projection_digest
    }

    pub fn body_fingerprint(&self) -> &str {
        &self.body_fingerprint
    }
}

/// Receipt and host grant check canonical identity, not execution authority.
/// Execution context is independently resolved by the scoped Store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreReceiptCheck<'a> {
    pub receipt: &'a AdmissionReceipt,
    pub host_passed_grant: &'a ActorGrant,
    pub expected_attempt: Option<&'a AttemptId>,
}

impl PreparedHostBinding {
    pub fn request_id(&self) -> &RequestId {
        &self.request_id
    }
    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }
    pub fn workspace_id(&self) -> &WorkspaceId {
        &self.workspace_id
    }
    pub fn actor_id(&self) -> &ActorId {
        &self.actor_id
    }
    pub fn host_passed_revision(&self) -> u64 {
        self.host_passed_revision
    }
    pub fn kind(&self) -> &str {
        &self.kind
    }
    pub fn request_bytes(&self) -> &str {
        &self.request_bytes
    }
    pub fn admission_bytes(&self) -> &str {
        &self.admission_bytes
    }
    /// SHA-256 of the canonical payload bytes. Retry comparison only.
    pub fn body_fingerprint(&self) -> &str {
        &self.body_fingerprint
    }
    pub fn request_projection_digest(&self) -> &str {
        &self.request_projection_digest
    }
    /// [`CanonicalAdmission::digest`]. This is the digest `Store::admit` stores.
    pub fn admission_digest(&self) -> &str {
        &self.admission_digest
    }

    pub fn request_projection(&self) -> RequestProjection {
        RequestProjection {
            digest: self.request_projection_digest.clone(),
        }
    }

    /// Accept a store receipt only when its digest is the typed admission digest.
    /// Does not mint a receipt and does not copy the request projection into
    /// [`AdmissionReceipt::digest`].
    pub fn verify_store_receipt(
        &self,
        check: StoreReceiptCheck<'_>,
    ) -> Result<VerifiedStoreReceipt, BindError> {
        let grant = check.host_passed_grant;
        if grant.revoked
            || grant.tenant_id != self.tenant_id
            || grant.workspace_id != self.workspace_id
            || grant.actor_id != self.actor_id
            || grant.revision != self.host_passed_revision
        {
            return Err(BindError::StaleGrant);
        }
        if check.receipt.request_id != self.request_id {
            return Err(BindError::RequestMismatch);
        }
        let attempt = check.receipt.attempt_id.as_str();
        if attempt.is_empty() {
            return Err(BindError::AttemptMismatch);
        }
        if let Some(expected) = check.expected_attempt
            && expected.as_str() != attempt
        {
            return Err(BindError::AttemptMismatch);
        }
        let digest = check.receipt.digest.as_str();
        if digest.is_empty()
            || digest == self.body_fingerprint
            || digest == self.request_projection_digest
            || digest != self.admission_digest
        {
            return Err(BindError::ForgedReceipt);
        }
        Ok(VerifiedStoreReceipt {
            receipt: check.receipt.clone(),
            request_projection_digest: self.request_projection_digest.clone(),
            body_fingerprint: self.body_fingerprint.clone(),
        })
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BindError {
    #[error("host-passed grant is revoked or does not cover this preparation")]
    Denied,
    #[error("client declared tenant, workspace, or actor scope")]
    ForgedScope,
    #[error("request id is empty")]
    EmptyRequestId,
    #[error("host-passed grant is missing tenant, workspace, or actor")]
    EmptyGrant,
    #[error("body is not a JSON object with a kind")]
    InvalidBody,
    #[error("top-level kind key is duplicated with conflicting values")]
    DuplicateKind,
    #[error("same request id was reused with a different canonical body")]
    SameIdDifferentBody,
    #[error("receipt or caller-held preparation is for a different request id")]
    RequestMismatch,
    #[error("receipt attempt does not match")]
    AttemptMismatch,
    #[error("receipt digest is not the stored canonical admission digest")]
    ForgedReceipt,
    #[error("host-passed grant actor or revision does not match this preparation")]
    StaleGrant,
}

pub fn prepare_host_binding(input: HostBindInput<'_>) -> Result<PreparedHostBinding, BindError> {
    let grant = input.host_passed_grant;
    if grant.revoked {
        return Err(BindError::Denied);
    }
    if grant.tenant_id.as_str().is_empty()
        || grant.workspace_id.as_str().is_empty()
        || grant.actor_id.as_str().is_empty()
    {
        return Err(BindError::EmptyGrant);
    }
    if input.request_id.as_str().is_empty() {
        return Err(BindError::EmptyRequestId);
    }
    if let Some(claim) = input.client_scope
        && (claim.tenant_id != grant.tenant_id.as_str()
            || claim.workspace_id != grant.workspace_id.as_str()
            || claim.actor_id != grant.actor_id.as_str())
    {
        return Err(BindError::ForgedScope);
    }
    let payload = parse_payload(input.body)?;
    if let Some(held) = input.caller_held {
        return match_caller_held(held, grant, input.request_id, &payload);
    }
    build_preparation(grant, input.request_id, payload)
}

fn match_caller_held(
    held: &PreparedHostBinding,
    grant: &ActorGrant,
    request_id: &RequestId,
    payload: &Value,
) -> Result<PreparedHostBinding, BindError> {
    if held.request_id.as_str() != request_id.as_str() {
        return Err(BindError::RequestMismatch);
    }
    if held.tenant_id.as_str() != grant.tenant_id.as_str()
        || held.workspace_id.as_str() != grant.workspace_id.as_str()
        || held.actor_id.as_str() != grant.actor_id.as_str()
    {
        return Err(BindError::Denied);
    }
    if held.host_passed_revision != grant.revision {
        return Err(BindError::StaleGrant);
    }
    let (fingerprint, _) = payload_wire(payload)?;
    if fingerprint != held.body_fingerprint {
        return Err(BindError::SameIdDifferentBody);
    }
    Ok(held.clone())
}

fn build_preparation(
    grant: &ActorGrant,
    request_id: &RequestId,
    payload: Value,
) -> Result<PreparedHostBinding, BindError> {
    let kind = match payload.get("kind") {
        Some(Value::String(kind)) if !kind.is_empty() => kind.clone(),
        _ => return Err(BindError::InvalidBody),
    };
    let request = CanonicalRequest {
        request_id: request_id.clone(),
        tenant_id: grant.tenant_id.clone(),
        workspace_id: grant.workspace_id.clone(),
        actor_id: grant.actor_id.clone(),
        kind,
        body: payload.clone(),
    };
    let admission = CanonicalAdmission::from_grant(grant, request_id.clone(), payload.clone());
    let request_bytes = wire_string(&request)?;
    let admission_bytes = wire_string(&admission)?;
    let (body_fingerprint, _) = payload_wire(&payload)?;
    Ok(PreparedHostBinding {
        request_id: request_id.clone(),
        tenant_id: grant.tenant_id.clone(),
        workspace_id: grant.workspace_id.clone(),
        actor_id: grant.actor_id.clone(),
        host_passed_revision: grant.revision,
        kind: request.kind.clone(),
        request_projection_digest: request.digest(),
        admission_digest: admission.digest(),
        body_fingerprint,
        request_bytes,
        admission_bytes,
    })
}

fn wire_string<T: serde::Serialize>(value: &T) -> Result<String, BindError> {
    let bytes = crate::canonical_bytes(value).map_err(|_| BindError::InvalidBody)?;
    String::from_utf8(bytes).map_err(|_| BindError::InvalidBody)
}

fn payload_wire(payload: &Value) -> Result<(String, String), BindError> {
    let text = wire_string(payload)?;
    Ok((sha256_hex(text.as_bytes()), text))
}

fn parse_payload(body: &str) -> Result<Value, BindError> {
    reject_conflicting_kind(body)?;
    let payload: Value = serde_json::from_str(body).map_err(|_| BindError::InvalidBody)?;
    let object = payload.as_object().ok_or(BindError::InvalidBody)?;
    if object.contains_key("tenant_id")
        || object.contains_key("workspace_id")
        || object.contains_key("actor_id")
    {
        return Err(BindError::ForgedScope);
    }
    Ok(payload)
}

fn reject_conflicting_kind(body: &str) -> Result<(), BindError> {
    let bytes = body.as_bytes();
    let mut i = 0;
    skip_ws(bytes, &mut i);
    if i >= bytes.len() || bytes[i] != b'{' {
        return Err(BindError::InvalidBody);
    }
    i += 1;
    let mut seen_kind: Option<Value> = None;
    loop {
        skip_ws(bytes, &mut i);
        if i < bytes.len() && bytes[i] == b'}' {
            return Ok(());
        }
        let key = decode_string(bytes, &mut i)?;
        skip_ws(bytes, &mut i);
        if i >= bytes.len() || bytes[i] != b':' {
            return Err(BindError::InvalidBody);
        }
        i += 1;
        skip_ws(bytes, &mut i);
        let raw = take_value(bytes, &mut i, 1)?;
        if key == "kind" {
            let value: Value = serde_json::from_slice(raw).map_err(|_| BindError::InvalidBody)?;
            if let Some(previous) = &seen_kind {
                if previous != &value {
                    return Err(BindError::DuplicateKind);
                }
            } else {
                seen_kind = Some(value);
            }
        }
        skip_ws(bytes, &mut i);
        if i < bytes.len() && bytes[i] == b',' {
            i += 1;
            continue;
        }
        if i < bytes.len() && bytes[i] == b'}' {
            return Ok(());
        }
        return Err(BindError::InvalidBody);
    }
}

fn skip_ws(bytes: &[u8], i: &mut usize) {
    while *i < bytes.len() && matches!(bytes[*i], b' ' | b'\n' | b'\r' | b'\t') {
        *i += 1;
    }
}

fn decode_string(bytes: &[u8], i: &mut usize) -> Result<String, BindError> {
    let quoted = take_string(bytes, i)?;
    serde_json::from_str(quoted).map_err(|_| BindError::InvalidBody)
}

fn take_string<'a>(bytes: &'a [u8], i: &mut usize) -> Result<&'a str, BindError> {
    if *i >= bytes.len() || bytes[*i] != b'"' {
        return Err(BindError::InvalidBody);
    }
    let start = *i;
    *i += 1;
    while *i < bytes.len() {
        match bytes[*i] {
            b'"' => {
                *i += 1;
                return std::str::from_utf8(&bytes[start..*i]).map_err(|_| BindError::InvalidBody);
            }
            b'\\' => {
                *i += 1;
                if *i >= bytes.len() {
                    return Err(BindError::InvalidBody);
                }
                if bytes[*i] == b'u' {
                    *i += 5;
                    if *i > bytes.len() {
                        return Err(BindError::InvalidBody);
                    }
                } else {
                    *i += 1;
                }
            }
            0x00..=0x1F => return Err(BindError::InvalidBody),
            byte => {
                let width = utf8_width(byte).ok_or(BindError::InvalidBody)?;
                if *i + width > bytes.len() {
                    return Err(BindError::InvalidBody);
                }
                *i += width;
            }
        }
    }
    Err(BindError::InvalidBody)
}

fn utf8_width(byte: u8) -> Option<usize> {
    if byte < 0x80 {
        Some(1)
    } else if byte & 0xE0 == 0xC0 {
        Some(2)
    } else if byte & 0xF0 == 0xE0 {
        Some(3)
    } else if byte & 0xF8 == 0xF0 {
        Some(4)
    } else {
        None
    }
}

fn take_value<'a>(bytes: &'a [u8], i: &mut usize, depth: usize) -> Result<&'a [u8], BindError> {
    let start = *i;
    skip_value(bytes, i, depth)?;
    Ok(&bytes[start..*i])
}

fn skip_value(bytes: &[u8], i: &mut usize, depth: usize) -> Result<(), BindError> {
    if depth > SERDE_RECURSION_LIMIT {
        return Err(BindError::InvalidBody);
    }
    if *i >= bytes.len() {
        return Err(BindError::InvalidBody);
    }
    match bytes[*i] {
        b'"' => {
            take_string(bytes, i)?;
        }
        b'{' => skip_container(bytes, i, depth, b'{', b'}')?,
        b'[' => skip_container(bytes, i, depth, b'[', b']')?,
        b't' => skip_lit(bytes, i, b"true")?,
        b'f' => skip_lit(bytes, i, b"false")?,
        b'n' => skip_lit(bytes, i, b"null")?,
        b'-' | b'0'..=b'9' => skip_number(bytes, i)?,
        _ => return Err(BindError::InvalidBody),
    }
    Ok(())
}

fn skip_container(
    bytes: &[u8],
    i: &mut usize,
    depth: usize,
    open: u8,
    close: u8,
) -> Result<(), BindError> {
    if *i >= bytes.len() || bytes[*i] != open {
        return Err(BindError::InvalidBody);
    }
    *i += 1;
    loop {
        skip_ws(bytes, i);
        if *i < bytes.len() && bytes[*i] == close {
            *i += 1;
            return Ok(());
        }
        if open == b'{' {
            take_string(bytes, i)?;
            skip_ws(bytes, i);
            if *i >= bytes.len() || bytes[*i] != b':' {
                return Err(BindError::InvalidBody);
            }
            *i += 1;
            skip_ws(bytes, i);
        }
        skip_value(bytes, i, depth + 1)?;
        skip_ws(bytes, i);
        if *i < bytes.len() && bytes[*i] == b',' {
            *i += 1;
            continue;
        }
        if *i < bytes.len() && bytes[*i] == close {
            *i += 1;
            return Ok(());
        }
        return Err(BindError::InvalidBody);
    }
}

fn skip_lit(bytes: &[u8], i: &mut usize, lit: &[u8]) -> Result<(), BindError> {
    if bytes[*i..].starts_with(lit) {
        *i += lit.len();
        Ok(())
    } else {
        Err(BindError::InvalidBody)
    }
}

fn skip_number(bytes: &[u8], i: &mut usize) -> Result<(), BindError> {
    if bytes[*i] == b'-' {
        *i += 1;
    }
    if *i >= bytes.len() || !bytes[*i].is_ascii_digit() {
        return Err(BindError::InvalidBody);
    }
    if bytes[*i] == b'0' {
        *i += 1;
    } else {
        while *i < bytes.len() && bytes[*i].is_ascii_digit() {
            *i += 1;
        }
    }
    if *i < bytes.len() && bytes[*i] == b'.' {
        *i += 1;
        let frac = *i;
        while *i < bytes.len() && bytes[*i].is_ascii_digit() {
            *i += 1;
        }
        if *i == frac {
            return Err(BindError::InvalidBody);
        }
    }
    if *i < bytes.len() && matches!(bytes[*i], b'e' | b'E') {
        *i += 1;
        if *i < bytes.len() && matches!(bytes[*i], b'+' | b'-') {
            *i += 1;
        }
        let exp = *i;
        while *i < bytes.len() && bytes[*i].is_ascii_digit() {
            *i += 1;
        }
        if *i == exp {
            return Err(BindError::InvalidBody);
        }
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEND_BODY: &str =
        r#"{"kind":"operation.run","resource_id":"resource-1","parent_id":null,"body":"xin chào"}"#;
    const TYPED_REQUEST_DIGEST: &str =
        "95fde878faa21e0825281a28fd883ce479a28e65464f4a78f6408000e39d292a";
    const TYPED_ADMISSION_DIGEST: &str =
        "790a8aa3d504b7967b907fa3c802390401af0bf4b0f6dc64dcab365521ed6c53";

    fn grant() -> ActorGrant {
        ActorGrant {
            tenant_id: TenantId::new("tenant-a"),
            workspace_id: WorkspaceId::new("workspace-a"),
            actor_id: ActorId::new("actor-owner"),
            revision: 3,
            revoked: false,
        }
    }

    fn prepare(body: &str) -> Result<PreparedHostBinding, BindError> {
        let host_passed_grant = grant();
        let request_id = RequestId::new("req-1");
        prepare_host_binding(HostBindInput {
            host_passed_grant: &host_passed_grant,
            request_id: &request_id,
            body,
            client_scope: None,
            caller_held: None,
        })
    }

    fn typed(body: &str) -> (CanonicalRequest, CanonicalAdmission) {
        let payload: Value = serde_json::from_str(body).expect("body");
        let request = CanonicalRequest {
            request_id: RequestId::new("req-1"),
            tenant_id: TenantId::new("tenant-a"),
            workspace_id: WorkspaceId::new("workspace-a"),
            actor_id: ActorId::new("actor-owner"),
            kind: payload
                .get("kind")
                .and_then(Value::as_str)
                .unwrap_or("operation.run")
                .to_string(),
            body: payload.clone(),
        };
        let admission = CanonicalAdmission::from_grant(&grant(), RequestId::new("req-1"), payload);
        (request, admission)
    }

    fn assert_typed_wire(body: &str, prepared: &PreparedHostBinding) {
        let (request, admission) = typed(body);
        let request_wire = crate::canonical_bytes(&request).expect("request wire");
        let admission_wire = crate::canonical_bytes(&admission).expect("admission wire");
        assert_eq!(prepared.request_bytes().as_bytes(), request_wire.as_slice());
        assert_eq!(
            prepared.admission_bytes().as_bytes(),
            admission_wire.as_slice()
        );
        assert_eq!(prepared.request_projection_digest(), request.digest());
        assert_eq!(prepared.admission_digest(), admission.digest());
        assert_eq!(
            prepared.request_projection_digest(),
            sha256_hex(&request_wire)
        );
        assert_eq!(prepared.admission_digest(), sha256_hex(&admission_wire));
        assert_eq!(prepared.request_projection().digest(), request.digest());
        assert_ne!(prepared.admission_digest(), prepared.body_fingerprint());
        assert_ne!(
            prepared.request_projection_digest(),
            prepared.body_fingerprint()
        );
    }

    fn receipt(digest: &str, attempt: &str) -> AdmissionReceipt {
        AdmissionReceipt {
            request_id: RequestId::new("req-1"),
            digest: digest.to_string(),
            attempt_id: AttemptId::new(attempt),
        }
    }

    fn check<'a>(
        prepared_grant: &'a ActorGrant,
        stored: &'a AdmissionReceipt,
    ) -> StoreReceiptCheck<'a> {
        StoreReceiptCheck {
            receipt: stored,
            host_passed_grant: prepared_grant,
            expected_attempt: None,
        }
    }

    #[test]
    fn authority_bytes_equal_typed_canonical_digest() {
        let prepared = prepare(SEND_BODY).expect("prepare");
        assert_typed_wire(SEND_BODY, &prepared);
        assert_eq!(prepared.request_projection_digest(), TYPED_REQUEST_DIGEST);
        assert_eq!(prepared.admission_digest(), TYPED_ADMISSION_DIGEST);
        assert!(prepared.request_bytes().starts_with("{\"request_id\":"));
        assert!(prepared.admission_bytes().starts_with("{\"tenant_id\":"));
        assert_eq!(prepared.kind(), "operation.run");
        assert_eq!(prepared.host_passed_revision(), 3);
        let payload: Value = serde_json::from_str(SEND_BODY).expect("body");
        let payload_wire = crate::canonical_bytes(&payload).expect("payload");
        assert_eq!(
            prepared.body_fingerprint(),
            sha256_hex(payload_wire.as_slice())
        );
    }

    #[test]
    fn reordered_nested_escaped_unicode_and_whitespace_share_typed_digest() {
        let prepared = prepare(SEND_BODY).expect("prepare");
        let vectors = [
            r#"{"resource_id":"resource-1","body":"xin chào","parent_id":null,"kind":"operation.run"}"#,
            r#"{"kind":"operation.run","meta":{"z":1,"a":2},"resource_id":"resource-1","parent_id":null,"body":"xin chào"}"#,
            r#"{"kind":"operation.run","meta":{"a":2,"z":1},"resource_id":"resource-1","parent_id":null,"body":"xin chào"}"#,
            r#"{"kind":"operation.run","path":"a\/b"}"#,
            r#"{"kind":"operation.run","path":"a/b"}"#,
            "{\"kind\":\"operation.run\",\"name\":\"\\u00e0\"}",
            "{\"kind\":\"operation.run\",\"name\":\"à\"}",
            "  \n{\"kind\":\"operation.run\",\"resource_id\":\"resource-1\",\"parent_id\":null,\"body\":\"xin chào\"}",
        ];
        let reordered = prepare(vectors[0]).expect("reorder");
        assert_eq!(
            reordered.request_projection_digest(),
            prepared.request_projection_digest()
        );
        assert_eq!(reordered.admission_digest(), prepared.admission_digest());
        assert_typed_wire(vectors[0], &reordered);

        let nested_z = prepare(vectors[1]).expect("nested z");
        let nested_a = prepare(vectors[2]).expect("nested a");
        assert_eq!(
            nested_z.request_projection_digest(),
            nested_a.request_projection_digest()
        );
        assert_eq!(nested_z.admission_digest(), nested_a.admission_digest());
        assert_typed_wire(vectors[1], &nested_z);
        assert_typed_wire(vectors[2], &nested_a);

        let escaped = prepare(vectors[3]).expect("escaped slash");
        let plain = prepare(vectors[4]).expect("plain slash");
        assert_eq!(
            escaped.request_projection_digest(),
            plain.request_projection_digest()
        );
        assert_eq!(escaped.admission_digest(), plain.admission_digest());
        assert_typed_wire(vectors[3], &escaped);
        assert_typed_wire(vectors[4], &plain);

        let escaped_unicode = prepare(vectors[5]).expect("unicode escape");
        let utf8 = prepare(vectors[6]).expect("utf8");
        assert_eq!(
            escaped_unicode.request_projection_digest(),
            utf8.request_projection_digest()
        );
        assert_eq!(escaped_unicode.admission_digest(), utf8.admission_digest());
        assert_typed_wire(vectors[5], &escaped_unicode);
        assert_typed_wire(vectors[6], &utf8);

        let padded = prepare(vectors[7]).expect("whitespace");
        assert_eq!(
            padded.request_projection_digest(),
            prepared.request_projection_digest()
        );
        assert_eq!(padded.admission_digest(), prepared.admission_digest());
        assert_eq!(padded.body_fingerprint(), prepared.body_fingerprint());
        assert_typed_wire(vectors[7], &padded);
    }

    #[test]
    fn store_receipt_must_carry_admission_digest() {
        let prepared = prepare(SEND_BODY).expect("prepare");
        let host = grant();
        let stored = receipt(prepared.admission_digest(), "attempt-1");
        let verified = prepared
            .verify_store_receipt(check(&host, &stored))
            .expect("stored admission digest");
        assert_eq!(verified.receipt().digest, prepared.admission_digest());
        assert_eq!(
            verified.request_projection_digest(),
            prepared.request_projection_digest()
        );
        assert_ne!(
            verified.receipt().digest,
            verified.request_projection_digest()
        );
        assert_ne!(verified.receipt().digest, verified.body_fingerprint());

        let swapped = receipt(prepared.request_projection_digest(), "attempt-1");
        assert_eq!(
            prepared.verify_store_receipt(check(&host, &swapped)),
            Err(BindError::ForgedReceipt)
        );
        let fingerprint = receipt(prepared.body_fingerprint(), "attempt-1");
        assert_eq!(
            prepared.verify_store_receipt(check(&host, &fingerprint)),
            Err(BindError::ForgedReceipt)
        );
        let forged = receipt(&"ab".repeat(32), "attempt-1");
        assert_eq!(
            prepared.verify_store_receipt(check(&host, &forged)),
            Err(BindError::ForgedReceipt)
        );
        let other_request = AdmissionReceipt {
            request_id: RequestId::new("req-other"),
            digest: prepared.admission_digest().to_string(),
            attempt_id: AttemptId::new("attempt-1"),
        };
        assert_eq!(
            prepared.verify_store_receipt(check(&host, &other_request)),
            Err(BindError::RequestMismatch)
        );
        let expected = AttemptId::new("attempt-1");
        let wrong_attempt = receipt(prepared.admission_digest(), "attempt-other");
        assert_eq!(
            prepared.verify_store_receipt(StoreReceiptCheck {
                receipt: &wrong_attempt,
                host_passed_grant: &host,
                expected_attempt: Some(&expected),
            }),
            Err(BindError::AttemptMismatch)
        );
        let empty_attempt = receipt(prepared.admission_digest(), "");
        assert_eq!(
            prepared.verify_store_receipt(check(&host, &empty_attempt)),
            Err(BindError::AttemptMismatch)
        );
    }

    #[test]
    fn stale_grant_does_not_verify() {
        let prepared = prepare(SEND_BODY).expect("prepare");
        let stored = receipt(prepared.admission_digest(), "attempt-1");
        let mut peer = grant();
        peer.actor_id = ActorId::new("actor-peer");
        assert_eq!(
            prepared.verify_store_receipt(check(&peer, &stored)),
            Err(BindError::StaleGrant)
        );
        let mut older = grant();
        older.revision = 2;
        assert_eq!(
            prepared.verify_store_receipt(check(&older, &stored)),
            Err(BindError::StaleGrant)
        );
        let mut revoked = grant();
        revoked.revoked = true;
        assert_eq!(
            prepared.verify_store_receipt(check(&revoked, &stored)),
            Err(BindError::StaleGrant)
        );
    }

    #[test]
    fn caller_held_is_not_durable_admission() {
        let first = prepare(SEND_BODY).expect("prepare");
        let host = grant();
        let request_id = RequestId::new("req-1");
        let other =
            r#"{"kind":"operation.run","resource_id":"resource-1","parent_id":null,"body":"khác"}"#;
        assert_eq!(
            prepare_host_binding(HostBindInput {
                host_passed_grant: &host,
                request_id: &request_id,
                body: other,
                client_scope: None,
                caller_held: Some(&first),
            }),
            Err(BindError::SameIdDifferentBody)
        );
        let replay = prepare_host_binding(HostBindInput {
            host_passed_grant: &host,
            request_id: &request_id,
            body: SEND_BODY,
            client_scope: None,
            caller_held: Some(&first),
        })
        .expect("same canonical body");
        assert_eq!(replay, first);
        let padded = format!(" {SEND_BODY}");
        let same_payload = prepare_host_binding(HostBindInput {
            host_passed_grant: &host,
            request_id: &request_id,
            body: &padded,
            client_scope: None,
            caller_held: Some(&first),
        })
        .expect("whitespace is the same canonical payload");
        assert_eq!(same_payload.admission_digest(), first.admission_digest());

        let fresh = prepare(other).expect("no caller-held is a new preparation");
        assert_ne!(fresh.body_fingerprint(), first.body_fingerprint());
        assert_eq!(fresh.request_id().as_str(), "req-1");

        let mut peer = grant();
        peer.actor_id = ActorId::new("actor-peer");
        assert_eq!(
            prepare_host_binding(HostBindInput {
                host_passed_grant: &peer,
                request_id: &request_id,
                body: SEND_BODY,
                client_scope: None,
                caller_held: Some(&first),
            }),
            Err(BindError::Denied)
        );
        let mut next_revision = grant();
        next_revision.revision = 4;
        assert_eq!(
            prepare_host_binding(HostBindInput {
                host_passed_grant: &next_revision,
                request_id: &request_id,
                body: SEND_BODY,
                client_scope: None,
                caller_held: Some(&first),
            }),
            Err(BindError::StaleGrant)
        );
    }

    #[test]
    fn top_level_scope_and_conflicting_kind_are_rejected() {
        assert_eq!(
            prepare(r#"{"kind":"operation.run","tenant_id":"user-made-up"}"#),
            Err(BindError::ForgedScope)
        );
        assert_eq!(
            prepare(r#"{"kind":"operation.run","tenant\u005fid":"user-made-up"}"#),
            Err(BindError::ForgedScope)
        );
        let nested = prepare(r#"{"kind":"operation.run","meta":{"tenant_id":"user-made-up"}}"#)
            .expect("nested scope is not authority");
        assert_eq!(nested.tenant_id().as_str(), "tenant-a");
        assert!(
            nested
                .request_bytes()
                .contains("\"tenant_id\":\"tenant-a\"")
        );
        assert!(
            !nested
                .request_bytes()
                .contains("\"tenant_id\":\"user-made-up\",\"workspace_id\"")
        );

        assert_eq!(
            prepare(r#"{"kind":"operation.run","kind":"operation.other"}"#),
            Err(BindError::DuplicateKind)
        );
        assert_eq!(
            prepare(r#"{"kind":"operation.run","\u006b\u0069\u006e\u0064":"operation.other"}"#),
            Err(BindError::DuplicateKind)
        );
        let repeated = prepare(
            r#"{"kind":"operation.run","kind":"operation.run","resource_id":"resource-1","parent_id":null,"body":"xin chào"}"#,
        )
        .expect("same kind collapses with serde");
        let prepared = prepare(SEND_BODY).expect("prepare");
        assert_eq!(repeated.admission_digest(), prepared.admission_digest());
        assert_eq!(
            prepare(r#"{"kind":"","resource_id":"resource-1"}"#),
            Err(BindError::InvalidBody)
        );
        assert_eq!(prepare(r#"{"kind":1}"#), Err(BindError::InvalidBody));
        assert_eq!(prepare("[1,2]"), Err(BindError::InvalidBody));
        assert_eq!(
            prepare(&format!("{SEND_BODY}{{}}")),
            Err(BindError::InvalidBody)
        );
    }

    #[test]
    fn syntax_and_depth_remain_without_a_copied_body_cap() {
        let large = format!(
            "{{\"kind\":\"operation.run\",\"pad\":\"{}\"}}",
            "x".repeat(70_000)
        );
        assert!(large.len() > 65_536);
        assert!(prepare(&large).is_ok());
        let deep = format!("{}{}", "{".repeat(129), "}".repeat(129));
        assert_eq!(prepare(&deep), Err(BindError::InvalidBody));
    }

    #[test]
    fn numeric_key_order_does_not_change_typed_digest() {
        let first =
            prepare(r#"{"kind":"operation.run","n":1,"neg":-2,"f":1.5,"z":0.1}"#).expect("numeric");
        let second = prepare(r#"{"z":0.1,"f":1.5,"neg":-2,"n":1,"kind":"operation.run"}"#)
            .expect("reordered numeric");
        assert_eq!(first.admission_digest(), second.admission_digest());
        assert_eq!(
            first.request_projection_digest(),
            second.request_projection_digest()
        );
        assert_eq!(first.body_fingerprint(), second.body_fingerprint());
        assert_typed_wire(
            r#"{"z":0.1,"f":1.5,"neg":-2,"n":1,"kind":"operation.run"}"#,
            &second,
        );
    }

    #[test]
    fn unsorted_runtime_wire_is_held_and_not_a_new_job() {
        use crate::{ExistingRequestDisposition, disposition_for_existing_request};
        let prepared = prepare(SEND_BODY).expect("prepare");
        let (request, admission) = typed(SEND_BODY);
        let old_admission = b"{\"tenant_id\":\"tenant-a\",\"workspace_id\":\"workspace-a\",\"actor_id\":\"actor-owner\",\"request_id\":\"req-1\",\"payload\":{\"kind\":\"operation.run\",\"resource_id\":\"resource-1\",\"parent_id\":null,\"body\":\"xin ch\xc3\xa0o\"}}";
        let old_digest = sha256_hex(old_admission);
        assert_ne!(old_digest, prepared.admission_digest());
        assert_eq!(
            old_digest,
            "ed4594de32b54c4df81a86a7de8a046c8e1ef4e30700661937cc86bc5195d53c"
        );
        assert_eq!(
            disposition_for_existing_request(&admission, &old_digest, Some(old_admission)),
            ExistingRequestDisposition::HoldRecognizedOldWire
        );
        assert_eq!(
            disposition_for_existing_request(&admission, &old_digest, None),
            ExistingRequestDisposition::HoldMismatch
        );
        assert_eq!(
            disposition_for_existing_request(
                &admission,
                prepared.admission_digest(),
                Some(old_admission)
            ),
            ExistingRequestDisposition::ReplayCurrent
        );
        let host = grant();
        let stored = receipt(&old_digest, "attempt-1");
        assert_eq!(
            prepared.verify_store_receipt(check(&host, &stored)),
            Err(BindError::ForgedReceipt)
        );
        let other = RequestId::new("req-other");
        assert_ne!(admission.request_id, other);
        assert_ne!(request.digest(), prepared.admission_digest());
        assert_ne!(
            disposition_for_existing_request(&admission, "not-a-digest", Some(old_admission)),
            ExistingRequestDisposition::ReplayCurrent
        );
    }

    #[test]
    fn foreign_wire_is_not_recognized_old_or_replay() {
        use crate::{ExistingRequestDisposition, disposition_for_existing_request};
        let (_request, admission) = typed(SEND_BODY);
        let cases = [
            br#"{"tenant_id":"tenant-b","workspace_id":"workspace-a","actor_id":"actor-owner","request_id":"req-1","payload":{"kind":"operation.run","resource_id":"resource-1","parent_id":null,"body":"xin ch\xc3\xa0o"}}"#.as_slice(),
            br#"{"tenant_id":"tenant-a","workspace_id":"workspace-a","actor_id":"actor-owner","request_id":"req-9","payload":{"kind":"operation.run","resource_id":"resource-1","parent_id":null,"body":"xin ch\xc3\xa0o"}}"#.as_slice(),
            br#"{"tenant_id":"tenant-a","workspace_id":"workspace-a","actor_id":"actor-owner","request_id":"req-1","payload":{"kind":"operation.cancel","resource_id":"resource-1"}}"#.as_slice(),
            br#"{"tenant_id":"tenant-a","workspace_id":"workspace-a","actor_id":"actor-owner","request_id":"req-1","payload":{"kind":"operation.run","resource_id":"resource-9","parent_id":null,"body":"xin ch\xc3\xa0o"}}"#.as_slice(),
            b"{",
        ];
        for wire in cases {
            let digest = sha256_hex(wire);
            assert_eq!(
                disposition_for_existing_request(&admission, &digest, Some(wire)),
                ExistingRequestDisposition::HoldMismatch,
                "{}",
                String::from_utf8_lossy(wire)
            );
            assert_ne!(
                disposition_for_existing_request(&admission, &digest, Some(wire)),
                ExistingRequestDisposition::ReplayCurrent
            );
        }
        assert_eq!(
            disposition_for_existing_request(&admission, "abc", None),
            ExistingRequestDisposition::HoldMismatch
        );
    }

    #[test]
    fn forged_scope_and_empty_grant_do_not_mint_ids() {
        let empty = ActorGrant {
            tenant_id: TenantId::new(""),
            workspace_id: WorkspaceId::new("workspace-a"),
            actor_id: ActorId::new(""),
            revision: 1,
            revoked: false,
        };
        let request_id = RequestId::new("req-1");
        let claim = UntrustedScope {
            tenant_id: "user-made-up".into(),
            workspace_id: "workspace-made-up".into(),
            actor_id: "actor-made-up".into(),
        };
        assert_eq!(
            prepare_host_binding(HostBindInput {
                host_passed_grant: &empty,
                request_id: &request_id,
                body: SEND_BODY,
                client_scope: Some(&claim),
                caller_held: None,
            }),
            Err(BindError::EmptyGrant)
        );
        let host = grant();
        let mismatched = UntrustedScope {
            tenant_id: "tenant-a".into(),
            workspace_id: "workspace-a".into(),
            actor_id: "user-made-up".into(),
        };
        assert_eq!(
            prepare_host_binding(HostBindInput {
                host_passed_grant: &host,
                request_id: &request_id,
                body: SEND_BODY,
                client_scope: Some(&mismatched),
                caller_held: None,
            }),
            Err(BindError::ForgedScope)
        );
        let matching = UntrustedScope {
            tenant_id: "tenant-a".into(),
            workspace_id: "workspace-a".into(),
            actor_id: "actor-owner".into(),
        };
        let with_claim = prepare_host_binding(HostBindInput {
            host_passed_grant: &host,
            request_id: &request_id,
            body: SEND_BODY,
            client_scope: Some(&matching),
            caller_held: None,
        })
        .expect("matching claim is not authority");
        let without_claim = prepare(SEND_BODY).expect("grant only");
        assert_eq!(with_claim.request_bytes(), without_claim.request_bytes());
        assert!(
            with_claim
                .request_bytes()
                .contains("\"actor_id\":\"actor-owner\"")
        );
        assert!(!with_claim.request_bytes().contains("user-made-up"));
        assert_eq!(
            prepare_host_binding(HostBindInput {
                host_passed_grant: &host,
                request_id: &RequestId::new(""),
                body: SEND_BODY,
                client_scope: None,
                caller_held: None,
            }),
            Err(BindError::EmptyRequestId)
        );
    }

    #[test]
    fn revoked_grant_and_wrong_caller_held_id_are_denied() {
        let mut host = grant();
        host.revoked = true;
        let request_id = RequestId::new("req-1");
        assert_eq!(
            prepare_host_binding(HostBindInput {
                host_passed_grant: &host,
                request_id: &request_id,
                body: SEND_BODY,
                client_scope: None,
                caller_held: None,
            }),
            Err(BindError::Denied)
        );
        let first = prepare(SEND_BODY).expect("prepare");
        let other_id = RequestId::new("req-2");
        assert_eq!(
            prepare_host_binding(HostBindInput {
                host_passed_grant: &grant(),
                request_id: &other_id,
                body: SEND_BODY,
                client_scope: None,
                caller_held: Some(&first),
            }),
            Err(BindError::RequestMismatch)
        );
    }
}
