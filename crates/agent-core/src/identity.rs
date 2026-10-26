//! Stable effect identity and the historical digests a payload can prove.
//!
//! [`LogicalCall`] is the call, before any args digest. A store must consult
//! that identity before it selects a digest-based effect id. New claims use
//! [`trace_effect_identity`]'s canonical digest. This module does not rewrite
//! a stored digest and does not invent key order the input no longer has.

use serde::Serialize;
use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::canonical::{CanonicalError, canonical_digest};
use crate::{AttemptId, EffectId, effect_id_for};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectIdentity {
    pub args_digest: String,
    pub effect_id: EffectId,
}

/// Canonical identity plus historical digests of the same logical payload.
///
/// `legacy` is empty when every proven encoding hashes to `canonical`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TracedEffectIdentity {
    pub call_id: String,
    /// Lookup key checked before a digest-based effect id is chosen.
    /// Defaults to [`Self::call_id`]. A caller that reuses `call_id` inside
    /// effect ids, such as a tool name, must set a per-request key instead.
    pub logical_call_id: String,
    pub canonical: EffectIdentity,
    pub legacy: Vec<EffectIdentity>,
}

/// One tool call inside an attempt. Independent of args digest and key order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogicalCall {
    pub attempt_id: AttemptId,
    pub call_id: String,
}

impl TracedEffectIdentity {
    pub fn contains_digest(&self, digest: &str) -> bool {
        self.canonical.args_digest == digest
            || self.legacy.iter().any(|item| item.args_digest == digest)
    }

    pub fn identities(&self) -> impl Iterator<Item = &EffectIdentity> {
        std::iter::once(&self.canonical).chain(self.legacy.iter())
    }

    pub fn include_digest(&mut self, attempt: &AttemptId, args_digest: String) {
        if self.contains_digest(&args_digest) {
            return;
        }
        self.legacy
            .push(identity(attempt, &self.call_id, args_digest));
    }

    /// Call identity used to find a row before any digest-based effect id.
    pub fn logical_call(&self, attempt: &AttemptId) -> LogicalCall {
        LogicalCall {
            attempt_id: attempt.clone(),
            call_id: self.logical_call_id.clone(),
        }
    }

    pub fn with_logical_call_id(mut self, logical_call_id: impl Into<String>) -> Self {
        self.logical_call_id = logical_call_id.into();
        self
    }
}

fn identity(attempt: &AttemptId, call_id: &str, args_digest: String) -> EffectIdentity {
    let effect_id = effect_id_for(attempt, call_id, &args_digest);
    EffectIdentity {
        args_digest,
        effect_id,
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Canonical digest, plus this binary's historical `serde_json::to_vec` digest
/// when that feature encoding differs. Does not recover an insertion order
/// this `Serialize` value has already lost.
pub fn trace_effect_identity<T: Serialize>(
    attempt: &AttemptId,
    call_id: &str,
    args: &T,
) -> TracedEffectIdentity {
    let canonical = canonical_digest(args);
    let mut traced = TracedEffectIdentity {
        call_id: call_id.to_string(),
        logical_call_id: call_id.to_string(),
        canonical: identity(attempt, call_id, canonical),
        legacy: Vec::new(),
    };
    if let Ok(bytes) = serde_json::to_vec(args) {
        traced.include_digest(attempt, sha256_hex(&bytes));
    }
    traced
}

/// Both historical encodings from JSON text that still has object key order.
///
/// Sorted bytes are the canonical / core-graph digest. Text order is the
/// `preserve_order` digest. Duplicate keys are rejected rather than guessed.
pub fn trace_effect_identity_from_json(
    attempt: &AttemptId,
    call_id: &str,
    raw: &str,
) -> Result<TracedEffectIdentity, CanonicalError> {
    let node = parse_ordered(raw)?;
    if has_duplicate_keys(&node) {
        return Err(CanonicalError);
    }
    let canonical = canonical_digest(&node.to_value());
    let mut traced = TracedEffectIdentity {
        call_id: call_id.to_string(),
        logical_call_id: call_id.to_string(),
        canonical: identity(attempt, call_id, canonical),
        legacy: Vec::new(),
    };
    traced.include_digest(attempt, sha256_hex(&node.insertion_bytes()?));
    Ok(traced)
}

/// Compact object in the caller's key order. Scalars use `serde_json`.
/// Nested objects are emitted by `serde_json` and therefore follow this
/// binary's map order; use [`trace_effect_identity_from_json`] when nested
/// order must survive a core graph.
pub fn ordered_object_bytes(fields: &[(&str, &Value)]) -> Result<Vec<u8>, CanonicalError> {
    let mut out = Vec::from(*b"{");
    for (index, (key, value)) in fields.iter().enumerate() {
        if index > 0 {
            out.push(b',');
        }
        out.extend(serde_json::to_vec(key).map_err(|_| CanonicalError)?);
        out.push(b':');
        out.extend(serde_json::to_vec(value).map_err(|_| CanonicalError)?);
    }
    out.push(b'}');
    Ok(out)
}

#[derive(Debug, Clone)]
enum Node {
    Null,
    Bool(bool),
    Number(serde_json::Number),
    String(String),
    Array(Vec<Node>),
    Object(Vec<(String, Node)>),
}

impl Node {
    fn to_value(&self) -> Value {
        match self {
            Node::Null => Value::Null,
            Node::Bool(value) => Value::Bool(*value),
            Node::Number(value) => Value::Number(value.clone()),
            Node::String(value) => Value::String(value.clone()),
            Node::Array(items) => Value::Array(items.iter().map(Node::to_value).collect()),
            Node::Object(fields) => {
                let mut object = serde_json::Map::new();
                for (key, value) in fields {
                    object.insert(key.clone(), value.to_value());
                }
                Value::Object(object)
            }
        }
    }

    fn insertion_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        let mut out = Vec::new();
        self.write_insertion(&mut out)?;
        Ok(out)
    }

    fn write_insertion(&self, out: &mut Vec<u8>) -> Result<(), CanonicalError> {
        match self {
            Node::Null => out.extend_from_slice(b"null"),
            Node::Bool(value) => out.extend_from_slice(if *value { b"true" } else { b"false" }),
            Node::Number(value) => {
                out.extend(
                    serde_json::to_vec(&Value::Number(value.clone()))
                        .map_err(|_| CanonicalError)?,
                );
            }
            Node::String(value) => {
                out.extend(
                    serde_json::to_vec(&Value::String(value.clone()))
                        .map_err(|_| CanonicalError)?,
                );
            }
            Node::Array(items) => {
                out.push(b'[');
                for (index, item) in items.iter().enumerate() {
                    if index > 0 {
                        out.push(b',');
                    }
                    item.write_insertion(out)?;
                }
                out.push(b']');
            }
            Node::Object(fields) => {
                out.push(b'{');
                for (index, (key, value)) in fields.iter().enumerate() {
                    if index > 0 {
                        out.push(b',');
                    }
                    out.extend(serde_json::to_vec(key).map_err(|_| CanonicalError)?);
                    out.push(b':');
                    value.write_insertion(out)?;
                }
                out.push(b'}');
            }
        }
        Ok(())
    }
}

fn has_duplicate_keys(node: &Node) -> bool {
    match node {
        Node::Array(items) => items.iter().any(has_duplicate_keys),
        Node::Object(fields) => {
            let mut names = Vec::new();
            for (key, value) in fields {
                if names.contains(key) || has_duplicate_keys(value) {
                    return true;
                }
                names.push(key.clone());
            }
            false
        }
        _ => false,
    }
}

fn parse_ordered(raw: &str) -> Result<Node, CanonicalError> {
    let mut deserializer = serde_json::Deserializer::from_str(raw);
    let node = Node::deserialize(&mut deserializer).map_err(|_| CanonicalError)?;
    deserializer.end().map_err(|_| CanonicalError)?;
    Ok(node)
}

impl<'de> de::Deserialize<'de> for Node {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(NodeVisitor)
    }
}

struct NodeVisitor;

impl<'de> Visitor<'de> for NodeVisitor {
    type Value = Node;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("json")
    }

    fn visit_unit<E: de::Error>(self) -> Result<Node, E> {
        Ok(Node::Null)
    }

    fn visit_bool<E: de::Error>(self, value: bool) -> Result<Node, E> {
        Ok(Node::Bool(value))
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Node, E> {
        Ok(Node::Number(value.into()))
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Node, E> {
        Ok(Node::Number(value.into()))
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Node, E> {
        let number = serde_json::Number::from_f64(value).ok_or_else(|| E::custom("non-finite"))?;
        Ok(Node::Number(number))
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Node, E> {
        Ok(Node::String(value.to_owned()))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Node, A::Error> {
        let mut items = Vec::new();
        while let Some(item) = seq.next_element()? {
            items.push(item);
        }
        Ok(Node::Array(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Node, A::Error> {
        let mut fields = Vec::new();
        while let Some((key, value)) = map.next_entry()? {
            fields.push((key, value));
        }
        Ok(Node::Object(fields))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical_bytes;

    #[test]
    fn raw_json_traces_both_graphs_without_preserve_order() {
        let raw = r#"{"method":"GET","host":"127.0.0.1","port":9,"path":"/x"}"#;
        let attempt = AttemptId::new("attempt-1");
        let traced = trace_effect_identity_from_json(&attempt, "call-1", raw).expect("trace");
        assert_eq!(
            traced.canonical.args_digest,
            "35d537242c9b8155be6ddb479ddefd8f628a6de4f2c16a210d8f0d59aa38f26e"
        );
        assert_eq!(
            traced.legacy.len(),
            1,
            "insertion order must stay visible on the core graph"
        );
        assert_eq!(
            traced.legacy[0].args_digest,
            "c8ca635abb3e729466d1f97e974f58df864abc4e7f6e8718d7cf6835c62580f9"
        );
        assert_ne!(traced.canonical.effect_id, traced.legacy[0].effect_id);
        let again = trace_effect_identity_from_json(&attempt, "call-1", raw).expect("trace");
        assert_eq!(traced, again);
    }

    #[test]
    fn duplicate_keys_are_not_a_proven_identity() {
        let attempt = AttemptId::new("attempt-1");
        assert!(trace_effect_identity_from_json(&attempt, "call-1", r#"{"a":1,"a":2}"#).is_err());
    }

    #[test]
    fn canonical_sorts_integer_and_non_bmp_keys_and_keeps_negative_zero() {
        let integers = serde_json::json!({"0": 5, "2": 2, "10": 1, "02": 4, "a": 3});
        assert_eq!(
            canonical_bytes(&integers).expect("integers"),
            br#"{"0":5,"02":4,"10":1,"2":2,"a":3}"#
        );
        let marks = serde_json::json!({"a": 1, "é": 2, "": 3, "😀": 4});
        assert_eq!(
            canonical_bytes(&marks).expect("marks"),
            "{\"a\":1,\"é\":2,\"\":3,\"😀\":4}".as_bytes()
        );
        let signed = serde_json::json!({"a": -0.0});
        assert_eq!(
            canonical_bytes(&signed).expect("signed zero"),
            br#"{"a":-0.0}"#
        );
    }

    #[test]
    fn logical_call_does_not_depend_on_digest() {
        let attempt = AttemptId::new("attempt-1");
        let left = trace_effect_identity(&attempt, "call-9", &serde_json::json!({"z": 1}));
        let right = trace_effect_identity(&attempt, "call-9", &serde_json::json!({"a": 2}));
        assert_eq!(left.logical_call(&attempt), right.logical_call(&attempt));
        assert_ne!(left.canonical.args_digest, right.canonical.args_digest);
        assert_eq!(left.logical_call(&attempt).call_id, "call-9");
    }
}
