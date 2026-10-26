//! Compact JSON bytes that do not follow `serde_json`'s map implementation.
//!
//! Struct fields stay in declaration order. JSON object keys are sorted.
//! Arrays, strings, and scalars use `serde_json`'s compact scalar encoding,
//! which does not depend on `preserve_order`.

use std::collections::BTreeMap;
use std::fmt;

use serde::ser::{
    Serialize, SerializeMap, SerializeSeq, SerializeStruct, SerializeStructVariant, SerializeTuple,
    SerializeTupleStruct, SerializeTupleVariant, Serializer,
};
use sha2::{Digest, Sha256};

use crate::CanonicalAdmission;

#[derive(Debug)]
pub struct CanonicalError;

impl fmt::Display for CanonicalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("value is not canonical JSON")
    }
}

impl std::error::Error for CanonicalError {}

impl serde::ser::Error for CanonicalError {
    fn custom<T: fmt::Display>(_message: T) -> Self {
        CanonicalError
    }
}

/// SHA-256 hex of [`canonical_bytes`].
pub fn canonical_digest<T: Serialize>(value: &T) -> String {
    let bytes = canonical_bytes(value).expect("canonical value serializes");
    hex::encode(Sha256::digest(bytes))
}

/// One byte encoding for request and admission digests and for the host binder.
pub fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, CanonicalError> {
    let mut out = Vec::new();
    value.serialize(Canon { out: &mut out })?;
    Ok(out)
}

/// What to do with a request id that already has a stored digest.
///
/// No variant admits another attempt. A mismatch is not a new job.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExistingRequestDisposition {
    /// Stored digest is the current canonical digest. Return the existing receipt.
    ReplayCurrent,
    /// Stored digest is the SHA-256 of `held_wire`, and those bytes are not the
    /// current canonical bytes. Hold. Do not rewrite the digest. Do not start
    /// another attempt.
    HoldRecognizedOldWire,
    /// Not current, and not a recognized old wire. Hold. Do not insert.
    HoldMismatch,
}

/// Classify a digest already stored for this admission's request id.
///
/// `held_wire` is the exact text the old worker persisted (`canonical_json`),
/// when that text still exists. Parsed JSON storage may lose key order, so a missing
/// wire cannot be recognized and must stay [`ExistingRequestDisposition::HoldMismatch`].
/// A hash-valid wire with a different tenant, workspace, actor, request, or
/// logical payload is not an old worker and is not a replay.
pub fn disposition_for_existing_request(
    admission: &CanonicalAdmission,
    stored_digest: &str,
    held_wire: Option<&[u8]>,
) -> ExistingRequestDisposition {
    let current = canonical_digest(admission);
    let wire = held_wire.filter(|bytes| !bytes.is_empty());
    let Some(wire) = wire else {
        return if stored_digest == current {
            ExistingRequestDisposition::ReplayCurrent
        } else {
            ExistingRequestDisposition::HoldMismatch
        };
    };
    if !wire_matches_admission(admission, wire) {
        return ExistingRequestDisposition::HoldMismatch;
    }
    if stored_digest == current {
        return ExistingRequestDisposition::ReplayCurrent;
    }
    let wire_digest = hex::encode(Sha256::digest(wire));
    let current_bytes = canonical_bytes(admission).ok();
    if stored_digest == wire_digest && current_bytes.as_deref() != Some(wire) {
        return ExistingRequestDisposition::HoldRecognizedOldWire;
    }
    ExistingRequestDisposition::HoldMismatch
}

fn wire_matches_admission(admission: &CanonicalAdmission, wire: &[u8]) -> bool {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(wire) else {
        return false;
    };
    let Some(object) = value.as_object() else {
        return false;
    };
    let expected = [
        "tenant_id",
        "workspace_id",
        "actor_id",
        "request_id",
        "payload",
    ];
    if object.len() != expected.len() || expected.iter().any(|key| !object.contains_key(*key)) {
        return false;
    }
    let same = |key: &str, expected: &str| {
        object.get(key).and_then(|item| item.as_str()) == Some(expected)
    };
    if !same("tenant_id", admission.tenant_id.as_str())
        || !same("workspace_id", admission.workspace_id.as_str())
        || !same("actor_id", admission.actor_id.as_str())
        || !same("request_id", admission.request_id.as_str())
    {
        return false;
    }
    let Some(payload) = object.get("payload") else {
        return false;
    };
    let Ok(wire_payload) = canonical_bytes(payload) else {
        return false;
    };
    let Ok(expected_payload) = canonical_bytes(&admission.payload) else {
        return false;
    };
    wire_payload == expected_payload
}

fn write_scalar<T: Serialize + ?Sized>(out: &mut Vec<u8>, value: &T) -> Result<(), CanonicalError> {
    let bytes = serde_json::to_vec(value).map_err(|_| CanonicalError)?;
    out.extend_from_slice(&bytes);
    Ok(())
}

struct Canon<'a> {
    out: &'a mut Vec<u8>,
}

impl<'a> Serializer for Canon<'a> {
    type Ok = ();
    type Error = CanonicalError;
    type SerializeSeq = Seq<'a>;
    type SerializeTuple = Seq<'a>;
    type SerializeTupleStruct = Seq<'a>;
    type SerializeTupleVariant = Seq<'a>;
    type SerializeMap = Map<'a>;
    type SerializeStruct = Struct<'a>;
    type SerializeStructVariant = Struct<'a>;

    fn serialize_bool(self, value: bool) -> Result<(), CanonicalError> {
        write_scalar(self.out, &value)
    }
    fn serialize_i8(self, value: i8) -> Result<(), CanonicalError> {
        write_scalar(self.out, &value)
    }
    fn serialize_i16(self, value: i16) -> Result<(), CanonicalError> {
        write_scalar(self.out, &value)
    }
    fn serialize_i32(self, value: i32) -> Result<(), CanonicalError> {
        write_scalar(self.out, &value)
    }
    fn serialize_i64(self, value: i64) -> Result<(), CanonicalError> {
        write_scalar(self.out, &value)
    }
    fn serialize_i128(self, _value: i128) -> Result<(), CanonicalError> {
        Err(CanonicalError)
    }
    fn serialize_u8(self, value: u8) -> Result<(), CanonicalError> {
        write_scalar(self.out, &value)
    }
    fn serialize_u16(self, value: u16) -> Result<(), CanonicalError> {
        write_scalar(self.out, &value)
    }
    fn serialize_u32(self, value: u32) -> Result<(), CanonicalError> {
        write_scalar(self.out, &value)
    }
    fn serialize_u64(self, value: u64) -> Result<(), CanonicalError> {
        write_scalar(self.out, &value)
    }
    fn serialize_u128(self, _value: u128) -> Result<(), CanonicalError> {
        Err(CanonicalError)
    }
    fn serialize_f32(self, value: f32) -> Result<(), CanonicalError> {
        write_scalar(self.out, &value)
    }
    fn serialize_f64(self, value: f64) -> Result<(), CanonicalError> {
        write_scalar(self.out, &value)
    }
    fn serialize_char(self, value: char) -> Result<(), CanonicalError> {
        write_scalar(self.out, &value)
    }
    fn serialize_str(self, value: &str) -> Result<(), CanonicalError> {
        write_scalar(self.out, value)
    }
    fn serialize_bytes(self, _value: &[u8]) -> Result<(), CanonicalError> {
        Err(CanonicalError)
    }
    fn serialize_none(self) -> Result<(), CanonicalError> {
        self.out.extend_from_slice(b"null");
        Ok(())
    }
    fn serialize_some<T: Serialize + ?Sized>(self, value: &T) -> Result<(), CanonicalError> {
        value.serialize(self)
    }
    fn serialize_unit(self) -> Result<(), CanonicalError> {
        self.out.extend_from_slice(b"null");
        Ok(())
    }
    fn serialize_unit_struct(self, _name: &'static str) -> Result<(), CanonicalError> {
        self.serialize_unit()
    }
    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
    ) -> Result<(), CanonicalError> {
        self.serialize_str(variant)
    }
    fn serialize_newtype_struct<T: Serialize + ?Sized>(
        self,
        _name: &'static str,
        value: &T,
    ) -> Result<(), CanonicalError> {
        value.serialize(self)
    }
    fn serialize_newtype_variant<T: Serialize + ?Sized>(
        self,
        _name: &'static str,
        _index: u32,
        _variant: &'static str,
        _value: &T,
    ) -> Result<(), CanonicalError> {
        Err(CanonicalError)
    }
    fn serialize_seq(self, _len: Option<usize>) -> Result<Seq<'a>, CanonicalError> {
        Ok(Seq {
            out: self.out,
            first: true,
        })
    }
    fn serialize_tuple(self, len: usize) -> Result<Seq<'a>, CanonicalError> {
        self.serialize_seq(Some(len))
    }
    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        len: usize,
    ) -> Result<Seq<'a>, CanonicalError> {
        self.serialize_seq(Some(len))
    }
    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Seq<'a>, CanonicalError> {
        Err(CanonicalError)
    }
    fn serialize_map(self, _len: Option<usize>) -> Result<Map<'a>, CanonicalError> {
        Ok(Map {
            out: self.out,
            entries: BTreeMap::new(),
            pending_key: None,
        })
    }
    fn serialize_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Struct<'a>, CanonicalError> {
        Ok(Struct {
            out: self.out,
            first: true,
        })
    }
    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Struct<'a>, CanonicalError> {
        Err(CanonicalError)
    }
}

struct Seq<'a> {
    out: &'a mut Vec<u8>,
    first: bool,
}

impl SerializeSeq for Seq<'_> {
    type Ok = ();
    type Error = CanonicalError;

    fn serialize_element<T: Serialize + ?Sized>(
        &mut self,
        value: &T,
    ) -> Result<(), CanonicalError> {
        if self.first {
            self.out.push(b'[');
            self.first = false;
        } else {
            self.out.push(b',');
        }
        value.serialize(Canon { out: self.out })
    }
    fn end(self) -> Result<(), CanonicalError> {
        if self.first {
            self.out.extend_from_slice(b"[]");
        } else {
            self.out.push(b']');
        }
        Ok(())
    }
}

impl SerializeTuple for Seq<'_> {
    type Ok = ();
    type Error = CanonicalError;

    fn serialize_element<T: Serialize + ?Sized>(
        &mut self,
        value: &T,
    ) -> Result<(), CanonicalError> {
        SerializeSeq::serialize_element(self, value)
    }
    fn end(self) -> Result<(), CanonicalError> {
        SerializeSeq::end(self)
    }
}

impl SerializeTupleStruct for Seq<'_> {
    type Ok = ();
    type Error = CanonicalError;

    fn serialize_field<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), CanonicalError> {
        SerializeSeq::serialize_element(self, value)
    }
    fn end(self) -> Result<(), CanonicalError> {
        SerializeSeq::end(self)
    }
}

impl SerializeTupleVariant for Seq<'_> {
    type Ok = ();
    type Error = CanonicalError;

    fn serialize_field<T: Serialize + ?Sized>(&mut self, _value: &T) -> Result<(), CanonicalError> {
        Err(CanonicalError)
    }
    fn end(self) -> Result<(), CanonicalError> {
        Err(CanonicalError)
    }
}

struct Map<'a> {
    out: &'a mut Vec<u8>,
    entries: BTreeMap<String, Vec<u8>>,
    pending_key: Option<String>,
}

impl SerializeMap for Map<'_> {
    type Ok = ();
    type Error = CanonicalError;

    fn serialize_key<T: Serialize + ?Sized>(&mut self, key: &T) -> Result<(), CanonicalError> {
        self.pending_key = Some(key.serialize(KeySink)?);
        Ok(())
    }
    fn serialize_value<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), CanonicalError> {
        let key = self.pending_key.take().ok_or(CanonicalError)?;
        let mut encoded = Vec::new();
        value.serialize(Canon { out: &mut encoded })?;
        self.entries.insert(key, encoded);
        Ok(())
    }
    fn end(self) -> Result<(), CanonicalError> {
        self.out.push(b'{');
        for (index, (key, value)) in self.entries.iter().enumerate() {
            if index > 0 {
                self.out.push(b',');
            }
            write_scalar(self.out, key)?;
            self.out.push(b':');
            self.out.extend_from_slice(value);
        }
        self.out.push(b'}');
        Ok(())
    }
}

struct Struct<'a> {
    out: &'a mut Vec<u8>,
    first: bool,
}

impl SerializeStruct for Struct<'_> {
    type Ok = ();
    type Error = CanonicalError;

    fn serialize_field<T: Serialize + ?Sized>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), CanonicalError> {
        if self.first {
            self.out.push(b'{');
            self.first = false;
        } else {
            self.out.push(b',');
        }
        write_scalar(self.out, key)?;
        self.out.push(b':');
        value.serialize(Canon { out: self.out })
    }
    fn end(self) -> Result<(), CanonicalError> {
        if self.first {
            self.out.extend_from_slice(b"{}");
        } else {
            self.out.push(b'}');
        }
        Ok(())
    }
}

impl SerializeStructVariant for Struct<'_> {
    type Ok = ();
    type Error = CanonicalError;

    fn serialize_field<T: Serialize + ?Sized>(
        &mut self,
        _key: &'static str,
        _value: &T,
    ) -> Result<(), CanonicalError> {
        Err(CanonicalError)
    }
    fn end(self) -> Result<(), CanonicalError> {
        Err(CanonicalError)
    }
}

struct KeySink;

impl Serializer for KeySink {
    type Ok = String;
    type Error = CanonicalError;
    type SerializeSeq = Impossible;
    type SerializeTuple = Impossible;
    type SerializeTupleStruct = Impossible;
    type SerializeTupleVariant = Impossible;
    type SerializeMap = Impossible;
    type SerializeStruct = Impossible;
    type SerializeStructVariant = Impossible;

    fn serialize_str(self, value: &str) -> Result<String, CanonicalError> {
        Ok(value.to_string())
    }
    fn serialize_newtype_struct<T: Serialize + ?Sized>(
        self,
        _name: &'static str,
        value: &T,
    ) -> Result<String, CanonicalError> {
        value.serialize(self)
    }
    fn serialize_bool(self, _value: bool) -> Result<String, CanonicalError> {
        Err(CanonicalError)
    }
    fn serialize_i8(self, _value: i8) -> Result<String, CanonicalError> {
        Err(CanonicalError)
    }
    fn serialize_i16(self, _value: i16) -> Result<String, CanonicalError> {
        Err(CanonicalError)
    }
    fn serialize_i32(self, _value: i32) -> Result<String, CanonicalError> {
        Err(CanonicalError)
    }
    fn serialize_i64(self, _value: i64) -> Result<String, CanonicalError> {
        Err(CanonicalError)
    }
    fn serialize_i128(self, _value: i128) -> Result<String, CanonicalError> {
        Err(CanonicalError)
    }
    fn serialize_u8(self, _value: u8) -> Result<String, CanonicalError> {
        Err(CanonicalError)
    }
    fn serialize_u16(self, _value: u16) -> Result<String, CanonicalError> {
        Err(CanonicalError)
    }
    fn serialize_u32(self, _value: u32) -> Result<String, CanonicalError> {
        Err(CanonicalError)
    }
    fn serialize_u64(self, _value: u64) -> Result<String, CanonicalError> {
        Err(CanonicalError)
    }
    fn serialize_u128(self, _value: u128) -> Result<String, CanonicalError> {
        Err(CanonicalError)
    }
    fn serialize_f32(self, _value: f32) -> Result<String, CanonicalError> {
        Err(CanonicalError)
    }
    fn serialize_f64(self, _value: f64) -> Result<String, CanonicalError> {
        Err(CanonicalError)
    }
    fn serialize_char(self, _value: char) -> Result<String, CanonicalError> {
        Err(CanonicalError)
    }
    fn serialize_bytes(self, _value: &[u8]) -> Result<String, CanonicalError> {
        Err(CanonicalError)
    }
    fn serialize_none(self) -> Result<String, CanonicalError> {
        Err(CanonicalError)
    }
    fn serialize_some<T: Serialize + ?Sized>(self, _value: &T) -> Result<String, CanonicalError> {
        Err(CanonicalError)
    }
    fn serialize_unit(self) -> Result<String, CanonicalError> {
        Err(CanonicalError)
    }
    fn serialize_unit_struct(self, _name: &'static str) -> Result<String, CanonicalError> {
        Err(CanonicalError)
    }
    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _index: u32,
        _variant: &'static str,
    ) -> Result<String, CanonicalError> {
        Err(CanonicalError)
    }
    fn serialize_newtype_variant<T: Serialize + ?Sized>(
        self,
        _name: &'static str,
        _index: u32,
        _variant: &'static str,
        _value: &T,
    ) -> Result<String, CanonicalError> {
        Err(CanonicalError)
    }
    fn serialize_seq(self, _len: Option<usize>) -> Result<Impossible, CanonicalError> {
        Err(CanonicalError)
    }
    fn serialize_tuple(self, _len: usize) -> Result<Impossible, CanonicalError> {
        Err(CanonicalError)
    }
    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Impossible, CanonicalError> {
        Err(CanonicalError)
    }
    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Impossible, CanonicalError> {
        Err(CanonicalError)
    }
    fn serialize_map(self, _len: Option<usize>) -> Result<Impossible, CanonicalError> {
        Err(CanonicalError)
    }
    fn serialize_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Impossible, CanonicalError> {
        Err(CanonicalError)
    }
    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Impossible, CanonicalError> {
        Err(CanonicalError)
    }
}

struct Impossible;

impl SerializeSeq for Impossible {
    type Ok = String;
    type Error = CanonicalError;
    fn serialize_element<T: Serialize + ?Sized>(
        &mut self,
        _value: &T,
    ) -> Result<(), CanonicalError> {
        Err(CanonicalError)
    }
    fn end(self) -> Result<String, CanonicalError> {
        Err(CanonicalError)
    }
}
impl SerializeTuple for Impossible {
    type Ok = String;
    type Error = CanonicalError;
    fn serialize_element<T: Serialize + ?Sized>(
        &mut self,
        _value: &T,
    ) -> Result<(), CanonicalError> {
        Err(CanonicalError)
    }
    fn end(self) -> Result<String, CanonicalError> {
        Err(CanonicalError)
    }
}
impl SerializeTupleStruct for Impossible {
    type Ok = String;
    type Error = CanonicalError;
    fn serialize_field<T: Serialize + ?Sized>(&mut self, _value: &T) -> Result<(), CanonicalError> {
        Err(CanonicalError)
    }
    fn end(self) -> Result<String, CanonicalError> {
        Err(CanonicalError)
    }
}
impl SerializeTupleVariant for Impossible {
    type Ok = String;
    type Error = CanonicalError;
    fn serialize_field<T: Serialize + ?Sized>(&mut self, _value: &T) -> Result<(), CanonicalError> {
        Err(CanonicalError)
    }
    fn end(self) -> Result<String, CanonicalError> {
        Err(CanonicalError)
    }
}
impl SerializeMap for Impossible {
    type Ok = String;
    type Error = CanonicalError;
    fn serialize_key<T: Serialize + ?Sized>(&mut self, _key: &T) -> Result<(), CanonicalError> {
        Err(CanonicalError)
    }
    fn serialize_value<T: Serialize + ?Sized>(&mut self, _value: &T) -> Result<(), CanonicalError> {
        Err(CanonicalError)
    }
    fn end(self) -> Result<String, CanonicalError> {
        Err(CanonicalError)
    }
}
impl SerializeStruct for Impossible {
    type Ok = String;
    type Error = CanonicalError;
    fn serialize_field<T: Serialize + ?Sized>(
        &mut self,
        _key: &'static str,
        _value: &T,
    ) -> Result<(), CanonicalError> {
        Err(CanonicalError)
    }
    fn end(self) -> Result<String, CanonicalError> {
        Err(CanonicalError)
    }
}
impl SerializeStructVariant for Impossible {
    type Ok = String;
    type Error = CanonicalError;
    fn serialize_field<T: Serialize + ?Sized>(
        &mut self,
        _key: &'static str,
        _value: &T,
    ) -> Result<(), CanonicalError> {
        Err(CanonicalError)
    }
    fn end(self) -> Result<String, CanonicalError> {
        Err(CanonicalError)
    }
}
