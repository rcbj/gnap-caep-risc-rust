// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

use crate::error::{fail, Error};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

pub(crate) type Obj = Map<String, Value>;

pub(crate) fn b64url(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

pub(crate) fn b64url_decode(value: &str) -> Result<Vec<u8>, Error> {
    URL_SAFE_NO_PAD.decode(value).map_err(|_| fail("signature", "the value is not base64url"))
}

pub(crate) fn b64std(data: &[u8]) -> String {
    STANDARD.encode(data)
}

pub(crate) fn b64std_decode(value: &str) -> Result<Vec<u8>, Error> {
    STANDARD.decode(value).map_err(|_| fail("signature", "the value is not base64"))
}

pub(crate) fn sha256(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}

pub(crate) fn parse(text: &str) -> Result<Value, Error> {
    serde_json::from_str(text).map_err(|err| fail("protocol", err.to_string()))
}

pub(crate) fn dump(value: &Value) -> Result<String, Error> {
    serde_json::to_string(value).map_err(|err| fail("protocol", err.to_string()))
}

pub(crate) fn obj<'a>(value: &'a Value) -> Option<&'a Obj> {
    value.as_object()
}

pub(crate) fn obj_mut<'a>(value: &'a mut Value) -> Option<&'a mut Obj> {
    value.as_object_mut()
}

pub(crate) fn as_str(value: &Value) -> Option<&str> {
    value.as_str()
}

pub(crate) fn as_f64(value: &Value) -> Option<f64> {
    if value.is_boolean() {
        return None;
    }
    value.as_f64().or_else(|| value.as_i64().map(|n| n as f64)).or_else(|| value.as_u64().map(|n| n as f64))
}

pub(crate) fn as_bool(value: &Value) -> Option<bool> {
    value.as_bool()
}

pub(crate) fn timing_eq(left: &str, right: &str) -> bool {
    let (a, b) = (left.as_bytes(), right.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

pub(crate) fn string_list(value: &Value) -> Option<Vec<String>> {
    let list = value.as_array()?;
    let mut out = Vec::new();
    for item in list {
        out.push(item.as_str()?.to_string());
    }
    Some(out)
}
