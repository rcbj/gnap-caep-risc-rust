// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

use crate::codec::{as_f64, as_str, b64url_decode, obj};
use crate::error::{fail, Error};
use crate::ssf::verify_compact;
use serde_json::{Map, Value};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug)]
pub struct Person {
    pub sub: String,
    pub claims: Map<String, Value>,
    pub assertion_verified: bool,
    pub iss: Option<String>,
    pub uid: Option<String>,
    pub email: Option<String>,
    pub name: Option<String>,
    pub preferred_username: Option<String>,
    pub sid: Option<String>,
    pub acr: Option<String>,
    pub amr: Vec<String>,
}

pub struct IdCheck<'a> {
    pub issuer: &'a str,
    pub audiences: Vec<String>,
    pub skew: f64,
    pub keys: &'a dyn Fn() -> Result<Vec<Map<String, Value>>, Error>,
}

pub fn uid_from_account(uri: &str) -> Option<String> {
    let rest = uri.strip_prefix("acct:")?;
    let (user, _host) = rest.split_once('@')?;
    Some(decode_user(user).unwrap_or_else(|| user.to_string()))
}

fn decode_user(value: &str) -> Option<String> {
    let mut bytes = Vec::new();
    let chars: Vec<char> = value.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] != '%' {
            let mut buf = [0u8; 4];
            bytes.extend_from_slice(chars[i].encode_utf8(&mut buf).as_bytes());
            i += 1;
            continue;
        }
        if i + 2 >= chars.len() {
            return None;
        }
        let hex: String = chars[i + 1..i + 3].iter().collect();
        bytes.push(u8::from_str_radix(&hex, 16).ok()?);
        i += 3;
    }
    let text = String::from_utf8(bytes).ok()?;
    if text.contains('\u{FFFD}') {
        return None;
    }
    Some(text)
}

pub fn person_from(subject: &Value, check: &IdCheck<'_>) -> Result<Option<Person>, Error> {
    let Some(doc) = obj(subject) else { return Ok(None) };
    let sub_ids = doc.get("sub_ids").and_then(|v| v.as_array());
    let iss_sub = find(sub_ids, "iss_sub", "sub");
    let opaque = find(sub_ids, "opaque", "id");
    let account = find(sub_ids, "account", "uri");
    let mut id_token = None;
    if let Some(list) = doc.get("assertions").and_then(|v| v.as_array()) {
        for item in list {
            if let Some(one) = obj(item) {
                if one.get("format").and_then(as_str) == Some("id_token") && one.get("value").and_then(as_str).is_some() {
                    id_token = Some(one);
                    break;
                }
            }
        }
    }
    let mut claims = Map::new();
    let mut sub = iss_sub.and_then(|one| one.get("sub")).and_then(as_str).map(|s| s.to_string());
    let mut iss = iss_sub.and_then(|one| one.get("iss")).and_then(as_str).map(|s| s.to_string());
    let mut verified = false;
    if let Some(token) = id_token {
        let keys = (check.keys)()?;
        let verified_jws = verify_compact(token.get("value").and_then(as_str).unwrap_or(""), &keys)?;
        let payload = verified_jws.payload;
        let token_iss = payload.get("iss").and_then(as_str).unwrap_or("");
        if token_iss != check.issuer {
            return Err(fail("validation", format!("the id_token was issued by {token_iss}, not {}", check.issuer)));
        }
        let token_sub = payload.get("sub").and_then(as_str).unwrap_or("").to_string();
        if token_sub.is_empty() {
            return Err(fail("validation", "the id_token has no sub"));
        }
        let exp = as_f64(payload.get("exp").unwrap_or(&Value::Null)).ok_or_else(|| fail("validation", "the id_token has no exp"))?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as f64).unwrap_or(0.0);
        if exp + check.skew < now {
            return Err(fail("validation", "the id_token has expired"));
        }
        if let Some(nbf) = payload.get("nbf").and_then(as_f64) {
            if nbf - check.skew > now {
                return Err(fail("validation", "the id_token is not valid yet"));
            }
        }
        if let Some(iat) = payload.get("iat").and_then(as_f64) {
            if iat - check.skew > now {
                return Err(fail("validation", "the id_token is issued in the future"));
            }
        }
        let aud = strings(payload.get("aud"));
        let known: Vec<&str> = check.audiences.iter().filter(|a| !a.is_empty()).map(|s| s.as_str()).collect();
        if !known.is_empty() && !aud.iter().any(|one| known.contains(&one.as_str())) {
            let shown = if aud.is_empty() { "(no audience)".into() } else { aud.join(", ") };
            return Err(fail("validation", format!("the id_token is for {shown}, not {}", known.join(" or "))));
        }
        if let Some(current) = &sub {
            if token_sub != *current {
                return Err(fail("validation", "the id_token is about somebody other than the subject identifier"));
            }
        }
        sub = Some(token_sub);
        iss = payload.get("iss").and_then(as_str).map(|s| s.to_string());
        claims = payload;
        verified = true;
    }
    if sub.is_none() {
        sub = opaque.and_then(|one| one.get("id")).and_then(as_str).map(|s| s.to_string());
    }
    if sub.is_none() {
        sub = account.and_then(|one| one.get("uri")).and_then(as_str).map(|s| s.to_string());
    }
    let Some(sub) = sub else { return Ok(None) };
    let uid = account.and_then(|one| one.get("uri")).and_then(as_str).and_then(uid_from_account);
    let _ = b64url_decode;
    Ok(Some(Person {
        sub,
        email: claims.get("email").and_then(as_str).map(|s| s.to_string()),
        name: claims.get("name").and_then(as_str).map(|s| s.to_string()),
        preferred_username: claims.get("preferred_username").and_then(as_str).map(|s| s.to_string()),
        sid: claims.get("sid").or_else(|| claims.get("session_id")).and_then(as_str).map(|s| s.to_string()),
        acr: claims.get("acr").and_then(as_str).map(|s| s.to_string()),
        amr: strings(claims.get("amr")),
        claims,
        assertion_verified: verified,
        iss,
        uid,
    }))
}

fn find<'a>(list: Option<&'a Vec<Value>>, format: &str, field: &str) -> Option<&'a Map<String, Value>> {
    let list = list?;
    for item in list {
        if let Some(doc) = obj(item) {
            if doc.get("format").and_then(as_str) == Some(format) && doc.get(field).and_then(as_str).is_some() {
                return Some(doc);
            }
        }
    }
    None
}

fn strings(value: Option<&Value>) -> Vec<String> {
    let Some(value) = value else { return Vec::new() };
    if let Some(list) = value.as_array() {
        return list.iter().map(|item| item.as_str().map(|s| s.to_string()).unwrap_or_else(|| item.to_string())).collect();
    }
    if let Some(text) = value.as_str() {
        return vec![text.to_string()];
    }
    vec![value.to_string()]
}
