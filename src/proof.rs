// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

use crate::codec::{b64std, b64url, dump, sha256};
use crate::error::Error;
use crate::keys::{sign, ClientKey};
use crate::urlutil::href;
use rand::RngCore;
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn interaction_hash(client_nonce: &str, server_nonce: &str, interact_ref: &str, grant_endpoint: &str) -> String {
    b64url(&sha256(format!("{client_nonce}\n{server_nonce}\n{interact_ref}\n{grant_endpoint}").as_bytes()))
}

pub fn sign_request(key: &ClientKey, method: &str, raw_url: &str, headers: &HashMap<String, String>, body: Option<&str>) -> Result<HashMap<String, String>, Error> {
    let target = href(raw_url)?;
    let mut lower = HashMap::new();
    for (name, value) in headers {
        lower.insert(name.to_ascii_lowercase(), value.clone());
    }
    let mut components = vec!["@method".to_string(), "@target-uri".to_string()];
    let mut added = HashMap::new();
    if let Some(body) = body {
        if !body.is_empty() {
            let digest = format!("sha-256=:{}:", b64std(&sha256(body.as_bytes())));
            added.insert("content-digest".into(), digest.clone());
            lower.insert("content-digest".into(), digest);
            components.push("content-digest".into());
        }
    }
    if lower.contains_key("authorization") {
        components.push("authorization".into());
    }
    let mut nonce = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut nonce);
    let created = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let covered = components.iter().map(|c| format!("\"{c}\"")).collect::<Vec<_>>().join(" ");
    let serialised = format!("({covered});created={created};nonce={};keyid={};tag=\"gnap\"", sf(&b64url(&nonce)), sf(&key.kid));
    let mut lines = Vec::new();
    for component in &components {
        let value = match component.as_str() {
            "@method" => method.to_ascii_uppercase(),
            "@target-uri" => target.clone(),
            other => lower.get(other).map(|v| v.trim().to_string()).unwrap_or_default(),
        };
        lines.push(format!("\"{component}\": {value}"));
    }
    lines.push(format!("\"@signature-params\": {serialised}"));
    let signature = sign(key, lines.join("\n").as_bytes())?;
    added.insert("signature-input".into(), format!("sig1={serialised}"));
    added.insert("signature".into(), format!("sig1=:{}:", b64std(&signature)));
    Ok(added)
}

pub fn detached_jws(key: &ClientKey, method: &str, raw_url: &str, body: Option<&str>, token: Option<&str>) -> Result<String, Error> {
    let mut header = Map::new();
    header.insert("alg".into(), Value::String(key.alg.clone()));
    header.insert("created".into(), Value::from(SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)));
    header.insert("htm".into(), Value::String(method.to_ascii_uppercase()));
    header.insert("kid".into(), Value::String(key.kid.clone()));
    header.insert("typ".into(), Value::String("gnap-binding-jwsd".into()));
    header.insert("uri".into(), Value::String(href(raw_url)?));
    if let Some(token) = token {
        if !token.is_empty() {
            header.insert("ath".into(), Value::String(b64url(&sha256(token.as_bytes()))));
        }
    }
    let encoded = b64url(dump(&Value::Object(header))?.as_bytes());
    let payload = match body {
        Some(body) if !body.is_empty() => b64url(&sha256(body.as_bytes())),
        _ => String::new(),
    };
    let signature = sign(key, format!("{encoded}.{payload}").as_bytes())?;
    Ok(format!("{encoded}.{payload}.{}", b64url(&signature)))
}

fn sf(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}
