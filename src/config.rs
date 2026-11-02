// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

use crate::codec::{as_bool, as_f64, as_str};
use crate::error::{fail, Error};
use crate::keys::{load_client_key, ClientKey, PROOFS};
use crate::urlutil::{href, is_loopback, origin};
use serde_json::{Map, Value};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub struct Display {
    pub name: Option<String>,
    pub uri: Option<String>,
}

#[derive(Clone, Debug)]
pub struct SsfConfig {
    pub transmitter: String,
    pub poll_interval_ms: i64,
}

pub struct Config {
    pub grant_endpoint: String,
    pub id_token_issuer: String,
    pub application: String,
    pub class_id: Option<String>,
    pub display: Option<Display>,
    pub access: Vec<Value>,
    pub signals: Option<bool>,
    pub sub_id_formats: Vec<String>,
    pub assertion_formats: Vec<String>,
    pub key: ClientKey,
    pub finish_uri: Option<String>,
    pub finish_method: String,
    pub interaction_start: Vec<String>,
    pub hash_method: String,
    pub require_bound_tokens: bool,
    pub use_instance_id: bool,
    pub tls_ca: String,
    pub allow_insecure: bool,
    pub clock_tolerance_sec: f64,
    pub max_wait_sec: f64,
    pub transaction_ttl_sec: f64,
    pub ssf: Option<SsfConfig>,
}

pub fn resolve(raw: &Value, base_dir: &Path) -> Result<Config, Error> {
    let doc = raw.as_object().ok_or_else(|| fail("config", "the configuration must be a JSON object"))?;
    if doc.contains_key("signals") && as_bool(doc.get("signals").unwrap()).is_none() {
        return Err(fail("config", "signals must be true or false"));
    }
    let signals_off = doc.get("signals").and_then(as_bool) == Some(false);
    let application = as_str(doc.get("application").unwrap_or(&Value::Null)).unwrap_or("").trim().to_string();
    if application.is_empty() {
        return Err(fail("config", "application is required: the registered GNAP client"));
    }
    let grant_raw = as_str(doc.get("grantEndpoint").unwrap_or(&Value::Null)).unwrap_or("").trim().to_string();
    if grant_raw.is_empty() {
        return Err(fail("config", "grantEndpoint is required"));
    }
    let allow_insecure = doc.get("allowInsecure").and_then(as_bool) == Some(true);
    let grant_endpoint = check_url(&grant_raw, "grantEndpoint", allow_insecure)?;
    let mut issuer = as_str(doc.get("idTokenIssuer").unwrap_or(&Value::Null)).unwrap_or("").trim().trim_end_matches('/').to_string();
    if issuer.is_empty() {
        issuer = origin(&grant_endpoint)?.trim_end_matches('/').to_string();
    }
    if !issuer.starts_with("https://") && !issuer.starts_with("http://") {
        return Err(fail("config", "idTokenIssuer must be an http(s) URL"));
    }
    let proof = as_str(doc.get("keyProof").unwrap_or(&Value::Null)).unwrap_or("").trim().to_string();
    if !proof.is_empty() && !PROOFS.contains(&proof.as_str()) {
        return Err(fail("config", format!("keyProof must be {}, not {proof}", PROOFS.join(", "))));
    }
    let private_raw = as_str(doc.get("privateKey").unwrap_or(&Value::Null)).ok_or_else(|| fail("config", "privateKey is required"))?;
    let private_key = key_value(private_raw, base_dir, "the private key")?;
    let certificate = match as_str(doc.get("certificate").unwrap_or(&Value::Null)) {
        Some(value) if !value.is_empty() => Some(key_value(value, base_dir, "the certificate")?),
        _ => None,
    };
    let key = load_client_key(&private_key, certificate.as_deref().unwrap_or(""), &proof)?;
    if key.proof == "mtls" && !grant_endpoint.starts_with("https://") {
        return Err(fail("config", "mutual TLS needs an https grant endpoint"));
    }
    let finish_method = as_str(doc.get("finishMethod").unwrap_or(&Value::Null)).unwrap_or("redirect").to_string();
    if finish_method != "redirect" && finish_method != "push" {
        return Err(fail("config", "finishMethod must be redirect or push"));
    }
    let finish_raw = as_str(doc.get("finishUri").unwrap_or(&Value::Null)).unwrap_or("").trim().to_string();
    let finish_uri = if finish_raw.is_empty() { None } else { Some(check_url(&finish_raw, "finishUri", allow_insecure || is_loopback(&finish_raw))?) };
    let hash = as_str(doc.get("hashMethod").unwrap_or(&Value::Null)).unwrap_or("sha-256");
    if hash != "sha-256" {
        return Err(fail("config", "hashMethod must be sha-256"));
    }
    let interaction = if !doc.contains_key("interactionStart") || doc.get("interactionStart").unwrap().is_null() {
        vec!["redirect".to_string()]
    } else {
        let list = doc.get("interactionStart").and_then(|v| v.as_array()).ok_or_else(|| fail("config", "interactionStart must name at least one mode"))?;
        if list.is_empty() {
            return Err(fail("config", "interactionStart must name at least one mode"));
        }
        let names: Vec<String> = list.iter().filter_map(|item| item.as_str().map(|s| s.to_string())).collect();
        if names.len() != list.len() || names.iter().any(|s| s.is_empty()) {
            return Err(fail("config", "interactionStart must name at least one mode"));
        }
        names
    };
    let requested = if !doc.contains_key("access") || doc.get("access").map(|v| v.is_null()).unwrap_or(true) {
        vec![Value::String("ssf.read".into()), Value::String("ssf.manage".into())]
    } else {
        doc.get("access").and_then(|v| v.as_array()).cloned().ok_or_else(|| fail("config", "access must list at least one right"))?
    };
    let access: Vec<Value> = if signals_off { requested.into_iter().filter(|right| !ssf_right(right)).collect() } else { requested };
    if access.is_empty() {
        return Err(fail(
            "config",
            if signals_off {
                "signals is false and access has no rights left after ssf.read and ssf.manage were removed; the caller must name a right this authorization server grants"
            } else {
                "access must list at least one right"
            },
        ));
    }
    let tls_ca = match doc.get("tlsCa") {
        None | Some(Value::Null) => String::new(),
        Some(value) => read_trust(as_str(value).unwrap_or(""), base_dir),
    };
    let ssf = if signals_off {
        None
    } else {
        let raw_ssf = doc.get("ssf").and_then(|v| v.as_object());
        let mut transmitter = raw_ssf.and_then(|ssf| ssf.get("transmitter")).and_then(as_str).unwrap_or("").to_string();
        if transmitter.is_empty() {
            transmitter = as_str(doc.get("transmitterIssuer").unwrap_or(&Value::Null)).unwrap_or("").to_string();
        }
        transmitter = transmitter.trim_end_matches('/').to_string();
        if transmitter.is_empty() {
            None
        } else if !transmitter.starts_with("https://") && !transmitter.starts_with("http://") {
            return Err(fail("config", "ssf.transmitter must be an http(s) URL"));
        } else {
            let interval = raw_ssf.and_then(|ssf| ssf.get("pollIntervalMs")).and_then(as_f64).unwrap_or(0.0) as i64;
            Some(SsfConfig { transmitter, poll_interval_ms: interval })
        }
    };
    let display = doc.get("display").and_then(|v| v.as_object()).and_then(|display| {
        let name = display.get("name").and_then(as_str).map(|s| s.to_string());
        let uri = display.get("uri").and_then(as_str).map(|s| s.to_string());
        if name.is_none() && uri.is_none() {
            None
        } else {
            Some(Display { name, uri })
        }
    });
    Ok(Config {
        grant_endpoint,
        id_token_issuer: issuer,
        application,
        class_id: doc.get("classId").and_then(as_str).map(|s| s.to_string()),
        display,
        access,
        signals: if signals_off { Some(false) } else { None },
        sub_id_formats: strings_or(doc.get("subIdFormats"), &["iss_sub", "account", "opaque"]),
        assertion_formats: strings_or(doc.get("assertionFormats"), &["id_token"]),
        key,
        finish_uri,
        finish_method,
        interaction_start: interaction,
        hash_method: "sha-256".into(),
        require_bound_tokens: doc.get("requireBoundTokens").and_then(as_bool) != Some(false),
        use_instance_id: doc.get("useInstanceId").and_then(as_bool) != Some(false),
        tls_ca,
        allow_insecure,
        clock_tolerance_sec: number_or(doc, "clockToleranceSec", 30.0),
        max_wait_sec: number_or(doc, "maxWaitSec", 30.0),
        transaction_ttl_sec: number_or(doc, "transactionTtlSec", 600.0),
        ssf,
    })
}

pub fn read_file(path: &Path) -> Result<Config, Error> {
    let text = fs::read_to_string(path).map_err(|err| fail("config", format!("could not read {}: {err}", path.display())))?;
    let doc: Value = serde_json::from_str(&text).map_err(|err| fail("config", format!("could not read {}: {err}", path.display())))?;
    if !doc.is_object() {
        return Err(fail("config", "the configuration must be a JSON object"));
    }
    let base = path.parent().unwrap_or_else(|| Path::new("."));
    resolve(&doc, &absolute_dir(base))
}

fn absolute_dir(base: &Path) -> PathBuf {
    if base.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        base.to_path_buf()
    }
}

fn ssf_right(right: &Value) -> bool {
    if let Some(text) = right.as_str() {
        let trimmed = text.trim();
        return trimmed == "ssf.read" || trimmed == "ssf.manage";
    }
    let Some(obj) = right.as_object() else { return false };
    matches!(obj.get("type").and_then(as_str), Some("ssf.read" | "ssf.manage"))
}

fn check_url(value: &str, name: &str, allow_http: bool) -> Result<String, Error> {
    let href = href(value).map_err(|_| fail("config", format!("{name} is not a URL: {value}")))?;
    let scheme = href.split(':').next().unwrap_or("");
    if scheme == "https" || (scheme == "http" && allow_http) {
        return Ok(href);
    }
    Err(fail("config", format!("{name} must use https{}: {value}", if allow_http { "" } else { ", or http on loopback" })))
}

fn key_value(raw: &str, base_dir: &Path, what: &str) -> Result<String, Error> {
    if raw.starts_with("env:") || raw.starts_with("file:") || raw.contains("-----BEGIN") {
        secret(raw, base_dir, what)
    } else {
        read_path(raw, base_dir, what)
    }
}

fn secret(raw: &str, base_dir: &Path, what: &str) -> Result<String, Error> {
    if let Some(name) = raw.strip_prefix("env:") {
        let value = std::env::var(name).unwrap_or_default();
        if value.is_empty() {
            return Err(fail("config", format!("{what} reads {name}, and that variable is empty")));
        }
        return Ok(value);
    }
    if let Some(path) = raw.strip_prefix("file:") {
        return read_path(path, base_dir, what);
    }
    Ok(raw.to_string())
}

fn read_path(path: &str, base_dir: &Path, what: &str) -> Result<String, Error> {
    let full = if Path::new(path).is_absolute() { PathBuf::from(path) } else { base_dir.join(path) };
    fs::read_to_string(&full).map_err(|err| fail("config", format!("could not read {what} at {}: {err}", full.display())))
}

pub fn read_trust(raw: &str, base_dir: &Path) -> String {
    if raw.is_empty() {
        return String::new();
    }
    if raw.contains("-----BEGIN") {
        return raw.to_string();
    }
    if let Some(name) = raw.strip_prefix("env:") {
        return std::env::var(name).unwrap_or_default();
    }
    let path = raw.strip_prefix("file:").unwrap_or(raw);
    let full = if Path::new(path).is_absolute() { PathBuf::from(path) } else { base_dir.join(path) };
    fs::read_to_string(full).unwrap_or_default()
}

fn strings_or(node: Option<&Value>, fallback: &[&str]) -> Vec<String> {
    let Some(list) = node.and_then(|v| v.as_array()) else { return fallback.iter().map(|s| s.to_string()).collect() };
    if list.is_empty() {
        return fallback.iter().map(|s| s.to_string()).collect();
    }
    list.iter().map(|item| item.as_str().unwrap_or("").to_string()).collect()
}

fn number_or(doc: &Map<String, Value>, key: &str, fallback: f64) -> f64 {
    doc.get(key).and_then(as_f64).unwrap_or(fallback)
}
