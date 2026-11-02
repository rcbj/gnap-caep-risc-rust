// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

use crate::codec::{b64url_decode, obj};
use crate::error::{fail, Error};
use crate::http::{self, TlsOpt};
use crate::keys::verify_jwk;
use crate::urlutil::well_known;
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const POLL: &str = "urn:ietf:rfc:8936";
const CAEP: &str = "https://schemas.openid.net/secevent/caep/event-type/";
const RISC: &str = "https://schemas.openid.net/secevent/risc/event-type/";
const SSF: &str = "https://schemas.openid.net/secevent/ssf/event-type/";

pub struct Events;

impl Events {
    pub const SESSION_REVOKED: &'static str = "https://schemas.openid.net/secevent/caep/event-type/session-revoked";
    pub const TOKEN_CLAIMS_CHANGE: &'static str = "https://schemas.openid.net/secevent/caep/event-type/token-claims-change";
    pub const CREDENTIAL_CHANGE: &'static str = "https://schemas.openid.net/secevent/caep/event-type/credential-change";
    pub const ASSURANCE_LEVEL_CHANGE: &'static str = "https://schemas.openid.net/secevent/caep/event-type/assurance-level-change";
    pub const DEVICE_COMPLIANCE_CHANGE: &'static str = "https://schemas.openid.net/secevent/caep/event-type/device-compliance-change";
    pub const SESSION_ESTABLISHED: &'static str = "https://schemas.openid.net/secevent/caep/event-type/session-established";
    pub const SESSION_PRESENTED: &'static str = "https://schemas.openid.net/secevent/caep/event-type/session-presented";
    pub const RISK_LEVEL_CHANGE: &'static str = "https://schemas.openid.net/secevent/caep/event-type/risk-level-change";
    pub const ACCOUNT_CREDENTIAL_CHANGE_REQUIRED: &'static str = "https://schemas.openid.net/secevent/risc/event-type/account-credential-change-required";
    pub const ACCOUNT_PURGED: &'static str = "https://schemas.openid.net/secevent/risc/event-type/account-purged";
    pub const ACCOUNT_DISABLED: &'static str = "https://schemas.openid.net/secevent/risc/event-type/account-disabled";
    pub const ACCOUNT_ENABLED: &'static str = "https://schemas.openid.net/secevent/risc/event-type/account-enabled";
    pub const IDENTIFIER_CHANGED: &'static str = "https://schemas.openid.net/secevent/risc/event-type/identifier-changed";
    pub const IDENTIFIER_RECYCLED: &'static str = "https://schemas.openid.net/secevent/risc/event-type/identifier-recycled";
    pub const CREDENTIAL_COMPROMISE: &'static str = "https://schemas.openid.net/secevent/risc/event-type/credential-compromise";
    pub const OPT_IN: &'static str = "https://schemas.openid.net/secevent/risc/event-type/opt-in";
    pub const OPT_OUT_INITIATED: &'static str = "https://schemas.openid.net/secevent/risc/event-type/opt-out-initiated";
    pub const OPT_OUT_CANCELLED: &'static str = "https://schemas.openid.net/secevent/risc/event-type/opt-out-cancelled";
    pub const OPT_OUT_EFFECTIVE: &'static str = "https://schemas.openid.net/secevent/risc/event-type/opt-out-effective";
    pub const RECOVERY_ACTIVATED: &'static str = "https://schemas.openid.net/secevent/risc/event-type/recovery-activated";
    pub const RECOVERY_INFORMATION_CHANGED: &'static str = "https://schemas.openid.net/secevent/risc/event-type/recovery-information-changed";
    pub const SESSIONS_REVOKED: &'static str = "https://schemas.openid.net/secevent/risc/event-type/sessions-revoked";
    pub const VERIFICATION: &'static str = "https://schemas.openid.net/secevent/ssf/event-type/verification";
    pub const STREAM_UPDATED: &'static str = "https://schemas.openid.net/secevent/ssf/event-type/stream-updated";
}

fn default_events() -> Vec<String> {
    [
        Events::SESSION_REVOKED,
        Events::CREDENTIAL_CHANGE,
        Events::ASSURANCE_LEVEL_CHANGE,
        Events::TOKEN_CLAIMS_CHANGE,
        Events::ACCOUNT_DISABLED,
        Events::ACCOUNT_ENABLED,
        Events::ACCOUNT_PURGED,
        Events::CREDENTIAL_COMPROMISE,
        Events::SESSIONS_REVOKED,
        Events::ACCOUNT_CREDENTIAL_CHANGE_REQUIRED,
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn default_ending() -> Vec<String> {
    [
        Events::SESSION_REVOKED,
        Events::ACCOUNT_DISABLED,
        Events::ACCOUNT_PURGED,
        Events::CREDENTIAL_COMPROMISE,
        Events::SESSIONS_REVOKED,
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

pub struct VerifiedJws {
    pub header: Map<String, Value>,
    pub payload: Map<String, Value>,
}

pub fn verify_compact(token: &str, keys: &[Map<String, Value>]) -> Result<VerifiedJws, Error> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 || parts[0].is_empty() || parts[1].is_empty() || parts[2].is_empty() {
        return Err(fail("signature", "the token is not a compact JWS"));
    }
    let header_b = b64_part(parts[0], "header")?;
    let payload_b = b64_part(parts[1], "payload")?;
    let signature = b64_part(parts[2], "signature")?;
    let header_val: Value = serde_json::from_slice(&header_b).map_err(|_| fail("signature", "the token's header or payload is not JSON"))?;
    let payload_val: Value = serde_json::from_slice(&payload_b).map_err(|_| fail("signature", "the token's header or payload is not JSON"))?;
    let header = header_val.as_object().cloned().ok_or_else(|| fail("signature", "the token's header or payload is not a JSON object"))?;
    let payload = payload_val.as_object().cloned().ok_or_else(|| fail("signature", "the token's header or payload is not a JSON object"))?;
    let alg = header.get("alg").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let spec = alg_kty(&alg).ok_or_else(|| {
        let shown = if alg.is_empty() { "(no alg)".to_string() } else { alg.clone() };
        fail("signature", format!("the token is signed with {shown}, which this client does not verify ({})", supported_algs()))
    })?;
    if header.contains_key("crit") {
        return Err(fail("signature", "the token's header has a crit member this client does not understand"));
    }
    let kid = header.get("kid").and_then(|v| v.as_str());
    let candidates: Vec<&Map<String, Value>> = keys
        .iter()
        .filter(|key| {
            (kid.is_none() || key.get("kid").and_then(|v| v.as_str()) == kid)
                && key.get("kty").and_then(|v| v.as_str()) == Some(spec)
                && key.get("use").and_then(|v| v.as_str()).map(|use_| use_ == "sig").unwrap_or(true)
                && key.get("alg").and_then(|v| v.as_str()).map(|one| one == alg).unwrap_or(true)
        })
        .collect();
    if candidates.is_empty() {
        let suffix = kid.map(|id| format!(" with kid {id}")).unwrap_or_default();
        return Err(fail("signature", format!("no {spec} signing key{suffix} was published")));
    }
    let data = format!("{}.{}", parts[0], parts[1]).into_bytes();
    for jwk in candidates {
        if verify_jwk(jwk, &alg, &data, &signature) {
            return Ok(VerifiedJws { header, payload });
        }
    }
    Err(fail("signature", "the token's signature does not verify against the published keys"))
}

fn b64_part(value: &str, what: &str) -> Result<Vec<u8>, Error> {
    if !value.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
        return Err(fail("signature", format!("the JWS {what} is not base64url")));
    }
    b64url_decode(value).map_err(|_| fail("signature", format!("the JWS {what} is not base64url")))
}

fn alg_kty(alg: &str) -> Option<&'static str> {
    match alg {
        "RS256" | "RS384" | "RS512" | "PS256" | "PS384" | "PS512" => Some("RSA"),
        "ES256" | "ES384" | "ES512" => Some("EC"),
        "EdDSA" | "Ed25519" => Some("OKP"),
        _ => None,
    }
}

fn supported_algs() -> &'static str {
    "RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512, EdDSA, Ed25519"
}

#[derive(Clone, Debug)]
pub struct TrackedSession {
    pub local_id: String,
    pub person: Option<String>,
    pub email: Option<String>,
    pub idp_session: Option<String>,
    pub expires_at: Option<f64>,
}

struct Index {
    sessions: Vec<TrackedSession>,
    max: usize,
}

impl Index {
    fn add(&mut self, session: TrackedSession) {
        if self.sessions.len() >= self.max && !self.sessions.iter().any(|one| one.local_id == session.local_id) {
            let now = now_ms();
            self.sessions.retain(|one| one.expires_at.map(|at| at > now).unwrap_or(true));
            while self.sessions.len() >= self.max {
                self.sessions.remove(0);
            }
        }
        let email = session.email.as_ref().map(|value| value.to_ascii_lowercase());
        let stored = TrackedSession { email, ..session };
        if let Some(existing) = self.sessions.iter_mut().find(|one| one.local_id == stored.local_id) {
            *existing = stored;
        } else {
            self.sessions.push(stored);
        }
    }

    fn remove(&mut self, local_id: &str) {
        self.sessions.retain(|one| one.local_id != local_id);
    }

    fn find<F: Fn(&TrackedSession) -> bool>(&mut self, pred: F) -> Vec<String> {
        let now = now_ms();
        self.sessions.retain(|one| one.expires_at.map(|at| at > now).unwrap_or(true));
        self.sessions.iter().filter(|one| pred(one)).map(|one| one.local_id.clone()).collect()
    }
}

pub fn subject_of(sub_id: &Value, issuer: &str) -> Map<String, Value> {
    let Some(doc) = obj(sub_id) else { return Map::new() };
    let fmt = doc.get("format").or_else(|| doc.get("subject_type")).and_then(|v| v.as_str()).unwrap_or("");
    if fmt == "complex" || (fmt.is_empty() && (doc.get("user").is_some() || doc.get("session").is_some())) {
        let user = simple(doc.get("user"), issuer);
        let session = simple(doc.get("session"), issuer);
        let mut out = Map::new();
        if let Some(sub) = user.get("sub") {
            out.insert("person".into(), Value::String(sub.clone()));
        }
        if let Some(email) = user.get("email") {
            out.insert("email".into(), Value::String(email.clone()));
        }
        if let Some(id) = session.get("opaque").or_else(|| session.get("sub")) {
            out.insert("idp_session".into(), Value::String(id.clone()));
        }
        return out;
    }
    let one = simple(Some(sub_id), issuer);
    let mut out = Map::new();
    if let Some(sub) = one.get("sub") {
        out.insert("person".into(), Value::String(sub.clone()));
    }
    if let Some(email) = one.get("email") {
        out.insert("email".into(), Value::String(email.clone()));
    }
    out
}

fn simple(identifier: Option<&Value>, issuer: &str) -> HashMap<String, String> {
    let Some(doc) = identifier.and_then(obj) else { return HashMap::new() };
    let fmt = doc.get("format").or_else(|| doc.get("subject_type")).and_then(|v| v.as_str()).unwrap_or("");
    let mut out = HashMap::new();
    if fmt == "iss_sub" {
        if let Some(sub) = doc.get("sub").and_then(|v| v.as_str()) {
            let iss_ok = doc.get("iss").and_then(|v| v.as_str()).map(|iss| iss == issuer).unwrap_or(true);
            if iss_ok {
                out.insert("sub".into(), sub.to_string());
            }
        }
    } else if fmt == "email" {
        if let Some(email) = doc.get("email").and_then(|v| v.as_str()) {
            out.insert("email".into(), email.to_string());
        }
    } else if fmt == "opaque" {
        if let Some(id) = doc.get("id").and_then(|v| v.as_str()) {
            out.insert("opaque".into(), id.to_string());
        }
    } else if fmt == "aliases" {
        if let Some(list) = doc.get("identifiers").and_then(|v| v.as_array()) {
            for one in list {
                for (key, value) in simple(Some(one), issuer) {
                    out.insert(key, value);
                }
            }
        }
    }
    out
}

#[derive(Clone)]
pub struct SignalEvent {
    pub event_type: String,
    pub payload: Value,
    pub subject: Map<String, Value>,
    pub jti: String,
    pub sessions: Vec<String>,
    pub ended: bool,
    pub iat: Option<f64>,
    pub txn: Option<String>,
}

pub type EndFn = dyn Fn(&[String], &mut SignalEvent) + Send + Sync;
pub type HeaderFn = dyn Fn(&str, &str, Option<&str>) -> Vec<(String, String)> + Send + Sync;
type HandlerFn = dyn Fn(&SignalEvent) + Send + Sync;

pub struct ReceiverOpt {
    pub transmitter: String,
    pub on_end: Arc<EndFn>,
    pub headers: Option<Arc<HeaderFn>>,
    pub tls: TlsOpt,
    pub events_requested: Option<Vec<String>>,
    pub end_on: Option<Vec<String>>,
    pub description: Option<String>,
    pub poll_interval_ms: i64,
    pub max_events: i64,
}

impl ReceiverOpt {
    pub fn new(transmitter: impl Into<String>, on_end: Arc<EndFn>) -> Self {
        Self {
            transmitter: transmitter.into(),
            on_end,
            headers: None,
            tls: TlsOpt::default(),
            events_requested: None,
            end_on: None,
            description: None,
            poll_interval_ms: 5000,
            max_events: 50,
        }
    }

    pub fn set_headers<F>(&mut self, headers: F)
    where
        F: Fn(&str, &str, Option<&str>) -> Vec<(String, String)> + Send + Sync + 'static,
    {
        self.headers = Some(Arc::new(headers));
    }
}

struct Inner {
    config: Option<Map<String, Value>>,
    stream: Option<Map<String, Value>>,
    keys: Vec<Map<String, Value>>,
    keys_at: f64,
    ack: Vec<String>,
    errs: Map<String, Value>,
    index: Index,
    handlers: HashMap<String, Vec<Arc<HandlerFn>>>,
}

struct Flight {
    done: Mutex<bool>,
    cv: Condvar,
    result: Mutex<Option<Result<bool, Error>>>,
}

struct Shared {
    transmitter: String,
    on_end: Arc<EndFn>,
    headers: Option<Arc<HeaderFn>>,
    tls: TlsOpt,
    events: Vec<String>,
    end_on: Vec<String>,
    description: Option<String>,
    interval: i64,
    max_events: i64,
    inner: Mutex<Inner>,
    flight: Mutex<Option<Arc<Flight>>>,
    running: AtomicBool,
    thread: Mutex<Option<JoinHandle<()>>>,
    entered: Mutex<bool>,
    entered_cv: Condvar,
    wait_mu: Mutex<()>,
    wait_cv: Condvar,
}

#[derive(Clone)]
pub struct SignalsReceiver {
    shared: Arc<Shared>,
}

impl SignalsReceiver {
    pub fn new(opt: ReceiverOpt) -> Result<Self, Error> {
        let transmitter = opt.transmitter.trim_end_matches('/').to_string();
        if !transmitter.starts_with("https://") && !transmitter.starts_with("http://") {
            return Err(fail("config", "transmitter must be an http(s) URL"));
        }
        Ok(Self {
            shared: Arc::new(Shared {
                transmitter,
                on_end: opt.on_end,
                headers: opt.headers,
                tls: opt.tls,
                events: opt.events_requested.unwrap_or_else(default_events),
                end_on: opt.end_on.unwrap_or_else(default_ending),
                description: opt.description,
                interval: opt.poll_interval_ms,
                max_events: opt.max_events,
                inner: Mutex::new(Inner {
                    config: None,
                    stream: None,
                    keys: Vec::new(),
                    keys_at: 0.0,
                    ack: Vec::new(),
                    errs: Map::new(),
                    index: Index { sessions: Vec::new(), max: 100_000 },
                    handlers: HashMap::new(),
                }),
                flight: Mutex::new(None),
                running: AtomicBool::new(false),
                thread: Mutex::new(None),
                entered: Mutex::new(false),
                entered_cv: Condvar::new(),
                wait_mu: Mutex::new(()),
                wait_cv: Condvar::new(),
            }),
        })
    }

    pub fn stream(&self) -> Option<Map<String, Value>> {
        self.shared.inner.lock().unwrap().stream.clone()
    }

    pub fn track(&self, session: TrackedSession) {
        self.shared.inner.lock().unwrap().index.add(session);
    }

    pub fn untrack(&self, local_id: &str) {
        self.shared.inner.lock().unwrap().index.remove(local_id);
    }

    pub fn on(&self, kind: &str, handler: Arc<HandlerFn>) {
        self.shared.inner.lock().unwrap().handlers.entry(kind.to_string()).or_default().push(handler);
    }

    pub fn start(&self) -> Result<(), Error> {
        if self.shared.running.load(Ordering::SeqCst) {
            return Ok(());
        }
        if let Some(handle) = self.shared.thread.lock().unwrap().take() {
            let _ = handle.join();
        }
        let config = self.discover()?;
        self.store_config(config);
        self.jwks(true)?;
        let stream = self.ensure_stream()?;
        let endpoint = stream.get("delivery").and_then(|v| v.as_object()).and_then(|d| d.get("endpoint_url")).and_then(|v| v.as_str()).unwrap_or("").to_string();
        if endpoint.is_empty() {
            return Err(fail("ssf", "the stream has no poll endpoint_url"));
        }
        let delivered = stream.get("events_delivered").and_then(|v| v.as_array()).map(|list| list.len()).unwrap_or(0);
        let id = stream.get("stream_id").and_then(|v| v.as_str()).unwrap_or("");
        println!("ssf: polling stream {id} at {endpoint}, delivering {delivered} event type(s)");
        {
            let mut inner = self.shared.inner.lock().unwrap();
            inner.stream = Some(stream);
        }
        *self.shared.entered.lock().unwrap() = false;
        self.shared.running.store(true, Ordering::SeqCst);
        let shared = self.shared.clone();
        let handle = thread::Builder::new().name("ssf-poll".into()).spawn(move || shared.background()).map_err(|err| fail("ssf", err.to_string()))?;
        *self.shared.thread.lock().unwrap() = Some(handle);
        let mut entered = self.shared.entered.lock().unwrap();
        while !*entered {
            entered = self.shared.entered_cv.wait(entered).unwrap();
        }
        Ok(())
    }

    pub fn stop(&self) {
        self.shared.running.store(false, Ordering::SeqCst);
        self.shared.wait_cv.notify_all();
        if let Some(handle) = self.shared.thread.lock().unwrap().take() {
            let _ = handle.join();
        }
    }

    pub fn poll_once(&self) -> Result<bool, Error> {
        self.shared.poll_once()
    }

    pub fn verify(&self, state: Option<&str>) -> Result<(), Error> {
        let (endpoint, stream_id) = {
            let inner = self.shared.inner.lock().unwrap();
            let endpoint = inner.config.as_ref().and_then(|cfg| cfg.get("verification_endpoint")).and_then(|v| v.as_str()).map(|s| s.to_string());
            let stream_id = inner.stream.as_ref().and_then(|stream| stream.get("stream_id")).and_then(|v| v.as_str()).unwrap_or("").to_string();
            (endpoint, stream_id)
        };
        let Some(endpoint) = endpoint else { return Err(fail("ssf", "the transmitter publishes no verification_endpoint")) };
        let mut body = Map::new();
        body.insert("stream_id".into(), Value::String(stream_id));
        if let Some(state) = state {
            if !state.is_empty() {
                body.insert("state".into(), Value::String(state.to_string()));
            }
        }
        let (status, _) = self.shared.call("POST", &endpoint, Some(&Value::Object(body)))?;
        if status != 200 && status != 204 {
            return Err(fail("ssf", format!("verification answered {status}")));
        }
        Ok(())
    }

    fn store_config(&self, config: Map<String, Value>) {
        self.shared.inner.lock().unwrap().config = Some(config);
    }

    fn discover(&self) -> Result<Map<String, Value>, Error> {
        let urls = well_known(&self.shared.transmitter, "ssf-configuration")?;
        let mut last = fail("ssf", format!("no transmitter configuration at {}", urls.join(" or ")));
        for (index, url) in urls.iter().enumerate() {
            let (status, doc) = self.shared.call("GET", url, None)?;
            if status == 404 && index + 1 != urls.len() {
                continue;
            }
            let usable = doc.as_object().and_then(|one| {
                let ready = one.get("configuration_endpoint").and_then(|v| v.as_str()).is_some() && one.get("jwks_uri").and_then(|v| v.as_str()).is_some();
                if status == 200 && ready {
                    Some(one.clone())
                } else {
                    None
                }
            });
            let Some(doc) = usable else {
                last = fail("ssf", format!("{url} answered {status} without a usable transmitter configuration"));
                continue;
            };
            if let Some(methods) = doc.get("delivery_methods_supported").and_then(|v| v.as_array()) {
                if !methods.iter().any(|item| item.as_str() == Some(POLL)) {
                    return Err(fail("ssf", "the transmitter does not offer poll delivery (RFC 8936)"));
                }
            }
            return Ok(doc);
        }
        Err(last)
    }

    fn jwks(&self, force: bool) -> Result<Vec<Map<String, Value>>, Error> {
        {
            let inner = self.shared.inner.lock().unwrap();
            if !force && !inner.keys.is_empty() && now_ms() - inner.keys_at < 3_600_000.0 {
                return Ok(inner.keys.clone());
            }
        }
        let uri = {
            let inner = self.shared.inner.lock().unwrap();
            inner.config.as_ref().and_then(|cfg| cfg.get("jwks_uri")).and_then(|v| v.as_str()).unwrap_or("").to_string()
        };
        let (status, doc) = self.shared.call("GET", &uri, None)?;
        let keys = doc.as_object().and_then(|one| one.get("keys")).and_then(|v| v.as_array()).cloned();
        let Some(keys) = keys else { return Err(fail("ssf", format!("the transmitter's JWKS answered {status}"))) };
        if status != 200 {
            return Err(fail("ssf", format!("the transmitter's JWKS answered {status}")));
        }
        let parsed: Vec<Map<String, Value>> = keys.into_iter().filter_map(|item| item.as_object().cloned()).collect();
        let mut inner = self.shared.inner.lock().unwrap();
        inner.keys = parsed.clone();
        inner.keys_at = now_ms();
        Ok(parsed)
    }

    fn ensure_stream(&self) -> Result<Map<String, Value>, Error> {
        let endpoint = {
            let inner = self.shared.inner.lock().unwrap();
            inner.config.as_ref().and_then(|cfg| cfg.get("configuration_endpoint")).and_then(|v| v.as_str()).unwrap_or("").to_string()
        };
        let (status, listed) = self.shared.call("GET", &endpoint, None)?;
        if status == 200 {
            let all = if let Some(list) = listed.as_array() {
                list.clone()
            } else if listed.is_object() {
                vec![listed]
            } else {
                Vec::new()
            };
            if let Some(mine) = all.into_iter().find(|stream| {
                stream.as_object().and_then(|one| one.get("delivery")).and_then(|v| v.as_object()).and_then(|d| d.get("method")).and_then(|v| v.as_str()) == Some(POLL)
                    && stream.as_object().and_then(|one| one.get("stream_id")).and_then(|v| v.as_str()).is_some()
            }) {
                return Ok(mine.as_object().cloned().unwrap_or_default());
            }
        } else if status != 404 {
            return Err(fail("ssf", format!("listing the streams at {endpoint} answered {status}: {}", clip(&listed))));
        }
        let mut payload = Map::new();
        let mut delivery = Map::new();
        delivery.insert("method".into(), Value::String(POLL.into()));
        payload.insert("delivery".into(), Value::Object(delivery));
        payload.insert("events_requested".into(), Value::Array(self.shared.events.iter().cloned().map(Value::String).collect()));
        if let Some(description) = &self.shared.description {
            payload.insert("description".into(), Value::String(description.clone()));
        }
        let (status, created) = self.shared.call("POST", &endpoint, Some(&Value::Object(payload)))?;
        let stream = created.as_object().filter(|one| one.get("stream_id").and_then(|v| v.as_str()).is_some()).cloned();
        if (status != 200 && status != 201) || stream.is_none() {
            return Err(fail("ssf", format!("creating a stream at {endpoint} answered {status}: {}", clip(&created))));
        }
        Ok(stream.unwrap())
    }
}

impl Shared {
    fn background(self: Arc<Self>) {
        {
            let mut entered = self.entered.lock().unwrap();
            *entered = true;
            self.entered_cv.notify_all();
        }
        loop {
            if !self.running.load(Ordering::SeqCst) {
                break;
            }
            let mut delay = self.interval;
            match self.poll_once() {
                Ok(true) => delay = 0,
                Ok(false) => {}
                Err(err) => {
                    println!("ssf: poll failed: {err}");
                    delay = (self.interval.saturating_mul(4)).min(60_000);
                }
            }
            if !self.running.load(Ordering::SeqCst) {
                break;
            }
            if delay > 0 {
                let guard = self.wait_mu.lock().unwrap();
                let _ = self.wait_cv.wait_timeout(guard, Duration::from_millis(delay as u64));
            }
        }
    }

    fn poll_once(&self) -> Result<bool, Error> {
        let (flight, owner) = {
            let mut slot = self.flight.lock().unwrap();
            if let Some(existing) = slot.clone() {
                (existing, false)
            } else {
                let flight = Arc::new(Flight { done: Mutex::new(false), cv: Condvar::new(), result: Mutex::new(None) });
                *slot = Some(flight.clone());
                (flight, true)
            }
        };
        if !owner {
            let mut done = flight.done.lock().unwrap();
            while !*done {
                done = flight.cv.wait(done).unwrap();
            }
            return flight.result.lock().unwrap().clone().unwrap_or_else(|| Err(fail("ssf", "the poll failed")));
        }
        let result = self.poll_now();
        *flight.result.lock().unwrap() = Some(result.clone());
        *flight.done.lock().unwrap() = true;
        flight.cv.notify_all();
        {
            let mut slot = self.flight.lock().unwrap();
            if slot.as_ref().map(|one| Arc::ptr_eq(one, &flight)).unwrap_or(false) {
                *slot = None;
            }
        }
        result
    }

    fn poll_now(&self) -> Result<bool, Error> {
        let url = {
            let inner = self.inner.lock().unwrap();
            inner
                .stream
                .as_ref()
                .and_then(|stream| stream.get("delivery"))
                .and_then(|v| v.as_object())
                .and_then(|d| d.get("endpoint_url"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string()
        };
        let (ack, set_errs) = {
            let mut inner = self.inner.lock().unwrap();
            let ack = std::mem::take(&mut inner.ack);
            let errs = std::mem::take(&mut inner.errs);
            (ack, errs)
        };
        let mut body = Map::new();
        body.insert("maxEvents".into(), Value::from(self.max_events));
        body.insert("returnImmediately".into(), Value::Bool(true));
        if !ack.is_empty() {
            body.insert("ack".into(), Value::Array(ack.iter().cloned().map(Value::String).collect()));
        }
        if !set_errs.is_empty() {
            body.insert("setErrs".into(), Value::Object(set_errs.clone()));
        }
        let (status, answer) = match self.call("POST", &url, Some(&Value::Object(body))) {
            Ok(pair) => pair,
            Err(err) => return Err(err),
        };
        if status != 200 {
            let mut inner = self.inner.lock().unwrap();
            let mut restored = ack;
            restored.append(&mut inner.ack);
            inner.ack = restored;
            for (key, value) in set_errs {
                inner.errs.entry(key).or_insert(value);
            }
            return Err(fail("ssf", format!("the poll answered {status}: {}", clip(&answer))));
        }
        let sets = answer.as_object().and_then(|doc| doc.get("sets")).and_then(|v| v.as_object()).cloned().unwrap_or_default();
        for (jti, token) in sets {
            let token = token.as_str().unwrap_or("").to_string();
            match self.handle(&jti, &token) {
                Ok(()) => self.inner.lock().unwrap().ack.push(jti),
                Err(err) => {
                    println!("ssf: SET {jti} refused: {err}");
                    let code = if err.code == "signature" { "invalid_key" } else { "invalid_request" };
                    let mut problem = Map::new();
                    problem.insert("err".into(), Value::String(code.into()));
                    problem.insert("description".into(), Value::String(err.message.clone()));
                    self.inner.lock().unwrap().errs.insert(jti, Value::Object(problem));
                }
            }
        }
        Ok(answer.as_object().and_then(|doc| doc.get("moreAvailable")).and_then(|v| v.as_bool()).unwrap_or(false))
    }

    fn handle(&self, jti: &str, token: &str) -> Result<(), Error> {
        let keys = {
            let receiver = self;
            let _ = receiver;
            jwks_of(self, false)?
        };
        let verified = match verify_compact(token, &keys) {
            Ok(value) => value,
            Err(err) => {
                let message = err.message.clone();
                if !(message.contains("publishes no") || message.contains("signing key") || message.contains("does not verify")) {
                    return Err(err);
                }
                let fresh = jwks_of(self, true)?;
                verify_compact(token, &fresh)?
            }
        };
        let header = verified.header;
        let payload = verified.payload;
        if let Some(typ) = header.get("typ").and_then(|v| v.as_str()) {
            if !typ.eq_ignore_ascii_case("secevent+jwt") {
                return Err(fail("validation", format!("the SET's typ is {typ}")));
            }
        }
        let issuer = {
            let inner = self.inner.lock().unwrap();
            inner.config.as_ref().and_then(|cfg| cfg.get("issuer")).and_then(|v| v.as_str()).unwrap_or("").to_string()
        };
        let token_iss = payload.get("iss").and_then(|v| v.as_str()).unwrap_or("");
        if token_iss != issuer {
            return Err(fail("validation", format!("the SET was issued by {token_iss}, not {issuer}")));
        }
        let want = {
            let inner = self.inner.lock().unwrap();
            inner.stream.as_ref().and_then(|stream| stream.get("aud")).cloned()
        };
        let want_list = stringish(want.as_ref());
        let aud_list = stringish(payload.get("aud"));
        if !want_list.is_empty() && !aud_list.iter().any(|one| want_list.iter().any(|item| item == one)) {
            return Err(fail("validation", format!("the SET is for {}, not this stream", aud_list.join(", "))));
        }
        if let Some(claimed) = payload.get("jti") {
            if !claimed.is_null() && claimed.as_str() != Some(jti) {
                return Err(fail("validation", "the SET's jti is not the one it was delivered under"));
            }
        }
        let events = payload.get("events").and_then(|v| v.as_object()).cloned().filter(|one| !one.is_empty()).ok_or_else(|| fail("validation", "the SET carries no events"))?;
        for (kind, body) in events {
            let sub_id = payload.get("sub_id").cloned().or_else(|| body.as_object().and_then(|one| one.get("subject")).cloned());
            let subject = subject_of(sub_id.as_ref().unwrap_or(&Value::Null), &issuer);
            let sessions = self.sessions_for(&kind, &subject);
            let ends = self.end_on.iter().any(|one| one == &kind) && !sessions.is_empty();
            let mut event = SignalEvent {
                event_type: kind.clone(),
                payload: if body.is_null() { Value::Object(Map::new()) } else { body },
                subject,
                jti: jti.to_string(),
                sessions: sessions.clone(),
                ended: ends,
                iat: payload.get("iat").and_then(crate::codec::as_f64),
                txn: payload.get("txn").and_then(|v| v.as_str()).map(|s| s.to_string()),
            };
            if ends {
                let outcome = catch_unwind(AssertUnwindSafe(|| (self.on_end)(&sessions, &mut event)));
                if outcome.is_err() {
                    println!("ssf: onEndSessions threw for {kind} (SET {jti} is still acknowledged)");
                    event.ended = false;
                }
                if event.ended {
                    let mut inner = self.inner.lock().unwrap();
                    for local_id in &sessions {
                        inner.index.remove(local_id);
                    }
                }
            }
            let handlers = {
                let inner = self.inner.lock().unwrap();
                let mut list = inner.handlers.get(&kind).cloned().unwrap_or_default();
                if let Some(star) = inner.handlers.get("*") {
                    list.extend(star.iter().cloned());
                }
                list
            };
            for handler in handlers {
                if catch_unwind(AssertUnwindSafe(|| handler(&event))).is_err() {
                    println!("ssf: a handler for {kind} threw (SET {jti} is still acknowledged)");
                }
            }
        }
        Ok(())
    }

    fn sessions_for(&self, kind: &str, subject: &Map<String, Value>) -> Vec<String> {
        if kind == Events::VERIFICATION || kind == Events::STREAM_UPDATED {
            return Vec::new();
        }
        let mut inner = self.inner.lock().unwrap();
        if let Some(idp) = subject.get("idp_session").and_then(|v| v.as_str()) {
            let found = inner.index.find(|session| session.idp_session.as_deref() == Some(idp));
            if !found.is_empty() || kind == Events::SESSION_REVOKED {
                return found;
            }
        }
        if let Some(person) = subject.get("person").and_then(|v| v.as_str()) {
            return inner.index.find(|session| session.person.as_deref() == Some(person));
        }
        if let Some(email) = subject.get("email").and_then(|v| v.as_str()) {
            let wanted = email.to_ascii_lowercase();
            return inner.index.find(|session| session.email.as_deref() == Some(wanted.as_str()));
        }
        Vec::new()
    }

    fn call(&self, method: &str, url: &str, body: Option<&Value>) -> Result<(u16, Value), Error> {
        let text = match body {
            Some(value) => Some(serde_json::to_string(value).map_err(|err| fail("ssf", err.to_string()))?),
            None => None,
        };
        let mut headers = Vec::new();
        if let Some(func) = &self.headers {
            headers.extend(func(method, url, text.as_deref()));
        }
        if !headers.iter().any(|(name, _)| name.eq_ignore_ascii_case("accept")) {
            headers.push(("accept".into(), "application/json".into()));
        }
        if text.is_some() && !headers.iter().any(|(name, _)| name.eq_ignore_ascii_case("content-type")) {
            headers.push(("content-type".into(), "application/json".into()));
        }
        let answer = http::send(url, method, &headers, text.as_deref(), &self.tls, "ssf")?;
        let parsed = if answer.body.is_empty() { Value::Null } else { serde_json::from_str(&answer.body).unwrap_or(Value::String(answer.body)) };
        Ok((answer.status, parsed))
    }
}

fn jwks_of(shared: &Shared, force: bool) -> Result<Vec<Map<String, Value>>, Error> {
    {
        let inner = shared.inner.lock().unwrap();
        if !force && !inner.keys.is_empty() && now_ms() - inner.keys_at < 3_600_000.0 {
            return Ok(inner.keys.clone());
        }
    }
    let uri = {
        let inner = shared.inner.lock().unwrap();
        inner.config.as_ref().and_then(|cfg| cfg.get("jwks_uri")).and_then(|v| v.as_str()).unwrap_or("").to_string()
    };
    let (status, doc) = shared.call("GET", &uri, None)?;
    let keys = doc.as_object().and_then(|one| one.get("keys")).and_then(|v| v.as_array()).cloned();
    if status != 200 || keys.is_none() {
        return Err(fail("ssf", format!("the transmitter's JWKS answered {status}")));
    }
    let parsed: Vec<Map<String, Value>> = keys.unwrap().into_iter().filter_map(|item| item.as_object().cloned()).collect();
    let mut inner = shared.inner.lock().unwrap();
    inner.keys = parsed.clone();
    inner.keys_at = now_ms();
    Ok(parsed)
}

fn stringish(value: Option<&Value>) -> Vec<String> {
    let Some(value) = value else { return Vec::new() };
    if let Some(list) = value.as_array() {
        return list.iter().map(|item| item.as_str().map(|s| s.to_string()).unwrap_or_else(|| item.to_string())).collect();
    }
    if value.is_null() {
        return Vec::new();
    }
    vec![value.as_str().map(|s| s.to_string()).unwrap_or_else(|| value.to_string())]
}

fn clip(value: &Value) -> String {
    let text = serde_json::to_string(value).unwrap_or_default();
    text.chars().take(300).collect()
}

fn now_ms() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64() * 1000.0).unwrap_or(0.0)
}

#[allow(dead_code)]
fn _anchors() {
    let _ = (CAEP, RISC, SSF, Instant::now());
}
