// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

use crate::codec::{as_f64, as_str, dump, parse, string_list, timing_eq};
use crate::config::{read_file, resolve, Config};
use crate::error::{fail, Continuation, Error};
use crate::http::{self, Answer, TlsOpt};
use crate::keys::public_key_object;
use crate::proof::{detached_jws, interaction_hash, sign_request};
use crate::subject::{person_from, IdCheck, Person};
use crate::urlutil::{href, is_loopback, origin, well_known};
use rand::RngCore;
use serde_json::{Map, Value};
use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const FRONT: &[&str] = &["access_token", "id_token", "token", "value", "continue", "refresh_token"];

#[derive(Clone, Debug)]
pub struct Pending {
    pub id: String,
    pub client_nonce: String,
    pub server_nonce: String,
    pub continuation: Continuation,
    pub continue_not_before: f64,
    pub grant_endpoint: String,
    pub created_at: f64,
    pub expected_sub: Option<String>,
}

#[derive(Clone, Debug)]
pub struct Grant {
    pub access_token: String,
    pub bearer: bool,
    pub access: Value,
    pub expires_in: Option<f64>,
    pub expires_at: Option<f64>,
    pub manage: Option<Continuation>,
    pub continuation: Option<Continuation>,
    pub instance_id: Option<String>,
    pub subject: Option<Person>,
    pub grant_id: Option<String>,
}

pub struct GrantResult {
    pub redirect_url: Option<String>,
    pub pending: Option<Pending>,
    pub grant: Option<Grant>,
}

pub struct Finished {
    pub grant: Grant,
}

struct State {
    metadata: Option<Map<String, Value>>,
    instance_id: Option<String>,
    sub_ids: Vec<String>,
    assertions: Vec<String>,
    jwks: Option<Vec<Map<String, Value>>>,
    pending: HashMap<String, Pending>,
    used: VecDeque<String>,
}

pub struct Client {
    pub config: Config,
    state: Mutex<State>,
}

impl Client {
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, Error> {
        Ok(Self::new(read_file(path.as_ref())?))
    }

    pub fn resolve(raw: &Value, base_dir: &Path) -> Result<Config, Error> {
        resolve(raw, base_dir)
    }

    pub fn new(config: Config) -> Self {
        let sub_ids = config.sub_id_formats.clone();
        let assertions = config.assertion_formats.clone();
        Self {
            config,
            state: Mutex::new(State {
                metadata: None,
                instance_id: None,
                sub_ids,
                assertions,
                jwks: None,
                pending: HashMap::new(),
                used: VecDeque::new(),
            }),
        }
    }

    pub fn tls(&self) -> TlsOpt {
        let key = &self.config.key;
        if key.proof == "mtls" && (!key.chain_pem.is_empty() || !key.cert_pem.is_empty()) {
            let cert = if key.chain_pem.is_empty() { key.cert_pem.clone() } else { key.chain_pem.clone() };
            let key_pem = key.private_pem().unwrap_or_default();
            return TlsOpt { ca: self.config.tls_ca.clone(), cert, key: key_pem, insecure: false };
        }
        TlsOpt { ca: self.config.tls_ca.clone(), ..TlsOpt::default() }
    }

    pub fn request_grant(&self) -> Result<GrantResult, Error> {
        self.request_grant_for(None, None, None)
    }

    pub fn request_grant_for(&self, access: Option<Vec<Value>>, expected_sub: Option<String>, user: Option<Value>) -> Result<GrantResult, Error> {
        self.discover()?;
        let rights = access.unwrap_or_else(|| self.config.access.clone());
        if rights.is_empty() {
            return Err(fail("config", "access is required"));
        }
        let mut nonce = [0u8; 24];
        rand::thread_rng().fill_bytes(&mut nonce);
        let client_nonce = crate::codec::b64url(&nonce);
        let mut body = Map::new();
        body.insert("access_token".into(), Value::Object(Map::from_iter([("access".into(), Value::Array(rights))])));
        body.insert("client".into(), self.client_member()?);
        if let Some(finish) = &self.config.finish_uri {
            let mut interact = Map::new();
            interact.insert("start".into(), Value::Array(self.config.interaction_start.iter().cloned().map(Value::String).collect()));
            let mut finish_doc = Map::new();
            finish_doc.insert("method".into(), Value::String(self.config.finish_method.clone()));
            finish_doc.insert("uri".into(), Value::String(finish.clone()));
            finish_doc.insert("nonce".into(), Value::String(client_nonce.clone()));
            interact.insert("finish".into(), Value::Object(finish_doc));
            body.insert("interact".into(), Value::Object(interact));
        }
        let (subs, asserts) = {
            let state = self.state.lock().unwrap();
            (state.sub_ids.clone(), state.assertions.clone())
        };
        if !subs.is_empty() || !asserts.is_empty() {
            let mut subject = Map::new();
            if !subs.is_empty() {
                subject.insert("sub_id_formats".into(), Value::Array(subs.into_iter().map(Value::String).collect()));
            }
            if !asserts.is_empty() {
                subject.insert("assertion_formats".into(), Value::Array(asserts.into_iter().map(Value::String).collect()));
            }
            body.insert("subject".into(), Value::Object(subject));
        }
        if let Some(user) = user {
            body.insert("user".into(), user);
        }
        let answer = self.signed_json("POST", &self.config.grant_endpoint, Some(&Value::Object(body)), None)?;
        self.remember_instance(answer.as_ref());
        if answer.as_ref().and_then(|doc| doc.get("interact")).is_some() {
            let doc = answer.as_ref().and_then(|v| v.as_object()).ok_or_else(|| fail("protocol", "the grant response has neither an interaction nor an access token"))?;
            return Ok(GrantResult { redirect_url: Some(self.redirect_of(doc)?), pending: Some(self.remember_pending(doc, &client_nonce, expected_sub)?), grant: None });
        }
        if has_token(answer.as_ref()) {
            let grant = self.grant_from(answer.as_ref().unwrap_or(&Value::Null), None, None)?;
            expect(&grant, expected_sub.as_deref())?;
            return Ok(GrantResult { redirect_url: None, pending: None, grant: Some(grant) });
        }
        Err(fail("protocol", "the grant response has neither an interaction nor an access token"))
    }

    pub fn finish_redirect(&self, query: impl QuerySource, allowed: &[impl AsRef<str>]) -> Result<Finished, Error> {
        let names = query.names()?;
        let injected: Vec<&str> = FRONT.iter().copied().filter(|name| names.contains_key(*name)).collect();
        if !injected.is_empty() {
            return Err(fail("validation", format!("the finish redirect carries {}; GNAP does not send tokens through the browser", injected.join(", "))));
        }
        for (key, values) in &names {
            if values.len() > 1 {
                return Err(fail("validation", format!("the finish redirect repeats \"{key}\"")));
            }
        }
        let digest = first(&names, "hash");
        let interact = first(&names, "interact_ref");
        if digest.is_none() || interact.is_none() {
            if let Some(code) = first(&names, "error") {
                let msg = first(&names, "error_description").unwrap_or_else(|| code.clone());
                let mut err = fail("protocol", msg);
                err.gnap = Some(code);
                return Err(err);
            }
            return Err(fail("validation", "the finish redirect has no hash or interact_ref"));
        }
        let allowed: Vec<String> = allowed.iter().map(|s| s.as_ref().to_string()).collect();
        let found = self.match_pending(digest.as_deref().unwrap(), interact.as_deref().unwrap(), Some(&allowed), true)?;
        self.finish(found, interact.unwrap(), digest.unwrap())
    }

    pub fn finish_push(&self, body: &Value) -> Result<Finished, Error> {
        let Some(doc) = body.as_object() else { return Err(fail("validation", "a push finish is a JSON object")) };
        let digest = doc.get("hash").and_then(as_str).map(|s| s.to_string());
        let interact = doc.get("interact_ref").and_then(as_str).map(|s| s.to_string());
        if digest.is_none() || interact.is_none() {
            if let Some(code) = doc.get("error").and_then(as_str) {
                let mut err = fail("protocol", code);
                err.gnap = Some(code.to_string());
                return Err(err);
            }
            return Err(fail("validation", "a push finish needs hash and interact_ref"));
        }
        let found = self.match_pending(digest.as_deref().unwrap(), interact.as_deref().unwrap(), None, false)?;
        self.finish(found, interact.unwrap(), digest.unwrap())
    }

    pub fn authorization_headers(&self, grant: &Grant, method: &str, url: &str, body: Option<&str>) -> Result<HashMap<String, String>, Error> {
        self.proof_headers(method, url, body, Some(grant.access_token.as_str()), None)
    }

    pub fn call(&self, grant: &Grant, url: &str, method: &str, headers: Option<HashMap<String, String>>, body: Option<&str>) -> Result<Answer, Error> {
        let proof = self.authorization_headers(grant, method, url, body)?;
        let mut merged = headers.unwrap_or_default();
        for (key, value) in proof {
            merged.insert(key, value);
        }
        let pairs: Vec<(String, String)> = merged.into_iter().collect();
        http::send(url, method, &pairs, body, &self.tls(), "protocol")
    }

    pub fn rotate(&self, grant: &Grant) -> Result<Grant, Error> {
        let manage = grant.manage.as_ref().ok_or_else(|| fail("protocol", "this access token has no manage URI"))?;
        self.check_origin(&manage.uri, "manage.uri")?;
        let answer = self.signed_json("POST", &manage.uri, None, Some(&manage.access_token))?;
        if !has_token(answer.as_ref()) {
            return Err(fail("protocol", "the rotation returned no access token"));
        }
        let next = self.grant_from(answer.as_ref().unwrap_or(&Value::Null), Some(grant), None)?;
        if !grant.bearer && next.bearer {
            return Err(fail("validation", "rotating a key-bound token returned a bearer token"));
        }
        Ok(next)
    }

    pub fn revoke(&self, grant: &Grant) -> Result<(), Error> {
        let cont = grant.continuation.as_ref().ok_or_else(|| fail("protocol", "this grant has no continuation, so it cannot be revoked"))?;
        self.check_origin(&cont.uri, "continue.uri")?;
        self.signed_json("DELETE", &cont.uri, None, Some(&cont.access_token))?;
        Ok(())
    }

    pub fn ensure_fresh(&self, grant: &Grant) -> Result<Grant, Error> {
        let now = now_ms();
        if grant.expires_at.map(|at| at - now > 60000.0).unwrap_or(true) {
            return Ok(grant.clone());
        }
        self.rotate(grant)
    }

    fn discover(&self) -> Result<(), Error> {
        if self.state.lock().unwrap().metadata.is_some() {
            return Ok(());
        }
        let answer = http::send(&self.config.grant_endpoint, "OPTIONS", &[("accept".into(), "application/json".into())], None, &self.tls(), "discovery")?;
        let parsed = parse(&answer.body).map_err(|_| fail("discovery", format!("{} did not answer JSON grant-server metadata ({})", self.config.grant_endpoint, answer.status)))?;
        if answer.status != 200 {
            return Err(fail("discovery", format!("{} answered {} for discovery", self.config.grant_endpoint, answer.status)));
        }
        let doc = parsed.as_object().cloned().ok_or_else(|| fail("discovery", "grant-server metadata must be a JSON object"))?;
        let endpoint = doc.get("grant_request_endpoint").and_then(as_str).unwrap_or("");
        if endpoint.is_empty() {
            return Err(fail("discovery", "grant-server metadata has no grant_request_endpoint"));
        }
        if href(endpoint)?.trim_end_matches('/') != href(&self.config.grant_endpoint)?.trim_end_matches('/') {
            return Err(fail("discovery", format!("the grant server says its endpoint is {endpoint}, not {}", self.config.grant_endpoint)));
        }
        if let Some(proofs) = doc.get("key_proofs_supported").and_then(string_list) {
            if !proofs.iter().any(|p| p == &self.config.key.proof) {
                return Err(fail("discovery", format!("the grant server does not accept the {} key proof", self.config.key.proof)));
            }
        }
        if let Some(finishes) = doc.get("interaction_finish_methods_supported").and_then(string_list) {
            if self.config.finish_uri.is_some() && !finishes.iter().any(|m| m == &self.config.finish_method) {
                return Err(fail("discovery", format!("the grant server does not accept a {} interaction finish", self.config.finish_method)));
            }
        }
        let mut state = self.state.lock().unwrap();
        if state.metadata.is_some() {
            return Ok(());
        }
        if let Some(subs) = doc.get("sub_id_formats_supported").and_then(string_list) {
            state.sub_ids.retain(|item| subs.iter().any(|s| s == item));
        }
        if let Some(asserts) = doc.get("assertion_formats_supported").and_then(string_list) {
            state.assertions.retain(|item| asserts.iter().any(|s| s == item));
        }
        state.metadata = Some(doc);
        Ok(())
    }

    fn client_member(&self) -> Result<Value, Error> {
        let instance = self.state.lock().unwrap().instance_id.clone();
        if self.config.use_instance_id {
            if let Some(instance) = instance {
                return Ok(Value::String(instance));
            }
        }
        let mut member = Map::new();
        member.insert("key".into(), public_key_object(&self.config.key)?);
        if let Some(display) = &self.config.display {
            let mut doc = Map::new();
            if let Some(name) = &display.name {
                doc.insert("name".into(), Value::String(name.clone()));
            }
            if let Some(uri) = &display.uri {
                doc.insert("uri".into(), Value::String(uri.clone()));
            }
            if !doc.is_empty() {
                member.insert("display".into(), Value::Object(doc));
            }
        }
        if let Some(class_id) = &self.config.class_id {
            if !class_id.is_empty() {
                member.insert("class_id".into(), Value::String(class_id.clone()));
            }
        }
        Ok(Value::Object(member))
    }

    fn remember_instance(&self, answer: Option<&Value>) {
        if !self.config.use_instance_id {
            return;
        }
        if let Some(id) = answer.and_then(|v| v.as_object()).and_then(|doc| doc.get("instance_id")).and_then(as_str) {
            if !id.is_empty() {
                self.state.lock().unwrap().instance_id = Some(id.to_string());
            }
        }
    }

    fn redirect_of(&self, answer: &Map<String, Value>) -> Result<String, Error> {
        let redirect = answer.get("interact").and_then(|v| v.as_object()).and_then(|doc| doc.get("redirect")).and_then(as_str).unwrap_or("");
        if redirect.is_empty() {
            return Err(fail("protocol", "the interaction is not a redirect"));
        }
        let Ok(url) = url::Url::parse(redirect) else { return Err(fail("protocol", format!("interact.redirect is not a URL: {redirect}"))) };
        if url.host_str().is_none() {
            return Err(fail("protocol", format!("interact.redirect is not a URL: {redirect}")));
        }
        if url.scheme() != "https" && !(url.scheme() == "http" && (self.config.allow_insecure || is_loopback(redirect))) {
            return Err(fail("validation", format!("interact.redirect must use https: {redirect}")));
        }
        Ok(redirect.to_string())
    }

    fn remember_pending(&self, answer: &Map<String, Value>, client_nonce: &str, expected_sub: Option<String>) -> Result<Pending, Error> {
        let finish = answer.get("interact").and_then(|v| v.as_object()).and_then(|doc| doc.get("finish")).and_then(as_str).unwrap_or("");
        if finish.is_empty() {
            return Err(fail("protocol", "the grant response has no interaction finish nonce"));
        }
        let cont = read_continuation(answer.get("continue"), "continue", &self.config)?;
        let wait = cont.wait.unwrap_or(0.0);
        let now = now_ms();
        let item = Pending {
            id: client_nonce.to_string(),
            client_nonce: client_nonce.to_string(),
            server_nonce: finish.to_string(),
            continuation: cont,
            continue_not_before: now + wait * 1000.0,
            grant_endpoint: self.config.grant_endpoint.clone(),
            created_at: now,
            expected_sub,
        };
        let mut state = self.state.lock().unwrap();
        let cutoff = now - self.config.transaction_ttl_sec * 1000.0;
        state.pending.retain(|_, value| value.created_at >= cutoff);
        state.pending.insert(item.id.clone(), item.clone());
        while state.pending.len() > 1000 {
            if let Some(key) = state.pending.keys().next().cloned() {
                state.pending.remove(&key);
            } else {
                break;
            }
        }
        Ok(item)
    }

    fn match_pending(&self, digest: &str, interact_ref: &str, allowed: Option<&[String]>, use_allow: bool) -> Result<Pending, Error> {
        let mut state = self.state.lock().unwrap();
        if state.used.iter().any(|item| item == digest) {
            return Err(fail("validation", "this interaction finish was already used"));
        }
        let now = now_ms();
        let mut found = None;
        for item in state.pending.values() {
            if use_allow && allowed.map(|ids| !ids.iter().any(|id| id == &item.id)).unwrap_or(true) {
                continue;
            }
            let expected = interaction_hash(&item.client_nonce, &item.server_nonce, interact_ref, &item.grant_endpoint);
            if !timing_eq(digest, &expected) {
                continue;
            }
            if now - item.created_at > self.config.transaction_ttl_sec * 1000.0 {
                let id = item.id.clone();
                state.pending.remove(&id);
                return Err(fail("validation", "the approval took too long; start again"));
            }
            found = Some(item.clone());
            break;
        }
        found.ok_or_else(|| fail("validation", if use_allow { "this finish is not a sign-in this browser started" } else { "the interaction hash matches no grant in progress" }))
    }

    fn finish(&self, item: Pending, interact_ref: String, digest: String) -> Result<Finished, Error> {
        {
            let mut state = self.state.lock().unwrap();
            state.pending.remove(&item.id);
            state.used.push_back(digest);
            while state.used.len() > 1000 {
                state.used.pop_front();
            }
        }
        let due = item.continue_not_before - now_ms();
        if due > 0.0 {
            let cap = self.config.max_wait_sec * 1000.0;
            thread::sleep(Duration::from_millis(due.min(cap) as u64));
        }
        let answer = self.continue_grant(&item.continuation, &interact_ref)?;
        if !has_token(answer.as_ref()) {
            let mut err = fail("protocol", "the resource owner did not approve the grant");
            err.gnap = Some("user_denied".into());
            return Err(err);
        }
        let grant = self.grant_from(answer.as_ref().unwrap_or(&Value::Null), None, Some(&item.continuation))?;
        expect(&grant, item.expected_sub.as_deref())?;
        Ok(Finished { grant })
    }

    fn continue_grant(&self, cont: &Continuation, interact_ref: &str) -> Result<Option<Value>, Error> {
        let mut current = cont.clone();
        let mut waited = 0.0;
        let mut immediate = 0;
        let body = Value::Object(Map::from_iter([("interact_ref".into(), Value::String(interact_ref.to_string()))]));
        loop {
            match self.signed_json("POST", &current.uri, Some(&body), Some(&current.access_token)) {
                Ok(answer) => return Ok(answer),
                Err(err) => {
                    if err.gnap.as_deref() != Some("too_fast") {
                        return Err(err);
                    }
                    if let Some(next) = &err.continuation {
                        self.check_origin(&next.uri, "continue.uri")?;
                        current = next.clone();
                    }
                    let wait = current.wait.unwrap_or(0.0).max(0.0);
                    if wait == 0.0 {
                        immediate += 1;
                        if immediate > 2 {
                            return Err(err);
                        }
                        continue;
                    }
                    if waited + wait > self.config.max_wait_sec {
                        return Err(err);
                    }
                    thread::sleep(Duration::from_secs_f64(wait));
                    waited += wait;
                }
            }
        }
    }

    fn signed_json(&self, method: &str, url: &str, body: Option<&Value>, token: Option<&str>) -> Result<Option<Value>, Error> {
        self.check_origin(url, "the request URL")?;
        let text = match body {
            Some(body) => Some(dump(body)?),
            None => None,
        };
        let mut extra = HashMap::new();
        if text.is_some() {
            extra.insert("content-type".into(), "application/json".into());
        }
        let mut headers = self.proof_headers(method, url, text.as_deref(), token, Some(extra))?;
        headers.insert("accept".into(), "application/json".into());
        let pairs: Vec<(String, String)> = headers.into_iter().collect();
        self.read(http::send(url, method, &pairs, text.as_deref(), &self.tls(), "protocol")?)
    }

    fn proof_headers(&self, method: &str, url: &str, body: Option<&str>, token: Option<&str>, extra: Option<HashMap<String, String>>) -> Result<HashMap<String, String>, Error> {
        let mut headers = extra.unwrap_or_default();
        if let Some(token) = token {
            if !token.is_empty() {
                headers.insert("authorization".into(), format!("GNAP {token}"));
            }
        }
        if self.config.key.proof == "httpsig" {
            for (key, value) in sign_request(&self.config.key, method, url, &headers, body)? {
                headers.insert(key, value);
            }
        } else if self.config.key.proof == "jwsd" {
            headers.insert("detached-jws".into(), detached_jws(&self.config.key, method, url, body, token)?);
        }
        Ok(headers)
    }

    fn read(&self, answer: Answer) -> Result<Option<Value>, Error> {
        if answer.status == 204 || answer.body.is_empty() {
            if answer.status >= 400 {
                return Err(fail("protocol", format!("the authorization server answered {}", answer.status)));
            }
            return Ok(None);
        }
        let parsed = parse(&answer.body).map_err(|_| fail("protocol", format!("the authorization server answered {} with a body that is not JSON", answer.status)))?;
        if (200..300).contains(&answer.status) {
            return Ok(Some(parsed));
        }
        let doc = parsed.as_object();
        let code = doc.and_then(|d| d.get("error")).and_then(as_str).map(|s| s.to_string());
        let mut cont = None;
        if let Some(raw) = doc.and_then(|d| d.get("continue")).and_then(|v| v.as_object()) {
            let token = raw.get("access_token").and_then(|v| v.as_object()).and_then(|t| t.get("value")).and_then(as_str);
            let uri = raw.get("uri").and_then(as_str);
            if let (Some(uri), Some(token)) = (uri, token) {
                cont = Some(Continuation { uri: uri.to_string(), access_token: token.to_string(), wait: raw.get("wait").and_then(as_f64) });
            }
        }
        let mut msg = doc.and_then(|d| d.get("error_description")).and_then(as_str).unwrap_or("").to_string();
        if msg.is_empty() {
            msg = code.clone().unwrap_or_default();
        }
        if msg.is_empty() {
            msg = format!("the authorization server answered {}", answer.status);
        }
        let mut err = fail("protocol", msg);
        err.gnap = code;
        err.continuation = cont;
        Err(err)
    }

    fn grant_from(&self, answer: &Value, previous: Option<&Grant>, previous_continue: Option<&Continuation>) -> Result<Grant, Error> {
        let doc = answer.as_object();
        let mut token = doc.and_then(|d| d.get("access_token"));
        if let Some(list) = token.and_then(|v| v.as_array()) {
            token = list.first();
        }
        let token_doc = token.and_then(|v| v.as_object()).ok_or_else(|| fail("protocol", "the access token is not an object"))?;
        let value = token_doc.get("value").and_then(as_str).unwrap_or("");
        if value.is_empty() {
            return Err(fail("protocol", "the access token has no value"));
        }
        let flags = token_doc.get("flags").and_then(|v| v.as_array()).map(|list| list.iter().filter_map(|item| item.as_str()).collect::<Vec<_>>()).unwrap_or_default();
        let bearer = flags.iter().any(|flag| *flag == "bearer");
        if bearer && self.config.require_bound_tokens {
            return Err(fail("validation", "the authorization server issued a bearer token, and this client requires a key-bound one"));
        }
        self.remember_instance(Some(answer));
        let manage = if let Some(raw) = token_doc.get("manage").and_then(|v| v.as_object()) {
            let manage_token = raw.get("access_token").and_then(|v| v.as_object()).and_then(|t| t.get("value")).and_then(as_str);
            let uri = raw.get("uri").and_then(as_str);
            let (Some(uri), Some(manage_token)) = (uri, manage_token) else { return Err(fail("protocol", "the access token manage object is not usable")) };
            self.check_origin(uri, "manage.uri")?;
            Some(Continuation { uri: uri.to_string(), access_token: manage_token.to_string(), wait: None })
        } else {
            previous.and_then(|grant| grant.manage.clone())
        };
        let cont = if doc.and_then(|d| d.get("continue")).is_some() {
            Some(read_continuation(doc.and_then(|d| d.get("continue")), "continue", &self.config)?)
        } else if let Some(previous_continue) = previous_continue {
            Some(previous_continue.clone())
        } else {
            previous.and_then(|grant| grant.continuation.clone())
        };
        let instance = self.state.lock().unwrap().instance_id.clone();
        let mut audiences = Vec::new();
        if let Some(instance) = &instance {
            audiences.push(instance.clone());
        }
        if !self.config.application.is_empty() {
            audiences.push(self.config.application.clone());
        }
        let subject = if doc.and_then(|d| d.get("subject")).is_some() {
            let keys_fn = || self.id_token_keys();
            person_from(doc.and_then(|d| d.get("subject")).unwrap(), &IdCheck { issuer: &self.config.id_token_issuer, audiences, skew: self.config.clock_tolerance_sec, keys: &keys_fn })?
        } else {
            previous.and_then(|grant| grant.subject.clone())
        };
        let expires_in = token_doc.get("expires_in").and_then(as_f64);
        let expires_at = expires_in.map(|secs| now_ms() + secs * 1000.0);
        Ok(Grant {
            access_token: value.to_string(),
            bearer,
            access: token_doc.get("access").cloned().unwrap_or(Value::Null),
            expires_in,
            expires_at,
            manage,
            continuation: cont.clone(),
            instance_id: instance,
            subject,
            grant_id: cont.as_ref().and_then(|item| grant_id_of(&item.uri)),
        })
    }

    fn id_token_keys(&self) -> Result<Vec<Map<String, Value>>, Error> {
        if let Some(keys) = &self.state.lock().unwrap().jwks {
            return Ok(keys.clone());
        }
        let urls = well_known(&self.config.id_token_issuer, "openid-configuration")?;
        let mut last = fail("discovery", format!("no OpenID Provider metadata at {}", urls.join(" or ")));
        let mut openid = None;
        for (i, one) in urls.iter().enumerate() {
            let answer = http::send(one, "GET", &[("accept".into(), "application/json".into())], None, &self.tls(), "discovery")?;
            let parsed = parse(&answer.body).ok();
            let doc = parsed.as_ref().and_then(|v| v.as_object());
            let issuer = doc.and_then(|d| d.get("issuer")).and_then(as_str).unwrap_or("").trim_end_matches('/');
            if answer.status == 200 && issuer == self.config.id_token_issuer.trim_end_matches('/') {
                openid = doc.cloned();
                break;
            }
            if answer.status == 404 && i + 1 != urls.len() {
                continue;
            }
            let got = doc.and_then(|d| d.get("issuer")).and_then(as_str).unwrap_or("");
            if !got.is_empty() && got != self.config.id_token_issuer {
                last = fail("discovery", format!("{one} says its issuer is {got}, not {}", self.config.id_token_issuer));
            } else {
                last = fail("discovery", format!("{one} answered {}", answer.status));
            }
        }
        let openid = openid.ok_or(last)?;
        let jwks_uri = openid.get("jwks_uri").and_then(as_str).unwrap_or("");
        let answer = http::send(jwks_uri, "GET", &[("accept".into(), "application/json".into())], None, &self.tls(), "discovery")?;
        let parsed = parse(&answer.body).map_err(|_| fail("discovery", "the issuer JWKS is not JSON"))?;
        let list = parsed.get("keys").and_then(|v| v.as_array()).ok_or_else(|| fail("discovery", format!("the issuer JWKS answered {}", answer.status)))?;
        if answer.status != 200 {
            return Err(fail("discovery", format!("the issuer JWKS answered {}", answer.status)));
        }
        let keys: Vec<Map<String, Value>> = list.iter().filter_map(|item| item.as_object().cloned()).collect();
        self.state.lock().unwrap().jwks = Some(keys.clone());
        Ok(keys)
    }

    fn check_origin(&self, uri: &str, what: &str) -> Result<(), Error> {
        let Ok(parts) = url::Url::parse(uri) else { return Err(fail("validation", format!("{what} is not a URL: {uri}"))) };
        if parts.scheme() != "http" && parts.scheme() != "https" || parts.host_str().is_none() {
            return Err(fail("validation", format!("{what} is not a URL: {uri}")));
        }
        if parts.scheme() != "https" && !self.config.allow_insecure {
            return Err(fail("validation", format!("{what} must use https: {uri}")));
        }
        if origin(uri)? != origin(&self.config.grant_endpoint)? {
            return Err(fail("validation", format!("{what} {uri} is not on the grant endpoint's origin")));
        }
        Ok(())
    }
}

pub trait QuerySource {
    fn names(self) -> Result<HashMap<String, Vec<String>>, Error>;
}

impl QuerySource for &str {
    fn names(self) -> Result<HashMap<String, Vec<String>>, Error> {
        query_text(self)
    }
}

impl QuerySource for String {
    fn names(self) -> Result<HashMap<String, Vec<String>>, Error> {
        query_text(&self)
    }
}

impl QuerySource for HashMap<String, String> {
    fn names(self) -> Result<HashMap<String, Vec<String>>, Error> {
        Ok(self.into_iter().map(|(k, v)| (k, vec![v])).collect())
    }
}

impl QuerySource for &HashMap<String, String> {
    fn names(self) -> Result<HashMap<String, Vec<String>>, Error> {
        Ok(self.iter().map(|(k, v)| (k.clone(), vec![v.clone()])).collect())
    }
}

fn query_text(text: &str) -> Result<HashMap<String, Vec<String>>, Error> {
    let mut text = text.to_string();
    if text.contains("://") || text.starts_with('/') {
        let parsed = if text.contains("://") { url::Url::parse(&text).ok() } else { url::Url::parse(&format!("http://local{text}")).ok() };
        let Some(parsed) = parsed else { return Err(fail("validation", "the finish redirect could not be read")) };
        text = parsed.query().unwrap_or("").to_string();
    } else if text.starts_with('?') || text.starts_with('#') {
        text = text[1..].to_string();
    }
    let mut names: HashMap<String, Vec<String>> = HashMap::new();
    if text.is_empty() {
        return Ok(names);
    }
    for pair in text.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let key = urlencoding_decode(key);
        let value = urlencoding_decode(value);
        names.entry(key).or_default().push(value);
    }
    Ok(names)
}

fn urlencoding_decode(value: &str) -> String {
    let mut out = Vec::new();
    let bytes = value.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'+' {
            out.push(b' ');
            i += 1;
        } else if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(byte) = u8::from_str_radix(std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or(""), 16) {
                out.push(byte);
                i += 3;
            } else {
                out.push(bytes[i]);
                i += 1;
            }
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

fn read_continuation(raw: Option<&Value>, what: &str, config: &Config) -> Result<Continuation, Error> {
    let doc = raw.and_then(|v| v.as_object()).ok_or_else(|| fail("protocol", format!("the response has no {what} object")))?;
    let token = doc.get("access_token").and_then(|v| v.as_object()).and_then(|t| t.get("value")).and_then(as_str);
    let uri = doc.get("uri").and_then(as_str);
    let (Some(uri), Some(token)) = (uri, token) else { return Err(fail("protocol", format!("the response has no usable {what} object"))) };
    check_origin_config(uri, &format!("{what}.uri"), config)?;
    let wait = if doc.contains_key("wait") && !doc.get("wait").unwrap().is_null() {
        let n = as_f64(doc.get("wait").unwrap()).filter(|n| *n >= 0.0).ok_or_else(|| fail("protocol", format!("{what}.wait is not a number of seconds")))?;
        Some(n)
    } else {
        None
    };
    Ok(Continuation { uri: uri.to_string(), access_token: token.to_string(), wait })
}

fn check_origin_config(uri: &str, what: &str, config: &Config) -> Result<(), Error> {
    let Ok(parts) = url::Url::parse(uri) else { return Err(fail("validation", format!("{what} is not a URL: {uri}"))) };
    if parts.scheme() != "https" && !config.allow_insecure {
        return Err(fail("validation", format!("{what} must use https: {uri}")));
    }
    if origin(uri)? != origin(&config.grant_endpoint)? {
        return Err(fail("validation", format!("{what} {uri} is not on the grant endpoint's origin")));
    }
    Ok(())
}

fn has_token(answer: Option<&Value>) -> bool {
    let Some(doc) = answer.and_then(|v| v.as_object()) else { return false };
    let Some(token) = doc.get("access_token") else { return false };
    if let Some(list) = token.as_array() {
        return !list.is_empty();
    }
    token.as_str().map(|s| !s.is_empty()).unwrap_or(true)
}

fn expect(grant: &Grant, expected: Option<&str>) -> Result<(), Error> {
    if let (Some(expected), Some(subject)) = (expected, &grant.subject) {
        if subject.sub != expected {
            return Err(fail("validation", "the grant was approved by somebody other than the account that was asked for"));
        }
    }
    Ok(())
}

fn grant_id_of(uri: &str) -> Option<String> {
    let url = url::Url::parse(uri).ok()?;
    let chunk = url.path_segments()?.filter(|s| !s.is_empty()).last()?;
    Some(urlencoding_decode(chunk))
}

fn first(names: &HashMap<String, Vec<String>>, key: &str) -> Option<String> {
    names.get(key).and_then(|values| values.first()).cloned()
}

fn now_ms() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64() * 1000.0).unwrap_or(0.0)
}
