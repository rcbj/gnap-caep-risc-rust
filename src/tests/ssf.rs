// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

use super::MustErr;
use crate::{subject_of, verify_compact, Events, ReceiverOpt, SignalEvent, SignalsReceiver, TrackedSession};
use base64::Engine;
use rsa::pkcs1v15::SigningKey;
use rsa::traits::PublicKeyParts;
use rsa::RsaPrivateKey;
use serde_json::{json, Map, Value};
use sha2::Sha256;
use signature::{SignatureEncoding, Signer};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::Duration;

fn b64url(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

fn rsa_key() -> &'static RsaPrivateKey {
    static KEY: OnceLock<RsaPrivateKey> = OnceLock::new();
    KEY.get_or_init(|| RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap())
}

fn other_key() -> &'static RsaPrivateKey {
    static KEY: OnceLock<RsaPrivateKey> = OnceLock::new();
    KEY.get_or_init(|| RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap())
}

fn jwk(key: &RsaPrivateKey, kid: &str) -> Map<String, Value> {
    let mut doc = Map::new();
    doc.insert("kty".into(), json!("RSA"));
    doc.insert("n".into(), json!(b64url(&key.n().to_bytes_be())));
    doc.insert("e".into(), json!(b64url(&key.e().to_bytes_be())));
    doc.insert("kid".into(), json!(kid));
    doc.insert("alg".into(), json!("RS256"));
    doc.insert("use".into(), json!("sig"));
    doc
}

fn jws(payload: &Value, key: &RsaPrivateKey, header: Option<&str>) -> String {
    let header = header.unwrap_or(r#"{"alg":"RS256","kid":"k1","typ":"secevent+jwt"}"#);
    let h = b64url(header.as_bytes());
    let p = b64url(serde_json::to_string(payload).unwrap().as_bytes());
    let sig = SigningKey::<Sha256>::new(key.clone()).sign(format!("{h}.{p}").as_bytes()).to_vec();
    format!("{h}.{p}.{}", b64url(&sig))
}

struct Tx {
    base: String,
    queue: Map<String, Value>,
    acked: Vec<String>,
    errs: Map<String, Value>,
    streams: Vec<Value>,
    created: i64,
    authorization: String,
}

fn start_transmitter() -> (thread::JoinHandle<()>, Arc<Mutex<Tx>>, String) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let base = format!("http://127.0.0.1:{port}");
    let state = Arc::new(Mutex::new(Tx {
        base: base.clone(),
        queue: Map::new(),
        acked: Vec::new(),
        errs: Map::new(),
        streams: Vec::new(),
        created: 0,
        authorization: String::new(),
    }));
    let shared = state.clone();
    let handle = thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut tcp) = stream else { continue };
            tcp.set_read_timeout(Some(Duration::from_secs(5))).ok();
            let shared = shared.clone();
            thread::spawn(move || {
                let Ok((method, path, headers, body)) = read_http(&mut tcp) else { return };
                let response = handle(&shared, &method, &path, &headers, &body);
                let _ = tcp.write_all(response.as_bytes());
            });
        }
    });
    (handle, state, base)
}

fn handle(state: &Mutex<Tx>, method: &str, path: &str, headers: &HashMap<String, String>, body: &str) -> String {
    let mut tx = state.lock().unwrap();
    tx.authorization = headers.get("authorization").cloned().unwrap_or_default();
    if tx.authorization != "GNAP app-token" && path != "/.well-known/ssf-configuration" && !path.starts_with("/jwks") {
        return http(401, &json!({"error": "invalid_token"}).to_string());
    }
    let base = tx.base.clone();
    if path == "/.well-known/ssf-configuration" {
        return http(200, &json!({
            "issuer": base,
            "jwks_uri": format!("{base}/jwks"),
            "configuration_endpoint": format!("{base}/ssf/stream"),
            "verification_endpoint": format!("{base}/ssf/verify"),
            "delivery_methods_supported": ["urn:ietf:rfc:8936"],
        }).to_string());
    }
    if path == "/jwks" {
        return http(200, &json!({"keys": [jwk(rsa_key(), "k1")]}).to_string());
    }
    if path == "/ssf/stream" && method == "GET" {
        return http(200, &Value::Array(tx.streams.clone()).to_string());
    }
    if path == "/ssf/stream" && method == "POST" {
        let parsed: Value = serde_json::from_str(body).unwrap_or(Value::Null);
        tx.created += 1;
        let id = tx.created;
        let events = parsed.get("events_requested").cloned().unwrap_or(Value::Array(Vec::new()));
        let stream = json!({
            "stream_id": format!("s{id}"),
            "iss": base,
            "aud": "my-app",
            "delivery": {"method": parsed["delivery"]["method"], "endpoint_url": format!("{base}/ssf/poll/s{id}")},
            "events_requested": events.clone(),
            "events_delivered": events,
        });
        tx.streams.push(stream.clone());
        return http(201, &stream.to_string());
    }
    if path == "/ssf/verify" {
        return http_empty(204);
    }
    if path.starts_with("/ssf/poll/") {
        let parsed: Value = serde_json::from_str(if body.is_empty() { "{}" } else { body }).unwrap_or(json!({}));
        if let Some(ack) = parsed.get("ack").and_then(|v| v.as_array()) {
            for jti in ack {
                if let Some(jti) = jti.as_str() {
                    tx.acked.push(jti.to_string());
                    tx.queue.remove(jti);
                }
            }
        }
        if let Some(errs) = parsed.get("setErrs").and_then(|v| v.as_object()) {
            for (jti, value) in errs {
                tx.errs.insert(jti.clone(), value.clone());
                tx.queue.remove(jti);
            }
        }
        let body = json!({"sets": tx.queue, "moreAvailable": false});
        return http(200, &body.to_string());
    }
    http(404, &json!({"error": "not_found"}).to_string())
}

fn deliver(state: &Mutex<Tx>, kind: &str, sub_id: Value, extra: Value, key: &RsaPrivateKey, aud: Option<&str>, iss: Option<&str>) -> String {
    let mut tx = state.lock().unwrap();
    let jti = format!("jti-{}", tx.queue.len() + tx.acked.len() + 1);
    let base = tx.base.clone();
    let mut event = Map::new();
    event.insert("event_timestamp".into(), json!(1));
    if let Some(extra) = extra.as_object() {
        for (key, value) in extra {
            event.insert(key.clone(), value.clone());
        }
    }
    let token = jws(
        &json!({
            "iss": iss.unwrap_or(&base),
            "aud": aud.unwrap_or("my-app"),
            "jti": jti,
            "iat": 1,
            "sub_id": sub_id,
            "events": {kind: event},
        }),
        key,
        None,
    );
    tx.queue.insert(jti.clone(), Value::String(token));
    jti
}

fn http(status: u16, body: &str) -> String {
    format!("HTTP/1.1 {status} OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len())
}

fn http_empty(status: u16) -> String {
    format!("HTTP/1.1 {status} No Content\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
}

fn read_http(stream: &mut impl Read) -> Result<(String, String, HashMap<String, String>, String), String> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        match stream.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            Err(err) => return Err(err.to_string()),
        }
        if let Some(split) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let header = String::from_utf8_lossy(&buf[..split]).to_string();
            let need = content_length(&header);
            if buf.len() >= split + 4 + need {
                break;
            }
        }
    }
    let split = buf.windows(4).position(|w| w == b"\r\n\r\n").ok_or("short")?;
    let header = String::from_utf8_lossy(&buf[..split]).to_string();
    let body = String::from_utf8_lossy(&buf[split + 4..]).to_string();
    let mut lines = header.split("\r\n");
    let request = lines.next().unwrap_or("");
    let mut parts = request.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("");
    let path = target.split('?').next().unwrap_or("").to_string();
    let mut headers = HashMap::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }
    Ok((method, path, headers, body))
}

fn content_length(header: &str) -> usize {
    header.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if name.eq_ignore_ascii_case("content-length") {
            value.trim().parse().ok()
        } else {
            None
        }
    }).unwrap_or(0)
}

#[test]
fn verifies_a_set_and_refuses_another_key() {
    let keys = vec![jwk(rsa_key(), "k1")];
    let ok = verify_compact(&jws(&json!({"a": 1}), rsa_key(), None), &keys).unwrap();
    assert_eq!(ok.payload.get("a").and_then(|v| v.as_i64()), Some(1));
    let bad = verify_compact(&jws(&json!({"a": 1}), other_key(), None), &keys).must_err();
    assert!(bad.to_string().contains("does not verify"));
    let kid = verify_compact(&jws(&json!({"a": 1}), rsa_key(), Some(r#"{"alg":"RS256","kid":"nope"}"#)), &keys).must_err();
    assert!(kid.to_string().contains("kid nope"));
    let none = verify_compact(&jws(&json!({"a": 1}), rsa_key(), Some(r#"{"alg":"none"}"#)), &keys).must_err();
    assert!(none.to_string().contains("does not verify"));
}

#[test]
fn reads_subject_forms() {
    assert_eq!(Events::SESSION_REVOKED, "https://schemas.openid.net/secevent/caep/event-type/session-revoked");
    assert_eq!(Events::CREDENTIAL_COMPROMISE, "https://schemas.openid.net/secevent/risc/event-type/credential-compromise");
    let complex = subject_of(
        &json!({
            "format": "complex",
            "user": {"format": "iss_sub", "iss": "https://i", "sub": "urn:uuid:a"},
            "session": {"format": "opaque", "id": "S1"},
        }),
        "https://i",
    );
    assert_eq!(complex.get("person").and_then(|v| v.as_str()), Some("urn:uuid:a"));
    assert_eq!(complex.get("idp_session").and_then(|v| v.as_str()), Some("S1"));
    let other = subject_of(&json!({"format": "iss_sub", "iss": "https://other", "sub": "urn:uuid:a"}), "https://i");
    assert!(other.is_empty());
    let email = subject_of(&json!({"format": "email", "email": "A@x.com"}), "https://i");
    assert_eq!(email.get("email").and_then(|v| v.as_str()), Some("A@x.com"));
}

#[test]
fn polls_with_the_gnap_token_and_acknowledges() {
    let (_server, state, base) = start_transmitter();
    let ended = Arc::new(Mutex::new(Vec::<Vec<String>>::new()));
    let seen = Arc::new(Mutex::new(Vec::<SignalEvent>::new()));
    let signed = Arc::new(Mutex::new(Vec::<(String, String, String)>::new()));
    let ended_cb = ended.clone();
    let seen_cb = seen.clone();
    let signed_cb = signed.clone();
    let mut opt = ReceiverOpt::new(base, Arc::new(move |ids, _event| ended_cb.lock().unwrap().push(ids.to_vec())));
    opt.poll_interval_ms = 60_000;
    opt.headers = Some(Arc::new(move |method, url, body| {
        signed_cb.lock().unwrap().push((method.to_string(), url.to_string(), body.unwrap_or("").to_string()));
        vec![("authorization".into(), "GNAP app-token".into())]
    }));
    let receiver = SignalsReceiver::new(opt).unwrap();
    receiver.on("*", Arc::new(move |event| seen_cb.lock().unwrap().push(event.clone())));
    receiver.start().unwrap();
    receiver.stop();
    {
        let tx = state.lock().unwrap();
        assert_eq!(tx.created, 1);
        assert_eq!(tx.authorization, "GNAP app-token");
    }
    assert_eq!(receiver.stream().unwrap().get("stream_id").and_then(|v| v.as_str()), Some("s1"));
    let created = signed.lock().unwrap().iter().find(|item| item.0 == "POST" && item.1.ends_with("/ssf/stream")).cloned().unwrap();
    assert!(created.2.contains("\"delivery\""));

    receiver.track(TrackedSession { local_id: "L-a1".into(), person: Some("urn:uuid:alice".into()), email: Some("alice@example.com".into()), idp_session: Some("IDP-A1".into()), expires_at: None });
    receiver.track(TrackedSession { local_id: "L-a2".into(), person: Some("urn:uuid:alice".into()), email: Some("alice@example.com".into()), idp_session: Some("IDP-A2".into()), expires_at: None });
    receiver.track(TrackedSession { local_id: "L-b1".into(), person: Some("urn:uuid:bob".into()), email: Some("bob@example.com".into()), idp_session: Some("IDP-B1".into()), expires_at: None });
    let iss = state.lock().unwrap().base.clone();
    let revoked = deliver(
        &state,
        Events::SESSION_REVOKED,
        json!({"format": "complex", "user": {"format": "iss_sub", "iss": iss, "sub": "urn:uuid:alice"}, "session": {"format": "opaque", "id": "IDP-A1"}}),
        json!({}),
        rsa_key(),
        None,
        None,
    );
    deliver(&state, Events::CREDENTIAL_CHANGE, json!({"format": "iss_sub", "iss": iss, "sub": "urn:uuid:bob"}), json!({"credential_type": "password"}), rsa_key(), None, None);
    receiver.poll_once().unwrap();
    assert_eq!(ended.lock().unwrap().clone(), vec![vec!["L-a1".to_string()]]);
    let seen = seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 2);
    assert!(seen[0].ended);
    assert_eq!(seen[1].event_type, Events::CREDENTIAL_CHANGE);
    assert!(!seen[1].ended);
    let poll = signed.lock().unwrap().iter().find(|item| item.1.contains("/ssf/poll/")).cloned().unwrap();
    assert_eq!(poll.0, "POST");
    assert!(poll.2.contains("maxEvents"));
    receiver.poll_once().unwrap();
    let acked = state.lock().unwrap().acked.clone();
    let rest: Vec<String> = acked.iter().filter(|item| *item != &revoked).cloned().collect();
    let mut expected = vec![revoked];
    expected.extend(rest);
    assert_eq!(acked, expected);
    let bad = deliver(&state, Events::ACCOUNT_DISABLED, json!({"format": "email", "email": "alice@example.com"}), json!({}), other_key(), None, None);
    receiver.poll_once().unwrap();
    receiver.poll_once().unwrap();
    let err = state.lock().unwrap().errs.get(&bad).cloned().unwrap();
    assert_eq!(err.get("err").and_then(|v| v.as_str()), Some("invalid_key"));
    receiver.verify(Some("abc")).unwrap();
    receiver.stop();
}
