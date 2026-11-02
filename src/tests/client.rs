// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

use super::MustErr;
use crate::{fingerprint, interaction_hash, load_client_key, public_key_object, Client};
use base64::Engine;
use p256::ecdsa::VerifyingKey;
use rcgen::{CertificateParams, DnType, KeyPair, SanType};
use rsa::pkcs1v15::SigningKey;
use rsa::traits::PublicKeyParts;
use rsa::RsaPrivateKey;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::danger::ClientCertVerifier;
use rustls::{DigitallySignedStruct, DistinguishedName, ServerConfig, ServerConnection};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use signature::{SignatureEncoding, Signer, Verifier};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn b64url(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

fn b64std(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

fn sha256(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}

fn id_key() -> &'static RsaPrivateKey {
    static KEY: OnceLock<RsaPrivateKey> = OnceLock::new();
    KEY.get_or_init(|| RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap())
}

fn id_jwk() -> Value {
    json!({
        "kty": "RSA",
        "n": b64url(&id_key().n().to_bytes_be()),
        "e": b64url(&id_key().e().to_bytes_be()),
        "kid": "id1",
        "alg": "RS256",
        "use": "sig",
    })
}

fn id_token(issuer: &str, aud: &str, sub: &str) -> String {
    let header = b64url(br#"{"alg":"RS256","kid":"id1","typ":"JWT"}"#);
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let payload = b64url(serde_json::to_string(&json!({
        "iss": issuer, "aud": aud, "sub": sub, "exp": now + 600, "iat": now,
        "email": format!("{sub}@example.com"), "sid": "sess-1", "name": "Ada",
    })).unwrap().as_bytes());
    let signing = format!("{header}.{payload}");
    let sig = SigningKey::<Sha256>::new(id_key().clone()).sign(signing.as_bytes()).to_vec();
    format!("{signing}.{}", b64url(&sig))
}

struct Material {
    cert_pem: String,
    key_pem: String,
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
}

fn material(name: &str, dns: &[&str], ips: &[IpAddr]) -> Material {
    let mut params = CertificateParams::new(dns.iter().map(|item| (*item).to_string()).collect::<Vec<_>>()).unwrap();
    params.distinguished_name.push(DnType::CommonName, name);
    for ip in ips {
        params.subject_alt_names.push(SanType::IpAddress(*ip));
    }
    let key = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    Material { cert_pem: cert.pem(), key_pem: key.serialize_pem(), cert_der: cert.der().as_ref().to_vec(), key_der: key.serialize_der() }
}

struct Behavior {
    foreign: bool,
    bearer: bool,
    too_fast: bool,
    aud: String,
    sub: String,
    iss_sub: Option<String>,
    too_fast_sent: bool,
}

struct Seen {
    method: String,
    url: String,
    body: String,
    authorization: String,
    signature: String,
    detached: String,
    cert: String,
}

struct Stub {
    base: String,
    server_cert: String,
    client_key: String,
    client_cert: String,
    client_fingerprint: String,
    seen: Mutex<Vec<Seen>>,
    public: Mutex<Option<VerifyingKey>>,
    kid: Mutex<String>,
    behavior: Mutex<Behavior>,
}

fn start_server() -> Arc<Stub> {
    let server = material("localhost", &["localhost"], &[IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))]);
    let client = material("gnap-client", &["gnap-client"], &[]);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let stub = Arc::new(Stub {
        base: format!("https://127.0.0.1:{port}"),
        server_cert: server.cert_pem.clone(),
        client_key: client.key_pem,
        client_cert: client.cert_pem,
        client_fingerprint: fingerprint(&client.cert_der),
        seen: Mutex::new(Vec::new()),
        public: Mutex::new(None),
        kid: Mutex::new(String::new()),
        behavior: Mutex::new(Behavior { foreign: false, bearer: false, too_fast: false, aud: "instance-1".into(), sub: "user-1".into(), iss_sub: None, too_fast_sent: false }),
    });
    let verifier = Arc::new(AllowAny);
    let mut config = ServerConfig::builder_with_provider(crate::provider())
        .with_protocol_versions(&[&rustls::version::TLS12, &rustls::version::TLS13])
        .unwrap()
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![CertificateDer::from(server.cert_der)], PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server.key_der)))
        .unwrap();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let config = Arc::new(config);
    let shared = stub.clone();
    thread_spawn(listener, config, shared);
    stub
}

fn thread_spawn(listener: TcpListener, config: Arc<ServerConfig>, stub: Arc<Stub>) {
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut tcp) = stream else { continue };
            tcp.set_read_timeout(Some(Duration::from_secs(8))).ok();
            tcp.set_write_timeout(Some(Duration::from_secs(8))).ok();
            let config = config.clone();
            let stub = stub.clone();
            std::thread::spawn(move || {
                let Ok(mut conn) = ServerConnection::new(config) else { return };
                loop {
                    match conn.complete_io(&mut tcp) {
                        Ok(_) if !conn.is_handshaking() => break,
                        Ok(_) => continue,
                        Err(err) if err.kind() == std::io::ErrorKind::WouldBlock || err.kind() == std::io::ErrorKind::TimedOut => {
                            if !conn.is_handshaking() {
                                break;
                            }
                        }
                        Err(_) => return,
                    }
                }
                let cert = conn.peer_certificates().and_then(|list| list.first()).map(|der| fingerprint(der.as_ref())).unwrap_or_default();
                let mut tls = rustls::Stream::new(&mut conn, &mut tcp);
                let Ok((method, path, headers, body)) = read_http(&mut tls) else { return };
                let response = dispatch(&stub, &method, &path, &headers, &body, &cert);
                if tls.write_all(response.as_bytes()).is_err() {
                    return;
                }
                let _ = tls.flush();
            });
        }
    });
}

fn dispatch(stub: &Stub, method: &str, path: &str, headers: &HashMap<String, String>, body: &str, cert: &str) -> String {
    let target = format!("{}{path}", stub.base);
    stub.seen.lock().unwrap().push(Seen {
        method: method.to_string(),
        url: path.to_string(),
        body: body.to_string(),
        authorization: headers.get("authorization").cloned().unwrap_or_default(),
        signature: headers.get("signature").cloned().unwrap_or_default(),
        detached: headers.get("detached-jws").cloned().unwrap_or_default(),
        cert: cert.to_string(),
    });
    if let Err(err) = check(stub, method, path, headers, body, &target) {
        return http(401, &json!({"error": "invalid_client", "error_description": err}).to_string());
    }
    let behavior = stub.behavior.lock().unwrap();
    if method == "OPTIONS" && path == "/gnap" {
        return http(200, &json!({
            "grant_request_endpoint": format!("{}/gnap", stub.base),
            "key_proofs_supported": ["httpsig", "jwsd", "mtls"],
            "interaction_start_modes_supported": ["redirect"],
            "interaction_finish_methods_supported": ["redirect", "push"],
            "sub_id_formats_supported": ["iss_sub", "opaque"],
            "assertion_formats_supported": ["id_token"],
        }).to_string());
    }
    if path == "/.well-known/openid-configuration" {
        return http(200, &json!({"issuer": stub.base, "jwks_uri": format!("{}/jwks", stub.base)}).to_string());
    }
    if path == "/jwks" {
        return http(200, &json!({"keys": [id_jwk()]}).to_string());
    }
    if path == "/gnap" && method == "POST" {
        let cont = if behavior.foreign { "https://evil.example/continue".to_string() } else { format!("{}/continue", stub.base) };
        return http(200, &json!({
            "instance_id": "instance-1",
            "interact": {"redirect": format!("{}/interact/1", stub.base), "finish": "server-nonce"},
            "continue": {"uri": cont, "wait": 0, "access_token": {"value": "cont-token"}},
        }).to_string());
    }
    if path == "/continue" && method == "POST" {
        if headers.get("authorization").map(String::as_str) != Some("GNAP cont-token") {
            return http(401, &json!({"error": "invalid_token"}).to_string());
        }
        drop(behavior);
        let mut behavior = stub.behavior.lock().unwrap();
        if behavior.too_fast && !behavior.too_fast_sent {
            behavior.too_fast_sent = true;
            return http(400, &json!({"error": "too_fast", "continue": {"uri": format!("{}/continue", stub.base), "wait": 0, "access_token": {"value": "cont-token"}}}).to_string());
        }
        let aud = behavior.aud.clone();
        let sub = behavior.sub.clone();
        let iss_sub = behavior.iss_sub.clone().unwrap_or(sub.clone());
        let bearer = behavior.bearer;
        drop(behavior);
        let token = id_token(&stub.base, &aud, &sub);
        let mut access = json!({
            "value": "access-1",
            "access": ["ssf.read", "ssf.manage"],
            "expires_in": 3600,
            "manage": {"uri": format!("{}/token/grant-9", stub.base), "access_token": {"value": "manage-1"}},
        });
        if bearer {
            access["flags"] = json!(["bearer"]);
        }
        return http(200, &json!({
            "instance_id": "instance-1",
            "access_token": access,
            "continue": {"uri": format!("{}/continue/grant-9", stub.base), "access_token": {"value": "cont-next"}},
            "subject": {"sub_ids": [{"format": "iss_sub", "iss": stub.base, "sub": iss_sub}], "assertions": [{"format": "id_token", "value": token}]},
        }).to_string());
    }
    if path == "/token/grant-9" && method == "POST" {
        if headers.get("authorization").map(String::as_str) != Some("GNAP manage-1") {
            return http(401, &json!({"error": "invalid_token", "error_description": "manage"}).to_string());
        }
        return http(200, &json!({"access_token": {"value": "access-2", "expires_in": 3600, "manage": {"uri": format!("{}/token/grant-9", stub.base), "access_token": {"value": "manage-2"}}}}).to_string());
    }
    if method == "DELETE" {
        return "HTTP/1.1 204 No Content\r\ncontent-length: 0\r\nconnection: close\r\n\r\n".to_string();
    }
    http(404, &json!({"error": "not_found"}).to_string())
}

fn check(stub: &Stub, method: &str, path: &str, headers: &HashMap<String, String>, body: &str, target: &str) -> Result<(), String> {
    if !body.is_empty() && path == "/gnap" {
        remember(stub, body)?;
    }
    if headers.contains_key("signature") {
        verify_httpsig(stub, headers, method, body, target)?;
    }
    if headers.contains_key("detached-jws") {
        verify_jwsd(stub, headers, method, body, target)?;
    }
    Ok(())
}

fn remember(stub: &Stub, body: &str) -> Result<(), String> {
    let doc: Value = serde_json::from_str(body).map_err(|err| err.to_string())?;
    let jwk = doc.get("client").and_then(|client| client.as_object()).and_then(|client| client.get("key")).and_then(|key| key.get("jwk"));
    let Some(jwk) = jwk else { return Ok(()) };
    let x = b64_decode(jwk.get("x").and_then(|v| v.as_str()).unwrap_or(""))?;
    let y = b64_decode(jwk.get("y").and_then(|v| v.as_str()).unwrap_or(""))?;
    let mut raw = vec![4];
    raw.extend_from_slice(&x);
    raw.extend_from_slice(&y);
    let key = VerifyingKey::from_sec1_bytes(&raw).map_err(|err| err.to_string())?;
    *stub.public.lock().unwrap() = Some(key);
    *stub.kid.lock().unwrap() = jwk.get("kid").and_then(|v| v.as_str()).unwrap_or("").to_string();
    Ok(())
}

fn verify_httpsig(stub: &Stub, headers: &HashMap<String, String>, method: &str, body: &str, target: &str) -> Result<(), String> {
    let input = headers.get("signature-input").cloned().unwrap_or_default();
    if input.contains(";alg=") {
        return Err("alg parameter".into());
    }
    let rest = input.strip_prefix("sig1=").ok_or("signature-input")?;
    let (covered, params) = rest.split_once(')').ok_or("signature-input")?;
    let covered = covered.trim_start_matches('(');
    if !params.contains("tag=\"gnap\"") {
        return Err("tag".into());
    }
    let kid = stub.kid.lock().unwrap().clone();
    if !params.contains(&format!("keyid=\"{kid}\"")) {
        return Err(format!("keyid {kid}"));
    }
    let components = quoted(covered);
    let serialised = format!("({covered}){params}");
    let mut lines = Vec::new();
    for component in &components {
        let value = match component.as_str() {
            "@method" => method.to_ascii_uppercase(),
            "@target-uri" => target.to_string(),
            other => headers.get(other).cloned().unwrap_or_default().trim().to_string(),
        };
        lines.push(format!("\"{component}\": {value}"));
    }
    lines.push(format!("\"@signature-params\": {serialised}"));
    let sig = headers.get("signature").cloned().unwrap_or_default();
    let raw = sig.strip_prefix("sig1=:").and_then(|value| value.strip_suffix(':')).ok_or("signature")?;
    let signature = base64::engine::general_purpose::STANDARD.decode(raw).map_err(|err| err.to_string())?;
    let parsed = p256::ecdsa::Signature::from_slice(&signature).map_err(|err| err.to_string())?;
    let key = stub.public.lock().unwrap().clone().ok_or("no key")?;
    key.verify(lines.join("\n").as_bytes(), &parsed).map_err(|err| format!("httpsig: {err}"))?;
    if !body.is_empty() {
        let digest = format!("sha-256=:{}:", b64std(&sha256(body.as_bytes())));
        if headers.get("content-digest").map(String::as_str) != Some(digest.as_str()) {
            return Err("content-digest".into());
        }
    }
    Ok(())
}

fn verify_jwsd(stub: &Stub, headers: &HashMap<String, String>, method: &str, body: &str, target: &str) -> Result<(), String> {
    let token = headers.get("detached-jws").cloned().unwrap_or_default();
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err("detached".into());
    }
    let header: Value = serde_json::from_slice(&b64_decode(parts[0])?).map_err(|err| err.to_string())?;
    if header.get("typ").and_then(|v| v.as_str()) != Some("gnap-binding-jwsd") || header.get("alg").and_then(|v| v.as_str()) != Some("ES256") {
        return Err("jws header".into());
    }
    let kid = stub.kid.lock().unwrap().clone();
    if header.get("kid").and_then(|v| v.as_str()) != Some(kid.as_str()) || header.get("htm").and_then(|v| v.as_str()) != Some(method.to_ascii_uppercase().as_str()) || header.get("uri").and_then(|v| v.as_str()) != Some(target) {
        return Err("jws binding".into());
    }
    let auth = headers.get("authorization").cloned().unwrap_or_default();
    if !auth.is_empty() {
        let token = auth.trim_start_matches("GNAP ");
        if header.get("ath").and_then(|v| v.as_str()) != Some(b64url(&sha256(token.as_bytes())).as_str()) {
            return Err("ath".into());
        }
    } else if header.get("ath").is_some() {
        return Err("ath present".into());
    }
    let payload = if body.is_empty() { String::new() } else { b64url(&sha256(body.as_bytes())) };
    if parts[1] != payload {
        return Err("jws payload".into());
    }
    let signature = b64_decode(parts[2])?;
    let parsed = p256::ecdsa::Signature::from_slice(&signature).map_err(|err| err.to_string())?;
    let key = stub.public.lock().unwrap().clone().ok_or("no key")?;
    key.verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &parsed).map_err(|err| format!("jwsd: {err}"))?;
    Ok(())
}

fn quoted(value: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut chars = value.chars();
    while let Some(ch) = chars.next() {
        if ch != '"' {
            continue;
        }
        let mut one = String::new();
        for ch in chars.by_ref() {
            if ch == '"' {
                break;
            }
            one.push(ch);
        }
        out.push(one);
    }
    out
}

fn b64_decode(value: &str) -> Result<Vec<u8>, String> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(value).map_err(|err| err.to_string())
}

fn http(status: u16, body: &str) -> String {
    format!("HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len())
}

fn read_http(stream: &mut impl Read) -> Result<(String, String, HashMap<String, String>, String), String> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    loop {
        match stream.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            Err(err) => return Err(err.to_string()),
        }
        if let Some(split) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let header = String::from_utf8_lossy(&buf[..split]).to_string();
            let need = header.lines().find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length").then(|| value.trim().parse::<usize>().ok())?
            }).unwrap_or(0);
            if buf.len() >= split + 4 + need {
                break;
            }
        }
        if buf.len() > 2 * 1024 * 1024 {
            break;
        }
    }
    let split = buf.windows(4).position(|w| w == b"\r\n\r\n").ok_or("short")?;
    let header = String::from_utf8_lossy(&buf[..split]).to_string();
    let body = String::from_utf8_lossy(&buf[split + 4..split + 4 + header.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("content-length").then(|| value.trim().parse::<usize>().ok())?
    }).unwrap_or(0)]).to_string();
    let mut lines = header.split("\r\n");
    let mut parts = lines.next().unwrap_or("").split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("").split('?').next().unwrap_or("").to_string();
    let mut headers = HashMap::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }
    Ok((method, path, headers, body))
}

#[derive(Debug)]
struct AllowAny;

impl ClientCertVerifier for AllowAny {
    fn offer_client_auth(&self) -> bool {
        true
    }
    fn client_auth_mandatory(&self) -> bool {
        false
    }
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }
    fn verify_client_cert(&self, _end: &CertificateDer<'_>, _intermediates: &[CertificateDer<'_>], _now: rustls::pki_types::UnixTime) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        Ok(rustls::server::danger::ClientCertVerified::assertion())
    }
    fn verify_tls12_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &crate::provider().signature_verification_algorithms)
    }
    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &crate::provider().signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        crate::provider().signature_verification_algorithms.supported_schemes()
    }
}

fn client(stub: &Stub, proof: &str) -> Client {
    let body = json!({
        "grantEndpoint": format!("{}/gnap", stub.base),
        "idTokenIssuer": stub.base,
        "application": "gnap-caep-risc-demo",
        "display": {"name": "GNAP CAEP RISC demo", "uri": "http://127.0.0.1:3000/"},
        "access": ["ssf.read", "ssf.manage"],
        "subIdFormats": ["iss_sub", "account", "opaque"],
        "assertionFormats": ["id_token"],
        "keyProof": proof,
        "privateKey": stub.client_key,
        "certificate": stub.client_cert,
        "finishUri": "http://127.0.0.1:3000/callback",
        "finishMethod": "redirect",
        "tlsCa": stub.server_cert,
    });
    Client::new(Client::resolve(&body, std::path::Path::new(".")).unwrap())
}

fn started(gnap: &Client, stub: &Stub) -> (crate::GrantResult, Value) {
    let result = gnap.request_grant().unwrap();
    assert!(result.pending.is_some());
    let body = stub.seen.lock().unwrap().iter().rev().find(|call| call.method == "POST" && call.url == "/gnap").unwrap().body.clone();
    (result, serde_json::from_str(&body).unwrap())
}

fn finish_hash(client_nonce: &str, interact_ref: &str, grant_endpoint: &str) -> String {
    interaction_hash(client_nonce, "server-nonce", interact_ref, grant_endpoint)
}

#[test]
fn interaction_hash_vector() {
    assert_eq!(interaction_hash("abc", "def", "xyz", "https://as.example/gnap"), "2o3b9NeEcvp0At5d-71yCgybP45eTGm1_pTNMmjv_V0");
}

#[test]
fn refuses_front_channel_foreign_and_a_hash_that_is_not_ours() {
    let stub = start_server();
    let gnap = client(&stub, "httpsig");
    stub.behavior.lock().unwrap().foreign = true;
    let err = gnap.request_grant().must_err();
    assert!(err.to_string().contains("not on the grant endpoint"), "{err}");
    assert!(stub.seen.lock().unwrap().iter().all(|call| call.url != "/continue"));
    stub.behavior.lock().unwrap().foreign = false;
    stub.seen.lock().unwrap().clear();
    let presenting = client(&stub, "httpsig");
    let (result, request) = started(&presenting, &stub);
    assert_eq!(request["client"]["key"]["proof"], "httpsig");
    assert!(request["client"].get("class_id").is_none());
    assert_eq!(request["subject"]["sub_id_formats"], json!(["iss_sub", "opaque"]));
    assert!(!stub.seen.lock().unwrap().last().unwrap().signature.is_empty());
    let nonce = request["interact"]["finish"]["nonce"].as_str().unwrap();
    let digest = finish_hash(nonce, "ref-1", &format!("{}/gnap", stub.base));
    let err = presenting.finish_redirect(format!("hash={digest}&interact_ref=ref-1&access_token=no"), &[result.pending.as_ref().unwrap().id.as_str()]).must_err();
    assert!(err.to_string().contains("tokens through the browser"));
    assert!(!err.to_string().contains("front"));
    let err = presenting.finish_redirect(format!("hash={digest}&interact_ref=ref-1"), &["somebody-else"]).must_err();
    assert!(err.to_string().contains("this browser"));
    assert!(stub.seen.lock().unwrap().iter().all(|call| call.url != "/continue"));
    let err = presenting.finish_redirect(format!("hash=nope&interact_ref=ref-1"), &[result.pending.as_ref().unwrap().id.as_str()]).must_err();
    assert!(err.to_string().contains("this browser"));
}

#[test]
fn finishes_a_redirect_checks_the_id_token_and_rotates() {
    let stub = start_server();
    stub.behavior.lock().unwrap().too_fast = true;
    let gnap = client(&stub, "httpsig");
    let (result, request) = started(&gnap, &stub);
    let nonce = request["interact"]["finish"]["nonce"].as_str().unwrap();
    let digest = finish_hash(nonce, "ref-1", &format!("{}/gnap", stub.base));
    let mut query = HashMap::new();
    query.insert("hash".into(), digest.clone());
    query.insert("interact_ref".into(), "ref-1".into());
    let done = gnap.finish_redirect(query, &[result.pending.as_ref().unwrap().id.as_str()]).unwrap();
    assert_eq!(done.grant.access_token, "access-1");
    assert!(!done.grant.bearer);
    let subject = done.grant.subject.as_ref().unwrap();
    assert_eq!(subject.sub, "user-1");
    assert_eq!(subject.email.as_deref(), Some("user-1@example.com"));
    assert_eq!(subject.sid.as_deref(), Some("sess-1"));
    assert!(subject.assertion_verified);
    assert_eq!(done.grant.grant_id.as_deref(), Some("grant-9"));
    assert!(stub.behavior.lock().unwrap().too_fast_sent);
    let again = gnap.request_grant().unwrap();
    assert!(again.pending.is_some());
    let second: Value = serde_json::from_str(&stub.seen.lock().unwrap().iter().rev().find(|call| call.method == "POST" && call.url == "/gnap").unwrap().body).unwrap();
    assert_eq!(second["client"], "instance-1");
    let rotated = gnap.rotate(&done.grant).unwrap();
    assert_eq!(rotated.access_token, "access-2");
    assert_eq!(rotated.subject.as_ref().unwrap().sub, "user-1");
    assert_eq!(rotated.continuation.as_ref().unwrap().uri, done.grant.continuation.as_ref().unwrap().uri);
    gnap.revoke(&rotated).unwrap();
    assert_eq!(stub.seen.lock().unwrap().last().unwrap().method, "DELETE");
    let err = gnap.finish_redirect(format!("hash={digest}&interact_ref=ref-1"), &[result.pending.as_ref().unwrap().id.as_str()]).must_err();
    assert!(err.to_string().contains("already used"));
}

#[test]
fn proves_the_key_with_detached_jws_and_mutual_tls() {
    let stub = start_server();
    let jwsd = client(&stub, "jwsd");
    let (first_result, first) = started(&jwsd, &stub);
    assert_eq!(first["client"]["key"]["proof"], "jwsd");
    let digest = finish_hash(first["interact"]["finish"]["nonce"].as_str().unwrap(), "ref-j", &format!("{}/gnap", stub.base));
    let done = jwsd.finish_redirect(format!("?hash={digest}&interact_ref=ref-j"), &[first_result.pending.as_ref().unwrap().id.as_str()]).unwrap();
    assert_eq!(done.grant.subject.as_ref().unwrap().name.as_deref(), Some("Ada"));
    assert!(stub.seen.lock().unwrap().iter().any(|call| call.url == "/continue" && call.detached.contains('.')));
    assert!(stub.seen.lock().unwrap().iter().find(|call| call.url == "/continue").unwrap().signature.is_empty());

    stub.seen.lock().unwrap().clear();
    let mtls = client(&stub, "mtls");
    let (second_result, second) = started(&mtls, &stub);
    assert_eq!(second["client"]["key"]["proof"], "mtls");
    let gnap_call = stub.seen.lock().unwrap().iter().find(|call| call.url == "/gnap" && call.method == "POST").unwrap().cert.clone();
    assert_eq!(gnap_call, stub.client_fingerprint);
    {
        let seen = stub.seen.lock().unwrap();
        let post = seen.iter().find(|call| call.url == "/gnap" && call.method == "POST").unwrap();
        assert!(post.signature.is_empty());
        assert!(post.detached.is_empty());
    }
    let digest2 = finish_hash(second["interact"]["finish"]["nonce"].as_str().unwrap(), "ref-m", &format!("{}/gnap", stub.base));
    let finished = mtls.finish_push(&json!({"hash": digest2, "interact_ref": "ref-m"})).unwrap();
    assert_eq!(finished.grant.access_token, "access-1");
    let answer = mtls.call(&finished.grant, &format!("{}/jwks", stub.base), "GET", None, None).unwrap();
    assert_eq!(answer.status, 200);
    assert_eq!(stub.seen.lock().unwrap().last().unwrap().authorization, "GNAP access-1");
    assert!(!second_result.pending.as_ref().unwrap().id.is_empty());
}

#[test]
fn refuses_bearer_bad_audience_and_a_subject_that_does_not_match() {
    let stub = start_server();
    stub.behavior.lock().unwrap().bearer = true;
    let gnap = client(&stub, "httpsig");
    let (result, request) = started(&gnap, &stub);
    let digest = finish_hash(request["interact"]["finish"]["nonce"].as_str().unwrap(), "ref-b", &format!("{}/gnap", stub.base));
    let mut query = HashMap::new();
    query.insert("hash".into(), digest);
    query.insert("interact_ref".into(), "ref-b".into());
    let err = gnap.finish_redirect(&query, &[result.pending.as_ref().unwrap().id.as_str()]).must_err();
    assert!(err.to_string().contains("bearer"));
    assert_eq!(err.code, "validation");
    stub.behavior.lock().unwrap().bearer = false;
    stub.behavior.lock().unwrap().aud = "someone-else".into();
    let audience = client(&stub, "httpsig");
    let (next_result, next_request) = started(&audience, &stub);
    let digest2 = finish_hash(next_request["interact"]["finish"]["nonce"].as_str().unwrap(), "ref-a", &format!("{}/gnap", stub.base));
    let err = audience.finish_redirect(format!("hash={digest2}&interact_ref=ref-a"), &[next_result.pending.as_ref().unwrap().id.as_str()]).must_err();
    assert!(err.to_string().contains("id_token is for"));
    stub.behavior.lock().unwrap().aud = "gnap-caep-risc-demo".into();
    stub.behavior.lock().unwrap().iss_sub = Some("other-user".into());
    stub.behavior.lock().unwrap().sub = "user-1".into();
    let (third_result, third) = started(&gnap, &stub);
    let digest3 = finish_hash(third["interact"]["finish"]["nonce"].as_str().unwrap(), "ref-s", &format!("{}/gnap", stub.base));
    let err = gnap.finish_redirect(format!("hash={digest3}&interact_ref=ref-s"), &[third_result.pending.as_ref().unwrap().id.as_str()]).must_err();
    assert!(err.to_string().contains("somebody other"));
}

#[test]
fn accepts_the_application_identifier_as_the_id_token_audience() {
    let stub = start_server();
    {
        let mut behavior = stub.behavior.lock().unwrap();
        behavior.aud = "gnap-caep-risc-demo".into();
        behavior.sub = "user-2".into();
    }
    let gnap = client(&stub, "httpsig");
    let (result, request) = started(&gnap, &stub);
    let digest = finish_hash(request["interact"]["finish"]["nonce"].as_str().unwrap(), "ref-app", &format!("{}/gnap", stub.base));
    let mut query = HashMap::new();
    query.insert("hash".into(), digest);
    query.insert("interact_ref".into(), "ref-app".into());
    let done = gnap.finish_redirect(query, &[result.pending.as_ref().unwrap().id.as_str()]).unwrap();
    assert_eq!(done.grant.subject.as_ref().unwrap().sub, "user-2");
    let mut grant = done.grant;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f64() * 1000.0;
    grant.expires_at = Some(now + 10_000.0);
    let fresh = gnap.ensure_fresh(&grant).unwrap();
    assert_eq!(fresh.access_token, "access-2");
    let mut held_grant = fresh;
    held_grant.expires_at = Some(now + 3_600_000.0);
    let held = gnap.ensure_fresh(&held_grant).unwrap();
    assert_eq!(held.access_token, "access-2");
}

#[test]
fn certificate_chain_puts_the_leaf_in_the_key_and_the_chain_on_tls() {
    let leaf = material("leaf.example", &["leaf.example"], &[]);
    let issuer = material("issuer.example", &["issuer.example"], &[]);
    let chain = format!("{}\n{}\n", leaf.cert_pem.trim(), issuer.cert_pem.trim());
    let key = load_client_key(&leaf.key_pem, &chain, "mtls").unwrap();
    let published = public_key_object(&key).unwrap();
    let cert = published.get("cert").and_then(|v| v.as_str()).unwrap();
    assert_eq!(cert.matches("BEGIN CERTIFICATE").count(), 1);
    assert_eq!(fingerprint(&pem_der(cert)), fingerprint(&leaf.cert_der));
    let gnap = Client::new(Client::resolve(&json!({
        "grantEndpoint": "https://as.example/gnap",
        "application": "chain-demo",
        "keyProof": "mtls",
        "privateKey": leaf.key_pem,
        "certificate": chain,
        "finishUri": "http://127.0.0.1:9/callback",
    }), std::path::Path::new(".")).unwrap());
    assert_eq!(gnap.tls().cert.matches("BEGIN CERTIFICATE").count(), 2);
}

fn pem_der(pem: &str) -> Vec<u8> {
    let start = pem.find("-----BEGIN CERTIFICATE-----").unwrap();
    let body = &pem[start + "-----BEGIN CERTIFICATE-----".len()..];
    let end = body.find("-----END CERTIFICATE-----").unwrap();
    let b64: String = body[..end].chars().filter(|c| !c.is_whitespace()).collect();
    base64::engine::general_purpose::STANDARD.decode(b64).unwrap()
}

impl Clone for Seen {
    fn clone(&self) -> Self {
        Self { method: self.method.clone(), url: self.url.clone(), body: self.body.clone(), authorization: self.authorization.clone(), signature: self.signature.clone(), detached: self.detached.clone(), cert: self.cert.clone() }
    }
}

