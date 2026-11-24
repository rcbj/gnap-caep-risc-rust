// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

//! The embedded PEP wired into the GNAP client (#39): the `pep` section and
//! its defaults, the key refusal, the `Person` adapter, `decide` and
//! `decide_grant` against a stub PDP, and the `pep-policies-changed` event
//! handed over by `SignalsReceiver`. The PEP's own behaviour (the
//! credential, both modes, the engine) is iya-pep's suite.

use super::ssf::{deliver, other_key, read_http, rsa_key, start_transmitter};
use super::MustErr;
use crate::pep::{default_pdp_url, subject_for, Access, Decision, POLICIES_CHANGED_EVENT};
use crate::{resolve, Client, Grant, Person, ReceiverOpt, SignalsReceiver};
use p256::pkcs8::EncodePrivateKey;
use serde_json::{json, Map, Value};
use std::io::Write;
use std::net::TcpListener;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// A stub iya-sts realm at `/realm/r1`: the PEP's token endpoint, register,
/// heartbeat, the catalogue, the policies and the AuthZEN evaluation, and the
/// GNAP grant's continuation URI (for `revoke`). `decisions` are answered in
/// order, then Permit.
struct Pdp {
    base: String,
    seen: Mutex<Vec<(String, String, String)>>,
    decisions: Mutex<Vec<bool>>,
    /// `local`: whether the policy pull answers.
    policies_up: AtomicBool,
}

impl Pdp {
    fn realm(&self) -> String {
        format!("{}/realm/r1", self.base)
    }

    fn count(&self, path: &str) -> usize {
        self.seen.lock().unwrap().iter().filter(|(_, p, _)| p == path).count()
    }

    fn bodies(&self, path: &str) -> Vec<Value> {
        self.seen.lock().unwrap().iter().filter(|(_, p, _)| p == path).map(|(_, _, b)| serde_json::from_str(b).unwrap_or(Value::Null)).collect()
    }
}

fn start_pdp() -> &'static Pdp {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let pdp: &'static Pdp = Box::leak(Box::new(Pdp {
        base: format!("http://127.0.0.1:{port}"),
        seen: Mutex::new(Vec::new()),
        decisions: Mutex::new(Vec::new()),
        policies_up: AtomicBool::new(true),
    }));
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut tcp) = stream else { continue };
            tcp.set_read_timeout(Some(Duration::from_secs(5))).ok();
            thread::spawn(move || {
                let Ok((method, path, headers, body)) = read_http(&mut tcp) else { return };
                let (status, body) = answer(pdp, &method, &path, &headers, &body);
                let text = if status == 204 { String::new() } else { body.to_string() };
                let _ = tcp.write_all(format!("HTTP/1.1 {status} OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{text}", text.len()).as_bytes());
            });
        }
    });
    pdp
}

fn answer(pdp: &Pdp, method: &str, path: &str, headers: &std::collections::HashMap<String, String>, body: &str) -> (u16, Value) {
    let path = path.trim_start_matches("/realm/r1").to_string();
    pdp.seen.lock().unwrap().push((method.to_string(), path.clone(), body.to_string()));
    if path.starts_with("/gnap/continue/") && method == "DELETE" {
        return (204, Value::Null);
    }
    if path != "/oauth2/token" && !headers.get("authorization").is_some_and(|a| a.starts_with("DPoP ")) {
        return (401, json!({"error": "invalid_token"}));
    }
    match path.as_str() {
        "/oauth2/token" => (200, json!({"access_token": "pep-token", "token_type": "DPoP", "expires_in": 300})),
        "/xacml/pep/register" => (201, json!({"registered": true})),
        "/xacml/pep/heartbeat" => (200, json!({"acknowledged": true, "current": true})),
        "/xacml/pep/authzen-catalogue" => (
            200,
            json!({"syncToken": "c1", "realm": "r1", "rows": [
                {"object": "subject", "property": "acr", "attributeId": "urn:example:acr"},
                {"object": "subject", "property": "email", "attributeId": "urn:example:email"}
            ], "settings": {"obligationsProfile": false}}),
        ),
        "/xacml/pep/policies" if pdp.policies_up.load(Ordering::SeqCst) => (
            200,
            json!({"syncToken": "p1", "root": "orders", "policies": [{
                "name": "orders", "policyId": "orders", "kind": "Policy", "version": "1.0", "isRoot": true, "description": "",
                "combiningAlgId": "urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:deny-unless-permit", "document": READ_ONLY}], "withheld": [], "note": ""}),
        ),
        "/xacml/pep/policies" => (503, json!({"error": "server_error", "error_description": "not now"})),
        "/admin-api/pep-audit" => (200, json!({"acknowledged": 0})),
        "/access/v1/evaluation" => {
            let mut queue = pdp.decisions.lock().unwrap();
            let decision = if queue.is_empty() { true } else { queue.remove(0) };
            (200, json!({"decision": decision}))
        }
        _ => (404, json!({"error": "not_found"})),
    }
}

/// Permits `read`, and nothing else.
const READ_ONLY: &str = r#"<Policy xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17" PolicyId="orders" Version="1.0" RuleCombiningAlgId="urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:deny-unless-permit"><Target/><Rule RuleId="read" Effect="Permit"><Target><AnyOf><AllOf><Match MatchId="urn:oasis:names:tc:xacml:1.0:function:string-equal"><AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">read</AttributeValue><AttributeDesignator Category="urn:oasis:names:tc:xacml:3.0:attribute-category:action" AttributeId="urn:oasis:names:tc:xacml:1.0:action:action-id" DataType="http://www.w3.org/2001/XMLSchema#string" MustBePresent="false"/></Match></AllOf></AnyOf></Target></Rule></Policy>"#;

static FILES: AtomicUsize = AtomicUsize::new(0);

/// Writes a key into a fresh directory and returns (directory, file name).
fn key_file(pem: &str) -> (std::path::PathBuf, String) {
    let n = FILES.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("gnap-pep-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("pep-key.pem"), pem).unwrap();
    (dir, "pep-key.pem".to_string())
}

fn ec_pem() -> String {
    let key = <p256::ecdsa::SigningKey as p256::elliptic_curve::Generate>::generate();
    key.to_pkcs8_pem(p256::pkcs8::LineEnding::LF).unwrap().to_string()
}

fn rsa_pem() -> String {
    use rsa::pkcs8::EncodePrivateKey as _;
    rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap().to_pkcs8_pem(rsa::pkcs8::LineEnding::LF).unwrap().to_string()
}

/// A client configuration on the stub's realm, with a `pep` section whose
/// key is a fresh one (relative to the configuration's directory) unless
/// `pep_key` names one. `extra` is laid over the top level, `pep` over the
/// section.
fn config(pdp: &Pdp, extra: Value, pep: Value, pep_key: Option<&str>) -> Result<crate::Config, crate::Error> {
    let (dir, file) = key_file(pep_key.unwrap_or(&ec_pem()));
    let mut section = json!({"name": "pep-demo", "assertionKey": file, "heartbeatIntervalMs": 60000});
    for (k, v) in pep.as_object().unwrap() {
        section[k] = v.clone();
    }
    let mut doc = json!({
        "grantEndpoint": format!("{}/gnap", pdp.realm()),
        "application": "gnap-caep-risc-demo",
        "privateKey": ec_pem(),
        "keyProof": "httpsig",
        "allowInsecure": true,
        "pep": section,
    });
    for (k, v) in extra.as_object().unwrap() {
        doc[k] = v.clone();
    }
    resolve(&doc, &dir)
}

fn client(pdp: &Pdp, extra: Value, pep: Value) -> Client {
    Client::create(config(pdp, extra, pep, None).unwrap()).unwrap()
}

fn person() -> Person {
    let mut claims = Map::new();
    claims.insert("iss".into(), json!("https://sts.example/realm/r1"));
    claims.insert("sub".into(), json!("0b6e-pairwise"));
    claims.insert("preferred_username".into(), json!("alice.token"));
    claims.insert("acr".into(), json!("urn:example:mfa"));
    claims.insert("amr".into(), json!(["pwd", "otp"]));
    claims.insert("auth_time".into(), json!(1_700_000_000));
    Person {
        sub: "0b6e-pairwise".into(),
        claims,
        assertion_verified: true,
        iss: Some("https://sts.example/realm/r1".into()),
        uid: Some("alice".into()),
        email: None,
        name: None,
        preferred_username: Some("alice.token".into()),
        sid: None,
        acr: Some("urn:example:mfa".into()),
        amr: vec!["pwd".into(), "otp".into()],
    }
}

fn grant(pdp: &Pdp, id: &str) -> Grant {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f64() * 1000.0;
    Grant {
        access_token: "at".into(),
        bearer: false,
        access: Value::Null,
        expires_in: Some(600.0),
        expires_at: Some(now + 600_000.0),
        manage: None,
        continuation: Some(crate::Continuation { uri: format!("{}/gnap/continue/{id}", pdp.realm()), access_token: "ct".into(), wait: None }),
        instance_id: None,
        subject: Some(person()),
        grant_id: Some(id.into()),
    }
}

#[test]
fn the_pdp_url_is_the_grant_endpoints_realm() {
    assert_eq!(default_pdp_url("https://sts.example/realm/acme/gnap"), "https://sts.example/realm/acme");
    assert_eq!(default_pdp_url("https://sts.example/realm/acme/orders-as/gnap"), "https://sts.example/realm/acme", "a named authorization server");
    assert_eq!(default_pdp_url("https://sts.example:8443/gnap"), "https://sts.example:8443", "the default realm");
    assert_eq!(default_pdp_url("https://sts.example/orders-as/gnap"), "https://sts.example");
}

#[test]
fn a_pep_section_builds_a_started_pep_with_the_librarys_defaults() {
    let pdp = start_pdp();
    let resolved = config(pdp, json!({}), json!({}), None).unwrap();
    let pep = resolved.pep.clone().expect("a PEP");
    assert_eq!(pep.config().pdp_url, pdp.realm(), "pdpUrl defaults to the grant endpoint's realm");
    assert_eq!(pep.config().application, "gnap-caep-risc-demo", "application defaults to the registered GNAP client");
    assert!(!pep.config().signals, "no transmitter, so no signal stream");
    assert!(Path::new(&pep.config().assertion_key).is_absolute(), "assertionKey is read relative to the configuration");
    assert!(!pep.status().running, "resolving sends nothing");
    assert_eq!(pdp.count("/xacml/pep/register"), 0);

    let client = Client::create(resolved).unwrap();
    assert!(client.pep().unwrap().status().running);
    let register = pdp.bodies("/xacml/pep/register");
    assert!(!register.is_empty(), "registered at create");
    assert_eq!(register[0]["kind"], "embedded");
    assert_eq!(register[0]["application"], "gnap-caep-risc-demo");

    let ca = rcgen::generate_simple_self_signed(vec!["sts.example".to_string()]).unwrap().cert.pem();
    let with = config(pdp, json!({"ssf": {"transmitter": "https://sts.example"}, "tlsCa": ca}), json!({}), None).unwrap();
    assert!(with.pep.as_ref().unwrap().config().signals, "signals follow the library's receiver");
    assert_eq!(with.pep.as_ref().unwrap().config().tls_ca, ca, "tlsCa follows the library's");
    let off = config(pdp, json!({"ssf": {"transmitter": "https://sts.example"}, "signals": false, "access": ["orders"]}), json!({}), None).unwrap();
    assert!(!off.pep.unwrap().config().signals);
    let own = config(pdp, json!({}), json!({"pdpUrl": "https://other.example/realm/x", "application": "orders", "signals": true}), None).unwrap();
    let own = own.pep.unwrap();
    assert_eq!((own.config().pdp_url.as_str(), own.config().application.as_str(), own.config().signals), ("https://other.example/realm/x", "orders", true));

    let mut doc = json!({"grantEndpoint": "https://sts.example/gnap", "application": "a", "privateKey": ec_pem(), "keyProof": "httpsig"});
    assert!(resolve(&doc, Path::new(".")).unwrap().pep.is_none(), "no section, no PEP");
    doc["pep"] = Value::Null;
    assert!(resolve(&doc, Path::new(".")).unwrap().pep.is_none(), "a null section is none");
}

/// `Client::from_file` reads the `pep` section as `resolve` does, and the
/// PEP it builds is started: the live run of oidc-caep-risc (its #46) found
/// that library's file reader dropped the section, so this one is held to it
/// too.
#[test]
fn from_file_keeps_the_pep_section() {
    let pdp = start_pdp();
    let (dir, file) = key_file(&ec_pem());
    let doc = json!({
        "grantEndpoint": format!("{}/gnap", pdp.realm()),
        "application": "gnap-caep-risc-demo",
        "privateKey": ec_pem(),
        "keyProof": "httpsig",
        "allowInsecure": true,
        "pep": {"name": "pep-demo", "assertionKey": file, "heartbeatIntervalMs": 60000},
    });
    let path = dir.join("gnap.json");
    std::fs::write(&path, doc.to_string()).unwrap();
    let client = Client::from_file(&path).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    let pep = client.pep().expect("the configuration file's pep section built a PEP");
    assert_eq!(pep.config().name, "pep-demo");
    assert!(Path::new(&pep.config().assertion_key).is_absolute(), "relative to the file's directory: {}", pep.config().assertion_key);
    assert!(pep.status().running);
    assert!(pdp.count("/xacml/pep/register") >= 1, "and started it");
}

#[test]
fn a_bad_section_is_refused() {
    let pdp = start_pdp();
    for (pep, says) in [
        (json!({"mode": "remote"}), "pep.mode"),
        (json!({"polIntervalMs": 1}), "polIntervalMs"),
        (json!({"name": "has space"}), "pep.name"),
        (json!({"permitCacheMs": 120000}), "permitCacheMs"),
        (json!({"assertionKey": "nowhere.pem"}), "nowhere.pem"),
    ] {
        let err = config(pdp, json!({}), pep, None).must_err();
        assert_eq!(err.code, "config");
        assert!(err.message.contains(says), "{} / {says}", err.message);
    }
    let err = config(pdp, json!({"pep": "on"}), json!({}), None).must_err();
    assert_eq!(err.message, "pep must be an object");
}

#[test]
fn the_pep_key_must_differ_from_the_client_instance_key() {
    let pdp = start_pdp();
    // An EC key behind httpsig proofs.
    let ec = ec_pem();
    let err = config(pdp, json!({"privateKey": ec}), json!({}), Some(&ec)).must_err();
    assert!(err.message.contains("client instance key"), "{}", err.message);
    // An RSA key behind jwsd proofs.
    let rsa = rsa_pem();
    let err = config(pdp, json!({"privateKey": rsa, "keyProof": "jwsd"}), json!({}), Some(&rsa)).must_err();
    assert!(err.message.contains("client instance key"), "{}", err.message);
    // The mTLS key, the certificate's.
    let ec = ec_pem();
    let pair = rcgen::KeyPair::from_pem(&ec).unwrap();
    let cert = rcgen::CertificateParams::new(vec!["client.example".to_string()]).unwrap().self_signed(&pair).unwrap().pem();
    let err = config(pdp, json!({"privateKey": ec, "certificate": cert, "keyProof": "mtls", "grantEndpoint": "https://sts.example/realm/r1/gnap"}), json!({}), Some(&ec)).must_err();
    assert!(err.message.contains("client instance key"), "{}", err.message);

    // Two different keys are fine.
    let resolved = config(pdp, json!({"privateKey": rsa_pem(), "keyProof": "jwsd"}), json!({}), None).unwrap();
    let client_thumb = iya_pep::jwk_thumbprint(&Value::Object(resolved.key.jwk.clone())).unwrap();
    assert_ne!(resolved.pep.unwrap().key_thumbprint(), client_thumb);
}

#[test]
fn a_grants_person_becomes_the_peps_subject() {
    let s = subject_for(&person());
    assert_eq!((s.kind.as_str(), s.id.as_str()), ("user", "alice"), "the account identifier's username, which the PIP resolves");
    assert_eq!(s.properties["acr"], "urn:example:mfa");
    assert_eq!(s.properties["amr"], json!(["pwd", "otp"]));
    assert_eq!(s.properties["auth_time"], 1_700_000_000);

    let mut no_account = person();
    no_account.uid = None;
    assert_eq!(subject_for(&no_account).id, "alice.token", "then the ID token's preferred_username");
    let mut bare = person();
    bare.uid = None;
    bare.preferred_username = None;
    bare.claims = Map::new();
    assert_eq!(subject_for(&bare).id, "0b6e-pairwise", "then sub");
    // No assertion: acr and amr still come from the person.
    let s = subject_for(&bare);
    assert_eq!(s.properties["acr"], "urn:example:mfa");
    assert_eq!(s.properties["amr"], json!(["pwd", "otp"]));
}

#[test]
fn decide_asks_the_service_with_the_declared_claims_only() {
    let pdp = start_pdp();
    let client = client(pdp, json!({}), json!({}));
    pdp.decisions.lock().unwrap().extend([true, false]);
    assert!(client.decide(&person(), &Access::new("read", "order", "42")).is_permit());
    assert!(matches!(client.decide(&person(), &Access::new("delete", "order", "42")), Decision::Deny { .. }));
    let bodies = pdp.bodies("/access/v1/evaluation");
    assert_eq!(bodies.len(), 2);
    assert_eq!(bodies[0]["subject"], json!({"type": "user", "id": "alice", "properties": {"acr": "urn:example:mfa"}}), "only the catalogue's claims");
    assert_eq!(bodies[0]["action"]["name"], "read");
    assert_eq!(bodies[0]["resource"], json!({"type": "order", "id": "42"}));
    assert_eq!(bodies[0]["context"]["application"], "gnap-caep-risc-demo");

    let none = Client::create(resolve(&json!({"grantEndpoint": "https://sts.example/gnap", "application": "a", "privateKey": ec_pem(), "keyProof": "httpsig"}), Path::new(".")).unwrap()).unwrap();
    assert!(matches!(none.decide(&person(), &Access::new("read", "order", "42")), Decision::Unavailable { .. }), "no section never permits");
}

#[test]
fn an_ended_grant_is_denied_without_asking() {
    let pdp = start_pdp();
    let client = client(pdp, json!({}), json!({}));
    let access = Access::new("read", "order", "42");
    assert!(client.decide_grant(&grant(pdp, "g1"), &access).is_permit());
    assert_eq!(pdp.count("/access/v1/evaluation"), 1);

    let mut nobody = grant(pdp, "g2");
    nobody.subject = None;
    assert!(matches!(client.decide_grant(&nobody, &access), Decision::Deny { .. }));
    let mut expired = grant(pdp, "g3");
    expired.expires_at = Some(1.0);
    assert!(matches!(client.decide_grant(&expired, &access), Decision::Deny { .. }));
    let live = grant(pdp, "g4");
    client.revoke(&live).unwrap();
    assert_eq!(pdp.count("/gnap/continue/g4"), 1, "revoked at the AS");
    match client.decide_grant(&live, &access) {
        Decision::Deny { why } => assert!(why.contains("revoked"), "{why}"),
        other => panic!("{other:?}"),
    }
    assert_eq!(pdp.count("/access/v1/evaluation"), 1, "nothing asked for an ended grant");
}

#[test]
fn the_receiver_asks_for_the_policy_event_and_hands_it_to_the_pep() {
    let pdp = start_pdp();
    let (_server, tx, transmitter) = start_transmitter();
    // central with a Permit cache: the event clears it.
    let client = client(pdp, json!({"ssf": {"transmitter": transmitter}}), json!({"permitCacheMs": 30000}));
    let receiver_for = |pep: Option<Arc<crate::pep::Pep>>| {
        let mut opt = ReceiverOpt::new(transmitter.clone(), Arc::new(|_, _| {}));
        opt.poll_interval_ms = 60_000;
        opt.headers = Some(Arc::new(|_, _, _| vec![("authorization".into(), "GNAP app-token".into())]));
        opt.pep = pep;
        SignalsReceiver::new(opt).unwrap()
    };
    assert!(!receiver_for(None).events_requested().iter().any(|e| e == POLICIES_CHANGED_EVENT), "no PEP, no event asked for");
    let plain = Client::create(config(pdp, json!({}), json!({}), None).unwrap()).unwrap();
    assert!(!receiver_for(plain.pep().cloned()).events_requested().iter().any(|e| e == POLICIES_CHANGED_EVENT), "central without a cache wants no events");
    let receiver = receiver_for(client.pep().cloned());
    assert!(receiver.events_requested().iter().any(|e| e == POLICIES_CHANGED_EVENT), "asked for on the client's own stream");

    let access = Access::new("read", "order", "42");
    assert!(client.decide(&person(), &access).is_permit());
    assert!(client.decide(&person(), &access).is_permit());
    assert_eq!(pdp.count("/access/v1/evaluation"), 1, "the second came from the Permit cache");

    receiver.start().unwrap();
    receiver.stop();
    let created = tx.lock().unwrap().streams[0]["events_requested"].clone();
    assert!(created.as_array().unwrap().iter().any(|e| e == POLICIES_CHANGED_EVENT), "the stream was created asking for it");
    let sub = json!({"format": "opaque", "id": "gnap-caep-risc-demo"});
    // A SET signed by another key is refused and never reaches the PEP.
    deliver(&tx, POLICIES_CHANGED_EVENT, sub.clone(), json!({"pep": "pep-demo", "changed": ["policies"]}), other_key(), None, None);
    receiver.poll_once().unwrap();
    assert!(client.decide(&person(), &access).is_permit());
    assert_eq!(pdp.count("/access/v1/evaluation"), 1, "an unverified event changes nothing");

    // A verified one is handed to the PEP, which clears its cache.
    deliver(&tx, POLICIES_CHANGED_EVENT, sub, json!({"pep": "pep-demo", "changed": ["policies"], "sync_token": "p2"}), rsa_key(), None, None);
    receiver.poll_once().unwrap();
    assert!(client.decide(&person(), &access).is_permit());
    assert_eq!(pdp.count("/access/v1/evaluation"), 2, "the event cleared the cache");
}

/// Waits up to 10 s for a heartbeat whose `policyEvents` is `want` (one
/// built before the receiver started can still be on its way).
fn assert_policy_events(pdp: &Pdp, want: &str) {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let last = pdp.bodies("/xacml/pep/heartbeat").last().map(|beat| beat["policyEvents"].clone());
        if last.as_ref().is_some_and(|value| value == want) {
            return;
        }
        assert!(std::time::Instant::now() < deadline, "no heartbeat said {want}; the last said {last:?}");
        thread::sleep(Duration::from_millis(100));
    }
}

/// oidc-caep-risc's live run (#46): a stream made while the PEP was
/// `central` (no event asked for) was found and reused by the `local` PEP's
/// receiver, so iya-sts never sent it `pep-policies-changed`. A reused stream
/// now gets the missing type PATCHed in, and the PEP's heartbeat says
/// `requested`, or `excluded` when the transmitter won't.
#[test]
fn a_reused_stream_gets_the_policy_event_added() {
    let pdp = start_pdp();
    let caep = "https://schemas.openid.net/secevent/caep/event-type/session-revoked";
    let old = |base: &str, id: &str| json!({
        "stream_id": id, "iss": base, "aud": "my-app",
        "delivery": {"method": "urn:ietf:rfc:8936", "endpoint_url": format!("{base}/ssf/poll/{id}")},
        "events_requested": [caep], "events_delivered": [caep]
    });
    let errors = Arc::new(Mutex::new(Vec::<String>::new()));
    let receiver_for = |transmitter: &str, pep: Option<Arc<crate::pep::Pep>>| {
        let mut opt = ReceiverOpt::new(transmitter.to_string(), Arc::new(|_, _| {}));
        opt.poll_interval_ms = 60_000;
        opt.headers = Some(Arc::new(|_, _, _| vec![("authorization".into(), "GNAP app-token".into())]));
        let seen = Arc::clone(&errors);
        opt.on_error = Some(Arc::new(move |line: &str| seen.lock().unwrap().push(line.to_string())));
        opt.pep = pep;
        SignalsReceiver::new(opt).unwrap()
    };
    // The section's signals false makes the PEP start out reporting `none`:
    // a `requested` heartbeat can only come from the receiver.
    let (_server, tx, transmitter) = start_transmitter();
    let client = client(pdp, json!({"ssf": {"transmitter": transmitter}}), json!({"permitCacheMs": 30000, "heartbeatIntervalMs": 1000, "signals": false}));
    tx.lock().unwrap().streams.push(old(&transmitter, "old"));
    let receiver = receiver_for(&transmitter, client.pep().cloned());
    receiver.start().unwrap();
    receiver.stop();
    assert_eq!(tx.lock().unwrap().created, 0, "the stream was reused, not made again");
    let patches = tx.lock().unwrap().patches.clone();
    assert_eq!(patches.len(), 1, "{patches:?}");
    assert_eq!(patches[0]["stream_id"], "old");
    let asked: Vec<&str> = patches[0]["events_requested"].as_array().unwrap().iter().filter_map(Value::as_str).collect();
    assert!(asked.contains(&caep), "what it asked for before is kept: {asked:?}");
    assert!(asked.contains(&POLICIES_CHANGED_EVENT), "the policy event is added: {asked:?}");
    let stream = receiver.stream().unwrap();
    assert!(stream["events_delivered"].as_array().unwrap().iter().any(|e| e == POLICIES_CHANGED_EVENT));
    assert_eq!(stream["delivery"]["endpoint_url"], format!("{transmitter}/ssf/poll/old"), "the delivery the listing gave is kept");
    assert!(errors.lock().unwrap().is_empty(), "{:?}", errors.lock().unwrap());
    assert_policy_events(pdp, "requested");

    // Nothing missing: no PATCH.
    let again = receiver_for(&transmitter, client.pep().cloned());
    again.start().unwrap();
    again.stop();
    assert_eq!(tx.lock().unwrap().patches.len(), 1, "a stream that already carries the event is left alone");

    // A transmitter that refuses: the receiver still starts, says so through
    // on_error, and the PEP's heartbeat reports the event excluded.
    let (_server, tx, transmitter) = start_transmitter();
    tx.lock().unwrap().refuse_patch = true;
    tx.lock().unwrap().streams.push(old(&transmitter, "fixed"));
    let refused = receiver_for(&transmitter, client.pep().cloned());
    refused.start().unwrap();
    refused.stop();
    assert_eq!(tx.lock().unwrap().patches.len(), 1);
    assert!(errors.lock().unwrap().iter().any(|l| l.contains("answered 405")), "{:?}", errors.lock().unwrap());
    assert_policy_events(pdp, "excluded");
}

#[cfg(feature = "local")]
#[test]
fn local_mode_fails_closed_then_decides_in_process() {
    let pdp = start_pdp();
    pdp.policies_up.store(false, Ordering::SeqCst);
    let client = client(pdp, json!({}), json!({"mode": "local", "pollIntervalMs": 1000}));
    assert!(matches!(client.decide(&person(), &Access::new("read", "order", "42")), Decision::Unavailable { .. }), "no policy held yet");

    pdp.policies_up.store(true, Ordering::SeqCst);
    let pep = client.pep().unwrap();
    let held = (0..50).any(|_| {
        thread::sleep(Duration::from_millis(100));
        pep.status().holds_policy
    });
    assert!(held, "the poll (no signal stream, pollIntervalMs) pulled once the service answered");
    assert!(client.decide(&person(), &Access::new("read", "order", "42")).is_permit());
    assert!(matches!(client.decide(&person(), &Access::new("write", "order", "42")), Decision::Deny { .. }));
    assert_eq!(pdp.count("/access/v1/evaluation"), 0, "decided in process");
    assert!(pdp.count("/xacml/pep/policies") >= 2);
}
