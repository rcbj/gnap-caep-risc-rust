// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

//! This library's AuthZEN cases for the embedded PEP (#39), from
//! `authzen_cases.json`: the catalogue rows, the policies and the
//! evaluations, each asked through this library's own API (`Client::decide`
//! with a `Person`, `Client::decide_grant` with a `Grant`, the `pep` section).
//!
//! - **Offline** (`the_table_decides_as_expected_in_local_mode`, in the
//!   normal suite): one `local` Client per PEP group, each against a stub
//!   realm serving that group's policies (the XACML iya-sts stored for the
//!   table's ALFA), the catalogue and the directory, and every case must give
//!   the table's answer.
//! - **Live** (`live_central_and_local_agree`): only when `GNAP_AUTHZEN_LIVE`
//!   names the file `scripts/live_iya_sts.py --authzen` writes. Two Clients
//!   per group, `central` and `local`, against a fresh iya-sts the script
//!   provisioned from this table; every case must give the same answer in
//!   both modes, and that answer must be the table's. Every mismatch is
//!   collected and the test fails once, listing them.
//!
//! An answer is what the host sees: `Permit` (with each handed obligation's
//! type and properties, and the advice ids), `Deny`, or `Unavailable`.

use super::pep::{ec_pem, key_file};
use super::ssf::read_http;
use crate::pep::{Access, Decision};
use crate::{resolve, Client, Continuation, Grant, Person};
use serde_json::{json, Map, Value};
use std::collections::BTreeSet;
use std::io::Write;
use std::net::TcpListener;
use std::path::Path;
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const TABLE: &str = include_str!("authzen_cases.json");

fn table() -> Value {
    serde_json::from_str(TABLE).expect("authzen_cases.json is JSON")
}

fn now_ms() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f64() * 1000.0
}

fn text(lines: &Value) -> String {
    lines.as_array().map(|l| l.iter().filter_map(Value::as_str).collect::<Vec<_>>().join("\n")).unwrap_or_default()
}

/// The case's person, as a verified ID token assertion would give it: the
/// table's person, with the case's `claims` laid over and `dropClaims`
/// removed. `acr` and `amr` follow the claims, as `person_from` reads them.
fn person(table: &Value, case: &Value) -> Person {
    let who = &table["people"][case["person"].as_str().unwrap()];
    let mut claims: Map<String, Value> = who["claims"].as_object().unwrap().clone();
    if let Some(extra) = case["claims"].as_object() {
        for (k, v) in extra {
            claims.insert(k.clone(), v.clone());
        }
    }
    for name in case["dropClaims"].as_array().into_iter().flatten() {
        claims.remove(name.as_str().unwrap());
    }
    let string = |v: &Value| v.as_str().map(str::to_string);
    Person {
        sub: who["sub"].as_str().unwrap().to_string(),
        acr: claims.get("acr").and_then(string),
        amr: claims.get("amr").and_then(Value::as_array).map(|a| a.iter().filter_map(string).collect()).unwrap_or_default(),
        claims,
        assertion_verified: true,
        iss: Some("https://sts.example".into()),
        uid: string(&who["uid"]),
        email: None,
        name: None,
        preferred_username: string(&who["preferred_username"]),
        sid: None,
    }
}

fn access(case: &Value) -> Access {
    let a = &case["access"];
    let map = |v: &Value| v.as_object().cloned().unwrap_or_default();
    let mut access = Access::new(a["action"].as_str().unwrap(), a["resource"]["type"].as_str().unwrap(), a["resource"]["id"].as_str().unwrap());
    access.resource_properties = map(&a["resource"]["properties"]);
    access.action_properties = map(&a["actionProperties"]);
    access.context = map(&a["context"]);
    access
}

/// The host's view of a decision, as the table writes an answer.
fn answer(decision: &Decision) -> Value {
    match decision {
        Decision::Permit { obligations, advice } => {
            let mut out = json!({"decision": "Permit"});
            if !obligations.is_empty() {
                out["obligations"] = obligations.iter().map(|o| json!({"type": o.kind, "properties": o.properties})).collect();
            }
            if !advice.is_empty() {
                out["advice"] = advice.iter().map(|a| json!(a.id)).collect();
            }
            out
        }
        Decision::Deny { .. } => json!({"decision": "Deny"}),
        Decision::Unavailable { .. } => json!({"decision": "Unavailable"}),
    }
}

fn why(decision: &Decision) -> String {
    match decision {
        Decision::Permit { .. } => String::new(),
        Decision::Deny { why } | Decision::Unavailable { why } => why.clone(),
    }
}

/// Asks one case through `client`: `decide`, or `decide_grant` when the case
/// names a grant. `revocable` gives a continuation the AS will accept a
/// DELETE of, for a grant the case has this client revoke first.
fn ask(client: &Client, table: &Value, case: &Value, revocable: &dyn Fn(&Client) -> Result<Continuation, String>) -> Result<Decision, String> {
    let person = person(table, case);
    let access = access(case);
    let Some(kind) = case["grant"].as_str() else {
        return Ok(client.decide(&person, &access));
    };
    let mut grant = Grant {
        access_token: "unused".into(),
        bearer: false,
        access: Value::Null,
        expires_in: Some(600.0),
        expires_at: Some(now_ms() + 600_000.0),
        manage: None,
        continuation: None,
        instance_id: None,
        subject: Some(person),
        grant_id: Some(case["id"].as_str().unwrap().to_string()),
    };
    match kind {
        "live" => {}
        "no-subject" => grant.subject = None,
        "expired" => grant.expires_at = Some(now_ms() - 1000.0),
        "revoked" => {
            grant.continuation = Some(revocable(client)?);
            client.revoke(&grant).map_err(|e| format!("revoke: {} {}", e.code, e.message))?;
        }
        other => return Err(format!("the table names an unknown grant kind {other}")),
    }
    Ok(client.decide_grant(&grant, &access))
}

/// Waits until the PEP is registered, its last pull succeeded (`central`
/// pulls the catalogue, `local` the catalogue and the policies, the first
/// time in `start`), and, `local`, it holds a policy set.
fn wait_ready(client: &Client, what: &str) {
    let pep = client.pep().expect("a pep section");
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        let s = pep.status();
        let policy = pep.config().mode == crate::pep::Mode::Central || s.holds_policy;
        if s.registered && policy && !s.last_error.contains("pull") {
            return;
        }
        assert!(Instant::now() < deadline, "{what}: the PEP did not get ready: registered {}, holds_policy {}, last_error {}", s.registered, s.holds_policy, s.last_error);
        thread::sleep(Duration::from_millis(200));
    }
}

fn pep_section(table: &Value, group: &Value, mode: &str) -> Value {
    json!({
        "mode": mode,
        "application": group["application"],
        "supportedObligations": table["supportedObligations"],
        "signals": false,
        "pollIntervalMs": 2000,
        "heartbeatIntervalMs": 60000,
    })
}

// ---------------------------------------------------------------------------
// Offline: a stub realm per group, and a local Client.
// ---------------------------------------------------------------------------

/// A stub iya-sts realm at `/realm/az`: what a `local` PEP calls, serving one
/// group's policies, the table's catalogue and its directory, and the GNAP
/// continuation URI `revoke` deletes.
struct Realm {
    base: String,
    policies: Value,
    catalogue: Value,
    directory: Value,
    seen: Mutex<Vec<String>>,
}

impl Realm {
    fn realm(&self) -> String {
        format!("{}/realm/az", self.base)
    }
}

/// `PolicyId` (or `PolicySetId`) and the kind of a policy document.
fn described(document: &str) -> (String, &'static str) {
    let start = document.find("<Policy").expect("a Policy or PolicySet element");
    let kind = if document[start..].starts_with("<PolicySet") { "PolicySet" } else { "Policy" };
    let marker = format!("{kind}Id=\"");
    let at = document[start..].find(&marker).unwrap() + start + marker.len();
    let end = document[at..].find('"').unwrap() + at;
    (document[at..end].to_string(), kind)
}

fn start_realm(table: &Value, group: &Value) -> &'static Realm {
    let policies: Vec<Value> = group["policies"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| {
            let document = text(&p["xacml"]);
            assert!(!document.is_empty(), "a policy of {} has no xacml in the table", group["application"]);
            let (id, kind) = described(&document);
            json!({"name": p["name"].as_str().unwrap_or("own"), "policyId": id, "kind": kind, "version": "1.0",
                   "isRoot": p["root"].as_bool().unwrap_or(false), "description": "", "document": document})
        })
        .collect();
    let fga: Vec<&Value> = if group["fga"].as_bool().unwrap_or(false) { vec![&group["application"]] } else { vec![] };
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let realm: &'static Realm = Box::leak(Box::new(Realm {
        base: format!("http://127.0.0.1:{port}"),
        policies: json!({"syncToken": "p1", "root": "", "policies": policies, "withheld": [], "note": ""}),
        catalogue: json!({"syncToken": "c1", "realm": "az", "rows": table["catalogue"],
                          "settings": {"obligationsProfile": table["obligationsProfile"]}, "fgaApplications": fga}),
        directory: table["directory"].clone(),
        seen: Mutex::new(Vec::new()),
    }));
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut tcp) = stream else { continue };
            tcp.set_read_timeout(Some(Duration::from_secs(5))).ok();
            thread::spawn(move || {
                let Ok((method, path, _headers, body)) = read_http(&mut tcp) else { return };
                let (status, kind, text) = serve(realm, &method, &path, &body);
                let _ = tcp.write_all(format!("HTTP/1.1 {status} OK\r\ncontent-type: {kind}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{text}", text.len()).as_bytes());
            });
        }
    });
    realm
}

fn serve(realm: &Realm, method: &str, path: &str, body: &str) -> (u16, &'static str, String) {
    let path = path.trim_start_matches("/realm/az");
    realm.seen.lock().unwrap().push(format!("{method} {path}"));
    let json = |status: u16, value: Value| (status, "application/json", value.to_string());
    match path {
        p if p.starts_with("/gnap/continue/") && method == "DELETE" => (204, "application/json", String::new()),
        "/oauth2/token" => json(200, json!({"access_token": "pep-token", "token_type": "DPoP", "expires_in": 300})),
        "/xacml/pep/register" => json(201, json!({"registered": true})),
        "/xacml/pep/heartbeat" => json(200, json!({"acknowledged": true, "current": true})),
        "/xacml/pep/authzen-catalogue" => json(200, realm.catalogue.clone()),
        "/xacml/pep/policies" => json(200, realm.policies.clone()),
        "/admin-api/pep-audit" => json(200, json!({"acknowledged": 0})),
        "/xacml/pip" => (200, "application/xml", pip_answer(&realm.directory, body)),
        "/access/v1/evaluation" => json(500, json!({"error": "this stub decides nothing; the case ran in central mode"})),
        _ => json(404, json!({"error": "not_found"})),
    }
}

/// The directory's attributes for the PIP query's subject, every one of
/// them (the PEP keeps those its policy asks for).
fn pip_answer(directory: &Value, query: &str) -> String {
    let subject = query
        .split("subject:subject-id\"")
        .nth(1)
        .and_then(|rest| rest.split("<AttributeValue").nth(1))
        .and_then(|rest| rest.split('>').nth(1))
        .and_then(|rest| rest.split('<').next())
        .unwrap_or("");
    let mut attributes = String::new();
    for (id, value) in directory[subject].as_object().into_iter().flatten() {
        attributes.push_str(&format!(
            "<Attribute AttributeId=\"{id}\" IncludeInResult=\"false\"><AttributeValue DataType=\"http://www.w3.org/2001/XMLSchema#string\">{}</AttributeValue></Attribute>",
            value.as_str().unwrap_or("")
        ));
    }
    format!(
        "<PIPResponse xmlns=\"urn:sts:xacml:pip:1.0\"><Attributes xmlns=\"urn:oasis:names:tc:xacml:3.0:core:schema:wd-17\" Category=\"urn:oasis:names:tc:xacml:1.0:subject-category:access-subject\">{attributes}</Attributes></PIPResponse>"
    )
}

fn local_client(table: &Value, group: &Value, realm: &Realm) -> Client {
    let (dir, file) = key_file(&ec_pem());
    let mut section = pep_section(table, group, "local");
    section["name"] = json!("pep-authzen-offline");
    section["assertionKey"] = json!(file);
    let doc = json!({
        "grantEndpoint": format!("{}/gnap", realm.realm()),
        "application": "gnap-caep-risc-demo",
        "privateKey": ec_pem(),
        "keyProof": "httpsig",
        "allowInsecure": true,
        "pep": section,
    });
    Client::create(resolve(&doc, &dir).unwrap()).unwrap()
}

/// Every case through a `local` Client against its group's stub realm. A
/// case the table marks `localDefect` (a local answer the live run proved
/// wrong, with where it is to be fixed) must still give that wrong answer:
/// the day it gives the table's answer, this fails, and the mark comes off.
#[test]
fn the_table_decides_as_expected_in_local_mode() {
    let table = table();
    let groups = table["peps"].as_object().unwrap();
    let mut clients = std::collections::HashMap::new();
    for (name, group) in groups {
        let realm = start_realm(&table, group);
        let client = local_client(&table, group, realm);
        wait_ready(&client, name);
        clients.insert(name.clone(), (realm, client));
    }
    let mut failures = Vec::new();
    let cases = table["cases"].as_array().unwrap();
    let mut ids = BTreeSet::new();
    for case in cases {
        let id = case["id"].as_str().unwrap();
        assert!(ids.insert(id), "two cases are called {id}");
        let (realm, client) = &clients[case["pep"].as_str().unwrap_or("main")];
        let revocable = |_: &Client| Ok(Continuation { uri: format!("{}/gnap/continue/{id}", realm.realm()), access_token: "ct".into(), wait: None });
        let asked = realm.seen.lock().unwrap().len();
        let decision = ask(client, &table, case, &revocable).unwrap_or_else(|e| panic!("{id}: {e}"));
        let got = answer(&decision);
        let want = match case.get("localDefect") {
            Some(defect) => defect["local"].clone(),
            None => case["expect"].clone(),
        };
        if got != want {
            failures.push(format!("{id}: local {got} ({}), expected {want}", why(&decision)));
        }
        if case["grant"].is_string() && case["grant"] != "live" {
            let evaluated = realm.seen.lock().unwrap()[asked..].iter().any(|s| s.ends_with("/xacml/pip"));
            assert!(!evaluated, "{id}: an ended grant was decided anyway");
        }
    }
    for (_, client) in clients.values() {
        assert_eq!(client.pep().unwrap().status().last_error, "", "the stub refused nothing");
    }
    assert!(failures.is_empty(), "{} of {} cases:\n{}", failures.len(), cases.len(), failures.join("\n"));
}

/// The table is this library's own and covers what it says it covers.
#[test]
fn the_table_covers_each_kind_of_case() {
    let table = table();
    let cases = table["cases"].as_array().unwrap();
    let decisions: BTreeSet<&str> = cases.iter().filter_map(|c| c["expect"]["decision"].as_str()).collect();
    assert_eq!(decisions, BTreeSet::from(["Deny", "Permit", "Unavailable"]));
    let types: BTreeSet<&str> = table["catalogue"].as_array().unwrap().iter().filter_map(|r| r["dataType"].as_str()).collect();
    for wanted in ["integer", "double", "boolean", "dateTime"] {
        assert!(types.contains(wanted), "a {wanted} row");
    }
    let rows = table["catalogue"].as_array().unwrap();
    assert!(rows.iter().any(|r| r["multiplicity"] == "bag"));
    assert!(rows.iter().any(|r| r["property"].as_str().unwrap().contains('.')));
    for grant in ["live", "no-subject", "expired", "revoked"] {
        assert!(cases.iter().any(|c| c["grant"] == grant), "a {grant} grant");
    }
    assert!(cases.iter().any(|c| c["expect"]["obligations"].is_array()));
    assert!(table["peps"].as_object().unwrap().values().any(|g| g["policies"].as_array().unwrap().iter().any(|p| p["references"].is_array())));
}

// ---------------------------------------------------------------------------
// Live: central against local, through a provisioned iya-sts.
// ---------------------------------------------------------------------------

/// `GNAP_AUTHZEN_LIVE` names the file `scripts/live_iya_sts.py --authzen`
/// writes: `config`, the registered client's configuration file, and
/// `peps.<group>.<mode>` with each provisioned PEP's `name` and
/// `assertionKey`. `GNAP_AUTHZEN_REPORT`, when set, receives the summary.
#[test]
fn live_central_and_local_agree() {
    let Ok(spec_file) = std::env::var("GNAP_AUTHZEN_LIVE") else {
        eprintln!("GNAP_AUTHZEN_LIVE is not set: the live differential run is scripts/live_iya_sts.py --authzen");
        return;
    };
    let table = table();
    let spec: Value = serde_json::from_str(&std::fs::read_to_string(&spec_file).unwrap()).unwrap();
    let config_file = Path::new(spec["config"].as_str().unwrap());
    let base: Value = serde_json::from_str(&std::fs::read_to_string(config_file).unwrap()).unwrap();
    let dir = config_file.parent().unwrap();

    let mut clients = std::collections::HashMap::new();
    for (name, group) in table["peps"].as_object().unwrap() {
        for mode in ["central", "local"] {
            let given = &spec["peps"][name][mode];
            let mut section = pep_section(&table, group, mode);
            section["name"] = given["name"].clone();
            section["assertionKey"] = given["assertionKey"].clone();
            let mut doc = base.clone();
            doc["pep"] = section;
            let client = Client::create(resolve(&doc, dir).unwrap_or_else(|e| panic!("{name} {mode}: {}", e.message))).unwrap();
            clients.insert((name.clone(), mode), client);
        }
    }
    for ((name, mode), client) in &clients {
        wait_ready(client, &format!("{name} {mode}"));
    }

    // A grant to revoke: a pending request at the AS, whose continuation
    // this client may DELETE.
    let revocable = |client: &Client| -> Result<Continuation, String> {
        let started = client.request_grant().map_err(|e| format!("request_grant: {} {}", e.code, e.message))?;
        started.pending.map(|p| p.continuation).ok_or_else(|| "the grant request did not wait for interaction".to_string())
    };
    let cases = table["cases"].as_array().unwrap();
    let (mut equal, mut expected) = (0, 0);
    let mut mismatches = Vec::new();
    for case in cases {
        let id = case["id"].as_str().unwrap();
        let group = case["pep"].as_str().unwrap_or("main").to_string();
        let run = |mode| match ask(&clients[&(group.clone(), mode)], &table, case, &revocable) {
            Ok(decision) => (answer(&decision), why(&decision)),
            Err(e) => (json!({"error": e}), String::new()),
        };
        let (central, central_why) = run("central");
        let (local, local_why) = run("local");
        let want = &case["expect"];
        if central == local {
            equal += 1;
        }
        if central == *want && local == *want {
            expected += 1;
        } else {
            mismatches.push(json!({"case": id, "central": central, "local": local, "expected": want,
                                   "centralWhy": central_why, "localWhy": local_why}));
        }
    }
    let report = json!({"cases": cases.len(), "centralEqualsLocal": equal, "bothEqualExpected": expected, "mismatches": mismatches});
    let text = serde_json::to_string_pretty(&report).unwrap();
    println!("{text}");
    if let Ok(out) = std::env::var("GNAP_AUTHZEN_REPORT") {
        std::fs::write(out, &text).unwrap();
    }
    for client in clients.values() {
        client.pep().unwrap().stop();
    }
    assert!(mismatches.is_empty(), "{} of {} cases: central, local and the table do not all agree:\n{text}", mismatches.len(), cases.len());
}
