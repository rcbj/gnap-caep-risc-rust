// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

//! A stub iya-sts realm for a `local` embedded PEP: what such a PEP calls
//! (token, registration, heartbeat, the AuthZEN catalogue, the bound
//! application's policies, the audit hand-in, the PIP), and the GNAP
//! continuation URI `revoke` deletes. Its PIP answers from a directory
//! keyed by the subject id the PEP sends (the person's `uid`).
//!
//! Shared by the library's tests (`src/tests/authzen.rs`, through
//! `src/tests/mod.rs`) and the demo's (`src/bin/demo.rs`, by `#[path]`), so
//! it uses only `std` and `serde_json`, never `crate::`.

#![allow(dead_code)]

use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

/// One HTTP/1.1 request off `stream`: method, path (no query), headers
/// (lower-case names) and body.
pub fn read_http(stream: &mut impl Read) -> Result<(String, String, HashMap<String, String>, String), String> {
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
    header
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.eq_ignore_ascii_case("content-length") {
                value.trim().parse().ok()
            } else {
                None
            }
        })
        .unwrap_or(0)
}

/// A running stub realm at `<base>/realm/<name>`.
pub struct Realm {
    pub base: String,
    pub name: String,
    pub policies: Value,
    pub catalogue: Value,
    pub directory: Value,
    /// `METHOD /path` of every request, the realm prefix removed.
    pub seen: Mutex<Vec<String>>,
}

impl Realm {
    pub fn realm(&self) -> String {
        format!("{}/realm/{}", self.base, self.name)
    }
}

/// `PolicyId` (or `PolicySetId`) and the kind of a policy document.
pub fn described(document: &str) -> (String, &'static str) {
    let start = document.find("<Policy").expect("a Policy or PolicySet element");
    let kind = if document[start..].starts_with("<PolicySet") { "PolicySet" } else { "Policy" };
    let marker = format!("{kind}Id=\"");
    let at = document[start..].find(&marker).unwrap() + start + marker.len();
    let end = document[at..].find('"').unwrap() + at;
    (document[at..end].to_string(), kind)
}

/// One entry of `GET /xacml/pep/policies`'s `policies`, as iya-sts lists it.
pub fn policy_entry(name: &str, document: &str, is_root: bool) -> Value {
    let (id, kind) = described(document);
    json!({"name": name, "policyId": id, "kind": kind, "version": "1.0",
           "isRoot": is_root, "description": "", "document": document})
}

/// Starts a stub realm `name` serving `policies` (entries from
/// `policy_entry`), the catalogue `rows` with `obligations_profile`, the
/// applications in `fga` as enforcing fine-grained authorization, and
/// `directory` (subject id to `{attribute id: value}`) through the PIP.
pub fn start(name: &str, policies: Vec<Value>, rows: Value, obligations_profile: Value, fga: Vec<Value>, directory: Value) -> &'static Realm {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let realm: &'static Realm = Box::leak(Box::new(Realm {
        base: format!("http://127.0.0.1:{port}"),
        name: name.to_string(),
        policies: json!({"syncToken": "p1", "root": "", "policies": policies, "withheld": [], "note": ""}),
        catalogue: json!({"syncToken": "c1", "realm": name, "rows": rows,
                          "settings": {"obligationsProfile": obligations_profile}, "fgaApplications": fga}),
        directory,
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
    let prefix = format!("/realm/{}", realm.name);
    let path = path.strip_prefix(&prefix).unwrap_or(path);
    realm.seen.lock().unwrap().push(format!("{method} {path}"));
    let json = |status: u16, value: Value| (status, "application/json", value.to_string());
    match path {
        p if p.starts_with("/gnap/continue/") && method == "DELETE" => (204, "application/json", String::new()),
        "/oauth2/token" => json(200, json!({"access_token": "pep-token", "token_type": "DPoP", "expires_in": 300})),
        "/xacml/pep/register" => json(201, json!({"registered": true, "identity": format!("uid=pep-{},ou=users,dc=example,dc=com", realm.name)})),
        "/xacml/pep/heartbeat" => json(200, json!({"acknowledged": true, "current": true})),
        "/xacml/pep/authzen-catalogue" => json(200, realm.catalogue.clone()),
        "/xacml/pep/policies" => json(200, realm.policies.clone()),
        "/admin-api/pep-audit" => json(200, json!({"acknowledged": 0})),
        "/xacml/pip" => (200, "application/xml", pip_answer(&realm.directory, body)),
        "/access/v1/evaluation" => json(500, json!({"error": "this stub decides nothing; the PEP ran in central mode"})),
        _ => json(404, json!({"error": "not_found"})),
    }
}

/// The directory's attributes for the PIP query's subject, every one of
/// them (the PEP keeps those its policy asks for). A subject the directory
/// does not hold gets an empty answer.
pub fn pip_answer(directory: &Value, query: &str) -> String {
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
