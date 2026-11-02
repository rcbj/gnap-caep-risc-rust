// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

use crate::{person_from, IdCheck};
use serde_json::{json, Map, Value};

fn person(subject: Value) -> crate::Person {
    let keys = || Ok(Vec::new());
    let check = IdCheck { issuer: "https://as.example", audiences: Vec::new(), skew: 0.0, keys: &keys };
    person_from(&subject, &check).unwrap().unwrap()
}

#[test]
fn uid_from_account_keeps_the_protocol_subject() {
    let person = person(json!({
        "sub_ids": [
            {"format": "iss_sub", "iss": "https://as.example", "sub": "urn:uuid:abc"},
            {"format": "account", "uri": "acct:gnap-demo-user@localhost:8081"},
        ],
    }));
    assert_eq!(person.sub, "urn:uuid:abc");
    assert_eq!(person.iss.as_deref(), Some("https://as.example"));
    assert_eq!(person.uid.as_deref(), Some("gnap-demo-user"));
}

#[test]
fn percent_decodes_the_user_part_and_keeps_invalid_encoding() {
    let decoded = person(json!({"sub_ids": [{"format": "account", "uri": "acct:ada%20lovelace@idp.example"}]}));
    assert_eq!(decoded.sub, "acct:ada%20lovelace@idp.example");
    assert_eq!(decoded.uid.as_deref(), Some("ada lovelace"));
    let kept = person(json!({"sub_ids": [{"format": "account", "uri": "acct:%E0%A4%A@idp.example"}]}));
    assert_eq!(kept.uid.as_deref(), Some("%E0%A4%A"));
}

#[test]
fn uid_stays_unset_without_an_account_identifier() {
    let person = person(json!({"sub_ids": [{"format": "iss_sub", "iss": "https://as.example", "sub": "urn:uuid:abc"}]}));
    assert!(person.uid.is_none());
    assert_eq!(person.sub, "urn:uuid:abc");
}

#[allow(dead_code)]
fn _types(value: Map<String, Value>) {
    let _ = value;
}
