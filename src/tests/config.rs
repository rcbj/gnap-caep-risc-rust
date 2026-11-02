// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

use super::MustErr;
use crate::{resolve, Error};
use p256::pkcs8::EncodePrivateKey;
use serde_json::{json, Value};
use std::path::Path;

fn private_pem() -> String {
    let key = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());
    key.to_pkcs8_pem(p256::pkcs8::LineEnding::LF).unwrap().to_string()
}

fn resolve_extra(extra: Value) -> Result<crate::Config, Error> {
    let mut body = json!({
        "grantEndpoint": "https://idp.example/gnap",
        "application": "app",
        "privateKey": private_pem(),
        "keyProof": "httpsig",
    });
    if let (Some(doc), Some(more)) = (body.as_object_mut(), extra.as_object()) {
        for (key, value) in more {
            doc.insert(key.clone(), value.clone());
        }
    }
    resolve(&body, Path::new("."))
}

#[test]
fn defaults_access_and_fills_transmitter() {
    let resolved = resolve_extra(json!({"transmitterIssuer": "https://idp.example/issuer/"})).unwrap();
    assert_eq!(resolved.access, vec![json!("ssf.read"), json!("ssf.manage")]);
    let ssf = resolved.ssf.unwrap();
    assert_eq!(ssf.transmitter, "https://idp.example/issuer");
    assert!(resolved.signals.is_none());
    let on = resolve_extra(json!({"signals": true, "transmitterIssuer": "https://idp.example/issuer"})).unwrap();
    assert!(on.signals.is_none());
    assert!(on.ssf.is_some());
}

#[test]
fn drops_ssf_rights_and_transmitter_when_signals_is_false() {
    let resolved = resolve_extra(json!({
        "signals": false,
        "access": ["openid", "ssf.read"],
        "transmitterIssuer": "https://idp.example",
        "ssf": {"transmitter": "https://idp.example/tx", "pollIntervalMs": 3000},
    }))
    .unwrap();
    assert_eq!(resolved.access, vec![json!("openid")]);
    assert!(resolved.ssf.is_none());
    assert_eq!(resolved.signals, Some(false));
    let kept = resolve_extra(json!({
        "signals": false,
        "access": ["openid", " ssf.read ", {"type": "ssf.manage", "actions": ["read"]}, {"type": "api"}, {"type": " ssf.read "}],
        "ssf": {"transmitter": "not a url"},
    }))
    .unwrap();
    assert_eq!(kept.access, vec![json!("openid"), json!({"type": "api"}), json!({"type": " ssf.read "})]);
    assert!(kept.ssf.is_none());
}

#[test]
fn refuses_signals_off_when_ssf_rights_were_the_only_ones() {
    let message = "signals is false and access has no rights left after ssf.read and ssf.manage were removed";
    let err = resolve_extra(json!({"signals": false, "access": ["ssf.read", "ssf.manage"]})).must_err();
    assert_eq!(err.code, "config");
    assert!(err.message.contains(message));
    assert!(err.to_string().contains("must name a right this authorization server grants"));
    let err = resolve_extra(json!({"signals": false, "transmitterIssuer": "https://idp.example"})).must_err();
    assert!(err.message.contains(message));
    let err = resolve_extra(json!({"signals": false, "access": [{"type": "ssf.read"}, {"type": "ssf.manage"}]})).must_err();
    assert!(err.message.contains(message));
}

#[test]
fn refuses_a_signals_value_that_is_not_true_or_false() {
    let err = resolve_extra(json!({"signals": "no"})).must_err();
    assert_eq!(err.code, "config");
    assert_eq!(err.to_string(), "signals must be true or false");
}
