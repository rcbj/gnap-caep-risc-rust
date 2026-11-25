// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

//! The embedded iya-sts PEP (the `pep` feature; rcbj/iya-sts#1206, this
//! repository's #39). The PEP itself is the shared `iya-pep` crate. This
//! library only wires it in, as `oidc-caep-risc` does:
//!
//! - **Configuration.** A `pep` section in `gnap.json`, off unless present.
//!   `pdpUrl` defaults to the iya-sts realm the grant endpoint belongs to
//!   ([`default_pdp_url`]) and `application` to `application`, the GNAP
//!   client registered in iya-sts. `signals` follows the library's Shared
//!   Signals receiver and `tlsCa` the library's trust anchors, unless the
//!   section says otherwise. `assertionKey` is read relative to the
//!   configuration's directory, like `privateKey`.
//! - **Keys (D1).** The PEP's assertion key must differ from the GNAP
//!   client instance key (the one behind every `httpsig`, `jwsd` or `mtls`
//!   proof, and the certificate's): resolving refuses a configuration where
//!   the two have the same JWK thumbprint. The library holds no other key.
//! - **The subject.** A grant's [`Person`] becomes the PEP's subject
//!   ([`subject_for`]). No request header is read.
//! - **Signals (D4).** A `SignalsReceiver` given this PEP asks for
//!   `pep-policies-changed` too (in `local` mode, or `central` with a Permit
//!   cache), verifies its SET like any other, and hands the event to the PEP.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde_json::{Map, Value};

use crate::error::{fail, Error};
use crate::keys::ClientKey;
use crate::subject::Person;

pub use iya_pep::{Access, Decision, EventStream, Mode, Obligation, Pep, PepConfig, Status, Subject, POLICIES_CHANGED_EVENT};

/// The library's values the `pep` section's defaults come from.
pub(crate) struct Defaults<'a> {
    pub grant_endpoint: &'a str,
    pub application: &'a str,
    /// The library runs a Shared Signals receiver: signals are on and a
    /// transmitter is configured.
    pub signals: bool,
    /// The library's `tlsCa`, already read (PEM text, or empty).
    pub tls_ca: &'a str,
    pub base_dir: &'a Path,
}

/// Builds the PEP from the configuration's `pep` section. Checks that its
/// key is not the client instance key. Sends nothing: [`crate::Client::create`]
/// starts it.
pub(crate) fn build(section: &Value, defaults: &Defaults<'_>, client_key: &ClientKey) -> Result<Arc<Pep>, Error> {
    let Some(map) = section.as_object() else {
        return Err(fail("config", "pep must be an object"));
    };
    let mut map = map.clone();
    // The library's own values, unless the section names its own.
    if !map.contains_key("signals") {
        map.insert("signals".into(), Value::Bool(defaults.signals));
    }
    if !map.contains_key("tlsCa") && defaults.tls_ca.contains("-----BEGIN") {
        map.insert("tlsCa".into(), Value::String(defaults.tls_ca.to_string()));
    }
    if let Some(Value::String(key)) = map.get("assertionKey") {
        if !key.is_empty() && !Path::new(key).is_absolute() {
            let full: PathBuf = defaults.base_dir.join(key);
            map.insert("assertionKey".into(), Value::String(full.to_string_lossy().into_owned()));
        }
    }
    let pdp_url = default_pdp_url(defaults.grant_endpoint);
    let config = PepConfig::from_json(&Value::Object(map), &pdp_url, defaults.application).map_err(|e| fail("config", e.message))?;
    let pep = Pep::new(config).map_err(|e| fail("config", e.message))?;
    // D1: the PEP's key is its own.
    let client = iya_pep::jwk_thumbprint(&Value::Object(client_key.jwk.clone()));
    if client.as_deref() == Some(pep.key_thumbprint().as_str()) {
        return Err(fail("config", "pep.assertionKey is the GNAP client instance key (privateKey); the PEP needs a key of its own"));
    }
    Ok(Arc::new(pep))
}

/// The iya-sts base a GNAP grant endpoint belongs to, the realm prefix
/// included: `https://sts/realm/acme/gnap` (or a named authorization
/// server's `https://sts/realm/acme/<as>/gnap`) gives `https://sts/realm/acme`,
/// and the default realm's `https://sts/gnap` gives `https://sts`. That is
/// where iya-sts serves `/oauth2/token`, `/xacml/pep/*` and
/// `/access/v1/evaluation` for the realm, and the same base
/// `scripts/configure_iya_sts.py` registers the application at.
/// `idTokenIssuer` is not used: it defaults to the grant endpoint's origin,
/// which drops the realm.
pub fn default_pdp_url(grant_endpoint: &str) -> String {
    let Ok(url) = url::Url::parse(grant_endpoint) else { return String::new() };
    let origin = url.origin().ascii_serialization();
    let segments: Vec<&str> = url.path_segments().map(|s| s.filter(|p| !p.is_empty()).collect()).unwrap_or_default();
    match segments.as_slice() {
        ["realm", realm, ..] => format!("{origin}/realm/{realm}"),
        _ => origin,
    }
}

/// The PEP's subject for the person a GNAP grant names.
///
/// The id is what iya-sts's PIP resolves, a username, so the first of:
/// - `uid`, the user part of the `account` subject identifier
///   (`acct:<username>@<host>`). iya-sts builds it from the directory
///   username itself (`gnap/gnap_subject.ts`), whatever the client's
///   `subject_type`, so it is the most direct handle on the person.
/// - iya-sts's own `username` claim from the verified ID token assertion,
///   on every ID token iya-sts issues.
/// - `preferred_username` from the assertion, a `profile` claim there only
///   when that scope was granted.
/// - `sub` otherwise. iya-sts's `iss_sub` (and the ID token's `sub`) can be
///   pairwise for this client, which the PIP may not resolve; it is the
///   last resort, so a grant without `account` still has a subject.
///
/// The properties are the verified ID token's claims (`acr`, `amr`,
/// `auth_time` and the rest), plus `acr` and `amr` from the person when the
/// claims lack them. The PEP sends only the ones the realm's AuthZEN
/// catalogue declares.
pub fn subject_for(person: &Person) -> Subject {
    let mut properties: Map<String, Value> = person.claims.clone();
    if let Some(acr) = &person.acr {
        properties.entry("acr").or_insert_with(|| Value::String(acr.clone()));
    }
    if !person.amr.is_empty() {
        properties.entry("amr").or_insert_with(|| Value::Array(person.amr.iter().cloned().map(Value::String).collect()));
    }
    let username = person.claims.get("username").and_then(Value::as_str);
    let id = [person.uid.as_deref(), username, person.preferred_username.as_deref()]
        .into_iter()
        .flatten()
        .find(|value| !value.is_empty())
        .unwrap_or(person.sub.as_str())
        .to_string();
    Subject::user(id, properties)
}

/// Whether a receiver built with this PEP asks for `pep-policies-changed`.
pub(crate) fn wants_events(pep: &Pep) -> bool {
    pep.config().mode == Mode::Local || pep.config().permit_cache_ms > 0
}
