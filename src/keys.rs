// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

use crate::codec::{b64url, b64url_decode, sha256};
use crate::error::{fail, Error};
use base64::Engine;
use p256::ecdsa::SigningKey;
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::traits::PublicKeyParts;
use rsa::{BigUint, RsaPrivateKey, RsaPublicKey};
use serde_json::{Map, Value};
use sha2::{Sha256, Sha384, Sha512};
use p256::ecdsa::signature::{Signer as _, Verifier as _};
use rsa::pkcs8::{DecodePrivateKey as _, EncodePrivateKey as _};
use signature::{RandomizedSigner, SignatureEncoding, Signer, Verifier};
use x509_parser::prelude::*;

pub const PROOFS: &[&str] = &["mtls", "httpsig", "jwsd"];

enum Secret {
    Ec(SigningKey),
    Rsa(RsaPrivateKey),
}

pub struct ClientKey {
    pub proof: String,
    pub alg: String,
    pub kid: String,
    pub jwk: Map<String, Value>,
    pub cert_pem: String,
    pub chain_pem: String,
    secret: Secret,
}

pub fn load_client_key(private_pem: &str, certificate_pem: &str, proof: &str) -> Result<ClientKey, Error> {
    let secret = parse_private(private_pem)?;
    let jwk = public_jwk(&secret)?;
    let cert_der = if certificate_pem.trim().is_empty() {
        None
    } else {
        Some(first_cert_der(certificate_pem)?)
    };
    if let Some(der) = &cert_der {
        if !same_public(&secret, der)? {
            return Err(fail("config", "the certificate is not the public half of the private key"));
        }
    }
    let mut chosen = proof.to_string();
    if chosen.is_empty() {
        chosen = if cert_der.is_some() { "mtls" } else { "httpsig" }.to_string();
    }
    if chosen == "mtls" && cert_der.is_none() {
        return Err(fail("config", "keyProof \"mtls\" needs certificate"));
    }
    let alg = jwk.get("alg").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let kid = jwk.get("kid").and_then(|v| v.as_str()).unwrap_or("").to_string();
    if chosen == "mtls" {
        let blocks = cert_blocks(certificate_pem);
        let leaf = blocks.first().cloned().unwrap_or_else(|| certificate_pem.to_string());
        let chain = if blocks.is_empty() { vec![certificate_pem.trim().to_string()] } else { blocks.iter().map(|b| b.trim().to_string()).collect::<Vec<_>>() };
        return Ok(ClientKey {
            proof: "mtls".into(),
            alg,
            kid,
            jwk,
            cert_pem: leaf.trim().to_string() + "\n",
            chain_pem: chain.join("\n") + "\n",
            secret,
        });
    }
    Ok(ClientKey {
        proof: chosen,
        alg,
        kid,
        jwk,
        cert_pem: certificate_pem.to_string(),
        chain_pem: String::new(),
        secret,
    })
}

pub fn public_key_object(key: &ClientKey) -> Result<Value, Error> {
    if key.proof == "mtls" {
        if key.cert_pem.trim().is_empty() {
            return Err(fail("config", "mutual TLS needs the client certificate"));
        }
        let mut doc = Map::new();
        doc.insert("proof".into(), Value::String("mtls".into()));
        doc.insert("cert".into(), Value::String(key.cert_pem.trim().to_string()));
        return Ok(Value::Object(doc));
    }
    let mut jwk = Map::new();
    for name in ["kty", "crv", "x", "y", "n", "e"] {
        if let Some(value) = key.jwk.get(name) {
            jwk.insert(name.into(), value.clone());
        }
    }
    jwk.insert("alg".into(), Value::String(key.alg.clone()));
    jwk.insert("kid".into(), Value::String(key.kid.clone()));
    let mut doc = Map::new();
    doc.insert("proof".into(), Value::String(key.proof.clone()));
    doc.insert("jwk".into(), Value::Object(jwk));
    Ok(Value::Object(doc))
}

pub fn sign(key: &ClientKey, data: &[u8]) -> Result<Vec<u8>, Error> {
    match &key.secret {
        Secret::Ec(secret) => {
            let sig: p256::ecdsa::Signature = secret.sign(data);
            Ok(sig.to_bytes().to_vec())
        }
        Secret::Rsa(secret) => sign_rsa(secret, &key.alg, data),
    }
}

pub fn verify_jwk(jwk: &Map<String, Value>, alg: &str, data: &[u8], signature: &[u8]) -> bool {
    let kty = jwk.get("kty").and_then(|v| v.as_str()).unwrap_or("");
    if kty == "RSA" {
        let Some(n) = jwk.get("n").and_then(|v| v.as_str()).and_then(|s| b64url_decode(s).ok()) else { return false };
        let Some(e) = jwk.get("e").and_then(|v| v.as_str()).and_then(|s| b64url_decode(s).ok()) else { return false };
        let Ok(public) = RsaPublicKey::new(BigUint::from_bytes_be(&n), BigUint::from_bytes_be(&e)) else { return false };
        return verify_rsa(&public, alg, data, signature);
    }
    if kty == "EC" && alg == "ES256" && jwk.get("crv").and_then(|v| v.as_str()) == Some("P-256") {
        let Some(x) = jwk.get("x").and_then(|v| v.as_str()).and_then(|s| b64url_decode(s).ok()) else { return false };
        let Some(y) = jwk.get("y").and_then(|v| v.as_str()).and_then(|s| b64url_decode(s).ok()) else { return false };
        let x = pad(&x, 32);
        let y = pad(&y, 32);
        let mut sec1 = vec![0x04];
        sec1.extend_from_slice(&x);
        sec1.extend_from_slice(&y);
        let Ok(key) = p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1) else { return false };
        let Ok(sig) = p256::ecdsa::Signature::from_slice(signature) else { return false };
        return key.verify(data, &sig).is_ok();
    }
    false
}

pub fn fingerprint(der: &[u8]) -> String {
    sha256(der).iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":")
}

pub fn thumb(jwk: &Map<String, Value>) -> Result<String, Error> {
    let kty = jwk.get("kty").and_then(|v| v.as_str()).unwrap_or("");
    let raw = match kty {
        "EC" => format!(
            "{{\"crv\":\"{}\",\"kty\":\"EC\",\"x\":\"{}\",\"y\":\"{}\"}}",
            field(jwk, "crv")?,
            field(jwk, "x")?,
            field(jwk, "y")?
        ),
        "RSA" => format!("{{\"e\":\"{}\",\"kty\":\"RSA\",\"n\":\"{}\"}}", field(jwk, "e")?, field(jwk, "n")?),
        "OKP" => format!(
            "{{\"crv\":\"{}\",\"kty\":\"OKP\",\"x\":\"{}\"}}",
            field(jwk, "crv")?,
            field(jwk, "x")?
        ),
        _ => return Err(fail("config", format!("a {kty} key is not a GNAP client key this library loads"))),
    };
    Ok(b64url(&sha256(raw.as_bytes())))
}

impl ClientKey {
    pub fn private_pem(&self) -> Result<String, Error> {
        match &self.secret {
            Secret::Ec(key) => key
                .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
                .map(|pem| pem.to_string())
                .map_err(|err| fail("config", err.to_string())),
            Secret::Rsa(key) => key
                .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
                .map(|pem| pem.to_string())
                .map_err(|err| fail("config", err.to_string())),
        }
    }
}

fn field(jwk: &Map<String, Value>, name: &str) -> Result<String, Error> {
    jwk.get(name).and_then(|v| v.as_str()).map(|s| s.to_string()).ok_or_else(|| fail("config", format!("the key has no {name}")))
}

fn public_jwk(secret: &Secret) -> Result<Map<String, Value>, Error> {
    let mut jwk = Map::new();
    match secret {
        Secret::Ec(key) => {
            let point = key.verifying_key().to_sec1_point(false);
            jwk.insert("kty".into(), Value::String("EC".into()));
            jwk.insert("crv".into(), Value::String("P-256".into()));
            jwk.insert("x".into(), Value::String(b64url(point.x().unwrap())));
            jwk.insert("y".into(), Value::String(b64url(point.y().unwrap())));
            jwk.insert("alg".into(), Value::String("ES256".into()));
        }
        Secret::Rsa(key) => {
            jwk.insert("kty".into(), Value::String("RSA".into()));
            jwk.insert("n".into(), Value::String(b64url(&key.n().to_bytes_be())));
            jwk.insert("e".into(), Value::String(b64url(&key.e().to_bytes_be())));
            jwk.insert("alg".into(), Value::String("RS256".into()));
        }
    }
    let kid = thumb(&jwk)?;
    jwk.insert("kid".into(), Value::String(kid));
    Ok(jwk)
}

fn parse_private(text: &str) -> Result<Secret, Error> {
    let mut last = "no PEM key".to_string();
    for (label, der) in pem_blocks(text) {
        let result = match label.as_str() {
            "PRIVATE KEY" => SigningKey::from_pkcs8_der(&der).map(Secret::Ec).or_else(|_| RsaPrivateKey::from_pkcs8_der(&der).map(Secret::Rsa)).map_err(|err| err.to_string()),
            "EC PRIVATE KEY" => p256::SecretKey::from_sec1_der(&der).map(|k| Secret::Ec(SigningKey::from(k))).map_err(|err| err.to_string()),
            "RSA PRIVATE KEY" => RsaPrivateKey::from_pkcs1_der(&der).map(Secret::Rsa).map_err(|err| err.to_string()),
            _ => continue,
        };
        match result {
            Ok(secret) => return Ok(secret),
            Err(err) => last = err,
        }
    }
    Err(fail("config", format!("the private key could not be read: {last}")))
}

fn same_public(secret: &Secret, cert_der: &[u8]) -> Result<bool, Error> {
    let (_, cert) = X509Certificate::from_der(cert_der).map_err(|err| fail("config", format!("the certificate could not be read: {err}")))?;
    let public = cert.public_key().parsed().map_err(|err| fail("config", format!("the certificate could not be read: {err}")))?;
    Ok(match (secret, public) {
        (Secret::Ec(key), x509_parser::public_key::PublicKey::EC(point)) => {
            let ours = key.verifying_key().to_sec1_point(false);
            point.data() == ours.as_bytes()
        }
        (Secret::Rsa(key), x509_parser::public_key::PublicKey::RSA(rsa_key)) => {
            BigUint::from_bytes_be(rsa_key.modulus) == *key.n() && BigUint::from_bytes_be(rsa_key.exponent) == *key.e()
        }
        _ => false,
    })
}

fn first_cert_der(text: &str) -> Result<Vec<u8>, Error> {
    pem_blocks(text)
        .into_iter()
        .find(|(label, _)| label == "CERTIFICATE")
        .map(|(_, der)| der)
        .ok_or_else(|| fail("config", "the certificate could not be read: no PEM certificate"))
}

pub(crate) fn cert_blocks(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("-----BEGIN CERTIFICATE-----") {
        let after = &rest[start..];
        if let Some(end) = after.find("-----END CERTIFICATE-----") {
            let stop = end + "-----END CERTIFICATE-----".len();
            out.push(after[..stop].trim().to_string());
            rest = &after[stop..];
        } else {
            break;
        }
    }
    out
}

fn pem_blocks(text: &str) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("-----BEGIN ") {
        let after = &rest[start + "-----BEGIN ".len()..];
        let Some(end_label) = after.find("-----") else { break };
        let label = after[..end_label].to_string();
        let body = &after[end_label + 5..];
        let marker = format!("-----END {label}-----");
        let Some(stop) = body.find(&marker) else { break };
        let b64: String = body[..stop].chars().filter(|c| !c.is_whitespace()).collect();
        if let Ok(der) = base64::engine::general_purpose::STANDARD.decode(b64) {
            out.push((label, der));
        }
        rest = &body[stop + marker.len()..];
    }
    out
}

fn pad(data: &[u8], size: usize) -> Vec<u8> {
    if data.len() >= size {
        return data[data.len() - size..].to_vec();
    }
    let mut out = vec![0u8; size];
    out[size - data.len()..].copy_from_slice(data);
    out
}

fn sign_rsa(key: &RsaPrivateKey, alg: &str, data: &[u8]) -> Result<Vec<u8>, Error> {
    let mut rng = rand::thread_rng();
    match alg {
        "RS256" => Ok(Signer::<rsa::pkcs1v15::Signature>::sign(&rsa::pkcs1v15::SigningKey::<Sha256>::new(key.clone()), data).to_vec()),
        "RS384" => Ok(Signer::<rsa::pkcs1v15::Signature>::sign(&rsa::pkcs1v15::SigningKey::<Sha384>::new(key.clone()), data).to_vec()),
        "RS512" => Ok(Signer::<rsa::pkcs1v15::Signature>::sign(&rsa::pkcs1v15::SigningKey::<Sha512>::new(key.clone()), data).to_vec()),
        "PS256" => Ok(RandomizedSigner::<rsa::pss::Signature>::sign_with_rng(&rsa::pss::SigningKey::<Sha256>::new(key.clone()), &mut rng, data).to_vec()),
        "PS384" => Ok(RandomizedSigner::<rsa::pss::Signature>::sign_with_rng(&rsa::pss::SigningKey::<Sha384>::new(key.clone()), &mut rng, data).to_vec()),
        "PS512" => Ok(RandomizedSigner::<rsa::pss::Signature>::sign_with_rng(&rsa::pss::SigningKey::<Sha512>::new(key.clone()), &mut rng, data).to_vec()),
        _ => Err(fail("config", "a key of this type is not a GNAP client key this library loads")),
    }
}

fn verify_rsa(key: &RsaPublicKey, alg: &str, data: &[u8], signature: &[u8]) -> bool {
    match alg {
        "RS256" => pkcs1_verify::<Sha256>(key, data, signature),
        "RS384" => pkcs1_verify::<Sha384>(key, data, signature),
        "RS512" => pkcs1_verify::<Sha512>(key, data, signature),
        "PS256" => pss_verify::<Sha256>(key, data, signature),
        "PS384" => pss_verify::<Sha384>(key, data, signature),
        "PS512" => pss_verify::<Sha512>(key, data, signature),
        _ => false,
    }
}

fn pkcs1_verify<D: sha2::digest::Digest + const_oid::AssociatedOid>(key: &RsaPublicKey, data: &[u8], signature: &[u8]) -> bool
where
    rsa::pkcs1v15::VerifyingKey<D>: Verifier<rsa::pkcs1v15::Signature>,
{
    let Ok(sig) = rsa::pkcs1v15::Signature::try_from(signature) else { return false };
    rsa::pkcs1v15::VerifyingKey::<D>::new(key.clone()).verify(data, &sig).is_ok()
}

fn pss_verify<D: sha2::digest::Digest + const_oid::AssociatedOid>(key: &RsaPublicKey, data: &[u8], signature: &[u8]) -> bool
where
    rsa::pss::VerifyingKey<D>: Verifier<rsa::pss::Signature>,
{
    let Ok(sig) = rsa::pss::Signature::try_from(signature) else { return false };
    rsa::pss::VerifyingKey::<D>::new(key.clone()).verify(data, &sig).is_ok()
}
