// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

//! tlsCa holds iya-sts's whole listener CA trust chain (leaf, TLS Issuing CA,
//! Intermediate, Root). These tests serve HTTPS from such a chain and check
//! that the install script writes all of it to the file tlsCa names (from
//! GET /tls/server-certificate, and from the handshake when that is missing),
//! that the library takes that file as its trust store with every block an
//! anchor, that a pinned certificate counts only when it is the presented leaf,
//! and that the host name is verified on both paths.

use crate::http::{send, TlsOpt};
use rcgen::{BasicConstraints, Certificate, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose, SanType};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, ServerConnection};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

struct Ca {
    cert: Certificate,
    key: KeyPair,
}

struct Chain {
    root: Ca,
    intermediate: Ca,
    issuing: Ca,
}

struct Leaf {
    cert: Certificate,
    key: KeyPair,
}

fn ca_params(name: &str) -> CertificateParams {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, name);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign, KeyUsagePurpose::DigitalSignature];
    params
}

fn chain() -> Chain {
    let root_key = KeyPair::generate().unwrap();
    let root = ca_params("test Root CA").self_signed(&root_key).unwrap();
    let intermediate_key = KeyPair::generate().unwrap();
    let intermediate = ca_params("test Intermediate CA").signed_by(&intermediate_key, &root, &root_key).unwrap();
    let issuing_key = KeyPair::generate().unwrap();
    let issuing = ca_params("test TLS Issuing CA").signed_by(&issuing_key, &intermediate, &intermediate_key).unwrap();
    Chain {
        root: Ca { cert: root, key: root_key },
        intermediate: Ca { cert: intermediate, key: intermediate_key },
        issuing: Ca { cert: issuing, key: issuing_key },
    }
}

/// A leaf issued by `issuer`, with the given DNS names and IP literals as SANs.
fn leaf(issuer: &Ca, dns: &[&str], ips: &[IpAddr]) -> Leaf {
    let mut params = CertificateParams::new(dns.iter().map(|name| (*name).to_string()).collect::<Vec<_>>()).unwrap();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, dns.first().copied().unwrap_or("listener"));
    for ip in ips {
        params.subject_alt_names.push(SanType::IpAddress(*ip));
    }
    params.is_ca = IsCa::NoCa;
    let key = KeyPair::generate().unwrap();
    let cert = params.signed_by(&key, &issuer.cert, &issuer.key).unwrap();
    Leaf { cert, key }
}

fn loopback() -> Vec<IpAddr> {
    vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))]
}

/// Leaf first, Root last: what iya-sts publishes and presents.
fn pem_of(leaf: &Leaf, chain: &Chain) -> String {
    format!("{}{}{}{}", leaf.cert.pem(), chain.issuing.cert.pem(), chain.intermediate.cert.pem(), chain.root.cert.pem())
}

/// HTTPS on 127.0.0.1 presenting `presented` (leaf first) under `leaf`'s key. `published`
/// decides whether GET /tls/server-certificate answers that chain or 404. Returns the port.
fn serve(leaf: &Leaf, presented: Vec<Vec<u8>>, published: Option<String>) -> u16 {
    let certs = presented.into_iter().map(CertificateDer::from).collect::<Vec<_>>();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf.key.serialize_der()));
    let mut config = ServerConfig::builder_with_provider(crate::provider())
        .with_protocol_versions(&[&rustls::version::TLS12, &rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let config = Arc::new(config);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut tcp) = stream else { continue };
            tcp.set_read_timeout(Some(Duration::from_secs(8))).ok();
            tcp.set_write_timeout(Some(Duration::from_secs(8))).ok();
            let config = config.clone();
            let published = published.clone();
            std::thread::spawn(move || {
                let Ok(mut conn) = ServerConnection::new(config) else { return };
                let mut tls = rustls::Stream::new(&mut conn, &mut tcp);
                let mut request = Vec::new();
                let mut buffer = [0u8; 2048];
                while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    match tls.read(&mut buffer) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => request.extend_from_slice(&buffer[..n]),
                    }
                }
                let text = String::from_utf8_lossy(&request);
                let path = text.split_whitespace().nth(1).unwrap_or("/").to_string();
                let (status, body) = match (&published, path.as_str()) {
                    (Some(pem), "/tls/server-certificate") => ("200 OK", pem.clone()),
                    (None, "/tls/server-certificate") => ("404 Not Found", String::new()),
                    _ => ("200 OK", "ok".to_string()),
                };
                let _ = write!(tls, "HTTP/1.1 {status}\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len());
                let _ = tls.flush();
            });
        }
    });
    port
}

fn full_chain(leaf: &Leaf, chain: &Chain) -> Vec<Vec<u8>> {
    vec![
        leaf.cert.der().to_vec(),
        chain.issuing.cert.der().to_vec(),
        chain.intermediate.cert.der().to_vec(),
        chain.root.cert.der().to_vec(),
    ]
}

fn get(url: &str, ca: &str) -> Result<u16, String> {
    let tls = TlsOpt { ca: ca.to_string(), ..TlsOpt::default() };
    send(url, "GET", &[], None, &tls, "discovery").map(|answer| answer.status).map_err(|err| err.message)
}

fn blocks(pem: &str) -> usize {
    pem.matches("-----BEGIN CERTIFICATE-----").count()
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("gnap-caep-risc-rust-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Runs scripts/trust_chain.py on a configuration whose tlsCa is the demo default, and returns
/// what it printed and what it wrote at tlsCa's path.
fn save_with_script(dir: &Path, port: u16) -> (String, String) {
    std::fs::write(dir.join("gnap.json"), format!(r#"{{
        "grantEndpoint": "https://127.0.0.1:{port}/gnap",
        "application": "gnap-caep-risc-demo",
        "tlsCa": "generated/idp-ca.pem"
    }}"#)).unwrap();
    let script = format!("{}/scripts/trust_chain.py", env!("CARGO_MANIFEST_DIR"));
    let out = Command::new("python3").arg(&script).arg("--config").arg(dir.join("gnap.json")).output().unwrap();
    assert!(out.status.success(), "{}\n{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    let printed = String::from_utf8_lossy(&out.stdout).into_owned();
    let written = std::fs::read_to_string(dir.join("generated/idp-ca.pem")).unwrap_or_default();
    (printed, written)
}

/// The install script resolves tlsCa the way trust_chain.py does: relative to the configuration.
#[test]
fn install_script_saves_the_chain_where_tls_ca_names_it() {
    let dir = scratch("files-of");
    std::fs::write(dir.join("gnap.json"), r#"{"grantEndpoint": "https://localhost:8081/gnap", "application": "gnap-caep-risc-demo", "tlsCa": "generated/idp-ca.pem"}"#).unwrap();
    let script = r#"import importlib.util, sys
from pathlib import Path
spec = importlib.util.spec_from_file_location("configure_iya_sts", sys.argv[1])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
files = mod.files_of(str(Path(sys.argv[2]) / "gnap.json"), "http://localhost:3000")
print(files["tlsCa"])
"#;
    let configure = format!("{}/scripts/configure_iya_sts.py", env!("CARGO_MANIFEST_DIR"));
    let out = Command::new("python3").arg("-c").arg(script).arg(&configure).arg(&dir).output().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let printed = String::from_utf8_lossy(&out.stdout);
    assert_eq!(Path::new(printed.trim()), dir.join("generated/idp-ca.pem"));
}

#[test]
fn script_writes_the_published_chain_to_tls_ca() {
    let chain = chain();
    let leaf = leaf(&chain.issuing, &["localhost"], &loopback());
    let pem = pem_of(&leaf, &chain);
    let port = serve(&leaf, full_chain(&leaf, &chain), Some(pem.clone()));
    let dir = scratch("published");
    let (printed, written) = save_with_script(&dir, port);
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(blocks(&written), 4, "{written}");
    assert_eq!(written.trim(), pem.trim());
    assert!(printed.contains("4 certificate(s)"), "{printed}");
    assert!(printed.contains("test Root CA"), "{printed}");
}

#[test]
fn script_falls_back_to_the_handshake_chain() {
    let chain = chain();
    let leaf = leaf(&chain.issuing, &["localhost"], &loopback());
    let port = serve(&leaf, full_chain(&leaf, &chain), None);
    let dir = scratch("handshake");
    let (printed, written) = save_with_script(&dir, port);
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(blocks(&written), 4, "{written}");
    assert!(printed.contains("test Root CA"), "{printed}");
}

#[test]
fn library_trusts_the_whole_chain_file_by_ip_and_by_name() {
    let chain = chain();
    let leaf = leaf(&chain.issuing, &["localhost"], &loopback());
    let pem = pem_of(&leaf, &chain);
    let port = serve(&leaf, full_chain(&leaf, &chain), Some(pem.clone()));
    assert_eq!(get(&format!("https://127.0.0.1:{port}/x"), &pem), Ok(200));
    assert_eq!(get(&format!("https://localhost:{port}/x"), &pem), Ok(200));
}

/// Every block is an anchor: a file holding only the Root, or only the Intermediate, verifies
/// the presented chain.
#[test]
fn every_block_of_the_file_is_an_anchor() {
    let chain = chain();
    let leaf = leaf(&chain.issuing, &["localhost"], &loopback());
    let port = serve(&leaf, full_chain(&leaf, &chain), None);
    let url = format!("https://127.0.0.1:{port}/x");
    assert_eq!(get(&url, &chain.root.cert.pem()), Ok(200));
    assert_eq!(get(&url, &chain.intermediate.cert.pem()), Ok(200));
    let other = chain_unrelated();
    assert!(get(&url, &other).is_err());
}

fn chain_unrelated() -> String {
    let key = KeyPair::generate().unwrap();
    ca_params("another Root CA").self_signed(&key).unwrap().pem()
}

/// A pinned certificate counts only as the presented LEAF. A server that sends its own leaf
/// followed by the real (public) CA certificates is refused.
#[test]
fn a_forged_leaf_followed_by_the_real_cas_is_refused() {
    let chain = chain();
    let real = leaf(&chain.issuing, &["localhost"], &loopback());
    let pem = pem_of(&real, &chain);
    // The forger's own CA under the real Issuing CA's name, so only the signature differs.
    let forger_key = KeyPair::generate().unwrap();
    let forger = Ca { cert: ca_params("test TLS Issuing CA").self_signed(&forger_key).unwrap(), key: forger_key };
    let forged = leaf(&forger, &["localhost"], &loopback());
    let presented = vec![
        forged.cert.der().to_vec(),
        chain.issuing.cert.der().to_vec(),
        chain.intermediate.cert.der().to_vec(),
        chain.root.cert.der().to_vec(),
    ];
    let port = serve(&forged, presented, None);
    let refused = get(&format!("https://127.0.0.1:{port}/x"), &pem);
    assert!(refused.is_err(), "a forged leaf before the real CAs was accepted");
    // The forger's leaf alone, self-signed, is refused as well.
    let alone_key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    params.subject_alt_names.push(SanType::IpAddress(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
    let alone = Leaf { cert: params.self_signed(&alone_key).unwrap(), key: alone_key };
    let presented = vec![alone.cert.der().to_vec(), chain.root.cert.der().to_vec()];
    let port = serve(&alone, presented, None);
    assert!(get(&format!("https://127.0.0.1:{port}/x"), &pem).is_err());
}

/// The right chain under the wrong name is refused, whether the leaf is pinned in the file
/// (the whole chain) or verified to an anchor (the Root alone).
#[test]
fn the_right_chain_with_the_wrong_name_is_refused() {
    let chain = chain();
    let leaf = leaf(&chain.issuing, &["sts.example.com"], &[]);
    let pem = pem_of(&leaf, &chain);
    let port = serve(&leaf, full_chain(&leaf, &chain), None);
    for url in [format!("https://127.0.0.1:{port}/x"), format!("https://localhost:{port}/x")] {
        let pinned = get(&url, &pem);
        assert!(pinned.is_err(), "{url} accepted with the whole chain as tlsCa");
        let anchored = get(&url, &chain.root.cert.pem());
        assert!(anchored.is_err(), "{url} accepted with the Root as tlsCa");
    }
}
