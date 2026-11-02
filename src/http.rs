// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

use crate::codec::b64std_decode;
use crate::error::{fail, Error};
use crate::provider;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, Error as TlsError, RootCertStore, SignatureScheme};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::{Duration, Instant};
use url::Url;
use x509_parser::prelude::*;

const MAX_BYTES: usize = 2 * 1024 * 1024;

#[derive(Clone, Default)]
pub struct TlsOpt {
    pub ca: String,
    pub cert: String,
    pub key: String,
    pub insecure: bool,
}

pub struct Answer {
    pub status: u16,
    pub content_type: String,
    pub body: String,
}

pub fn send(raw_url: &str, method: &str, headers: &[(String, String)], body: Option<&str>, tls: &TlsOpt, code: &'static str) -> Result<Answer, Error> {
    let url = Url::parse(raw_url).map_err(|_| fail(code, format!("{raw_url} is not an http(s) URL")))?;
    if url.scheme() != "http" && url.scheme() != "https" {
        return Err(fail(code, format!("{raw_url} is not an http(s) URL")));
    }
    let host = url.host_str().ok_or_else(|| fail(code, format!("{raw_url} is not an http(s) URL")))?;
    let port = url.port_or_known_default().unwrap_or(80);
    let mut stream = TcpStream::connect((host, port)).map_err(|err| fail(code, format!("{raw_url}: {err}")))?;
    stream.set_read_timeout(Some(Duration::from_secs(15))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(15))).ok();
    let deadline = Instant::now() + Duration::from_secs(15);
    if url.scheme() == "https" {
        let name = ServerName::try_from(host.to_string()).map_err(|_| fail(code, format!("{raw_url} is not an http(s) URL")))?;
        let config = tls_config(tls, code)?;
        let mut conn = ClientConnection::new(config, name).map_err(|err| fail(code, format!("{raw_url}: {err}")))?;
        let mut tls_stream = rustls::Stream::new(&mut conn, &mut stream);
        exchange(&mut tls_stream, &url, method, headers, body, deadline, code)
    } else {
        exchange(&mut stream, &url, method, headers, body, deadline, code)
    }
}

fn tls_config(tls: &TlsOpt, code: &'static str) -> Result<Arc<ClientConfig>, Error> {
    let verifier = Arc::new(Pinned::new(&tls.ca, tls.insecure).map_err(|err| fail(code, err.message.clone()))?);
    let builder = ClientConfig::builder_with_provider(provider().clone())
        .with_protocol_versions(&[&rustls::version::TLS12, &rustls::version::TLS13])
        .map_err(|err| fail(code, err.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(verifier);
    let mut config = if tls.cert.trim().is_empty() || tls.key.trim().is_empty() {
        builder.with_no_client_auth()
    } else {
        let certs = load_certs(&tls.cert).map_err(|err| fail(code, err.message))?;
        let key = load_key(&tls.key).map_err(|err| fail(code, err.message))?;
        builder.with_client_auth_cert(certs, key).map_err(|err| fail(code, err.to_string()))?
    };
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

fn exchange<S: Read + Write>(stream: &mut S, url: &Url, method: &str, headers: &[(String, String)], body: Option<&str>, deadline: Instant, code: &'static str) -> Result<Answer, Error> {
    let path = if url.path().is_empty() { "/" } else { url.path() };
    let target = format!("{path}{}", url.query().map(|q| format!("?{q}")).unwrap_or_default());
    let host = url.host_str().unwrap_or("");
    let host_header = match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    };
    let mut request = format!("{} {} HTTP/1.1\r\nhost: {}\r\nconnection: close\r\n", method, target, host_header);
    let mut saw_type = false;
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("host") || name.eq_ignore_ascii_case("content-length") || name.eq_ignore_ascii_case("connection") {
            continue;
        }
        if name.eq_ignore_ascii_case("content-type") {
            saw_type = true;
        }
        request.push_str(&format!("{}: {}\r\n", name.to_ascii_lowercase(), value));
    }
    if let Some(body) = body {
        if !saw_type {
            request.push_str("content-type: application/json\r\n");
        }
        request.push_str(&format!("content-length: {}\r\n\r\n{}", body.len(), body));
    } else {
        request.push_str("\r\n");
    }
    stream.write_all(request.as_bytes()).map_err(|err| fail(code, format!("{url}: {err}")))?;
    let raw = read_message(stream, deadline, code, url.as_str())?;
    parse_response(&raw, code, url.as_str())
}

fn read_message<S: Read>(stream: &mut S, deadline: Instant, code: &'static str, url: &str) -> Result<Vec<u8>, Error> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    loop {
        if Instant::now() > deadline {
            return Err(fail(code, format!("{url} did not answer within 15 s")));
        }
        let n = match stream.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => n,
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock || err.kind() == std::io::ErrorKind::TimedOut => {
                return Err(fail(code, format!("{url} did not answer within 15 s")));
            }
            Err(err) => return Err(fail(code, format!("{url}: {err}"))),
        };
        buf.extend_from_slice(&tmp[..n]);
        if buf.len() > MAX_BYTES + 8192 {
            return Err(fail(code, format!("{url} answered more than {MAX_BYTES} bytes")));
        }
        if let Some(split) = find_header_end(&buf) {
            let header = String::from_utf8_lossy(&buf[..split]).to_string();
            if header_chunked(&header) {
                continue;
            }
            if let Some(need) = content_length(&header).map_err(|err| fail(code, err.message))? {
                if buf.len() >= split + 4 + need {
                    return Ok(buf);
                }
            }
        }
    }
    Ok(buf)
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn header_chunked(header: &str) -> bool {
    header.lines().any(|line| {
        line.split_once(':').is_some_and(|(name, value)| name.eq_ignore_ascii_case("transfer-encoding") && value.to_ascii_lowercase().contains("chunked"))
    })
}

fn content_length(header: &str) -> Result<Option<usize>, Error> {
    for line in header.split("\r\n").skip(1) {
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                return Ok(Some(value.trim().parse::<usize>().map_err(|_| fail("protocol", "content-length is not a number"))?));
            }
        }
    }
    Ok(None)
}

fn parse_response(raw: &[u8], code: &'static str, url: &str) -> Result<Answer, Error> {
    let split = find_header_end(raw).ok_or_else(|| fail(code, format!("{url}: the response was incomplete")))?;
    let header = String::from_utf8_lossy(&raw[..split]).to_string();
    let mut body = raw[split + 4..].to_vec();
    let status = header.lines().next().and_then(|line| line.split_whitespace().nth(1)).and_then(|s| s.parse().ok()).unwrap_or(0);
    let mut content_type = String::new();
    let mut chunked = false;
    for line in header.split("\r\n").skip(1) {
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-type") {
                content_type = value.trim().to_string();
            }
            if name.eq_ignore_ascii_case("transfer-encoding") && value.to_ascii_lowercase().contains("chunked") {
                chunked = true;
            }
        }
    }
    if chunked {
        body = unchunk(&body).map_err(|err| fail(code, err.message))?;
    }
    if body.len() > MAX_BYTES {
        return Err(fail(code, format!("{url} answered more than {MAX_BYTES} bytes")));
    }
    Ok(Answer { status, content_type, body: String::from_utf8_lossy(&body).to_string() })
}

fn unchunk(data: &[u8]) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    let mut rest = data;
    loop {
        let Some(split) = rest.windows(2).position(|w| w == b"\r\n") else { break };
        let line = std::str::from_utf8(&rest[..split]).unwrap_or("0");
        let size = usize::from_str_radix(line.split(';').next().unwrap_or("0").trim(), 16).unwrap_or(0);
        rest = &rest[split + 2..];
        if size == 0 {
            break;
        }
        if rest.len() < size + 2 {
            return Err(fail("protocol", "the chunked response was incomplete"));
        }
        out.extend_from_slice(&rest[..size]);
        rest = &rest[size + 2..];
    }
    Ok(out)
}

#[derive(Debug)]
struct Pinned {
    roots: Vec<CertificateDer<'static>>,
    insecure: bool,
}

impl Pinned {
    fn new(ca_pem: &str, insecure: bool) -> Result<Self, Error> {
        let mut roots = Vec::new();
        for block in crate::keys::cert_blocks(ca_pem) {
            let der = pem_der(&block)?;
            roots.push(CertificateDer::from(der));
        }
        Ok(Self { roots, insecure })
    }
}

impl ServerCertVerifier for Pinned {
    fn verify_server_cert(&self, end_entity: &CertificateDer<'_>, _intermediates: &[CertificateDer<'_>], server_name: &ServerName<'_>, _ocsp: &[u8], _now: UnixTime) -> Result<ServerCertVerified, TlsError> {
        if self.insecure {
            return Ok(ServerCertVerified::assertion());
        }
        let exact = self.roots.iter().any(|one| one.as_ref() == end_entity.as_ref());
        if exact {
            if name_matches(end_entity.as_ref(), server_name) {
                return Ok(ServerCertVerified::assertion());
            }
            return Err(TlsError::General("pinned certificate name mismatch".into()));
        }
        let mut store = RootCertStore::empty();
        for cert in &self.roots {
            let _ = store.add(cert.clone());
        }
        let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(store), provider().clone())
            .build()
            .map_err(|err| TlsError::General(err.to_string().into()))?;
        verifier.verify_server_cert(end_entity, _intermediates, server_name, _ocsp, _now)
    }

    fn verify_tls12_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &provider().signature_verification_algorithms)
    }

    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &provider().signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        provider().signature_verification_algorithms.supported_schemes()
    }
}

fn name_matches(der: &[u8], server_name: &ServerName<'_>) -> bool {
    let Ok((_, cert)) = X509Certificate::from_der(der) else { return false };
    let Ok(Some(sans)) = cert.subject_alternative_name() else { return false };
    let host = match server_name {
        ServerName::DnsName(name) => name.as_ref().to_string(),
        ServerName::IpAddress(ip) => match ip {
            rustls::pki_types::IpAddr::V4(addr) => std::net::Ipv4Addr::from(*addr).to_string(),
            rustls::pki_types::IpAddr::V6(addr) => std::net::Ipv6Addr::from(*addr).to_string(),
        },
        _ => return false,
    };
    for name in &sans.value.general_names {
        match name {
            GeneralName::DNSName(dns) if dns.eq_ignore_ascii_case(&host) => return true,
            GeneralName::IPAddress(bytes) => {
                if let Ok(ip) = host.parse::<std::net::IpAddr>() {
                    let raw: &[u8] = match ip {
                        std::net::IpAddr::V4(v4) => &v4.octets(),
                        std::net::IpAddr::V6(v6) => &v6.octets(),
                    };
                    if raw == *bytes {
                        return true;
                    }
                }
            }
            _ => {}
        }
    }
    false
}

fn load_certs(pem: &str) -> Result<Vec<CertificateDer<'static>>, Error> {
    let certs: Vec<_> = crate::keys::cert_blocks(pem).into_iter().map(|block| pem_der(&block).map(CertificateDer::from)).collect::<Result<_, _>>()?;
    if certs.is_empty() {
        return Err(fail("config", "the certificate could not be read: no PEM certificate"));
    }
    Ok(certs)
}

fn load_key(pem: &str) -> Result<PrivateKeyDer<'static>, Error> {
    for (label, der) in pem_pairs(pem) {
        if label == "PRIVATE KEY" || label == "RSA PRIVATE KEY" || label == "EC PRIVATE KEY" {
            return Ok(PrivateKeyDer::try_from(der).map_err(|err| fail("config", format!("the private key could not be read: {err}")))?);
        }
    }
    Err(fail("config", "the private key could not be read: no PEM key"))
}

fn pem_der(block: &str) -> Result<Vec<u8>, Error> {
    pem_pairs(block).into_iter().next().map(|(_, der)| der).ok_or_else(|| fail("config", "the certificate could not be read"))
}

fn pem_pairs(text: &str) -> Vec<(String, Vec<u8>)> {
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
        if let Ok(der) = b64std_decode(&b64) {
            out.push((label, der));
        }
        rest = &body[stop + marker.len()..];
    }
    out
}
