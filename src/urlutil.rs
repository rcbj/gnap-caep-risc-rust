// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

use crate::error::{fail, Error};
use url::Url;

pub fn origin(raw: &str) -> Result<String, Error> {
    let url = absolute(raw)?;
    Ok(format!("{}://{}", url.scheme(), host_port(&url)))
}

pub fn href(raw: &str) -> Result<String, Error> {
    let url = absolute(raw)?;
    let path = if url.path().is_empty() { "/" } else { url.path() };
    Ok(format!("{}://{}{}{}", url.scheme(), host_port(&url), path, url.query().map(|q| format!("?{q}")).unwrap_or_default()))
}

pub fn is_loopback(raw: &str) -> bool {
    let Ok(url) = Url::parse(raw) else { return false };
    matches!(url.host_str().unwrap_or("").trim_matches(['[', ']']).to_ascii_lowercase().as_str(), "localhost" | "127.0.0.1" | "::1")
}

pub fn well_known(issuer: &str, suffix: &str) -> Result<Vec<String>, Error> {
    let url = absolute(issuer)?;
    let origin = format!("{}://{}", url.scheme(), host_port(&url));
    let mut path = url.path().trim_end_matches('/').to_string();
    if path == "/" {
        path.clear();
    }
    let inserted = format!("{origin}/.well-known/{suffix}{path}");
    let appended = format!("{origin}{path}/.well-known/{suffix}");
    if inserted == appended {
        Ok(vec![inserted])
    } else {
        Ok(vec![inserted, appended])
    }
}

fn absolute(raw: &str) -> Result<Url, Error> {
    let url = Url::parse(raw).map_err(|_| fail("validation", format!("{raw} is not a URL")))?;
    if url.scheme() != "http" && url.scheme() != "https" || url.host_str().is_none() {
        return Err(fail("validation", format!("{raw} is not a URL")));
    }
    Ok(url)
}

fn host_port(url: &Url) -> String {
    let host = url.host_str().unwrap_or("");
    let shown = if host.contains(':') && !host.starts_with('[') { format!("[{host}]") } else { host.to_string() };
    match url.port() {
        Some(port) => format!("{shown}:{port}"),
        None => shown,
    }
}
