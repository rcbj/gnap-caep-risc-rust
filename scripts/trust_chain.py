# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT

"""Fetch the authorization server's listener CA trust chain and write the file tlsCa names.

GET /tls/server-certificate is tried first, with verification off. If that document is missing, the
handshake's own chain is used. A failure of this program leaves the file as it is and exits 0.

    python scripts/trust_chain.py --config demo/gnap.json
"""

import base64
import json
import os
import re
import socket
import ssl
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit

TIMEOUT_S = 10
CERT_RE = re.compile(r"-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----")


def trust_path(raw, base_dir):
    """A path or file: path. PEM and env: are the configuration's own value, and are not a file to write."""
    if not isinstance(raw, str):
        return None
    value = raw.strip()
    if not value or "-----BEGIN" in value or value.startswith("env:"):
        return None
    path = value[5:] if value.startswith("file:") else value
    if not path:
        return None
    return path if os.path.isabs(path) else str(Path(base_dir) / path)


def _certs(pem):
    return CERT_RE.findall(str(pem or ""))


def _openssl_names(pem):
    """subject, issuer, and sha256 hex from openssl. Empty strings when openssl cannot read the certificate."""
    try:
        done = subprocess.run(
            ["openssl", "x509", "-noout", "-subject", "-issuer", "-fingerprint", "-sha256"],
            input=str(pem).encode(), capture_output=True, timeout=TIMEOUT_S, check=False,
        )
        if done.returncode != 0:
            return "", "", ""
        subject = issuer = digest = ""
        for line in done.stdout.decode("utf-8", "replace").splitlines():
            if line.startswith("subject="):
                subject = line.split("=", 1)[1].strip()
            elif line.startswith("issuer="):
                issuer = line.split("=", 1)[1].strip()
            elif "Fingerprint=" in line:
                digest = line.split("=", 1)[1].strip().replace(":", "")
        return subject, issuer, digest
    except Exception:
        return "", "", ""


def _subject(pem):
    subject, _issuer, digest = _openssl_names(pem)
    if subject or digest:
        return subject, digest
    return pem.split("BEGIN CERTIFICATE", 1)[0].strip() or "certificate", ""


def bundle_of(blocks):
    if not blocks:
        raise RuntimeError("the trust chain has no certificates")
    anchor = blocks[-1]
    for block in reversed(blocks):
        subject, issuer, _digest = _openssl_names(block)
        # A self-signed certificate is the trust anchor when subject and issuer match.
        if subject and subject == issuer:
            anchor = block
            break
    subject, digest = _subject(anchor)
    pretty = ":".join(digest[i:i + 2] for i in range(0, len(digest), 2)).upper() if digest else ""
    return {
        "pem": "\n".join(block.strip() for block in blocks) + "\n",
        "anchor_subject": subject,
        "anchor_fingerprint": pretty,
        "count": len(blocks),
    }


def _servername(hostname):
    try:
        socket.inet_pton(socket.AF_INET, hostname)
        return None
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, hostname.strip("[]"))
        return None
    except OSError:
        return hostname


def fetch_published(origin):
    parts = urlsplit(origin if "://" in origin else f"https://{origin}")
    host = parts.hostname
    port = parts.port or 443
    target = f"{parts.scheme}://{host}:{port}/tls/server-certificate" if port not in (443,) else f"{parts.scheme}://{host}/tls/server-certificate"
    context = ssl._create_unverified_context()
    raw = b""
    status = 0
    conn_host = host
    try:
        import http.client
        conn = http.client.HTTPSConnection(conn_host, port, context=context, timeout=TIMEOUT_S)
        conn.request("GET", "/tls/server-certificate", headers={"accept": "text/plain"})
        response = conn.getresponse()
        status = response.status
        raw = response.read()
        conn.close()
    except Exception as err:
        raise RuntimeError(f"{target} {err}") from err
    if status != 200:
        raise RuntimeError(f"{target} answered {status}")
    return bundle_of(_certs(raw.decode("utf-8", "replace")))


def fetch_handshake(origin):
    parts = urlsplit(origin if "://" in origin else f"https://{origin}")
    host = parts.hostname
    port = parts.port or 443
    servername = _servername(host)
    command = ["openssl", "s_client", "-showcerts", "-connect", f"{host}:{port}"]
    if servername:
        command.extend(["-servername", servername])
    try:
        done = subprocess.run(command, input=b"", capture_output=True, timeout=TIMEOUT_S, check=False)
        blocks = _certs((done.stdout or b"").decode("utf-8", "replace"))
        if blocks:
            return bundle_of(blocks)
    except Exception:
        pass
    context = ssl._create_unverified_context()
    with socket.create_connection((host, port), timeout=TIMEOUT_S) as sock:
        with context.wrap_socket(sock, server_hostname=servername) as tls:
            der = tls.getpeercert(binary_form=True)
    if not der:
        raise RuntimeError(f"{origin} presented no certificate")
    body = base64.encodebytes(der).decode("ascii")
    pem = "-----BEGIN CERTIFICATE-----\n" + body + "-----END CERTIFICATE-----\n"
    return bundle_of([pem])


def fetch_trust_chain(origin):
    try:
        return fetch_published(origin)
    except Exception:
        return fetch_handshake(origin)


def save_trust_chain(origin, dest):
    chain = fetch_trust_chain(origin)
    path = Path(dest)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(chain["pem"], encoding="utf-8")
    chain["path"] = str(path)
    chain["origin"] = origin
    return chain


def _config_from_argv(argv):
    config = os.environ.get("GNAP_CONFIG") or ""
    index = 0
    while index < len(argv):
        if argv[index] == "--config":
            index += 1
            if index >= len(argv) or not argv[index]:
                raise RuntimeError("--config needs a value")
            config = argv[index]
        index += 1
    if not config:
        raise RuntimeError("trust-chain needs --config <file> or GNAP_CONFIG")
    return str(Path(config).resolve())


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    try:
        config_path = _config_from_argv(argv)
        raw = json.loads(Path(config_path).read_text(encoding="utf-8"))
        grant = str(raw.get("grantEndpoint") or "").strip()
        if not grant:
            raise RuntimeError(f"{config_path} has no grantEndpoint")
        dest = trust_path(raw.get("tlsCa"), str(Path(config_path).parent))
        if not dest:
            raise RuntimeError(f"{config_path} tlsCa is not a file this process can update")
        origin = f"{urlsplit(grant).scheme}://{urlsplit(grant).netloc}"
        saved = save_trust_chain(origin, dest)
        print(f"Saved {saved['origin']}'s listener CA trust chain ({saved['count']} certificate(s)) to {saved['path']}")
        print(f"  trust anchor {saved['anchor_subject']}")
        print(f"  sha256 {saved['anchor_fingerprint']}")
    except Exception as err:
        print(f"tls ca: not updated: {err}", file=sys.stderr)
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
