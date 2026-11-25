#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""Sign this demo in to a fresh iya-sts and confirm two Shared Signals events.

Starts the latest main branch of iya-sts in memory mode, with persistence and
clustering off and no request workers, unless IYA_STS_URL is already set.
Registers the demo, signs in through it, emits a credential-change and a
session-revoked event, and requires the demo's /live-status to show both. The
second one also ends the local session.

The unit suite stays `docker build --target test`. This file is the live half.
It uses only the host's Python standard library and Docker. Cargo never runs on
the host: the key is generated with openssl and the client registered by
`scripts/configure_iya_sts.py`, both in this repository's `tools` image as the
invoking user, and the demo runs in its own image. Do not bind port 3000, 8081,
or 18481 to 18495.

IYA_STS_URL, when set, uses an iya-sts that is already running and does not
stop it. This script never removes iya-sts-live-main, iya-sts-live-probe, or a
container whose name starts with sts. Otherwise it clones main (or builds
IYA_STS_SRC) and removes only the container it started, iya-sts-live-gnap-caep-risc-rust.
The demo container it removes is gnap-caep-risc-rust-live-demo.

The trust chain goes in the way a user's does. The script copies this checkout
to a scratch build context (without .git, target or demo/generated), generates
the client key and runs the install script there, which writes the listener CA
trust chain to the file tlsCa names, and only then builds the demo image, which
carries that file from build time. The demo container gets no CA mount (only
the client key and certificate, one file each) and does not refresh the chain
at start (TLS_CA_REFRESH=0). tlsCa is never rewritten. This script reads the
saved chain for its own HTTPS client.

--pep (or LIVE_PEP=1) adds the demo's embedded PEP: the install script sets it up
(--pep central), the demo is checked on /orders/42 in central and then local
mode, and the application's own policy is flipped to deny read, which local
mode must apply by pep-policies-changed. LIVE_KEEP=1 leaves the containers.

--authzen runs the embedded PEP's differential test instead (#39): it registers
the client, provisions src/tests/authzen_cases.json (people, catalogue rows,
ALFA policies, applications, a central and a local PEP per group), and runs the
env-gated Rust test live_central_and_local_agree in rust:1-bookworm. The final
JSON reports cases, centralEqualsLocal, bothEqualExpected and the mismatches.
--write-xacml takes the XACML iya-sts stored into the table.
"""

import base64
import email.message
import http.client
import http.cookiejar
import json
import os
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STS_REPO = "https://github.com/rcbj/iya-sts.git"
CAEP = "https://schemas.openid.net/secevent/caep/event-type/"
CREDENTIAL_CHANGE = CAEP + "credential-change"
SESSION_REVOKED = CAEP + "session-revoked"
FORBIDDEN_PORTS = {3000, 8081, *range(18481, 18496)}
PROTECTED_CONTAINERS = {"iya-sts-live-main", "iya-sts-live-probe"}

PROFILE = {
    "repo": "gnap-caep-risc-rust",
    "login_path": "/login",
    "status_path": "/live-status",
    "configure": ["python3", "scripts/configure_iya_sts.py"],
    # A P-256 key and a self-signed certificate at the paths demo/gnap.json names, relative to
    # the configuration file. The certificate is what iya-sts registers for mutual TLS.
    "generate_key": [
        "sh", "-c",
        "mkdir -p /work/generated && openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes"
        " -keyout /work/generated/client.key -out /work/generated/client.crt -days 1095"
        " -subj /CN=gnap-caep-risc-demo -addext basicConstraints=critical,CA:FALSE"
        " -addext keyUsage=critical,digitalSignature 2>/dev/null",
    ],
    "config_file": "demo/gnap.json",
    # The NAME of the variable that carries the test user's password to the install
    # script (-e NAME). The key is not called "password...": the name goes on the printed
    # command line, and a static checker treats such a key as the password itself.
    "user_env": "GNAP_DEMO_USER_PASSWORD",
    "test_user": "gnap-demo-user",
}


class LoopbackCookiePolicy(http.cookiejar.DefaultCookiePolicy):
    """Send a Secure cookie to loopback HTTP. Browsers do this for localhost."""

    def _loopback(self, request):
        host = (request.host or "").split(":")[0].strip("[]")
        return host in ("localhost", "127.0.0.1", "::1")

    def set_ok_secure(self, cookie, request):
        if cookie.secure and self._loopback(request):
            return True
        return http.cookiejar.DefaultCookiePolicy.set_ok_secure(self, cookie, request)

    def return_ok_secure(self, cookie, request):
        if cookie.secure and self._loopback(request):
            return True
        return http.cookiejar.DefaultCookiePolicy.return_ok_secure(self, cookie, request)


class _CookieResponse:
    def __init__(self, headers):
        self._headers = email.message.Message()
        for name, value in headers:
            self._headers[name] = value

    def info(self):
        return self._headers


class FormFinder(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms = []
        self._form = None

    def handle_starttag(self, tag, attrs):
        found = {key.lower(): value for key, value in attrs}
        if tag == "form":
            self._form = {
                "action": found.get("action") or "",
                "method": (found.get("method") or "get").lower(),
                "fields": [],
            }
        elif tag == "input" and self._form is not None and found.get("name"):
            self._form["fields"].append((found["name"], found.get("value") or ""))

    def handle_endtag(self, tag):
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None


class Client:
    def __init__(self, ca_file):
        self.jar = http.cookiejar.CookieJar(policy=LoopbackCookiePolicy())
        self.ssl = ssl.create_default_context(cafile=str(ca_file))
        self.ssl.minimum_version = ssl.TLSVersion.TLSv1_2

    def request(self, method, url, body=None, headers=None, timeout=60):
        parts = urllib.parse.urlsplit(url)
        if parts.scheme not in ("http", "https"):
            raise RuntimeError(f"refusing {url}")
        port = parts.port or (443 if parts.scheme == "https" else 80)
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        target = urllib.request.Request(url, headers=headers or {}, method=method)
        self.jar.add_cookie_header(target)
        sent = {key.lower(): value for key, value in (headers or {}).items()}
        cookie = target.get_header("Cookie")
        if cookie and "cookie" not in sent:
            sent["cookie"] = cookie
        if body is not None and "content-length" not in sent:
            sent["content-length"] = str(len(body))
        if parts.scheme == "https":
            conn = http.client.HTTPSConnection(parts.hostname, port, context=self.ssl, timeout=timeout)
        else:
            conn = http.client.HTTPConnection(parts.hostname, port, timeout=timeout)
        try:
            conn.request(method, path, body=body, headers=sent)
            response = conn.getresponse()
            payload = response.read()
            header_pairs = response.getheaders()
        finally:
            conn.close()
        self.jar.extract_cookies(_CookieResponse(header_pairs), target)
        return response.status, header_pairs, payload


def header_map(pairs):
    found = {}
    for name, value in pairs:
        found.setdefault(name.lower(), []).append(value)
    return found


def one_header(pairs, name):
    values = header_map(pairs).get(name.lower()) or []
    return values[-1] if values else ""


def resolve_url(base, location):
    return urllib.parse.urljoin(base, location)


def origin_of(url):
    parts = urllib.parse.urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


def path_of(url):
    return urllib.parse.urlsplit(url).path or "/"


def query_of(url):
    return urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)


def run(command, **kwargs):
    print("+ " + " ".join(command), flush=True)
    completed = subprocess.run(command, check=False, text=True, **kwargs)
    if completed.returncode != 0:
        if completed.stdout:
            print(completed.stdout, flush=True)
        if completed.stderr:
            print(completed.stderr, file=sys.stderr, flush=True)
        raise RuntimeError(f"{command[0]} exited {completed.returncode}")
    return completed


def docker(*args, **kwargs):
    return run(["docker", *args], **kwargs)


def docker_rm(name):
    if not name:
        return
    if name in PROTECTED_CONTAINERS or name.startswith("sts"):
        raise RuntimeError(f"refusing to remove {name}")
    subprocess.run(["docker", "rm", "-f", name], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def wait_port(port, timeout):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), 2):
                return
        except OSError:
            time.sleep(1)
    raise RuntimeError(f"127.0.0.1:{port} did not accept a connection")


def wait_ready(origin, timeout):
    """Wait for iya-sts discovery to answer. Readiness only: nothing is trusted from it."""
    parts = urllib.parse.urlsplit(origin)
    context = ssl._create_unverified_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        conn = http.client.HTTPSConnection(parts.hostname, parts.port or 443, context=context, timeout=10)
        try:
            conn.request("GET", "/.well-known/openid-configuration")
            response = conn.getresponse()
            response.read()
            if response.status == 200:
                return
            last = f"answered {response.status}"
        except OSError as err:
            last = str(err)
        finally:
            conn.close()
        time.sleep(2)
    raise RuntimeError(f"{origin} discovery did not answer 200: {last}")


def copy_context(dest):
    """This checkout as a build context, without .git, target, or demo/generated."""
    clutter = {".git", "target", "__pycache__", ".venv", "venv"}

    def ignore(directory, names):
        skipped = {name for name in names if name in clutter}
        if Path(directory).resolve() == (ROOT / "demo").resolve() and "generated" in names:
            skipped.add("generated")
        return skipped

    shutil.copytree(ROOT, dest, ignore=ignore)


def _swap_origin(value, origin):
    parts = urllib.parse.urlsplit(value)
    base = urllib.parse.urlsplit(origin)
    return urllib.parse.urlunsplit((base.scheme, base.netloc, parts.path or "", parts.query, parts.fragment))


def _localhost_8081(value):
    parts = urllib.parse.urlsplit(value)
    return parts.scheme == "https" and (parts.hostname or "") == "localhost" and (parts.port or 443) == 8081


def rewrite_config(source, dest, sts_origin, demo_origin):
    """Point the demo at this iya-sts and this demo origin. tlsCa is left alone."""
    raw = json.loads(source.read_text(encoding="utf-8"))
    sts = sts_origin.rstrip("/")
    demo = demo_origin.rstrip("/")
    for key in ("grantEndpoint", "transmitterIssuer", "idTokenIssuer"):
        value = raw.get(key)
        if isinstance(value, str) and _localhost_8081(value):
            raw[key] = _swap_origin(value, sts)
    finish = raw.get("finishUri")
    if isinstance(finish, str) and finish:
        parts = urllib.parse.urlsplit(finish)
        if (parts.hostname or "") in ("localhost", "127.0.0.1", "::1"):
            raw["finishUri"] = demo + (parts.path or "/")
    display = raw.get("display")
    if isinstance(display, dict):
        uri = display.get("uri")
        if isinstance(uri, str) and uri:
            parts = urllib.parse.urlsplit(uri)
            if (parts.hostname or "") in ("localhost", "127.0.0.1", "::1"):
                display["uri"] = demo + (parts.path or "/")
                raw["display"] = display
    ssf = raw.get("ssf")
    if not isinstance(ssf, dict):
        ssf = {}
    transmitter = ssf.get("transmitter")
    if isinstance(transmitter, str) and _localhost_8081(transmitter):
        ssf["transmitter"] = _swap_origin(transmitter, sts).rstrip("/") or sts
    elif not transmitter:
        ssf["transmitter"] = sts
    ssf["pollIntervalMs"] = 1000
    raw["ssf"] = ssf
    dest.write_text(json.dumps(raw, indent=2) + "\n", encoding="utf-8")


def json_body(payload):
    try:
        parsed = json.loads(payload.decode() if payload else "{}")
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def autopost_form(payload):
    parser = FormFinder()
    try:
        parser.feed(payload.decode("utf-8", "replace"))
    except Exception:
        return None
    for form in parser.forms:
        names = {name for name, _value in form["fields"]}
        if names.intersection({"SAMLResponse", "wresult"}) and form["method"] == "post":
            return form
    return None


class Driver:
    def __init__(self, client, sts_origin, demo_origin, username, password):
        self.client = client
        self.sts_origin = sts_origin.rstrip("/")
        self.demo_origin = demo_origin.rstrip("/")
        self.username = username
        self.password = password

    def sts(self, url):
        return origin_of(url).rstrip("/") == self.sts_origin

    def get(self, url):
        return self.client.request("GET", url, headers={"accept": "text/html,application/json"})

    def post_json(self, url, body, csrf):
        raw = json.dumps(body).encode()
        return self.client.request("POST", url, body=raw, headers={
            "accept": "application/json",
            "content-type": "application/json",
            "origin": self.sts_origin,
            "x-csrf-token": csrf,
        })

    def open_view(self, shell_url, api_url):
        status, headers, payload = self.get(shell_url)
        if status in (301, 302, 303, 307, 308):
            return {"redirect": resolve_url(shell_url, one_header(headers, "location"))}
        view_status, _headers, view_payload = self.client.request("GET", api_url, headers={"accept": "application/json"})
        parsed = json_body(view_payload) or {}
        if view_status in (301, 302, 303, 307, 308):
            return {"redirect": resolve_url(api_url, one_header(_headers, "location"))}
        if not parsed.get("csrf"):
            snippet = (view_payload or payload or b"")[:400].decode("utf-8", "replace")
            raise RuntimeError(f"{api_url} answered {view_status} without a csrf token: {snippet}")
        return {"view": parsed.get("view") or {}, "csrf": parsed["csrf"], "json": parsed}

    def act(self, url):
        """One sign-in step. Returns the next absolute URL, or None when the demo has the browser."""
        status, headers, payload = self.get(url)
        if status in (301, 302, 303, 307, 308):
            return resolve_url(url, one_header(headers, "location"))
        path = path_of(url)
        query = query_of(url)
        if self.sts(url) and path.startswith("/authn/login"):
            pending = (query.get("authn") or [""])[0]
            opened = self.open_view(url, f"{self.sts_origin}/authn-api/pending/{urllib.parse.quote(pending)}")
            if opened.get("redirect"):
                return opened["redirect"]
            posted, post_headers, post_body = self.post_json(
                f"{self.sts_origin}/authn-api/pending/{urllib.parse.quote(pending)}/password",
                {"username": self.username, "password": self.password},
                opened["csrf"],
            )
            return self.after_act(url, posted, post_headers, post_body)
        if self.sts(url) and path.startswith("/oauth2/consent"):
            pending = (query.get("consent") or [""])[0]
            opened = self.open_view(url, f"{self.sts_origin}/authn-api/consent/{urllib.parse.quote(pending)}")
            if opened.get("redirect"):
                return opened["redirect"]
            posted, post_headers, post_body = self.post_json(
                f"{self.sts_origin}/authn-api/consent/{urllib.parse.quote(pending)}",
                {"action": "allow"},
                opened["csrf"],
            )
            return self.after_act(url, posted, post_headers, post_body)
        if self.sts(url) and (path.startswith("/authn/mfa-setup") or path.startswith("/authn/post-login")):
            return self.skip_step(url, path)
        if self.sts(url) and path.startswith("/gnap/approve/"):
            return self.approve_gnap(url)
        form = autopost_form(payload) if status == 200 else None
        if form:
            action = resolve_url(url, form["action"])
            encoded = urllib.parse.urlencode(form["fields"]).encode()
            posted, post_headers, _post_body = self.client.request("POST", action, body=encoded, headers={
                "content-type": "application/x-www-form-urlencoded",
                "origin": origin_of(url),
            })
            if posted in (301, 302, 303, 307, 308):
                return resolve_url(action, one_header(post_headers, "location"))
            if origin_of(action).rstrip("/") == self.demo_origin:
                return None
            raise RuntimeError(f"the auto-posted form stayed at {action} ({posted})")
        if origin_of(url).rstrip("/") == self.demo_origin and status < 400:
            return None
        snippet = payload[:500].decode("utf-8", "replace")
        raise RuntimeError(f"the sign-in stopped at {status} {url}: {snippet}")

    def after_act(self, url, status, headers, payload):
        parsed = json_body(payload) or {}
        if status in (301, 302, 303, 307, 308):
            return resolve_url(url, one_header(headers, "location"))
        if parsed.get("location"):
            nxt = parsed.get("next")
            step = parsed.get("step")
            location = resolve_url(self.sts_origin + "/", parsed["location"])
            if nxt == "mfa" and step == "enrol":
                return self.skip_step(location, path_of(location))
            return location
        if parsed.get("ok") is False:
            raise RuntimeError(f"the sign-in act was refused: {json.dumps(parsed)[:500]}")
        snippet = payload[:500].decode("utf-8", "replace")
        raise RuntimeError(f"the sign-in act answered {status} without a location: {snippet}")

    def skip_step(self, url, path):
        query = query_of(url)
        pending = (query.get("mfa") or query.get("authn") or [""])[0]
        if not pending:
            parts = [part for part in path.split("/") if part]
            pending = parts[-1] if parts else ""
        page = "post-login" if path.startswith("/authn/post-login") else "setup"
        operation = "post-login/skip" if page == "post-login" else "skip"
        opened = self.open_view(url, f"{self.sts_origin}/authn-api/mfa/{urllib.parse.quote(pending)}?page={page}")
        if opened.get("redirect"):
            return opened["redirect"]
        view = opened["view"]
        optional = page == "post-login" or (isinstance(view.get("setup"), dict) and view["setup"].get("optional"))
        if not optional:
            raise RuntimeError(f"a required step is in the way at {url}")
        posted, post_headers, post_body = self.post_json(
            f"{self.sts_origin}/authn-api/mfa/{urllib.parse.quote(pending)}/{operation}",
            {},
            opened["csrf"],
        )
        return self.after_act(url, posted, post_headers, post_body)

    def approve_gnap(self, url):
        approval_id = path_of(url).rstrip("/").split("/")[-1]
        opened = self.open_view(url, f"{self.sts_origin}/gnap-api/approve/{urllib.parse.quote(approval_id)}")
        if opened.get("redirect"):
            return opened["redirect"]
        view = opened["view"]
        rights = []
        for token in view.get("tokens") or []:
            for right in token.get("rights") or []:
                if right.get("field"):
                    rights.append(right["field"])
        body = {"action": "allow", "right": rights}
        if view.get("subject"):
            body["subject"] = "yes"
        posted, post_headers, post_body = self.post_json(
            f"{self.sts_origin}/gnap-api/approve/{urllib.parse.quote(approval_id)}",
            body,
            opened["csrf"],
        )
        return self.after_act(url, posted, post_headers, post_body)

    def sign_in(self):
        url = self.demo_origin + PROFILE["login_path"]
        for _hop in range(24):
            nxt = self.act(url)
            if not nxt:
                return
            url = nxt
        raise RuntimeError(f"the sign-in did not finish; last URL {url}")

    def status(self):
        status, _headers, payload = self.client.request(
            "GET", self.demo_origin + PROFILE["status_path"], headers={"accept": "application/json"}
        )
        parsed = json_body(payload)
        if status != 200 or not isinstance(parsed, dict):
            raise RuntimeError(f"/live-status answered {status}: {payload[:300]!r}")
        return parsed


def mint_admin(client, sts_origin, secret):
    raw = urllib.parse.urlencode({
        "grant_type": "client_credentials",
        "scope": "admin:read admin:write",
        "resource": sts_origin + "/admin-api",
    }).encode()
    token = base64.b64encode(f"sts-api-client:{secret}".encode()).decode()
    status, _headers, payload = client.request("POST", sts_origin + "/oauth2/token", body=raw, headers={
        "content-type": "application/x-www-form-urlencoded",
        "authorization": f"Basic {token}",
        "accept": "application/json",
    })
    parsed = json_body(payload) or {}
    if status != 200 or not isinstance(parsed.get("access_token"), str):
        raise RuntimeError(f"the admin token request answered {status}: {json.dumps(parsed)[:300]}")
    return parsed["access_token"]


def admin_json(client, sts_origin, token, method, path, body=None):
    headers = {"accept": "application/json", "authorization": f"Bearer {token}"}
    raw = None
    if body is not None:
        raw = json.dumps(body).encode()
        headers["content-type"] = "application/json"
    status, _headers, payload = client.request(method, sts_origin + path, body=raw, headers=headers)
    parsed = json_body(payload)
    if parsed is None:
        raise RuntimeError(f"{method} {path} answered {status} with non-JSON: {payload[:300]!r}")
    return status, parsed


def session_id_for(client, sts_origin, token, username):
    deadline = time.time() + 20
    while time.time() < deadline:
        _status, parsed = admin_json(client, sts_origin, token, "GET", "/admin-api/caep")
        sessions = parsed.get("sessions") or []
        for row in sessions:
            if str(row.get("username") or "") == username and str(row.get("state") or "") != "revoked":
                found = row.get("sessionId")
                if found:
                    return str(found)
        time.sleep(1)
    raise RuntimeError(f"no CAEP session for {username}: {json.dumps(sessions)[:500]}")


def emit(client, sts_origin, token, session_id, event_type):
    status, parsed = admin_json(client, sts_origin, token, "POST", "/admin-api/caep/emit", {
        "session_id": session_id,
        "type": event_type,
        "initiating_entity": "admin",
    })
    if status != 200 or parsed.get("ok") is False:
        raise RuntimeError(f"emitting {event_type} answered {status}: {json.dumps(parsed)[:500]}")
    message = str(parsed.get("message") or "")
    if "Nothing was sent" in message:
        raise RuntimeError(f"emitting {event_type} reached no stream: {message}")
    print(f"emitted {event_type}: {message or json.dumps(parsed)[:200]}", flush=True)


def wait_for(driver, predicate, what):
    deadline = time.time() + 30
    last = None
    while time.time() < deadline:
        last = driver.status()
        if predicate(last):
            return last
        time.sleep(1)
    raise RuntimeError(f"timed out waiting for {what}: {json.dumps(last)[:600]}")


# --pep: the demo with its embedded PEP (#39). The install script sets the PEP
# up (--pep central), exactly as a user does; its names come from there.
sys.path.insert(0, str(ROOT / "scripts"))
from configure_iya_sts import (  # noqa: E402
    PEP_EVENT, PEP_KEY, SSF_ROLES, TEST_ATTRIBUTE, orders_policy, user_attributes,
)
PEP_LOCAL_CONFIG = "gnap.pep-local.json"
# The second test user (#41): signed in like the first, but its attr1 is not
# abc123, so the demo's policy refuses it GET /attribute-protected.
DENIED_USER = "gnap-demo-denied"
DENIED_VALUE = "not-abc123"
# What the unit tests' local PEP holds (src/bin/demo.rs's `protected`): the
# XACML iya-sts stores for the install script's orders_policy() ALFA. The
# --pep run compares it with what iya-sts stored.
POLICY_FIXTURE = ROOT / "src" / "tests" / "demo_orders_policy.xml"


def add_denied_user(client, sts_origin, token, password):
    """The denied test user: created with `password` (never printed), in the
    groups the first user is in, with attr1=not-abc123. The install script
    defined attr1 before this runs."""
    admin_ok(client, sts_origin, token, "/admin-api/users/create", {
        "username": DENIED_USER, "invent": False, "credential": "password",
        "password": password, "passwordConfirm": password, "attributes": user_attributes(DENIED_USER),
    }, f"the denied test user {DENIED_USER}")
    for role in SSF_ROLES:
        admin_ok(client, sts_origin, token, "/admin-api/groups/add-member",
                 {"group": role["group"], "member": DENIED_USER}, f"{DENIED_USER} in {role['group']}")
    admin_ok(client, sts_origin, token, "/admin-api/users/set-attribute",
             {"user": DENIED_USER, "attribute": TEST_ATTRIBUTE, "value": DENIED_VALUE},
             f"{DENIED_USER} has {TEST_ATTRIBUTE}={DENIED_VALUE}")


def own_policy_name(client, sts_origin, token, application):
    status, page = admin_json(client, sts_origin, token, "GET",
                              "/admin-api/applications?application=" + urllib.parse.quote(application, safe=""))
    fga = ((page.get("page") or {}).get("fga") or {}) if status == 200 else {}
    name = (fga.get("policy") or {}).get("name") or fga.get("reference")
    if not name:
        raise RuntimeError(f"{application}'s page names no policy of its own: {json.dumps(fga)[:400]}")
    return name


def policy_matches_fixture(client, sts_origin, token, application):
    """Whether iya-sts stored, for the install script's ALFA, exactly the
    XACML the unit tests' PEP holds. A difference prints iya-sts's document
    (a policy, no secret) so the fixture can be brought in line."""
    stored = stored_xacml(client, sts_origin, token, own_policy_name(client, sts_origin, token, application))
    fixture = POLICY_FIXTURE.read_text(encoding="utf-8").rstrip("\n").split("\n")
    if stored != fixture:
        print(f"iya-sts stored other XACML than {POLICY_FIXTURE.relative_to(ROOT)}:\n" + "\n".join(stored), flush=True)
    return stored == fixture


def admin_ok(client, sts_origin, token, path, body, what):
    status, parsed = admin_json(client, sts_origin, token, "POST", path, body)
    if status != 200 or parsed.get("ok") is False:
        raise RuntimeError(f"{what}: POST {path} answered {status}: {json.dumps(parsed)[:500]}")
    print(f"{what}: {status}", flush=True)
    return parsed


def flip_policy(client, sts_origin, token, application):
    """The application's OWN policy (the install script's) now denies read
    too. The realm root is never touched."""
    name = own_policy_name(client, sts_origin, token, application)
    admin_ok(client, sts_origin, token, "/admin-api/xacml/import-alfa",
             {"name": name, "alfa": orders_policy("gnapdemolocked", "deny")}, f"{name} now denies read on order")


def local_copy(config, dest):
    """The install script wrote a central pep section; a copy says local."""
    raw = json.loads(config.read_text(encoding="utf-8"))
    if not isinstance(raw.get("pep"), dict) or raw["pep"].get("mode") != "central":
        raise RuntimeError(f"the install script did not write a central pep section: {json.dumps(raw.get('pep'))}")
    raw["pep"] = dict(raw["pep"], mode="local")
    dest.write_text(json.dumps(raw, indent=2) + "\n", encoding="utf-8")


def protected_page(driver, method, path):
    status, _headers, payload = driver.client.request(method, driver.demo_origin + path,
                                                      body=b"" if method == "POST" else None, headers={"accept": "text/html"})
    print(f"{method} {status} demo {path} as {driver.username}", flush=True)
    return status, payload


def order(driver, method):
    return protected_page(driver, method, "/orders/42")


def pep_state(driver):
    return driver.status().get("pep") or {}


def pep_checks(driver, mode, denied=None):
    """GET /orders/42 is read (Permit, 200) and POST is write (Deny, 403);
    GET /attribute-protected is 200 for the allowed user (attr1=abc123) and
    403 for the `denied` one (attr1=not-abc123), whose GET /orders/42 is
    still 200 (it has an acr)."""
    deadline = time.time() + 60
    state = {}
    while time.time() < deadline:
        state = pep_state(driver)
        if state.get("registered") and (mode == "central" or state.get("holdsPolicy")):
            break
        time.sleep(1)
    else:
        raise RuntimeError(f"the {mode} PEP did not get ready: {json.dumps(state)[:600]}")
    read_status, read_body = order(driver, "GET")
    write_status, write_body = order(driver, "POST")
    attr_status, attr_body = protected_page(driver, "GET", "/attribute-protected")
    checks = {"mode": state.get("mode"), "registered": bool(state.get("registered")),
              "readIs200": read_status == 200, "writeIs403": write_status == 403,
              "attributeProtected": {"allowedUser": attr_status}}
    if mode == "local":
        checks["policyCount"] = state.get("policyCount")
    if read_status != 200 or write_status != 403:
        why = (read_body if read_status != 200 else write_body)[:400].decode("utf-8", "replace")
        raise RuntimeError(f"{mode}: GET /orders/42 answered {read_status}, POST {write_status}: {why}; pep {json.dumps(pep_state(driver))[:600]}")
    failures = []
    if attr_status != 200 or b"The PEP permitted it" not in attr_body:
        failures.append(f"GET /attribute-protected answered {attr_status} for {driver.username}: {attr_body[:400].decode('utf-8', 'replace')}")
    if denied is not None:
        denied_status, denied_body = protected_page(denied, "GET", "/attribute-protected")
        denied_read, _ = order(denied, "GET")
        checks["attributeProtected"]["deniedUser"] = denied_status
        checks["deniedUserReadIs200"] = denied_read == 200
        if denied_status != 403 or b"The PEP denied it" not in denied_body:
            failures.append(f"GET /attribute-protected answered {denied_status} for {denied.username}: {denied_body[:400].decode('utf-8', 'replace')}")
        if denied_read != 200:
            failures.append(f"GET /orders/42 answered {denied_read} for {denied.username}")
    if failures:
        raise RuntimeError(f"{mode}: " + "; ".join(failures) + f"; pep {json.dumps(pep_state(driver))[:600]}")
    return checks


def flip_check(driver, client, sts_origin, token, application):
    """local: the application's own policy moves to deny read, and the PEP
    hears of it through pep-policies-changed."""
    before = pep_state(driver)
    events_before = sum(1 for item in driver.status().get("events") or [] if item.get("type") == PEP_EVENT)
    flipped_at = time.time()
    flip_policy(client, sts_origin, token, application)
    limit = float(os.environ.get("PEP_FLIP_TIMEOUT") or 30)
    status = None
    while time.time() - flipped_at < limit:
        status, _body = order(driver, "GET")
        if status == 403:
            break
        time.sleep(1)
    after = driver.status()
    state = after.get("pep") or {}
    events = sum(1 for item in after.get("events") or [] if item.get("type") == PEP_EVENT)
    result = {
        "readIs403AfterFlip": status == 403,
        "seconds": round(time.time() - flipped_at, 1),
        "eventReceived": events > events_before or (state.get("eventsReceived") or 0) > (before.get("eventsReceived") or 0),
        "syncTokenMoved": bool(state.get("syncToken")) and state.get("syncToken") != before.get("syncToken"),
    }
    # The fallback poll stays at its 300 s default, so a change applied within
    # the bound with the event received came through the event.
    result["via"] = "event" if result["eventReceived"] and result["readIs403AfterFlip"] and result["seconds"] < 300 else "poll"
    if status != 403 or result["via"] != "event":
        raise RuntimeError(f"local: after the flip {json.dumps(result)}; pep {json.dumps(state)[:600]}")
    return result


def prepare_sts(sts_port, secret):
    given = os.environ.get("IYA_STS_URL", "").rstrip("/")
    if given:
        print(f"using {given}", flush=True)
        return given, None
    if sts_port in FORBIDDEN_PORTS:
        raise SystemExit(f"refusing to bind port {sts_port}")
    image = os.environ.get("IYA_STS_IMAGE", "")
    source = os.environ.get("IYA_STS_SRC", "")
    cloned = None
    if not image:
        if not source:
            cloned = tempfile.mkdtemp(prefix="iya-sts-main-")
            run(["git", "clone", "--depth", "1", "--branch", "main", STS_REPO, cloned])
            run(["git", "-C", cloned, "submodule", "update", "--init", "--recursive"])
            source = cloned
        image = "iya-sts-live:main"
        docker("build", "-t", image, source)
    name = "iya-sts-live-" + PROFILE["repo"]
    docker_rm(name)
    env = os.environ.copy()
    env["STS_ADMIN_API_CLIENT_SECRET"] = secret
    docker(
        "run", "-d", "--name", name,
        "-p", f"127.0.0.1:{sts_port}:{sts_port}",
        "-e", f"STS_PORT={sts_port}",
        "-e", "STS_PERSISTENCE_MODE=memory",
        "-e", "STS_CLUSTER_MODE=off",
        "-e", "STS_WORKERS_REQUEST_COUNT=0",
        "-e", "STS_WORKERS_SURFACE_COUNT=0",
        "-e", "STS_ADMIN_API_CLIENT_SECRET",
        "-e", "STS_LOG_LEVEL=info",
        image,
        env=env,
    )
    return f"https://127.0.0.1:{sts_port}", name


def as_me():
    """Run a container as the invoking user, so the files it writes in the work directory are ours."""
    if hasattr(os, "getuid"):
        return ["--user", f"{os.getuid()}:{os.getgid()}"]
    return []


def configure_demo(tools_image, work, sts_origin, demo_origin, demo_port, username, password, secret, pep=False):
    """Generate the client key and register the demo, both in the tools image. Nothing runs on the host.
    `pep` is False, or the install script's --pep mode ("central" when True)."""
    config = "/work/gnap.json"
    base = ["run", "--rm", "--network", "host", *as_me(), "-v", f"{work}:/work"]
    docker(*base, tools_image, *PROFILE["generate_key"])
    env = os.environ.copy()
    env["ADMIN_API_CLIENT_SECRET"] = secret
    env[PROFILE["user_env"]] = password
    # Values pass by name (-e NAME), so the secret is not on the command line or in this log.
    completed = run(
        [
            "docker", *base,
            "-e", "ADMIN_API_CLIENT_SECRET",
            "-e", PROFILE["user_env"],
            "-e", f"PUBLIC_URL={demo_origin}",
            "-e", f"PORT={demo_port}",
            tools_image,
            *PROFILE["configure"],
            "--config", config,
            "--idp", sts_origin,
            "--public-url", demo_origin,
            "--test-user", username,
            *(["--pep", "central" if pep is True else pep] if pep else []),
        ],
        env=env,
        capture_output=True,
    )
    if completed.stdout:
        print(completed.stdout, flush=True)
    if completed.stderr:
        print(completed.stderr, file=sys.stderr, flush=True)


def start_demo(image, demo_name, demo_port, demo_origin, mounts, env=None):
    """A fresh demo container, as the invoking user, with only `mounts` (file
    by file, read-only) and no CA mount or refresh."""
    docker_rm(demo_name)
    args = ["run", "-d", "--name", demo_name, "--network", "host", *as_me()]
    for source, target in mounts:
        args += ["-v", f"{source}:{target}:ro"]
    args += ["-e", f"PORT={demo_port}", "-e", f"PUBLIC_URL={demo_origin}", "-e", "TLS_CA_REFRESH=0"]
    for name, value in (env or {}).items():
        args += ["-e", f"{name}={value}"]
    docker(*args, image)
    deadline = time.time() + 90
    while time.time() < deadline:
        try:
            conn = http.client.HTTPConnection("127.0.0.1", demo_port, timeout=3)
            conn.request("GET", "/healthz")
            response = conn.getresponse()
            body = response.read()
            conn.close()
            if response.status == 200 and body == b"ok":
                return
        except OSError:
            pass
        time.sleep(1)
    logs = subprocess.run(["docker", "logs", demo_name], check=False, text=True, capture_output=True)
    if logs.stdout:
        print(logs.stdout, flush=True)
    if logs.stderr:
        print(logs.stderr, file=sys.stderr, flush=True)
    raise RuntimeError("the demo /healthz did not answer ok")


def main():
    pep = "--pep" in sys.argv[1:] or os.environ.get("LIVE_PEP", "") in ("1", "true", "yes")
    sts_port = int(os.environ.get("LIVE_STS_PORT") or 18558)
    demo_port = int(os.environ.get("LIVE_DEMO_PORT") or 18658)
    sts_given = bool(os.environ.get("IYA_STS_URL", "").strip())
    bound = [demo_port] if sts_given else [sts_port, demo_port]
    if any(port in FORBIDDEN_PORTS for port in bound) or len(set(bound)) != len(bound):
        raise SystemExit("LIVE_STS_PORT and LIVE_DEMO_PORT must not bind 3000, 8081, or 18481 to 18495")
    secret = os.environ.get("ADMIN_API_CLIENT_SECRET") or os.environ.get("STS_ADMIN_API_CLIENT_SECRET") or secrets.token_urlsafe(24)
    password = os.environ.get(PROFILE["user_env"]) or secrets.token_urlsafe(18)
    denied_password = secrets.token_urlsafe(18)
    username = PROFILE["test_user"]
    sts_origin, sts_name = prepare_sts(sts_port, secret)
    demo_origin = f"http://127.0.0.1:{demo_port}"
    demo_name = PROFILE["repo"] + "-live-demo"
    image = PROFILE["repo"] + "-live:demo"
    tools_image = PROFILE["repo"] + "-live:tools"
    work = Path(tempfile.mkdtemp(prefix=PROFILE["repo"] + "-live-"))
    try:
        wait_port(urllib.parse.urlsplit(sts_origin).port or 443, 120)
        wait_ready(sts_origin, 90)
        context = work / "context"
        copy_context(context)
        config = context / PROFILE["config_file"]
        rewrite_config(config, config, sts_origin, demo_origin)
        tls_ca = json.loads(config.read_text(encoding="utf-8")).get("tlsCa")
        chain_file = config.parent / tls_ca
        generated_dir = config.parent / "generated"
        # The key and the install script run in the tools image, on the context's demo/.
        docker("build", "--target", "tools", "-t", tools_image, str(context))
        configure_demo(tools_image, config.parent, sts_origin, demo_origin, demo_port, username, password, secret, pep=pep)
        if "BEGIN CERTIFICATE" not in (chain_file.read_text(encoding="utf-8") if chain_file.exists() else ""):
            raise RuntimeError(f"the install script did not write tlsCa's file {tls_ca}")
        pep_key = config.parent / PEP_KEY
        application = json.loads(config.read_text(encoding="utf-8"))["application"]
        pep_result = {}
        if pep:
            # The install script set the PEP up and wrote a central section; the
            # local run uses a copy that says local. Both go into the image, the
            # key never does.
            if not pep_key.exists():
                raise RuntimeError("the install script did not make the PEP's key")
            pep_result = {"application": application, "name": json.loads(config.read_text(encoding="utf-8"))["pep"]["name"]}
            local_copy(config, config.parent / PEP_LOCAL_CONFIG)
        # The demo image, built after the install script, carries the chain and no key.
        docker("build", "-t", image, str(context))
        baked = docker(
            "run", "--rm", "--entrypoint", "cat", image, f"/app/demo/{tls_ca}",
            capture_output=True,
        ).stdout
        if baked != chain_file.read_text(encoding="utf-8"):
            raise RuntimeError(f"the demo image's /app/demo/{tls_ca} is not the chain the install script saved")
        listed = docker(
            "run", "--rm", "--entrypoint", "ls", image, "-A", "/app/demo/generated",
            capture_output=True,
        ).stdout.split()
        if listed != [Path(tls_ca).name]:
            raise RuntimeError(f"the demo image's /app/demo/generated holds {listed}, not only the trust chain")
        print(f"the demo image carries {tls_ca} from build time, and no key", flush=True)
        mounts = [(generated_dir / "client.key", "/app/demo/generated/client.key"),
                  (generated_dir / "client.crt", "/app/demo/generated/client.crt")]
        if pep:
            mounts.append((pep_key, "/app/demo/" + PEP_KEY))
        start_demo(image, demo_name, demo_port, demo_origin, mounts)
        client = Client(chain_file)
        if pep:
            token = mint_admin(client, sts_origin, secret)
            add_denied_user(client, sts_origin, token, denied_password)
            pep_result["storedXacmlIsTheUnitFixture"] = policy_matches_fixture(client, sts_origin, token, application)
        driver = Driver(client, sts_origin, demo_origin, username, password)
        driver.sign_in()
        signed_in = wait_for(
            driver,
            lambda row: row.get("signedIn") is True and "polling" in str(row.get("receiver") or ""),
            "a signed-in demo polling its stream",
        )
        print(f"signed in as {signed_in.get('subject')}; {signed_in.get('receiver')}", flush=True)
        if pep:
            denied = Driver(Client(chain_file), sts_origin, demo_origin, DENIED_USER, denied_password)
            denied.sign_in()
            central = pep_checks(driver, "central", denied)
        token = mint_admin(client, sts_origin, secret)
        session_id = session_id_for(client, sts_origin, token, username)
        emit(client, sts_origin, token, session_id, "credential-change")
        wait_for(
            driver,
            lambda row: row.get("signedIn") is True and any(
                item.get("type") == CREDENTIAL_CHANGE for item in row.get("events") or []
            ),
            "credential-change while still signed in",
        )
        emit(client, sts_origin, token, session_id, "session-revoked")
        finished = wait_for(
            driver,
            lambda row: row.get("signedIn") is False and any(
                item.get("type") == SESSION_REVOKED for item in row.get("events") or []
            ),
            "session-revoked to end the local session",
        )
        result = {
            "ok": True,
            "subject": signed_in.get("subject"),
            "trustChain": f"demo/{tls_ca}, baked into the demo image",
            "idpCaInImage": True,
            "events": finished.get("events"),
        }
        if pep:
            pep_result["central"] = central
            # THEN local: the same image and iya-sts, the copy that says local.
            # Guards against the central demo's unacknowledged session-revoked SET being redelivered on the reused stream and ending the local sign-in (without it, 3 of 3 runs failed).
            time.sleep(5)
            start_demo(image, demo_name, demo_port, demo_origin, mounts,
                       env={"GNAP_CONFIG": "/app/demo/" + PEP_LOCAL_CONFIG})
            local_driver = Driver(Client(chain_file), sts_origin, demo_origin, username, password)
            local_driver.sign_in()
            wait_for(local_driver, lambda row: row.get("signedIn") is True and "polling" in str(row.get("receiver") or ""),
                     "a signed-in local-mode demo polling its stream")
            local_denied = Driver(Client(chain_file), sts_origin, demo_origin, DENIED_USER, denied_password)
            local_denied.sign_in()
            local = pep_checks(local_driver, "local", local_denied)
            token = mint_admin(client, sts_origin, secret)
            local["policyChange"] = flip_check(local_driver, client, sts_origin, token, application)
            pep_result["local"] = local
            result["pep"] = pep_result
            # The unit tests' policy must be what iya-sts stores; reported
            # after everything else ran, and the run fails on a difference.
            result["ok"] = pep_result["storedXacmlIsTheUnitFixture"]
        print(json.dumps(result, indent=2))
        if not result["ok"]:
            raise RuntimeError(f"iya-sts stored other XACML than {POLICY_FIXTURE.relative_to(ROOT)} (printed above)")
    finally:
        if os.environ.get("LIVE_KEEP", "") == "1":
            # For a failure's post-mortem: both containers stay. The next run
            # removes them before it starts its own.
            print(f"LIVE_KEEP=1: left {demo_name} and {sts_name or 'the given iya-sts'} running", flush=True)
        else:
            docker_rm(demo_name)
            if sts_name:
                docker_rm(sts_name)
        shutil.rmtree(work, ignore_errors=True)


# ---------------------------------------------------------------------------
# --authzen: the embedded PEP's differential run (#39). src/tests/authzen_cases.json
# is provisioned into the fresh iya-sts (its people, catalogue rows and policies,
# and per PEP group an application, a central and a local PEP service account,
# each with its own key, certified and bound to it), then the env-gated Rust
# test runs every case through a central and a local Client and requires both
# to give the table's answer. Cargo runs in rust:1-bookworm, never on the host.
# ---------------------------------------------------------------------------

AUTHZEN_TABLE = ROOT / "src" / "tests" / "authzen_cases.json"
AUTHZEN_MODES = ("central", "local")
CARGO_VOLUME = "iya-pep-cargo"
RUST_IMAGE = "rust:1-bookworm"


def admin_step(client, sts_origin, token, path, body, what, method="POST"):
    status, parsed = admin_json(client, sts_origin, token, method, path, body)
    if status != 200 or parsed.get("ok") is False:
        raise RuntimeError(f"{what}: {method} {path} answered {status}: {json.dumps(parsed)[:600]}")
    print(f"{what}: {status}", flush=True)
    return parsed


def pep_key(tools_image, work, name):
    """A P-256 key for one PEP, made in the tools image as the invoking user,
    0600, and its certificate request. Neither is printed; only the request
    is sent."""
    peps = work / "peps"
    peps.mkdir(exist_ok=True)
    docker(
        "run", "--rm", *as_me(), "-v", f"{peps}:/peps", tools_image, "sh", "-c",
        f"umask 077 && openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out /peps/{name}.pem"
        f" && openssl req -new -key /peps/{name}.pem -subj /CN={name} -out /peps/{name}.csr",
        capture_output=True,
    )
    return peps / f"{name}.pem", (peps / f"{name}.csr").read_text(encoding="utf-8")


def stored_xacml(client, sts_origin, token, name):
    status, parsed = admin_json(client, sts_origin, token, "GET", "/admin-api/xacml/editor?policy=" + urllib.parse.quote(name))
    document = parsed.get("document") if status == 200 else None
    if not isinstance(document, str) or not document:
        raise RuntimeError(f"the editor gave no document for {name}: {status}")
    return document.rstrip("\n").split("\n")


def provision_authzen(client, sts_origin, token, table, tools_image, work):
    """The table's people, catalogue, applications, policies and PEPs. Answers
    peps.<group>.<mode> for the Rust test, and the policies whose stored XACML
    is not the table's."""
    for username, attributes in table["directory"].items():
        admin_step(client, sts_origin, token, "/admin-api/users/create", {
            "username": username, "invent": False, "credential": "none",
            "attributes": {"cn": username, "sn": username, **attributes},
        }, f"the directory person {username}")
    # iya-sts hands a central PEP the answer's advice only while the realm
    # returns reasons; without it a Permit's advice reaches local mode alone.
    admin_step(client, sts_origin, token, "/admin-api/config/set",
               {"key": "authzen.returnReasons", "value": True}, "authzen.returnReasons on")
    for row in table["catalogue"]:
        admin_step(client, sts_origin, token, "/admin-api/xacml/authzen/set-attribute", row,
                   f"the catalogue row {row['object']}.{row['property']}")
    peps, drift = {}, []
    for group_name, group in table["peps"].items():
        application = group["application"]
        if group.get("fga"):
            admin_step(client, sts_origin, token, "/admin-api/applications/create", {
                "identifier": application, "name": application, "kind": "gnap-client", "protocols": ["gnap"], "fields": {},
            }, f"the application {application}")
        for index, policy in enumerate(group["policies"]):
            name = policy.get("name")
            if policy.get("own"):
                _status, page = admin_json(client, sts_origin, token, "GET",
                                           "/admin-api/applications?application=" + urllib.parse.quote(application))
                name = (((page.get("page") or {}).get("fga") or {}).get("policy") or {}).get("name")
                if not name:
                    raise RuntimeError(f"{application} names no fine-grained policy: {json.dumps(page)[:400]}")
            admin_step(client, sts_origin, token, "/admin-api/xacml/import-alfa",
                       {"name": name, "alfa": "\n".join(policy["alfa"]) + "\n"}, f"{group_name}: the policy {name}")
            for ref in policy.get("references") or []:
                admin_step(client, sts_origin, token, "/admin-api/xacml/add-policy-reference",
                           {"policy": name, "path": "", "ref": ref}, f"{group_name}: {name} references {ref}")
            if policy.get("root") and not policy.get("own"):
                admin_step(client, sts_origin, token, "/admin-api/xacml/set-root", {"name": name},
                           f"{group_name}: {name} is the realm root")
            stored = stored_xacml(client, sts_origin, token, name)
            if stored != policy.get("xacml"):
                drift.append((group_name, index, stored))
        peps[group_name] = {}
        for mode in AUTHZEN_MODES:
            pep_name = f"pep-gnap-{group_name}-{mode}"
            admin_step(client, sts_origin, token, "/admin-api/users/create", {
                "username": pep_name, "invent": False, "credential": "none", "serviceAccount": True,
                "owners": ["admin-write"], "attributes": {"cn": pep_name, "displayName": pep_name},
            }, f"the service account {pep_name}")
            admin_step(client, sts_origin, token, "/admin-api/groups/add-member",
                       {"group": "remote-peps", "member": pep_name}, f"{pep_name} in remote-peps")
            key_file, csr = pep_key(tools_image, work, pep_name)
            admin_step(client, sts_origin, token, "/admin-api/xacml/issue-pep-credential",
                       {"name": pep_name, "csr": csr, "application": application},
                       f"{pep_name}: its key certified and bound to {application}")
            peps[group_name][mode] = {"name": pep_name, "assertionKey": "/work/peps/" + key_file.name}
        if group.get("fga"):
            admin_step(client, sts_origin, token, "/admin-api/applications/fga-enable", {"application": application},
                       f"{application} enforces fine-grained authorization")
    return peps, drift


def run_authzen_test(work):
    """The env-gated test, in rust:1-bookworm as the invoking user, with the
    shared cargo cache and a target directory inside this checkout."""
    completed = subprocess.run([
        "docker", "run", "--rm", "--network", "host", *as_me(),
        "-v", f"{CARGO_VOLUME}:/cargo", "-e", "CARGO_HOME=/cargo", "-e", "HOME=/tmp",
        "-v", f"{ROOT}:/src", "-w", "/src", "-e", "CARGO_TARGET_DIR=/src/target/live-authzen",
        "-v", f"{work}:/work", "-e", "GNAP_AUTHZEN_LIVE=/work/authzen-live.json", "-e", "GNAP_AUTHZEN_REPORT=/work/authzen-report.json",
        RUST_IMAGE, "cargo", "test", "--locked", "--features", "local", "--lib", "live_central_and_local_agree", "--", "--nocapture",
    ], check=False, text=True)
    report = work / "authzen-report.json"
    return completed.returncode, (json.loads(report.read_text(encoding="utf-8")) if report.exists() else None)


def authzen_main():
    sts_port = int(os.environ.get("LIVE_STS_PORT") or 18558)
    demo_port = int(os.environ.get("LIVE_DEMO_PORT") or 18658)
    if sts_port in FORBIDDEN_PORTS or demo_port in FORBIDDEN_PORTS or sts_port == demo_port:
        raise SystemExit("LIVE_STS_PORT and LIVE_DEMO_PORT must not bind 3000, 8081, or 18481 to 18495")
    write_xacml = "--write-xacml" in sys.argv[1:]
    table = json.loads(AUTHZEN_TABLE.read_text(encoding="utf-8"))
    secret = os.environ.get("ADMIN_API_CLIENT_SECRET") or os.environ.get("STS_ADMIN_API_CLIENT_SECRET") or secrets.token_urlsafe(24)
    password = os.environ.get(PROFILE["user_env"]) or secrets.token_urlsafe(18)
    sts_origin, sts_name = prepare_sts(sts_port, secret)
    demo_origin = f"http://127.0.0.1:{demo_port}"
    tools_image = PROFILE["repo"] + "-live:tools"
    work = Path(tempfile.mkdtemp(prefix=PROFILE["repo"] + "-authzen-"))
    try:
        wait_port(urllib.parse.urlsplit(sts_origin).port or 443, 120)
        wait_ready(sts_origin, 90)
        context = work / "context"
        copy_context(context)
        config = context / PROFILE["config_file"]
        rewrite_config(config, config, sts_origin, demo_origin)
        docker("build", "--target", "tools", "-t", tools_image, str(context))
        # The GNAP client registered as the demo is; no demo runs, the test is the host.
        configure_demo(tools_image, config.parent, sts_origin, demo_origin, demo_port, PROFILE["test_user"], password, secret)
        chain_file = config.parent / json.loads(config.read_text(encoding="utf-8"))["tlsCa"]
        client = Client(chain_file)
        token = mint_admin(client, sts_origin, secret)
        peps, drift = provision_authzen(client, sts_origin, token, table, tools_image, work)
        if drift:
            if not write_xacml:
                names = ", ".join(f"{group} policy {index}" for group, index, _ in drift)
                raise RuntimeError(f"iya-sts stored other XACML than the table's for {names}; "
                                   "run with --write-xacml to take iya-sts's into the table")
            for group, index, stored in drift:
                table["peps"][group]["policies"][index]["xacml"] = stored
            AUTHZEN_TABLE.write_text(json.dumps(table, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
            print(f"wrote iya-sts's XACML for {len(drift)} policies into {AUTHZEN_TABLE.relative_to(ROOT)}", flush=True)
        live = {"config": "/work/context/" + PROFILE["config_file"], "peps": peps}
        (work / "authzen-live.json").write_text(json.dumps(live, indent=2), encoding="utf-8")
        code, report = run_authzen_test(work)
        summary = {"ok": code == 0 and bool(report) and not report.get("mismatches")}
        summary.update(report or {"error": f"the test exited {code} without a report"})
        print(json.dumps(summary, indent=2))
        if not summary["ok"]:
            raise RuntimeError(f"the AuthZEN differential run failed ({code})")
    finally:
        if sts_name:
            docker_rm(sts_name)
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    try:
        authzen_main() if "--authzen" in sys.argv[1:] else main()
    except Exception as err:
        print(str(err), file=sys.stderr)
        sys.exit(1)
