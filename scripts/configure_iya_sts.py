# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT

"""Register the demo as a GNAP client on a running iya-sts.

    ADMIN_API_CLIENT_SECRET=… python scripts/configure_iya_sts.py
    ADMIN_API_CLIENT_SECRET=… python scripts/configure_iya_sts.py --pep central
    python scripts/configure_iya_sts.py --config demo/gnap.json --dry-run

--pep [central|local] also sets up the demo's embedded PEP (docs/remote-pep.md,
steps 2 to 6; local when the mode is left out) and writes the configuration's pep section. Run again, it keeps
the PEP's account, key and policy, binds it again and switches the mode.

The management API token is minted as sts-api-client (client_credentials, HTTP Basic), audienced
to <base>/admin-api, scope admin:read admin:write. The secret is ADMIN_API_CLIENT_SECRET or
STS_ADMIN_API_CLIENT_SECRET. The running container's PORT wins over the shell PORT.
"""

import base64
import json
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.parse import quote, urlsplit, urlunsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))

from redirects import demo_port, redirects_for  # noqa: E402
from trust_chain import save_trust_chain, trust_path, unverified_context  # noqa: E402

REPO = Path(__file__).resolve().parent.parent

SSF_ROLES = (
    {"scope": "ssf.read", "role": "SSF_READ", "group": "ssf-read"},
    {"scope": "ssf.manage", "role": "SSF_MANAGE", "group": "ssf-manage"},
)
MULTIPLE_ACCOUNTS = {"key": "authn.multipleAccounts", "value": True}

# --pep: the demo's embedded PEP (#39).
PEP_MODES = ("central", "local")
PEP_NAME = "pep-gnap-demo"
# Beside the configuration; the pep section names it relative to the
# configuration's directory, as this library reads assertionKey. .dockerignore
# keeps it out of the image.
PEP_KEY = "generated/pep-key.pem"
PEP_GROUP = "remote-peps"
PEP_EVENT = "urn:iya:sts:secevent:event-type:pep-policies-changed"
ACR_ATTRIBUTE = "urn:example:acr"


def orders_policy(namespace="gnapdemo", read_effect="permit"):
    """ALFA for the demo application's own policy: `read` on an `order` is
    `read_effect`, and anything else is denied. `permit` also needs the
    subject's acr, which only the catalogue row brings, so a Permit shows the
    ID token's claim arrived."""
    condition = "            condition integerGreaterThan(stringBagSize(acr), 0)\n" if read_effect == "permit" else ""
    return (
        f"namespace {namespace} {{\n"
        '    attribute act { category = actionCat\n'
        '        id = "urn:oasis:names:tc:xacml:1.0:action:action-id" type = string }\n'
        '    attribute rtype { category = resourceCat\n'
        '        id = "urn:sts:xacml:authzen:resource-type" type = string }\n'
        f'    attribute acr {{ category = subjectCat id = "{ACR_ATTRIBUTE}" type = string }}\n'
        f"    policy {namespace}Orders {{\n"
        f'        id = "urn:example:{namespace}-orders"\n'
        "        apply firstApplicable\n"
        "        rule readOrder {\n"
        f"            {read_effect}\n"
        '            target clause act == "read"\n'
        '            target clause rtype == "order"\n'
        f"{condition}"
        "        }\n"
        "        rule otherwise {\n"
        "            deny\n"
        "        }\n"
        "    }\n"
        "}\n"
    )


def admin_tls():
    return {"reject_unauthorized": False}


def usage():
    return """Usage: python scripts/configure_iya_sts.py [--config path] [--idp url] [--public-url url]
                                        [--test-user name | --no-test-user]
                                        [--pep [MODE]] [--pep-name name] [--dry-run]

  --config        The demo's GNAP configuration (default: demo/gnap.json)
  --idp           iya-sts's base URL; the realm's, e.g. https://host/realm/acme, for a trust realm
                  (default: the grant endpoint's origin, with a trailing /gnap removed, or $IYA_STS_URL)
  --public-url    Replace the origin of the file's finish URI and display URI with this URL, and
                  keep their paths (default: unset; $PUBLIC_URL). Without it, a loopback finish
                  URI follows the running demo's PORT, then $PORT. A non-loopback finish URI is
                  left as written.
  --test-user     The test user to create (default: gnap-demo-user). Its password is
                  $GNAP_DEMO_USER_PASSWORD, or one is generated and written to
                  generated/<user>.password beside the configuration (mode 0600); only the
                  path is printed. With that variable set, an existing user's password is
                  replaced.
  --no-test-user  Do not create a test user.
  --pep [MODE]    Also set up the demo's embedded PEP in this mode, local (the default: it
                  caches the application's policies and decides in process) or central:
                  its service account in remote-peps, a P-256 key made with openssl in
                  generated/pep-key.pem beside the configuration (0600, never printed),
                  the key certified and the PEP bound to the application, the catalogue
                  row subject.acr, and the application's OWN policy, which it then
                  enforces (written only while it enforces none; the realm root is never
                  touched). It writes the pep section into the configuration.
  --pep-name      The PEP's name and service account (default: pep-gnap-demo).
  --dry-run       Print what would be done, and send nothing.

The management API secret is ADMIN_API_CLIENT_SECRET or STS_ADMIN_API_CLIENT_SECRET.
Generate the key at the privateKey path before a real run, so the public key exists."""


def parse_args(argv, env=None):
    env = os.environ if env is None else env
    out = {
        "config": str(REPO / "demo" / "gnap.json"),
        "idp": (env.get("IYA_STS_URL") or "").rstrip("/"),
        "public_url": (env.get("PUBLIC_URL") or "http://localhost:3000").rstrip("/"),
        "public_url_given": bool(env.get("PUBLIC_URL")),
        "test_user": "gnap-demo-user",
        "dry_run": False,
        "help": False,
        "idp_given": bool(env.get("IYA_STS_URL")),
        "pep": "",
        "pep_name": PEP_NAME,
    }
    index = 0
    while index < len(argv):
        arg = argv[index]

        def value():
            nonlocal index
            index += 1
            if index >= len(argv):
                raise RuntimeError(f"{arg} needs a value\n{usage()}")
            return argv[index]

        if arg in ("--help", "-h"):
            out["help"] = True
        elif arg == "--config":
            out["config"] = str(Path(value()).resolve())
        elif arg == "--idp":
            out["idp"] = value().rstrip("/")
            out["idp_given"] = True
        elif arg == "--public-url":
            out["public_url"] = value().rstrip("/")
            out["public_url_given"] = True
        elif arg == "--test-user":
            out["test_user"] = value().strip()
        elif arg == "--no-test-user":
            out["test_user"] = ""
        elif arg == "--dry-run":
            out["dry_run"] = True
        elif arg == "--pep":
            # The mode may be left out: then local, iya-pep's default (the
            # PEP caches the application's policies and decides in process).
            if index + 1 < len(argv) and not argv[index + 1].startswith("--"):
                out["pep"] = value().strip()
            else:
                out["pep"] = "local"
            if out["pep"] not in PEP_MODES:
                raise RuntimeError(f"--pep is central or local, not {out['pep']}")
        elif arg == "--pep-name":
            out["pep_name"] = value().strip()
            if not __import__("re").fullmatch(r"[A-Za-z0-9._-]{1,64}", out["pep_name"]):
                raise RuntimeError("--pep-name is letters, digits, dot, dash or underscore")
        else:
            raise RuntimeError(f"Unknown argument {arg}\n{usage()}")
        index += 1
    if out["idp"]:
        parsed = urlsplit(out["idp"])
        if parsed.scheme != "https":
            raise RuntimeError(f"--idp must be https, not {out['idp']}")
    if not out["public_url"]:
        raise RuntimeError("--public-url is empty")
    return out


def files_of(config_path, public_url):
    raw = json.loads(Path(config_path).read_text(encoding="utf-8"))
    base = str(Path(config_path).parent)
    application = str(raw.get("application") or "").strip()
    grant = str(raw.get("grantEndpoint") or "").strip()
    if not application:
        raise RuntimeError(f"{config_path} has no application")
    if not grant:
        raise RuntimeError(f"{config_path} has no grantEndpoint")
    origin = public_url if public_url.endswith("/") else f"{public_url}/"
    finish = str(raw.get("finishUri") or "").strip()
    if not finish:
        parts = urlsplit(origin)
        finish = urlunsplit((parts.scheme, parts.netloc, "/callback", "", ""))
    signals_off = raw.get("signals") is False
    access = raw.get("access") if isinstance(raw.get("access"), list) else ["ssf.read", "ssf.manage"]
    scopes = []
    for item in access:
        if not isinstance(item, str) or not item.strip():
            continue
        if signals_off and item.strip() in ("ssf.read", "ssf.manage"):
            continue
        scopes.append(item.strip())
    key_proof = str(raw.get("keyProof") or ("mtls" if raw.get("certificate") else "httpsig"))
    transmitter = None
    if not signals_off:
        ssf = raw.get("ssf") if isinstance(raw.get("ssf"), dict) else {}
        transmitter = ssf.get("transmitter") or raw.get("transmitterIssuer")
        if isinstance(transmitter, str):
            transmitter = transmitter.rstrip("/")
    display = raw.get("display") if isinstance(raw.get("display"), dict) else {}
    tls_ca = trust_path(raw.get("tlsCa"), base)
    files = {
        "application": application,
        "name": (display.get("name") or "").strip() or f"{application} demo",
        "finishUri": finish,
        "scopes": scopes,
        "interactionStart": raw.get("interactionStart") or ["redirect"],
        "keyProof": key_proof,
        "grantEndpoint": grant,
    }
    if display.get("uri"):
        files["displayUri"] = display["uri"]
    if tls_ca:
        files["tlsCa"] = tls_ca
    if transmitter:
        files["transmitter"] = transmitter
    return files


def idp_from_grant(grant_endpoint):
    parts = urlsplit(grant_endpoint)
    path = parts.path
    if path.endswith("/gnap"):
        path = path[: -len("/gnap")]
    elif path.endswith("/gnap/"):
        path = path[: -len("/gnap/")]
    href = urlunsplit((parts.scheme, parts.netloc, path, "", ""))
    return href.rstrip("/")


def realm_of(idp):
    parts = urlsplit(idp)
    if parts.scheme != "https":
        raise RuntimeError(f"the provider must be https, not {idp}")
    path = parts.path.rstrip("/")
    if path and not __import__("re").fullmatch(r"/realm/[^/]+", path):
        raise RuntimeError(f"--idp must be iya-sts's base URL or a realm's (/realm/<id>), not {idp}")
    origin = f"{parts.scheme}://{parts.netloc}"
    return {"origin": origin, "base": f"{origin}{path}"}


def application_fields(files, key_json, include_key):
    fields = {}
    if include_key:
        fields["gnapKey"] = key_json
    fields["gnapFinishUri"] = [files["finishUri"]]
    fields["gnapInteractionStartModes"] = files["interactionStart"]
    fields["gnapBearerTokens"] = "FALSE"
    if files.get("displayUri"):
        fields["gnapDisplayUri"] = files["displayUri"]
    fields["oauthAllowedScope"] = files["scopes"]
    return fields


def user_attributes(username):
    return {
        "cn": f"GNAP Demo {username}",
        "givenName": "GNAP",
        "sn": "Demo",
        "displayName": f"GNAP Demo {username}",
        "mail": f"{username}@gnap-demo.test",
    }


def plan_for(files, base, test_user, key_json):
    calls = [{
        "method": "POST",
        "path": f"{base}/admin-api/applications/create",
        "when": "create",
        "why": f"register {files['application']}",
        "body": {
            "identifier": files["application"],
            "name": files["name"],
            "kind": "gnap-client",
            "protocols": ["gnap"],
            "fields": application_fields(files, key_json, True),
        },
    }]
    calls.append({
        "method": "POST",
        "path": f"{base}/admin-api/applications/add",
        "when": "exists",
        "why": "declare protocol gnap",
        "body": {"application": files["application"], "attribute": "appAllowedProtocol", "value": "gnap"},
    })
    again = application_fields(files, key_json, False)
    for attribute, raw in again.items():
        if not isinstance(raw, list):
            calls.append({
                "method": "POST",
                "path": f"{base}/admin-api/applications/set",
                "when": "exists",
                "why": f"set {attribute}",
                "body": {"application": files["application"], "attribute": attribute, "value": str(raw)},
            })
            continue
        for item in raw:
            calls.append({
                "method": "POST",
                "path": f"{base}/admin-api/applications/add",
                "when": "exists",
                "why": f"add {attribute}",
                "body": {"application": files["application"], "attribute": attribute, "value": str(item)},
            })
    calls.append({
        "method": "POST",
        "path": f"{base}/admin-api/config/set",
        "when": "always",
        "why": "let one browser hold several accounts",
        "body": MULTIPLE_ACCOUNTS,
    })
    for role in SSF_ROLES:
        if role["scope"] not in files["scopes"]:
            continue
        calls.append({
            "method": "POST",
            "path": f"{base}/admin-api/roles/add-member",
            "when": "always",
            "why": f"hold {role['role']}, which authorizes {role['scope']}",
            "body": {"role": role["role"], "kind": "application", "member": files["application"]},
        })
    calls.append({
        "method": "POST",
        "path": f"{base}/admin-api/applications/set-custom-claim",
        "when": "always",
        "why": "put the directory username on the access-token JWT as uid",
        "body": {
            "application": files["application"],
            "set": "gnap_access_token",
            "name": "uid",
            "value": "${username}",
        },
    })
    if test_user:
        calls.append({
            "method": "POST",
            "path": f"{base}/admin-api/users/create",
            "when": "always",
            "why": f"create the test user {test_user}",
            "body": {"username": test_user, "invent": False, "credential": "generate", "attributes": user_attributes(test_user)},
        })
        for role in SSF_ROLES:
            if role["scope"] not in files["scopes"]:
                continue
            calls.append({
                "method": "POST",
                "path": f"{base}/admin-api/groups/add-member",
                "when": "always",
                "why": f"put {test_user} in {role['group']}",
                "body": {"group": role["group"], "member": test_user},
            })
    return calls


def _send(url, method, headers, body):
    """POST or GET with verification off. The registrar talks to a local iya-sts listener."""
    import http.client
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise RuntimeError(f"{url} is not an http(s) URL")
    port = parts.port or (443 if parts.scheme == "https" else 80)
    path = parts.path or "/"
    if parts.query:
        path = f"{path}?{parts.query}"
    payload = None if body is None else body.encode("utf-8") if isinstance(body, str) else body
    outgoing = {str(name): str(value) for name, value in (headers or {}).items()}
    if payload is not None:
        outgoing["content-length"] = str(len(payload))
    try:
        if parts.scheme == "https":
            conn = http.client.HTTPSConnection(parts.hostname, port, context=unverified_context(), timeout=15)
        else:
            conn = http.client.HTTPConnection(parts.hostname, port, timeout=15)
        conn.request(method, path, body=payload, headers=outgoing)
        response = conn.getresponse()
        raw = response.read()
        status = response.status
        conn.close()
    except Exception as err:
        raise RuntimeError(f"{method} {url}: {err}") from err

    class Answer:
        pass
    answer = Answer()
    answer.status = status
    answer.body = raw.decode("utf-8", "replace")
    return answer


def _json(url, method="GET", headers=None, body=None):
    answer = _send(url, method, headers or {}, body)
    try:
        parsed = json.loads(answer.body) if answer.body else {}
    except Exception as err:
        raise RuntimeError(f"{method} {url} answered {answer.status} with non-JSON: {answer.body[:300]}") from err
    if answer.status in (401, 403):
        raise RuntimeError(f"{method} {url} answered {answer.status}: {json.dumps(parsed)[:300]}")
    return {"status": answer.status, "body": parsed if isinstance(parsed, dict) else {}}


def _errors(body):
    raw = body.get("errors") or []
    if not isinstance(raw, list):
        raw = [raw]
    return [str(item) for item in raw]


def mint_admin_token(base, secret):
    form = f"grant_type=client_credentials&scope={quote('admin:read admin:write')}&resource={quote(base + '/admin-api', safe='')}"
    basic = base64.b64encode(f"sts-api-client:{secret}".encode()).decode()
    reply = _json(f"{base}/oauth2/token", "POST", {
        "content-type": "application/x-www-form-urlencoded",
        "authorization": f"Basic {basic}",
    }, form)
    token = reply["body"].get("access_token")
    if reply["status"] != 200 or not isinstance(token, str):
        raise RuntimeError(f"the token endpoint answered {reply['status']} {json.dumps(reply['body'])[:300]}")
    return token


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _pem_der(text):
    import base64
    lines = [line.strip() for line in str(text).splitlines() if line.strip() and not line.startswith("-----")]
    return base64.b64decode("".join(lines))


def _find_ec_point(der):
    """Uncompressed EC point embedded in a PKCS#8 or SEC1 private key."""
    for size, curve, alg in ((32, "P-256", "ES256"), (48, "P-384", "ES384"), (66, "P-521", "ES512")):
        marker = b"\x00\x04"
        need = 2 + size * 2
        start = 0
        while True:
            found = der.find(marker, start)
            if found < 0:
                break
            chunk = der[found:found + need]
            if len(chunk) == need:
                return curve, alg, chunk[2:2 + size], chunk[2 + size:]
            start = found + 1
    return None


def _public_key_fallback(config_path):
    """Public key JSON. Standard library only; the private scalar is not sent."""
    import hashlib
    raw = json.loads(Path(config_path).read_text(encoding="utf-8"))
    base = Path(config_path).resolve().parent

    def material(value, what):
        if not isinstance(value, str) or not value.strip():
            raise RuntimeError(f"{what} is missing")
        text = value.strip()
        if text.startswith("env:"):
            found = os.environ.get(text[4:])
            if not found:
                raise RuntimeError(f"{text} is not set")
            return found
        if "-----BEGIN" in text:
            return text
        path = text[5:] if text.startswith("file:") else text
        full = Path(path) if os.path.isabs(path) else base / path
        return full.read_text(encoding="utf-8")

    proof = str(raw.get("keyProof") or ("mtls" if raw.get("certificate") else "httpsig"))
    if proof == "mtls":
        cert = material(raw.get("certificate"), "certificate")
        begin = "-----BEGIN CERTIFICATE-----"
        end = "-----END CERTIFICATE-----"
        start = cert.find(begin)
        stop = cert.find(end)
        if start < 0 or stop < 0:
            raise RuntimeError("the certificate PEM could not be read")
        block = cert[start:stop + len(end)].strip()
        return json.dumps({"proof": "mtls", "cert": block})
    private = material(raw.get("privateKey"), "privateKey")
    found = _find_ec_point(_pem_der(private))
    if not found:
        raise RuntimeError("the private key is not an EC key this registrar can read")
    curve, alg, x_bytes, y_bytes = found
    jwk = {"kty": "EC", "crv": curve, "x": _b64url(x_bytes), "y": _b64url(y_bytes)}
    canonical = json.dumps({"crv": jwk["crv"], "kty": "EC", "x": jwk["x"], "y": jwk["y"]}, separators=(",", ":")).encode()
    jwk["alg"] = alg
    jwk["kid"] = _b64url(hashlib.sha256(canonical).digest())
    return json.dumps({"proof": proof, "jwk": jwk})


def key_json_of(config_path):
    return _public_key_fallback(config_path)


def pep_plan(files, base, name, mode):
    """What --pep does, for --dry-run. No key and no request leaves here."""
    app = files["application"]
    return [
        f"GET  {base}/admin-api/users?user={name}  # create the service account unless it exists",
        f"POST {base}/admin-api/users/create  # {name}: a service account, owned by admin-write, no credential",
        f"POST {base}/admin-api/groups/add-member  # {name} in {PEP_GROUP}",
        f"# make a P-256 key in {PEP_KEY} beside the configuration (0600) unless one is there",
        f"POST {base}/admin-api/xacml/issue-pep-credential  # its certificate request, bound to {app} (a new key or account)",
        f"POST {base}/admin-api/xacml/set-pep-application  # or, with both kept, the binding to {app} again",
        f"POST {base}/admin-api/xacml/authzen/set-attribute  # subject.acr -> {ACR_ATTRIBUTE}",
        f"POST {base}/admin-api/applications/fga-create-policy  # {app}'s own policy, unless it has one",
        f"POST {base}/admin-api/xacml/import-alfa  # the demo policy into it (only while {app} enforces none)",
        f"POST {base}/admin-api/applications/fga-enable  # {app} enforces its own policy; the realm root is untouched",
        f"POST {base}/admin-api/applications/add  # {PEP_EVENT} in ssfAllowedEvents, only if {app} restricts them",
        f"# write \"pep\": {{\"name\": \"{name}\", \"mode\": \"{mode}\", \"assertionKey\": \"{PEP_KEY}\"}} into the configuration",
    ]


def make_pep_key(key_file):
    """A P-256 key made with openssl, created 0600. It is never printed; the
    certificate request is made from the file by pep_csr()."""
    key_file.parent.mkdir(parents=True, exist_ok=True)
    old = os.umask(0o077)
    try:
        made = subprocess.run(
            ["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", str(key_file)],
            check=False, capture_output=True, text=True,
        )
    finally:
        os.umask(old)
    if made.returncode != 0:
        raise RuntimeError("openssl could not make the PEP's key (is openssl installed?)")
    os.chmod(key_file, stat.S_IRUSR | stat.S_IWUSR)


def pep_csr(key_file, name):
    """The key's certificate request, the only thing about it that is sent."""
    with tempfile.TemporaryDirectory() as work:
        csr = Path(work) / "pep.csr"
        asked = subprocess.run(
            ["openssl", "req", "-new", "-key", str(key_file), "-subj", f"/CN={name}", "-out", str(csr)],
            check=False, capture_output=True, text=True,
        )
        if asked.returncode != 0:
            raise RuntimeError("openssl could not make the PEP's certificate request from its key")
        return csr.read_text(encoding="utf-8")


def _ok(answer, what, allow=""):
    """An /admin-api act that worked, or one refused only because it is
    already so (`allow`, matched in the refusal's words). Answers whether it
    changed something."""
    body = answer["body"]
    if answer["status"] == 200 and body.get("ok") is not False:
        return True
    words = " ".join(_errors(body)) + " " + str(body.get("why") or "")
    if allow and allow in words.lower():
        return False
    raise RuntimeError(f"{what}: refused ({answer['status']}): {json.dumps(body)[:400]}")


def write_pep_section(config_path, name, mode):
    """The configuration's `pep` section: the name, the mode and the key's
    path; any other member already there is kept."""
    path = Path(config_path)
    raw = json.loads(path.read_text(encoding="utf-8"))
    section = raw.get("pep") if isinstance(raw.get("pep"), dict) else {}
    section.update({"name": name, "mode": mode, "assertionKey": PEP_KEY})
    raw["pep"] = section
    path.write_text(json.dumps(raw, indent=2) + "\n", encoding="utf-8")


def _fga_of(api, app):
    page = api(f"/applications?application={quote(app, safe='')}", None, "GET")["body"].get("page") or {}
    return page, page.get("fga") or {}


def setup_pep(api, files, config_path, name, mode):
    """docs/remote-pep.md's steps 2 to 6. Safe to run again: an account, a
    key and a policy already there are kept, and the binding is set again."""
    app = files["application"]
    # Step 2: the service account, in remote-peps.
    found = api(f"/users?user={quote(name)}", None, "GET")
    made_account = found["body"].get("known") is not True
    if made_account:
        _ok(api("/users/create", {
            "username": name, "invent": False, "credential": "none", "serviceAccount": True,
            "owners": ["admin-write"], "attributes": {"cn": name, "displayName": name},
        }), f"creating the service account {name}")
        print(f"Created the PEP's service account {name}.")
    else:
        print(f"The PEP's service account {name} already exists.")
    _ok(api("/groups/add-member", {"group": PEP_GROUP, "member": name}), f"adding {name} to {PEP_GROUP}")
    # Step 3: the key, certified from its own request, and the binding.
    key_file = Path(config_path).resolve().parent / PEP_KEY
    made_key = not key_file.exists()
    if made_key:
        make_pep_key(key_file)
        print(f"Generated the PEP's P-256 key in {key_file} (readable by you only).")
    if made_key or made_account:
        _ok(api("/xacml/issue-pep-credential", {"name": name, "csr": pep_csr(key_file, name), "application": app}),
            "certifying the PEP's key")
        print(f"Certified the PEP's {'new' if made_key else 'existing'} key and bound {name} to {app}.")
    else:
        _ok(api("/xacml/set-pep-application", {"name": name, "application": app}), f"binding {name} to {app}")
        print(f"Kept the PEP's key; {name} is bound to {app}.")
    # Step 4: the claim the policy reads.
    _ok(api("/xacml/authzen/set-attribute", {"object": "subject", "property": "acr", "attributeId": ACR_ATTRIBUTE}),
        "the catalogue row subject.acr")
    # Step 5: the application's OWN policy, never the realm root, written
    # only while the application enforces none, so an administrator's edits
    # survive a re-run.
    page, fga = _fga_of(api, app)
    if fga.get("enforced") is True:
        print(f"{app} already enforces its own policy; it is left as it is.")
    else:
        _ok(api("/applications/fga-create-policy", {"application": app}), f"{app}'s own policy", allow="already")
        page, fga = _fga_of(api, app)
        policy = (fga.get("policy") or {}).get("name") or fga.get("reference")
        if not policy:
            raise RuntimeError(f"{app}'s page names no policy of its own: {json.dumps(fga)[:300]}")
        _ok(api("/xacml/import-alfa", {"name": policy, "alfa": orders_policy()}), f"writing {policy}")
        _ok(api("/applications/fga-enable", {"application": app}), f"enforcing {app}'s own policy")
        print(f"{app} now enforces its own policy {policy}: read on an order needs an acr; anything else is denied.")
    # Step 6: only an application that restricts its streams needs the event named.
    allowed = (page.get("attributes") or {}).get("ssfAllowedEvents") or []
    if isinstance(allowed, str):
        allowed = [allowed]
    if allowed and PEP_EVENT not in allowed:
        _ok(api("/applications/add", {"application": app, "attribute": "ssfAllowedEvents", "value": PEP_EVENT}),
            "letting pep-policies-changed through ssfAllowedEvents", allow="already")
        print(f"Added {PEP_EVENT} to {app}'s ssfAllowedEvents.")
    write_pep_section(config_path, name, mode)
    print(f"Wrote a {mode} pep section into {config_path}.")


def container_port(cwd=None):
    """PORT from the running gnap-demo container, when compose has one. Docker being absent is not an error."""
    cwd = str(cwd or REPO)
    try:
        listed = subprocess.run(
            ["docker", "compose", "ps", "-q", "gnap-demo"],
            cwd=cwd, capture_output=True, text=True, check=False,
        )
        if listed.returncode != 0:
            return None
        container = (listed.stdout or "").strip().split("\n")[0].strip()
        if not container:
            return None
        inspected = subprocess.run(
            ["docker", "inspect", "-f", "{{range .Config.Env}}{{println .}}{{end}}", container],
            capture_output=True, text=True, check=False,
        )
        if inspected.returncode != 0:
            return None
        for line in (inspected.stdout or "").split("\n"):
            if line.startswith("PORT="):
                return line[len("PORT="):]
    except Exception:
        return None
    return None


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    args = parse_args(argv)
    if args["help"]:
        print(usage())
        return 0
    files = files_of(args["config"], args["public_url"])
    port = demo_port(os.environ.get("PORT"), container_port())
    uris = redirects_for(files["finishUri"], files.get("displayUri"), args["public_url"], args["public_url_given"], port)
    files["finishUri"] = uris["finishUri"]
    if uris.get("displayUri"):
        files["displayUri"] = uris["displayUri"]
    idp = args["idp"] or idp_from_grant(files["grantEndpoint"])
    realm = realm_of(idp)
    origin, base = realm["origin"], realm["base"]
    try:
        key_json = key_json_of(args["config"])
    except Exception as err:
        if not args["dry_run"]:
            raise RuntimeError(f"the client key could not be read ({err}). Generate the key at the privateKey path first.") from err
        key_json = "<the public key>"
    if args["dry_run"]:
        if files.get("tlsCa"):
            print(f"# would save {origin}'s listener CA trust chain to {files['tlsCa']}")
        print(f"# key proof {files['keyProof']}; management calls set rejectUnauthorized false")
        for call in plan_for(files, base, args["test_user"], key_json):
            print(f"{call['method']} {call['path']}  # {call['when']}: {call['why']}\n{json.dumps(call.get('body') or {}, indent=2)}")
        if args["pep"]:
            for line in pep_plan(files, base, args["pep_name"], args["pep"]):
                print(line)
        return 0
    if files.get("tlsCa"):
        chain = save_trust_chain(origin, files["tlsCa"])
        print(f"Saved {origin}'s listener CA trust chain ({chain['count']} certificate(s)) to {files['tlsCa']}")
        print(f"  trust anchor {chain['anchor_subject']}")
        print(f"  sha256 {chain['anchor_fingerprint']}")
        print("  Compare the anchor with the Root CA on iya-sts's Server configuration, PKI page.")
        print("  The demo image build copies that chain in. Rebuild it after running this against another iya-sts.")
    secret = os.environ.get("ADMIN_API_CLIENT_SECRET") or os.environ.get("STS_ADMIN_API_CLIENT_SECRET") or ""
    if not secret:
        raise RuntimeError("neither ADMIN_API_CLIENT_SECRET nor STS_ADMIN_API_CLIENT_SECRET is set, so no /admin-api token can be minted.")
    token = mint_admin_token(base, secret)

    def api(path, body=None, method="POST"):
        headers = {"accept": "application/json", "authorization": f"Bearer {token}"}
        payload = None
        if body is not None:
            headers["content-type"] = "application/json"
            payload = json.dumps(body)
        return _json(f"{base}/admin-api{path}", method, headers, payload)

    plan = plan_for(files, base, args["test_user"], key_json)
    create = next(call for call in plan if call["when"] == "create")
    created = api("/applications/create", create["body"])
    fresh = False
    if created["body"].get("ok"):
        fresh = True
        print(f"Registered {files['application']}. The key is the one in the configuration; it was not written here.")
    elif any("already in this registry" in item.lower() for item in _errors(created["body"])):
        print(f"{files['application']} is already registered; adding the demo's values. The registered key is unchanged.")
        for call in plan:
            if call["when"] != "exists":
                continue
            added = api(call["path"][len(f"{base}/admin-api"):], call["body"])
            errors = " ".join(_errors(added["body"]))
            if not added["body"].get("ok") and "not one of the" in errors and call["path"].endswith("/applications/add"):
                # A single-valued attribute `add` does not take is SET instead.
                added = api("/applications/set", call["body"])
                errors = " ".join(_errors(added["body"]))
            if not added["body"].get("ok") and "already" not in errors.lower():
                raise RuntimeError(f"{call['why']}: refused: {json.dumps(added['body'])[:400]}")
    else:
        raise RuntimeError(f"iya-sts refused to create {files['application']}: {json.dumps(created['body'])[:500]}")
    for call in plan:
        if call["when"] != "always":
            continue
        if not (call["path"].endswith("/config/set") or call["path"].endswith("/roles/add-member") or call["path"].endswith("/applications/set-custom-claim")):
            continue
        answered = api(call["path"][len(f"{base}/admin-api"):], call["body"])
        errors = " ".join(_errors(answered["body"]))
        # An iya-sts older than the gnap_access_token claim set refuses it as "not one of" the sets
        # it knows. The uid claim is not required to sign in, so only that refusal is passed over.
        if (call["path"].endswith("/applications/set-custom-claim")
                and not answered["body"].get("ok")
                and "not one of" in errors):
            print(f"  {call['why']}: this iya-sts has no {call['body'].get('set')} claim set; continuing.")
            continue
        if not answered["body"].get("ok") and "already" not in errors.lower():
            raise RuntimeError(f"{call['why']}: refused: {json.dumps(answered['body'])[:400]}")
        if not answered["body"].get("ok"):
            print(f"  {call['why']}: already so")
        elif call["path"].endswith("/applications/set-custom-claim"):
            print(f"Access-token JWT claim uid is set on {files['application']}.")
    if fresh:
        print("authn.multipleAccounts is on, and the Shared Signals roles were granted for the access rights in the file.")
    if args["test_user"]:
        found = api(f"/users?user={quote(args['test_user'])}", None, "GET")
        password = os.environ.get("GNAP_DEMO_USER_PASSWORD") or ""
        if found["body"].get("known") is True and password:
            set_password = api("/users/set-password", {"user": args["test_user"], "password": password, "passwordConfirm": password})
            if not set_password["body"].get("ok"):
                raise RuntimeError(f"setting {args['test_user']}'s password was refused: {json.dumps(set_password['body'])[:300]}")
            print(f"User {args['test_user']} already exists; its password is now GNAP_DEMO_USER_PASSWORD.")
        elif found["body"].get("known") is True:
            print(f"User {args['test_user']} already exists; its password is unchanged (set GNAP_DEMO_USER_PASSWORD to replace it).")
        else:
            body = {
                "username": args["test_user"],
                "invent": False,
                "credential": "password" if password else "generate",
                "attributes": user_attributes(args["test_user"]),
            }
            if password:
                body["password"] = password
                body["passwordConfirm"] = password
            made = api("/users/create", body)
            if not made["body"].get("ok"):
                raise RuntimeError(f"creating {args['test_user']} was refused: {json.dumps(made['body'])[:300]}")
            print(f"Created user {args['test_user']}.")
            if made["body"].get("password"):
                # Never printed: a password does not belong in a log. It goes to a file only its
                # owner can read, created 0600, in demo/generated beside the client key, which
                # never enters an image (.dockerignore admits only tlsCa's chain).
                saved = Path(args["config"]).resolve().parent / "generated" / f"{args['test_user']}.password"
                saved.parent.mkdir(parents=True, exist_ok=True)
                descriptor = os.open(saved, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(descriptor, "w", encoding="utf-8") as out:
                    os.fchmod(out.fileno(), 0o600)
                    out.write(f"{made['body']['password']}\n")
                print(f"Generated a password for {args['test_user']}; it is in {saved} (readable by you only).")
        for call in plan:
            if not call["path"].endswith("/groups/add-member"):
                continue
            added = api("/groups/add-member", call["body"])
            if not added["body"].get("ok"):
                raise RuntimeError(f"adding {args['test_user']} to a group was refused: {json.dumps(added['body'])[:300]}")
            group = call["body"].get("group")
            print(f"{args['test_user']} {'was already' if added['body'].get('changed') is False else 'is now'} in {group}.")
    if args["pep"]:
        setup_pep(api, files, args["config"], args["pep_name"], args["pep"])
    print(f"application: {files['application']}")
    print(f"grant:       {files['grantEndpoint']}")
    print(f"finish:      {files['finishUri']}")
    print(f"proof:       {files['keyProof']}")
    print("Done. Start the demo with: docker compose up --build")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as err:
        print(str(err), file=sys.stderr)
        sys.exit(1)
