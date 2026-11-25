# gnap-caep-risc

A server-side [GNAP](https://www.rfc-editor.org/rfc/rfc9635) client. The key is registered by value and proved with mutual TLS, an HTTP message signature, or a detached JWS. Access tokens are key-bound; a bearer token is refused. One Shared Signals poll stream carries CAEP and RISC events.

The private key stays in this process. The same `gnap.json` shape as the Python and Node libraries loads: the JSON keys are identical.

## Build and tests

```bash
docker build --target test .
```

The `test` stage runs `cargo test`, then `cargo test --all-features`, in `rust:1-bookworm`. GitHub Actions uses that command. Do not run Cargo on the host. The demo image does not run the suite.

Crate name: `gnap-caep-risc`. A pull request merged into `main` publishes the crate to crates.io after the test workflow succeeds on that commit. A direct push does not. The token is the `CARGO_REGISTRY_TOKEN` repository secret. A release happens when the library's files changed since the last release's tag: `publish.yml` takes one patch above the highest published version, publishes it, and creates the matching tag and GitHub Release. A change to tests, the demo, or the docs releases nothing. To choose a version or start a new minor, raise `VERSION`; the version is stamped in CI and is not committed, so the manifests can trail what is published.

## Three calls

```rust
let client = gnap_caep_risc::Client::from_file("gnap.json")?;
let started = client.request_grant()?;
let done = client.finish_redirect(query, &[started.pending.as_ref().unwrap().id.clone()])?;
```

`request_grant` returns a redirect and a pending grant. `finish_redirect` checks the interaction hash against grants this process started, then continues the grant with the key proof. Pass the pending ids this browser was given.

`Client::resolve` loads the same document without starting a grant.

## Signals

`signals` omitted or `true` keeps CAEP and RISC on. The resolved configuration omits the key, fills `ssf` from `ssf.transmitter` or `transmitterIssuer`, and asks for `ssf.read` and `ssf.manage` when `access` does not say otherwise.

`signals: false` does not start the Shared Signals receiver, does not require transmitter metadata, and drops `ssf.read` and `ssf.manage` from the GNAP access. The resolved configuration includes `signals: false`. If those two rights were the only ones, configuration fails and asks for another right the authorization server grants. Any other value fails with `signals must be true or false`.

`ssf.pollIntervalMs` is the poll interval in milliseconds. `SignalsReceiver::stop` waits until the background poll has finished.

## Credentials

Every credential the library, its demo and its embedded PEP hold, who makes each one, and what it proves. No value of any of them is in this repository, in the demo image, or in a log line. The demo keeps its key material in `demo/generated/`, which `.gitignore` and `.dockerignore` keep out (only the public `tlsCa` chain enters the image).

### The application's own credentials

| Credential | Type | Made or issued by | Where it lives | Used for | How iya-sts knows it | Rotation |
|---|---|---|---|---|---|---|
| **Client instance key** and its certificate | EC P-256 (ES256) in the demo; the library also loads RSA keys | Development: you, with `openssl` (a self-signed certificate; `scripts/live_iya_sts.py` makes one the same way). Product: the realm's TLS client Issuing CA, through `POST /admin-api/applications/issue-tls-client-certificate`, which the install script calls (below) | `privateKey` and `certificate` (`file:`, `env:` or inline PEM): the demo's are `file:generated/client.key` and `file:generated/client.crt`. Keep the key readable by you only; the install script writes an issued key 0600 | Proves every GNAP request: `keyProof` `mtls` (the TLS client certificate), `httpsig` (RFC 9421 signatures) or `jwsd` (detached JWS). Every access token is bound to it; a bearer token is refused | The application entry's `gnapKey`, written when the install script registers the application: the certificate under `mtls`, the public JWK otherwise | Re-registering an existing application leaves `gnapKey` as it is. Under PKI trust, remove the certificate file and run the install script: it has a new one issued and sets `gnapKey`. It also replaces a self-signed certificate. Otherwise, set `gnapKey` to the new public key (`/admin-api/applications/set`) |
| **GNAP access token** | Key-bound token | iya-sts, at the end of a grant | In process memory only (the demo's session table); never written or shown (pages show a SHA-256 fingerprint) | The grant's access rights (`ssf.read`, `ssf.manage` in the demo), sent with the key proof | It issued it | `ensure_fresh` rotates it through the management URI when 60 s or less are left; `POST /session/rotate` in the demo |
| **Management access token** | Key-bound token | iya-sts, with the grant | Memory only | Rotating the access token (`rotate`) | It issued it | Comes back with each rotation |
| **Continuation access token** | Key-bound token | iya-sts, with the pending and the finished grant | Memory only | Continuing the grant after interaction (`finish_redirect`), and revoking it (`revoke`, a DELETE of the continuation URI at sign-out) | It issued it | Per grant |
| **The token for Shared Signals calls** | The GNAP access token above | — | Memory only | Stream discovery, creation, update, polls and verification (`ReceiverOpt::headers`): the demo signs each call with the latest grant's access token and the client instance key's proof | The `ssf.read` / `ssf.manage` rights on that token, which the install script lets the application grant (roles `SSF_READ`, `SSF_MANAGE`) | Follows the access token |
| **The test user's password** (demo only) | Password | iya-sts generates it, or you give `GNAP_DEMO_USER_PASSWORD` | `demo/generated/<user>.password`, created 0600, only when iya-sts generated it; only the path is printed | Signing in to iya-sts as `gnap-demo-user` to try the demo | The directory | Set `GNAP_DEMO_USER_PASSWORD` and run the install script again: an existing user's password is set to it |

### The embedded PEP's credentials

The PEP is a principal of its own: the service account `pep-gnap-demo` (`--pep-name`), created with no password (`credential: none`) as a service account and put in the `remote-peps` group.

| Credential | Type | Made or issued by | Where it lives | Used for | How iya-sts knows it | Rotation |
|---|---|---|---|---|---|---|
| **PEP key** | EC P-256 (RSA of 2048 bits or more is accepted) | Made locally with `openssl` by the install script (or by you); only its certificate request is sent | `pep.assertionKey`, relative to the configuration's directory; the demo's is `generated/pep-key.pem`, created 0600, never printed, never in the image | Signs an RFC 7523 JWT assertion (`iss` and `sub` the PEP's name) at the realm's `/oauth2/token` (client `sts-remote-pep`), and the DPoP proof of every call. That yields DPoP-bound tokens for the PEP's three audiences: `xacml:pep` (registration, heartbeat, catalogue, policies, `POST /xacml/pip`), `xacml:pep-audit` and `authzen:evaluate` | `POST /admin-api/xacml/issue-pep-credential` certifies the request and registers the key for the PEP's entry, binding the PEP to the application (`set-pep-application` alone rebinds) | Remove the key file and run the install script with `--pep`: it makes a new key and certifies it. The PEP reads the file again when it changes, and a changed key drops every token it held |
| **The PEP's access tokens** | DPoP-bound | The realm's token endpoint | Memory only; never logged | The calls above, one token per audience, renewed 30 s before expiry | It issued them | Automatic |

**The library refuses a PEP key that is the client instance key** (same JWK thumbprint): `pep.assertionKey is the GNAP client instance key (privateKey); the PEP needs a key of its own`. The two are different principals: the application proves GNAP requests and holds grants, while the PEP is a service account with its own entry, group and binding. A shared key would let either be taken for the other, and would tie a rotation or a compromise of one to both. See [docs/remote-pep.md](docs/remote-pep.md#credentials).

### Install-time only

| Credential | Where | Used for |
|---|---|---|
| `ADMIN_API_CLIENT_SECRET` (or `STS_ADMIN_API_CLIENT_SECRET`) | The environment of `scripts/configure_iya_sts.py` only; never stored, printed or passed on a command line (the live script passes it as `-e NAME`) | The secret of iya-sts's `sts-api-client`. It is sent by HTTP Basic to the realm's `/oauth2/token` (`client_credentials`, resource `<realm>/admin-api`) for a token with `admin:read admin:write`, which every `/admin-api` call carries. For one call alone, defining the realm's custom attribute `attr1`, the script mints a second token with `admin:read admin:security`; that needs the client to hold `SECURITY_ADMIN`, which iya-sts seeds |
| `GNAP_DEMO_USER_PASSWORD` | Environment, optional | The test user's password (above) |

The tokens minted from the secret live only while the script runs. The running demo needs neither.

### Trust material

- **`tlsCa`** (demo: `generated/idp-ca.pem`) is the iya-sts TLS listener's CA trust chain, public material. The install script writes it on every run (`GET /tls/server-certificate`, else the handshake) and prints the anchor's SHA-256; the demo image carries it from build time. The library verifies every connection to iya-sts with it: the grant endpoint, discovery and the ID token issuer's JWKS, and the Shared Signals transmitter. The embedded PEP uses it too unless `pep.tlsCa` names another. Each certificate in the file is an anchor; a pinned certificate counts only as the presented leaf, and the host name is always checked. `allowInsecure` does not turn verification off.
- **What iya-sts verifies:** the client instance key's proof against `gnapKey` (and under PKI, the certificate's chain to the realm's client truststore and its binding to the application); the PEP's assertion and proofs against the key `issue-pep-credential` registered.
- **What the library verifies:** the ID token assertion against `idTokenIssuer`'s JWKS (issuer, audience, time), and each Security Event Token against the transmitter's JWKS (issuer, audience, `typ`).

### Development and product iya-sts

- **GNAP mTLS trust**, `gnap.mtlsTrust`: `auto` is `pinned` in development and `pki` in product.
  - **`pinned`**: iya-sts accepts the exact certificate registered in `gnapKey`, so a self-signed client certificate works.
  - **`pki`**: a self-signed certificate is refused (`STS-GNAP-0287`). The certificate must chain to the realm's client truststore and be bound to the application.
  - **The install script** asks the realm which model it uses. With `keyProof` `mtls` under `pki`, it has the realm issue the client certificate: `issue-tls-client-certificate`, `ec-p256`, subject `urn:sts:application:<id>`. It decrypts the one-time encrypted key with `openssl` into `privateKey`'s file (0600), writes the certificate and chain to `certificate`'s file, and registers the key as `gnapKey`. A realm-issued certificate already there is kept.
  - **`httpsig` and `jwsd`** register a public JWK, and `gnap.mtlsTrust` does not apply to them.
- **The listener CA:** a development iya-sts makes a new listener CA when it restarts. Run the install script again (it rewrites `tlsCa`'s file) and rebuild the demo image, or let the demo's start-time refresh fetch it (`TLS_CA_REFRESH`, on by default). In product the chain is stable.
- **The PEP key** is certified by `issue-pep-credential` the same way in both modes.

## Embedded PEP (features `pep` and `local`)

Ask iya-sts's authorization policy whether a signed-in person may act on a resource, through the embedded Remote PEP (the shared [`iya-pep`](https://github.com/rcbj/iya-pep-rust) crate; iya-sts [#1206](https://github.com/rcbj/iya-sts/issues/1206)). **[docs/remote-pep.md](docs/remote-pep.md) is the full guide**: setting up iya-sts, choosing `central` or `local`, every configuration member, obligations, policy-change events, operating it and troubleshooting.

```toml
gnap-caep-risc = { version = "…", features = ["pep"] }    # central: AuthZEN at iya-sts
gnap-caep-risc = { version = "…", features = ["local"] }  # local too: decided in process
```

```json
"pep": { "name": "pep-orders", "mode": "local", "assertionKey": "pep-key.pem" }
```

```rust
let decision = client.decide_grant(&grant, &Access::new("read", "order", "42"));
let status = decision.http_status(); // 200 for a Permit, 403 for anything else
match decision {
    Decision::Permit { obligations, .. } => { /* discharge them, then serve */ }
    Decision::Deny { .. } => { /* 403 */ }
    Decision::Unavailable { .. } => { /* 403: fail closed, never a Permit */ }
}
```

The section is off unless present, and a build without the feature refuses it. A section that names no `mode` is `local`, so a `pep`-only build must name `central`. The PEP's key must be its own, and only the claims the realm's AuthZEN catalogue declares are sent. Every PEP failure is a 403: `Unavailable` (no policy held, iya-sts unreachable, or a panic while deciding, which the PEP catches) is refused like a Deny, and in `central` mode a failed evaluation or heartbeat drops every cached Permit. The Shared Signals receiver tells the PEP how its stream is doing (`requested` or `excluded` while polls succeed, `down` after a failed poll or `stop()`), and the PEP polls its policies itself while it is `down`. The demo protects `GET /orders/<id>` and `GET /attribute-protected` with the PEP.

`src/tests/authzen_cases.json` is this library's AuthZEN table for the PEP. The unit suite runs it in `local` mode against a stub; `python3 scripts/live_iya_sts.py --authzen` runs every case through a `central` and a `local` PEP on a fresh iya-sts and fails unless both give the table's answer. All 58 cases agree against iya-sts `feature/2028` with iya-pep `c0d61ca`; see [docs/remote-pep.md](docs/remote-pep.md#test-that-central-and-local-agree), including the `authzen.returnReasons` setting the run turns on.

## Demo

```bash
docker compose up --build
```

`PORT` defaults to 3000 and is the bind port. Loopback finish and display URLs follow `PORT`. Any other host is left as written. `PUBLIC_URL` or `--public-url` replaces the origin and keeps the path. `GET /healthz` returns `ok`. The home page has a sign-in control; `/login` starts a grant and `/callback` finishes it.

Signed in, the top bar links the demo's pages (Demo home and, with the PEP, Attribute-protected and Order 42) and carries a user menu: the person's name, **Sign in with another account** and **Sign out** (`POST /logout`, which revokes the grant; it is nowhere else on the page). The name is the username the grant returned (the `account` subject identifier's user part, else the ID token assertion's `username` or `preferred_username`), else the email, and the subject identifier only when nothing else names the person. GNAP has no prompt to make iya-sts ask again, so **Sign in with another account** (`POST /login/another`) ends the sign-in here and returns to the sign-in page; iya-sts asks who you are unless it still holds a sign-on session for you.

The signed-in page has three tabs, each block on them a collapsible pane, with a **Collapse all** / **Expand all** toggle:

- **Session** (`/`): the protections in effect (the key proof, the client key's thumbprint, the interaction's hash and nonces, token binding, the subject's assertion, TLS, the server-side token cache, Shared Signals); the subject the grant names and every claim of its verified ID token assertion; the token cache (expiry, automatic rotation when 60 s or less are left, rotations, the token management and continuation URIs held, the access rights) with **Rotate now** (`POST /session/rotate`); and the grant's credentials. A credential's value never reaches the page: each is shown by a SHA-256 fingerprint, and a JWT by its decoded header and claims.
- **CAEP & RISC events** (`/?tab=events`): the stream's status, **Ask for a verification event** (`POST /signals/verify`) and the log, newest first, which `app.js` keeps current from `GET /api/signals?after=<id>`. The application has one stream, so this tab shows every user's events; it says so, and a real application must show a person only the events about their own session or account.
- **Policy enforcement** (`/?tab=pep`): the embedded PEP (below).

The shipped `demo/gnap.json` leaves `signals` on by omitting the key. Key material is `file:` or `env:` and is not in the tree. Register the application with:

```bash
ADMIN_API_CLIENT_SECRET=… python scripts/configure_iya_sts.py --config demo/gnap.json
```

`--dry-run` prints the admin API calls and sends nothing.

The script never prints a password or secret. When it generates the test user's password it writes it to `demo/generated/<user>.password` (created 0600) and prints only that path.

### The demo with its embedded PEP

```bash
ADMIN_API_CLIENT_SECRET=… python scripts/configure_iya_sts.py --config demo/gnap.json --pep central   # or --pep (local)
docker compose up --build
```

`--pep [central|local]` (local when the mode is left out; with `--pep-name`, default `pep-gnap-demo`) also does [docs/remote-pep.md](docs/remote-pep.md)'s steps 2 to 6: the PEP's service account in `remote-peps`, a P-256 key made with your `openssl` in `demo/generated/pep-key.pem` (0600, never printed, never in the image), the key certified and the PEP bound to the demo's application, the catalogue row `subject.acr`, and the application's own policy (read on an order needs an `acr`; read on `attribute-protected` needs the directory attribute `attr1` to be `abc123`; anything else is denied), which it then enforces. The realm root is not touched. It writes the `pep` section into `demo/gnap.json`. Run it again, against the same iya-sts or a fresh one, to switch the mode: the account and the key are kept, and a kept key is certified again for a new account. The application's policy is written again on every run while it is this script's own (PolicyId `urn:example:gnapdemo-orders`), so a new rule reaches an existing install; a policy under any other PolicyId is left as it is. `--dry-run` lists these calls too. Then `GET /orders/42` is 200 and `POST /orders/42` 403. The **Policy enforcement** tab's panes (Decisions, Cached policy, The PEP, Control plane, and Try it, which links the two protected pages) draw the PEP's `status()`; `pep.js` redraws them every 2 seconds from `GET /pep-status.html` and keeps a pane you closed closed. `GET /pep-status` is the same as JSON; both answer 401 without a session.

**`GET /attribute-protected`** is decided on a directory attribute rather than a claim: the policy permits `read` on `attribute-protected` when the person's `attr1` is `abc123`, and the PEP asks iya-sts's PIP for it (`POST /xacml/pip`). 401 without a sign-in, 200 on a Permit, 403 on a Deny and on any PEP failure. The install script gives the test user `attr1=abc123`. Defining the realm's custom attribute `attr1` is a Security Administrator's act (it changes the attribute policy): it needs a token carrying `admin:security` whose subject holds `SECURITY_ADMIN`. iya-sts seeds `sts-api-client` in that role, so the script defines `attr1` itself, with an `admin:security` token minted for that one call (every other call carries `admin:read admin:write`). Where an operator has taken the client out of the role, the definition is refused; the value is still tried, and only when it cannot be set because `attr1` is not defined does the script say what a Security Administrator adds under **Directory > Policies > Attribute policy > Custom attributes** (label "Attribute 1", syntax string, one value).

Enforcing the demo application's policy decides nothing at GNAP issuance: its grant asks for plain access rights (`ssf.read`, `ssf.manage`), and iya-sts asks an application's policy only about an `authorization_details` type that application declares.

### The iya-sts trust chain: `tlsCa`

`tlsCa` (demo default `generated/idp-ca.pem`, relative to `demo/`) is the iya-sts TLS listener CA trust chain the library verifies the listener against. The install script, `scripts/configure_iya_sts.py`, writes it on every run: the whole chain iya-sts publishes at `GET /tls/server-certificate` (leaf, TLS Issuing CA, Intermediate, Root), or the chain the TLS handshake presents when that is missing. It prints the path, the trust anchor's subject and its SHA-256.

The library reads every certificate in the file as a trust anchor. A certificate in the file counts as pinned only when it is the leaf the server presents; anything else must verify to an anchor. The host name (DNS name, or an IP literal against an IP SAN) is checked either way. `allowInsecure` is not a TLS switch: there is no way to turn verification off from `gnap.json`.

The demo image carries that file from build time: the Dockerfile copies `demo/`, and `.dockerignore` admits only `demo/generated/idp-ca.pem` from `demo/generated` (never the client key or certificate). Run the install script first, then build. After running it against a different iya-sts, rebuild the image. A build without the file (a fresh clone, CI) still succeeds. At start the demo also refreshes the file from the provider, unless `TLS_CA_REFRESH=0`. When the `gnap-demo` container is running, its `PORT` wins over the shell `PORT`.

## Live test against iya-sts

```bash
python3 scripts/live_iya_sts.py
```

The script starts the latest `main` of iya-sts in memory mode (no persistence, no clustering, no request workers), registers the demo, signs in through it over GNAP with mutual TLS, emits a CAEP credential-change and then a session-revoked event, and requires the demo's `GET /live-status` to show both, with the second ending the local session. It prints JSON that ends `{"ok": true ...}`.

It needs only Docker and the host's `python3` standard library. The client key (openssl) and the registration (`scripts/configure_iya_sts.py`) run in the `tools` image as the invoking user; the demo runs in its own image. Cargo never runs on the host.

The trust chain goes in the way a user's does: the script copies the checkout (without `.git`, `target` and `demo/generated`) to a scratch build context, runs the install script there, which writes `tlsCa`'s file, then builds the demo image and checks that the image's `demo/generated` holds that chain and nothing else. The demo runs with only the client key and certificate mounted (one file each), no CA mount, and `TLS_CA_REFRESH=0`. `tlsCa` is never rewritten.

- `IYA_STS_URL` uses an iya-sts that is already running and does not stop it.
- `IYA_STS_IMAGE` starts a fresh container from that image.
- Otherwise the script clones and builds iya-sts `main`, which is what the nightly run does.
- `LIVE_STS_PORT` (default 18558) and `LIVE_DEMO_PORT` (default 18658) pick the ports. 3000, 8081 and 18481 to 18495 are refused.

The script starts a fresh iya-sts each time. `--pep` (or `LIVE_PEP=1`) sets the demo's PEP up with the install script (`--pep central`), checks `GET /orders/42` (200) and `POST` (403) in `central` and then `local`, and then rewrites the application's own policy to deny read, which the `local` demo must apply by `pep-policies-changed` within `PEP_FLIP_TIMEOUT` seconds (30). It does not check `/attribute-protected`. Against iya-sts `feature/2028` at `a6cb55cb3` (image `iya-sts:live-2028-gnapscope`) both modes gave 200/403 and the flip arrived by event in 1.1 s; that run predates `/attribute-protected` and the `attr1` setup. The nightly run does not pass `--pep`, because `main` lacks iya-sts #2026–#2028. `LIVE_KEEP=1` leaves the containers running for a post-mortem.

The Nightly workflow runs `docker build --target test .` and then this script every day at 06:59 UTC, and on demand.

## License

MIT. Copyright (c) 2026 Iya CyberSecurity Solutions, LLC.
