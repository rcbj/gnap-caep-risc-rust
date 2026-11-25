# gnap-caep-risc

A server-side [GNAP](https://www.rfc-editor.org/rfc/rfc9635) client. The key is registered by value and proved with mutual TLS, an HTTP message signature, or a detached JWS. Access tokens are key-bound; a bearer token is refused. One Shared Signals poll stream carries CAEP and RISC events.

The private key stays in this process. The same `gnap.json` shape as the Python and Node libraries loads: the JSON keys are identical.

## Build and tests

```bash
docker build --target test .
```

The `test` stage runs `cargo test`, then `cargo test --all-features`, in `rust:1-bookworm`. GitHub Actions uses that command. Do not run Cargo on the host. The demo image does not run the suite.

With every feature, the suite also drives the demo's two PEP-protected pages through its real routes (`src/bin/demo.rs`, `mod tests::protected`): a `local` PEP holds the demo application's own policy (`src/tests/demo_orders_policy.xml`, the XACML iya-sts stores for the install script's ALFA) against a stub realm whose PIP answers `attr1` per person. A signed-in person with `attr1=abc123` and an `acr` gets 200 on `GET /attribute-protected` and `GET /orders/42`; `attr1` another value or absent gets 403 on `/attribute-protected`; `POST /orders/42` is 403; a sign-in without an `acr` gets 403 on `GET /orders/42`; signed out, both are 401. Each status is checked against the decision's `http_status()`.

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

The script starts a fresh iya-sts each time. `--pep` (or `LIVE_PEP=1`) sets the demo's PEP up with the install script (`--pep central`) and adds a second test user, `gnap-demo-denied`, with `attr1=not-abc123`. In `central` and then `local` it requires `GET /orders/42` 200 and `POST` 403, and `GET /attribute-protected` 200 for the test user and 403 for the denied one (whose `GET /orders/42` stays 200). It requires that iya-sts stored exactly `src/tests/demo_orders_policy.xml` for the install script's ALFA (`storedXacmlIsTheUnitFixture`), the policy the unit tests use. Then it rewrites the application's own policy to deny read, which the `local` demo must apply by `pep-policies-changed` within `PEP_FLIP_TIMEOUT` seconds (30). Against iya-sts `feature/2028` at `a6cb55cb3` (image `iya-sts:local`) all of it passed, the flip by event in 1.2 s.

`--ui` (or `LIVE_UI=1`) is the same provisioning with `--pep local`, then a real headless browser: the Dockerfile's `ui-browser` stage (Playwright's `mcr.microsoft.com/playwright/python:v1.49.0-noble` with its Python package) runs `scripts/live_ui_browser.py` on the host network. Chromium clicks **Sign in**, completes iya-sts's sign-in and GNAP approval pages, comes back through `/callback`, and opens `/attribute-protected` and `/orders/42` from the top bar and by address, checking each response's status and the page text. The test user gets 200 on both and 403 on `POST /orders/42` (sent with the browser's cookies), signs out from the user menu, and then both pages are 401. The denied user signs in in a fresh browser context (GNAP cannot make iya-sts ask again; new cookies do) and gets 403 on `/attribute-protected`, 200 on `GET /orders/42` and 403 on `POST`. Screenshots and `summary.json` go to `LIVE_UI_OUT` (default: a new temporary directory, kept); the JSON summary is printed last and any mismatch fails the run. The browser trusts iya-sts's self-signed development listener (`ignore_https_errors`). All 31 checks passed against `iya-sts:local` (`feature/2028`). The nightly run does not pass `--pep`, because `main` lacks iya-sts #2026–#2028. `LIVE_KEEP=1` leaves the containers running for a post-mortem.

The Nightly workflow runs `docker build --target test .` and then this script every day at 06:59 UTC, and on demand.

## License

MIT. Copyright (c) 2026 Iya CyberSecurity Solutions, LLC.
