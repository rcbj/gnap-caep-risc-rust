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
match client.decide_grant(&grant, &Access::new("read", "order", "42")) {
    Decision::Permit { obligations, .. } => { /* discharge them, then serve */ }
    Decision::Deny { .. } => { /* 403 */ }
    Decision::Unavailable { .. } => { /* 503: fail closed, never a Permit */ }
}
```

The section is off unless present, and a build without the feature refuses it. The PEP's key must be its own, and only the claims the realm's AuthZEN catalogue declares are sent. The demo protects `GET /orders/<id>` with the PEP.

`src/tests/authzen_cases.json` is this library's AuthZEN table for the PEP. The unit suite runs it in `local` mode against a stub; `python3 scripts/live_iya_sts.py --authzen` runs every case through a `central` and a `local` PEP on a fresh iya-sts and fails unless both give the table's answer. All 58 cases agree against iya-sts `feature/2028` with iya-pep `c0d61ca`; see [docs/remote-pep.md](docs/remote-pep.md#test-that-central-and-local-agree), including the `authzen.returnReasons` setting the run turns on.

## Demo

```bash
docker compose up --build
```

`PORT` defaults to 3000 and is the bind port. Loopback finish and display URLs follow `PORT`. Any other host is left as written. `PUBLIC_URL` or `--public-url` replaces the origin and keeps the path. `GET /healthz` returns `ok`. The home page has a sign-in control; `/login` starts a grant, `/callback` finishes it, and `POST /logout` signs out.

The shipped `demo/gnap.json` leaves `signals` on by omitting the key. Key material is `file:` or `env:` and is not in the tree. Register the application with:

```bash
ADMIN_API_CLIENT_SECRET=… python scripts/configure_iya_sts.py --config demo/gnap.json
```

`--dry-run` prints the admin API calls and sends nothing.

The script never prints a password or secret. When it generates the test user's password it writes it to `demo/generated/<user>.password` (created 0600) and prints only that path.

### The demo with its embedded PEP

```bash
ADMIN_API_CLIENT_SECRET=… python scripts/configure_iya_sts.py --config demo/gnap.json --pep central   # or local
docker compose up --build
```

`--pep central|local` (with `--pep-name`, default `pep-gnap-demo`) also does [docs/remote-pep.md](docs/remote-pep.md)'s steps 2 to 6: the PEP's service account in `remote-peps`, a P-256 key made with your `openssl` in `demo/generated/pep-key.pem` (0600, never printed, never in the image), the key certified and the PEP bound to the demo's application, the catalogue row `subject.acr`, and the application's own policy (read on an order needs an `acr`; anything else is denied), which it then enforces. The realm root is not touched. It writes the `pep` section into `demo/gnap.json`. Run it again, against the same iya-sts or a fresh one, to switch the mode: the account, the key and the policy are kept (a policy is written only while the application enforces none, so your edits survive), and a kept key is certified again for a new account. `--dry-run` lists these calls too. Then `GET /orders/42` is 200 and `POST /orders/42` 403. Enforcing the demo application's policy decides nothing at GNAP issuance: its grant asks for plain access rights (`ssf.read`, `ssf.manage`), and iya-sts asks an application's policy only about an `authorization_details` type that application declares.

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

The script starts a fresh iya-sts each time. `--pep` sets the demo's PEP up with the install script (`--pep central`), checks `GET /orders/42` (200) and `POST` (403) in `central` and then `local`, and then rewrites the application's own policy to deny read, which the `local` demo must apply by `pep-policies-changed`. That last check fails today: iya-sts's GNAP subject scope (`gnap/gnap_signals.ts` `scope()`) refuses the event's application subject on a GNAP web client's stream (`STS-SSF-0029`, "went to 0 of 1 stream(s)"), so a `local` PEP hears of a change only at its heartbeat or poll. `LIVE_KEEP=1` leaves the containers running for a post-mortem.

The Nightly workflow runs `docker build --target test .` and then this script every day at 06:59 UTC, and on demand.

## License

MIT. Copyright (c) 2026 Iya CyberSecurity Solutions, LLC.
