# gnap-caep-risc

A server-side [GNAP](https://www.rfc-editor.org/rfc/rfc9635) client. The key is registered by value and proved with mutual TLS, an HTTP message signature, or a detached JWS. Access tokens are key-bound; a bearer token is refused. One Shared Signals poll stream carries CAEP and RISC events.

The private key stays in this process. The same `gnap.json` shape as the Python and Node libraries loads: the JSON keys are identical.

## Build and tests

```bash
docker build --target test .
```

The `test` stage runs `cargo test` in `rust:1-bookworm`. GitHub Actions uses that command. Do not run Cargo on the host. The demo image does not run the suite.

Crate name: `gnap-caep-risc`. A pull request merged into `main` publishes the crate to crates.io after the test workflow succeeds on that commit. A direct push does not. The token is the `CARGO_REGISTRY_TOKEN` repository secret. A version already on crates.io stays there; the next release is a new `version` in `Cargo.toml`.

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

A registered GNAP key is not replaced, so run it against a fresh iya-sts each time.

The Nightly workflow runs `docker build --target test .` and then this script every day at 06:59 UTC, and on demand.

## License

MIT. Copyright (c) 2026 Iya CyberSecurity Solutions, LLC.
