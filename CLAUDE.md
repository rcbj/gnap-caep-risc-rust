# gnap-caep-risc

Server-side GNAP client. The crate is `gnap-caep-risc`. The public type is `Client`.

```rust
let client = gnap_caep_risc::Client::from_file("gnap.json")?;
let started = client.request_grant()?;
let done = client.finish_redirect(query, &[started.pending.as_ref().unwrap().id.clone()])?;
```

`Client::resolve` loads the same JSON keys as the Python and Node libraries. Methods are `from_file`, `request_grant`, and `finish_redirect`. Errors carry a code: `config`, `discovery`, `protocol`, `validation`, `signature`, or `ssf`.

## Tests

```bash
docker build --target test .
```

The `test` stage runs `cargo test` in `rust:1-bookworm`. GitHub Actions uses that command. Do not run Cargo on the host. The demo image does not run the suite.

Tests use an in-process stub on 127.0.0.1. They do not need a live authorization server.

## Live test

`python3 scripts/live_iya_sts.py` signs the demo in to a fresh iya-sts `main` and checks two CAEP events through `GET /live-status` (`signedIn`, `subject`, `receiver`, `events` of `type` and `jti`; never a token). It runs openssl and `scripts/configure_iya_sts.py` in the `tools` stage as the invoking user, never Cargo on the host. Environment: `IYA_STS_URL`, `IYA_STS_IMAGE`, `LIVE_STS_PORT` (18558), `LIVE_DEMO_PORT` (18658). Never bind 3000, 8081 or 18481-18495. Always a fresh iya-sts: a registered GNAP key is not replaced and the second run is refused.

`.github/workflows/nightly.yml` runs the unit image and the live script at 06:59 UTC (`59 6 * * *`). Do not add a schedule to `tests.yml`.

The driver copies the checkout to a scratch context (no `.git`, `target`, `demo/generated`), runs the install script there, then builds the demo image, asserts the image's `/app/demo/generated` is exactly `tlsCa`'s chain, and runs it with only `client.key` and `client.crt` mounted and `TLS_CA_REFRESH=0`. It never fetches the CA for the demo, rewrites `tlsCa`, or mounts a CA. Its progress lines never print a URL or status from the signed-in client (CodeQL clear-text logging); secrets reach `docker run` as `-e NAME`. The install script never prints a password or secret: a generated test-user password goes to `demo/generated/<user>.password` (created 0600) and only that path is printed. Every `ssl` context in `scripts/` sets TLS 1.2 as the minimum.

The registrar passes over only a `set-custom-claim` refusal that says "not one of" (an iya-sts without the `gnap_access_token` claim set). Any other refusal fails.

The demo source is `src/bin/demo.rs`. `.gitignore` ignores `/bin/` at the root only, so the demo is tracked.

## tlsCa, the iya-sts trust chain

`tlsCa` (demo default `generated/idp-ca.pem`) is the iya-sts TLS listener CA trust chain. `scripts/configure_iya_sts.py` writes the whole chain there on every run through `scripts/trust_chain.py`'s `save_trust_chain()` (`GET /tls/server-certificate`, falling back to the handshake) and prints the anchor's subject and SHA-256. The Dockerfile's final stage runs `COPY demo demo` after the binary is built (the `build` stage copies only `Cargo.toml`, `Cargo.lock` and `src`, so a new chain does not recompile), and `.dockerignore` admits only `demo/generated/idp-ca.pem` from `demo/generated`. Copying the directory, not the file, keeps a build without the chain working; a file or glob COPY fails. Rebuild the demo image after re-running the install script against another iya-sts. The start-time refresh (`scripts/trust_chain.py` in `CMD`) stays, and `TLS_CA_REFRESH=0` turns it off.

`src/http.rs` `Pinned` reads every PEM block of `tlsCa` as an anchor. The exact-match shortcut compares only the presented LEAF with the file's certificates (never any presented certificate with any file certificate: CA certificates are public) and still checks the name; otherwise webpki verifies the chain to an anchor and the name. `src/tests/trust_chain.rs` covers the script writing the chain, the library taking the file, every block as an anchor, a forged leaf before the real CAs refused, and the right chain with the wrong name refused. Every `ssl.SSLContext` the scripts make sets TLS 1.2 as the minimum.

## Layout

- `src` the client, key proofs (mtls, httpsig, jwsd), and one poll stream
- `src/tests` config, subject, client, and the Shared Signals receiver
- `src/bin/demo.rs` the HTTP demo; `demo/gnap.json` the sample configuration
- `scripts/configure_iya_sts.py` registers the app; `scripts/redirects.py` and `scripts/trust_chain.py` support it

## Demo

`docker compose up --build`. `PORT` defaults to 3000 and is the bind port. Loopback redirect and finish URLs follow `PORT`. `PUBLIC_URL` or `--public-url` replaces the origin and keeps the path. `GET /healthz` returns `ok`. `ssf.pollIntervalMs` is a millisecond interval.

## Signals

Omitted or `true` keeps CAEP and RISC on, and the resolved configuration omits `signals`. `false` does not start the receiver, does not require transmitter metadata, drops `ssf.read` and `ssf.manage`, and is kept on the resolved configuration. Anything else returns `signals must be true or false`. `SignalsReceiver::stop` waits until the background poll has finished.

## License

MIT. Copyright (c) 2026 Iya CyberSecurity Solutions, LLC.

`develop` and `main` must be the same commit. A pull request merged into `main` publishes the crate to crates.io after the test workflow succeeds on that commit. A direct push does not. The token is the `CARGO_REGISTRY_TOKEN` repository secret. A version already on crates.io stays there; the next release is a new `version` in `Cargo.toml`.
