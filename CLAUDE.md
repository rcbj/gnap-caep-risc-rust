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

The `test` stage runs `cargo test` and then `cargo test --all-features` in `rust:1-bookworm`. GitHub Actions uses that command. Do not run Cargo on the host. The demo image does not run the suite.

Tests use an in-process stub on 127.0.0.1. They do not need a live authorization server.

## Live test

`python3 scripts/live_iya_sts.py` signs the demo in to a fresh iya-sts `main` and checks two CAEP events through `GET /live-status` (`signedIn`, `subject`, `receiver`, `events` of `type` and `jti`; never a token). It runs openssl and `scripts/configure_iya_sts.py` in the `tools` stage as the invoking user, never Cargo on the host. Environment: `IYA_STS_URL`, `IYA_STS_IMAGE`, `LIVE_STS_PORT` (18558), `LIVE_DEMO_PORT` (18658). Never bind 3000, 8081 or 18481-18495. The live script always starts a fresh iya-sts, but the install script may be run again against the same one: it adds the demo's values to the existing client (a single-valued attribute `add` refuses with "not one of the" is `set` instead), and with `--pep` keeps the PEP's account, key and policy. `LIVE_KEEP=1` leaves the containers running.

`.github/workflows/nightly.yml` runs the unit image and the live script at 06:59 UTC (`59 6 * * *`). Do not add a schedule to `tests.yml`.

The driver copies the checkout to a scratch context (no `.git`, `target`, `demo/generated`), runs the install script there, then builds the demo image, asserts the image's `/app/demo/generated` is exactly `tlsCa`'s chain, and runs it with only `client.key` and `client.crt` mounted and `TLS_CA_REFRESH=0`. It never fetches the CA for the demo, rewrites `tlsCa`, or mounts a CA. Its progress lines never print a URL or status from the signed-in client (CodeQL clear-text logging); secrets reach `docker run` as `-e NAME`. The install script never prints a password or secret: a generated test-user password goes to `demo/generated/<user>.password` (created 0600) and only that path is printed. Every `ssl` context in `scripts/` sets TLS 1.2 as the minimum.

The registrar passes over only a `set-custom-claim` refusal that says "not one of" (an iya-sts without the `gnap_access_token` claim set). Any other refusal fails.

The demo source is `src/bin/demo.rs`. Signed in, it has a **Session** tab and a **Policy enforcement** tab (`/?tab=pep`): `pep_fragment` draws `pep_json` (the PEP's `status()`) as four `<details class="card pane" id="pep-…" open>` panes (Decisions, Cached policy, The PEP, Control plane), everything escaped, problems in `.problem`, a notice without a `pep` section; `demo/public/pep.js` refetches `GET /pep-status.html` every 2 s and keeps closed panes closed; `GET /pep-status` is JSON; both 401 without a session. Every page sends a CSP with `connect-src 'self'` (pep.js's fetch needs it). Its tests are `src/bin/demo.rs`'s `mod tests`. `.gitignore` ignores `/bin/` at the root only, so the demo is tracked.

## tlsCa, the iya-sts trust chain

`tlsCa` (demo default `generated/idp-ca.pem`) is the iya-sts TLS listener CA trust chain. `scripts/configure_iya_sts.py` writes the whole chain there on every run through `scripts/trust_chain.py`'s `save_trust_chain()` (`GET /tls/server-certificate`, falling back to the handshake) and prints the anchor's subject and SHA-256. The Dockerfile's final stage runs `COPY demo demo` after the binary is built (the `build` stage copies only `Cargo.toml`, `Cargo.lock` and `src`, so a new chain does not recompile), and `.dockerignore` admits only `demo/generated/idp-ca.pem` from `demo/generated`. Copying the directory, not the file, keeps a build without the chain working; a file or glob COPY fails. Rebuild the demo image after re-running the install script against another iya-sts. The start-time refresh (`scripts/trust_chain.py` in `CMD`) stays, and `TLS_CA_REFRESH=0` turns it off.

`src/http.rs` `Pinned` reads every PEM block of `tlsCa` as an anchor. The exact-match shortcut compares only the presented LEAF with the file's certificates (never any presented certificate with any file certificate: CA certificates are public) and still checks the name; otherwise webpki verifies the chain to an anchor and the name. `src/tests/trust_chain.rs` covers the script writing the chain, the library taking the file, every block as an anchor, a forged leaf before the real CAs refused, and the right chain with the wrong name refused. Every `ssl.SSLContext` the scripts make sets TLS 1.2 as the minimum.

## Embedded PEP

#39 (iya-sts#1206 work item 8), behind the `pep` feature (`local` adds the engine): `src/pep.rs` wires in the shared `iya-pep` crate (rcbj/iya-pep-rust), following oidc-caep-risc-rust#46.
- `resolve` builds the PEP (nothing sent) from the `pep` section and stores it on `Config.pep`; `Client::create` (and `from_file`) starts it. `Client::new` does not.
  - `pdpUrl` defaults to the grant endpoint's realm (`/realm/<id>` kept, a named server's segment and `/gnap` dropped; else the origin). Not `idTokenIssuer`, which defaults to the origin and drops the realm.
  - `application` defaults to `application`; `signals` to whether the library runs a receiver (`ssf` resolved); `tlsCa` to the library's; `assertionKey` is relative to the config's directory.
  - It refuses an assertion key that is the client instance key (by JWK thumbprint). That is the only key this library holds (the mTLS certificate is the same key).
- Without the feature, a `pep` section is refused rather than ignored.
- `decide` / `decide_grant` adapt a `Person` (`uid` from `account`, else `preferred_username`, else `sub`; the ID token claims) into the PEP's subject. `decide_grant` denies without asking a grant with no subject, one this client revoked (`revoke` remembers the continuation URI, 10000 at most), or one whose access token expired.
- `ReceiverOpt::pep`: `SignalsReceiver::new` adds `pep-policies-changed` to the events requested and registers the hand-over when the PEP wants events (`local`, or `central` with a Permit cache).
- `src/tests/pep.rs` has its own stub PDP (also the realm's GNAP continuation URI), and reuses `src/tests/ssf.rs`'s transmitter for the receiver test. The no-feature refusal is in `src/tests/config.rs`.
- **The dependency is a git dependency on iya-pep-rust's `feature/1`** until that crate's first release. Switch it to the crates.io version then, because crates.io refuses a git dependency at publish.
- The live test of the PEP waits for iya-sts #2026–#2028; `demo/gnap.json` has no `pep` section until then.
- oidc-caep-risc's live run (its #46) found two defects; both are held here by `src/tests/pep.rs`. `Client::from_file` keeps the `pep` section (`from_file_keeps_the_pep_section`; `read_file` always passed the whole document to `resolve`). A reused poll stream gets the event types it lacks PATCHed in (`with_requested_events`); a refusal goes to `ReceiverOpt::on_error` (new: it also takes the receiver's other error lines, which still print to standard output without it), and `start` tells the PEP `set_event_stream(Requested)` or `Excluded` from the stream's events, which the heartbeat reports as `policyEvents` (`a_reused_stream_gets_the_policy_event_added`, with PATCH on `src/tests/ssf.rs`'s transmitter).
- **AuthZEN table** (`src/tests/authzen_cases.json`, `src/tests/authzen.rs`, feature `local`): this library's own cases, not copied from iya-sts or a sibling. Offline, `the_table_decides_as_expected_in_local_mode` runs every case through a `local` Client against a stub realm per PEP group (policies from each policy's `xacml`, the catalogue, the directory as the PIP). A case marked `localDefect` must still give that wrong local answer, so the mark comes off when iya-pep is fixed; the live run ignores the mark. Live, `python3 scripts/live_iya_sts.py --authzen` turns `authzen.returnReasons` on (iya-sts sends central advice only then), provisions people, catalogue rows, ALFA policies (refusing a table whose `xacml` is not what iya-sts stored; `--write-xacml` takes it), FGA applications, and a central and a local PEP service account per group (`pep-gnap-<group>-<mode>`, keys made in the tools image), then runs `live_central_and_local_agree` (env `GNAP_AUTHZEN_LIVE`) in `rust:1-bookworm` with `-v iya-pep-cargo:/cargo` and `CARGO_TARGET_DIR=target/live-authzen`. It fails on any case where central, local and `expect` differ. Never weaken a case to make it pass. All 58 agree against iya-sts `feature/2028` (image `iya-sts:live-2028-fga`) with iya-pep `c0d61ca`; the three differences it first found (`advice`, `fga-reference`, `fga-stage`) were fixed upstream. The offline stub's catalogue carries `fgaApplications` and its registration answer an `identity` DN, as iya-sts's do.
- **The demo's PEP in one command:** `scripts/configure_iya_sts.py --pep central|local` (`--pep-name`, default `pep-gnap-demo`) is docs/remote-pep.md's steps 2 to 6: the service account in `remote-peps` (created only when `/users?user=` says unknown), a P-256 key made with `openssl` in `demo/generated/pep-key.pem` (0600, never printed, out of the image by `.dockerignore`), `issue-pep-credential` with its CSR and the demo's application when the key or the account is new (else `set-pep-application`), the catalogue row `subject.acr` → `urn:example:acr`, and the application's OWN policy (`fga-create-policy`, `import-alfa`, `fga-enable`; written only while `page.fga.enforced` is not true; never the realm root), `pep-policies-changed` in `ssfAllowedEvents` only when the application restricts its events, then the `pep` section (`assertionKey: generated/pep-key.pem`, relative to the config's directory). Verified against `iya-sts:live-2028-fga`: two runs (central, then local) keep account, key and policy and switch the mode; a fresh iya-sts with the key kept certifies that key. FGA enforcement on the demo client decides nothing at GNAP issuance (its rights are strings; `authorization_details.ts` asks only about a type an enforcing application declares), and the sign-in after setup works.
- **`live_iya_sts.py --pep`** (or `LIVE_PEP=1`) runs the install script with `--pep central` in the tools image, copies the configuration to `demo/gnap.pep-local.json` with `mode` `local`, mounts only the client key, certificate and PEP key, and requires 200/403 on `/orders/42` in both modes; between the two it waits 5 s: it guards against the central demo's unacknowledged session-revoked SET being redelivered on the reused stream and ending the local sign-in (3 of 3 runs failed without it). Then it rewrites the application's own policy to deny read and requires a 403 within `PEP_FLIP_TIMEOUT` (30) by event. Live against iya-sts `feature/2028` at `a6cb55cb3` (`iya-sts:live-2028-gnapscope`): both modes 200/403 and the flip by event in 1.1 s. That commit is the fix for the GNAP subject scope (`GnapSignals.scope()`), which had refused pep-policies-changed's application subject on a GNAP client's stream (`STS-SSF-0029`).

## Layout

- `src` the client, key proofs (mtls, httpsig, jwsd), and one poll stream
- `src/tests` config, subject, client, the Shared Signals receiver, and (feature `pep`) the embedded PEP
- `src/pep.rs` the embedded iya-sts PEP (feature `pep`)
- `src/bin/demo.rs` the HTTP demo; `demo/gnap.json` the sample configuration
- `scripts/configure_iya_sts.py` registers the app; `scripts/redirects.py` and `scripts/trust_chain.py` support it

## Demo

`docker compose up --build`. `PORT` defaults to 3000 and is the bind port. Loopback redirect and finish URLs follow `PORT`. `PUBLIC_URL` or `--public-url` replaces the origin and keeps the path. `GET /healthz` returns `ok`. `ssf.pollIntervalMs` is a millisecond interval.

## Signals

Omitted or `true` keeps CAEP and RISC on, and the resolved configuration omits `signals`. `false` does not start the receiver, does not require transmitter metadata, drops `ssf.read` and `ssf.manage`, and is kept on the resolved configuration. Anything else returns `signals must be true or false`. `SignalsReceiver::stop` waits until the background poll has finished.

## License

MIT. Copyright (c) 2026 Iya CyberSecurity Solutions, LLC.

`develop` and `main` must be the same commit. A pull request merged into `main` publishes the crate to crates.io after the test workflow succeeds on that commit. A direct push does not. The token is the `CARGO_REGISTRY_TOKEN` repository secret. A release happens when the library's files changed since the last release's tag: `publish.yml` takes one patch above the highest published version, publishes it, and creates the matching tag and GitHub Release. A change to tests, the demo, or the docs releases nothing. To choose a version or start a new minor, raise `VERSION`; the version is stamped in CI and is not committed, so the manifests can trail what is published.

- **The user guide is `docs/remote-pep.md`**, generated for the four Rust libraries from one outline; keep its sections in step with the siblings' when changing it. The README's section is a summary that links to it.
