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

`develop` and `main` must be the same commit. Publishing is not set up.
