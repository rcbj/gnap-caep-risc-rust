# `docker build --target test` runs the suite in this image.
# The demo image below does not run it.
FROM rust:1-bookworm AS test
# python3 and openssl run scripts/trust_chain.py in src/tests/trust_chain.rs.
RUN apt-get update && apt-get install -y --no-install-recommends python3 openssl && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN cargo test

FROM rust:1-bookworm AS build
WORKDIR /src
# Only what the binary is compiled from, so a new trust chain in demo/ does not rebuild it.
COPY Cargo.toml Cargo.lock ./
COPY src src
RUN cargo build --release --bin demo

# The setup tools: python3 for scripts/configure_iya_sts.py and openssl for the client key.
# scripts/live_iya_sts.py generates the key and registers the demo in this image, as the invoking
# user, so no toolchain runs on the host. `--target tools`.
FROM debian:bookworm-slim AS tools
RUN apt-get update && apt-get install -y --no-install-recommends python3 openssl ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY demo demo
COPY scripts scripts

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends python3 ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /src/target/release/demo /app/gnap-demo
# The demo, and with it tlsCa's file: demo/generated/idp-ca.pem, the iya-sts listener CA
# trust chain scripts/configure_iya_sts.py saved. The image trusts that iya-sts with no
# bind mount and no fetch; rebuild after running the install script against another one.
# .dockerignore admits that one file of demo/generated (never the client key or
# certificate). A COPY of the demo DIRECTORY succeeds with or without it, so a fresh
# clone and CI still build; naming the file, or a glob matching nothing, fails the build.
COPY demo demo
COPY scripts scripts
EXPOSE 3000
ENV PORT=3000
HEALTHCHECK --interval=15s --timeout=3s --start-period=20s \
  CMD python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:${PORT}/healthz').read()" || exit 1
# The chain comes from build time. A start also refreshes it from the provider (a
# development iya-sts makes a new CA when it restarts) unless TLS_CA_REFRESH=0.
CMD ["sh", "-c", "if [ \"${TLS_CA_REFRESH:-1}\" != 0 ]; then python3 scripts/trust_chain.py --config \"${GNAP_CONFIG:-demo/gnap.json}\" || true; fi; exec /app/gnap-demo"]
