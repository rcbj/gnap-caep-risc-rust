# `docker build --target test` runs the suite in this image.
# The demo image below does not run it.
FROM rust:1-bookworm AS test
WORKDIR /src
COPY . .
RUN cargo test

FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --bin demo

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends python3 ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /src/target/release/demo /app/gnap-demo
COPY demo demo
COPY scripts scripts
EXPOSE 3000
ENV PORT=3000
HEALTHCHECK --interval=15s --timeout=3s --start-period=20s \
  CMD python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:${PORT}/healthz').read()" || exit 1
CMD ["sh", "-c", "python3 scripts/trust_chain.py --config \"${GNAP_CONFIG:-demo/gnap.json}\" || true; exec /app/gnap-demo"]
