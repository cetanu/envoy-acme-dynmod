FROM docker.io/library/rust:1.96-bookworm AS module-builder

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        clang \
        cmake \
        libclang-dev \
        protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY Cargo.toml Cargo.lock build.rs ./
COPY src ./src
RUN cargo build --locked --release

FROM docker.io/envoyproxy/envoy:v1.39.0

USER root
RUN mkdir -p /etc/pebble /usr/local/lib/envoy-dynamic-modules
COPY --from=module-builder /src/target/release/libenvoy_acme_dynmod.so /usr/local/lib/envoy-dynamic-modules/
COPY e2e/pebble.minica.pem /etc/pebble/pebble.minica.pem
COPY e2e/envoy.yaml /etc/envoy/envoy.yaml

ENTRYPOINT ["/usr/local/bin/envoy"]
CMD ["-c", "/etc/envoy/envoy.yaml", "--log-level", "info"]
