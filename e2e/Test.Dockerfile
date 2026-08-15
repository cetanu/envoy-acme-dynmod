FROM docker.io/library/rust:1.96-alpine AS builder

RUN apk add --no-cache musl-dev
WORKDIR /src
COPY verifier/Cargo.toml verifier/Cargo.lock ./
COPY verifier/tests ./tests
RUN cargo test --locked --release --test e2e --no-run \
    && find target/release/deps -type f -name 'e2e-*' -perm -111 \
        -exec cp '{}' /envoy-acme-e2e ';'

FROM docker.io/library/alpine:3.22

COPY --from=builder /envoy-acme-e2e /usr/local/bin/
COPY pebble.minica.pem /etc/pebble/pebble.minica.pem
ENTRYPOINT ["/usr/local/bin/envoy-acme-e2e"]
CMD ["--nocapture"]
