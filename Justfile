set shell := ["bash", "-euo", "pipefail", "-c"]

compose := "podman compose -f e2e/compose.yaml"

# Build the environment, issue a certificate, and run the Rust integration test.
e2e: e2e-up e2e-verify

# Start a fresh E2E environment without running verification.
e2e-up: e2e-down
    {{ compose }} up --detach --build envoy

# Verify HTTP-01 issuance, file delivery, and certificate validity.
e2e-verify:
    {{ compose }} --profile test run --rm --no-deps -T --build test

# Follow logs from the services involved in ACME issuance.
e2e-logs:
    {{ compose }} logs --follow envoy pebble challtestsrv

# Remove the E2E containers, network, and persisted test certificates.
e2e-down:
    {{ compose }} --profile test down --volumes --remove-orphans
