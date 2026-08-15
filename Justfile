set shell := ["bash", "-euo", "pipefail", "-c"]

compose := "podman compose -f e2e/compose.yaml"

# Build the environment, issue a certificate, and run the Rust integration test.
e2e: e2e-up e2e-verify

# Start the E2E services without running verification or automatic cleanup.
e2e-up:
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
