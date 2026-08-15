# End-to-end environment

This environment builds the dynamic module, loads it into Envoy `v1.39.0`, and
uses Pebble to perform a real HTTP-01 validation for `acme.test`.

Requirements: Just, Podman with a Compose provider, and internet access for
image, crate, and protobuf downloads. Assertions are implemented by the Rust
crate under `e2e/verifier`; Just only invokes Podman Compose.

Run the complete test from the repository root:

```console
just e2e
```

The test proves that:

1. Pebble resolves `acme.test` to the Envoy container through
   `pebble-challtestsrv`.
2. Pebble fetches the HTTP-01 response from Envoy on port 80. Validation is not
   bypassed.
3. The module persists its account and issued certificate.
4. The module writes the issued certificate and private key to PEM files.
5. The issued certificate contains the `acme.test` SAN and matches the
   persisted certificate.

Host ports are HTTP `8080` and Envoy admin `9901`. The environment is retained
after the test so failures can be inspected. It can be controlled with:

```console
just e2e-up
just e2e-verify
just e2e-logs
just e2e-down
```
