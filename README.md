# Envoy ACME dynamic module

An Envoy HTTP dynamic module that obtains and renews one SAN certificate with
ACME HTTP-01 and intercepts challenge requests. By default it writes the
certificate and private key to PEM files for Envoy to consume. It can also
serve the certificate over the v3 Secret Discovery Service (SDS).

The module currently uses local disk storage. The account credentials and the
certificate/private-key pair are each written atomically with owner-only Unix
permissions.

## Build

The module ABI must exactly match the Envoy version. This crate currently uses
the SDK from Envoy `v1.39.0`.

```console
cargo build --release
```

The resulting module is `target/release/libenvoy_acme_dynmod.so`. Put its
directory in `ENVOY_DYNAMIC_MODULES_SEARCH_PATH`.

The build downloads protobuf archives from GitHub and extracts them only under
Cargo's build output. The human-readable tag and branch names are grouped at
the top of `build.rs`: Envoy and protoc-gen-validate use release tags, xDS uses
`main`, and Google APIs uses `master`. A clean build therefore requires network
access.

## JSON configuration

```json
{
  "domains": ["example.com", "www.example.com"],
  "contact_email": "ops@example.com",
  "storage_path": "/var/lib/envoy-acme",
  "certificate_delivery": "file",
  "certificate_path": "/var/lib/envoy-acme/certificate.pem",
  "private_key_path": "/var/lib/envoy-acme/private-key.pem",
  "acme_directory_url": "https://acme-v02.api.letsencrypt.org/directory",
  "renew_before_days": 30,
  "check_interval_seconds": 43200
}
```

`certificate_delivery` defaults to `file`. In file mode,
`certificate_path` and `private_key_path` default to `certificate.pem` and
`private-key.pem` inside `storage_path`; each file is replaced atomically and
written with owner-only permissions. In `grpc` mode, set `sds_address` and
`secret_name` as described below. `acme_directory_url`, `renew_before_days`,
and `check_interval_seconds` are optional and use the values shown above by
default. Wildcards are rejected because ACME does not permit HTTP-01
validation for wildcard identifiers. All paths must be absolute.

All domains are placed in one certificate. In gRPC mode it is published under
`secret_name`. Only one process-wide configuration is allowed, even if the
filter appears in more than one filter chain.

## Envoy wiring

Install the dynamic filter on the plaintext port 80 listener before the router:

```yaml
- name: envoy.extensions.filters.http.dynamic_modules
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.http.dynamic_modules.v3.DynamicModuleFilter
    dynamic_module_config:
      name: envoy_acme_dynmod
      do_not_close: true
    filter_name: envoy_acme
    filter_config:
      "@type": type.googleapis.com/google.protobuf.StringValue
      value: |
        {
          "domains": ["example.com", "www.example.com"],
          "contact_email": "ops@example.com",
          "storage_path": "/var/lib/envoy-acme",
          "sds_address": "127.0.0.1:50051",
          "secret_name": "example-certificate"
        }
- name: envoy.filters.http.router
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
```

Configure an HTTP/2 static cluster for the in-process SDS server:

```yaml
- name: acme_sds
  connect_timeout: 1s
  type: STATIC
  typed_extension_protocol_options:
    envoy.extensions.upstreams.http.v3.HttpProtocolOptions:
      "@type": type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions
      explicit_http_config:
        http2_protocol_options: {}
  load_assignment:
    cluster_name: acme_sds
    endpoints:
      - lb_endpoints:
          - endpoint:
              address:
                socket_address:
                  address: 127.0.0.1
                  port_value: 50051
```

For the default file delivery, reference the generated PEM files from a
downstream TLS context:

```yaml
common_tls_context:
  tls_certificates:
    - certificate_chain:
        filename: /var/lib/envoy-acme/certificate.pem
      private_key:
        filename: /var/lib/envoy-acme/private-key.pem
```

The files are created asynchronously after ACME validation. Arrange for Envoy
to load the files after the first issuance and reload it after renewals.

To use SDS instead, set `certificate_delivery` to `grpc` and include the SDS
settings in the module configuration:

```json
{
  "certificate_delivery": "grpc",
  "sds_address": "127.0.0.1:50051",
  "secret_name": "example-certificate"
}
```

Then use the SDS cluster and `tls_certificate_sds_secret_configs` wiring shown
below. The SDS listener is not created in file mode.

Requests beneath `/.well-known/acme-challenge/` are always terminated by the
filter. A current token for the request host returns `200`; missing tokens
return `404`; methods other than GET and HEAD return `405`. Other paths pass
through unchanged.
