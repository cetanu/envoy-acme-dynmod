# Envoy ACME dynamic module

An Envoy HTTP dynamic module that obtains and renews one SAN certificate with
ACME HTTP-01 and intercepts challenge requests.

The module currently uses local disk to store the account credentials and
certificates.

## Example Configuration

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

## Envoy wiring

Add the filter on the plaintext port 80 listener before the router:

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
          "storage_path": "/var/lib/envoy-acme"
        }
- name: envoy.filters.http.router
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
```

Requests beneath `/.well-known/acme-challenge/` are always terminated by the
filter. A current token for the request host returns `200`; missing tokens
return `404`; methods other than GET and HEAD return `405`. Other paths pass
through unchanged.

Reference the generated PEM files from a downstream TLS context:

```yaml
common_tls_context:
  tls_certificates:
    - certificate_chain:
        filename: /var/lib/envoy-acme/certificate.pem
      private_key:
        filename: /var/lib/envoy-acme/private-key.pem
```

### Optional SDS delivery

Use SDS when you specifically want Envoy to receive certificate updates
through xDS. Set `certificate_delivery` to `grpc` and include the SDS settings
in the module configuration:

```json
{
  "certificate_delivery": "grpc",
  "sds_address": "127.0.0.1:50051",
  "secret_name": "example-certificate"
}
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

Then use `tls_certificate_sds_secret_configs` with that cluster.
