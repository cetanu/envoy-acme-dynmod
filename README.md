# Envoy ACME dynamic module

An Envoy HTTP dynamic module that obtains and renews one SAN certificate with
ACME HTTP-01 and intercepts challenge requests.

The module stores ACME account credentials and certificates on local disk and
publishes the certificate chain and private key as PEM files.

## Example Configuration

```json
{
  "domains": ["example.com", "www.example.com"],
  "contact_email": "ops@example.com",
  "storage_path": "/var/lib/envoy-acme",
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

Certificate delivery is filesystem-only; the module does not expose an SDS server.
Renewal replaces the PEM files, but Envoy does not automatically reload static
`tls_certificates` when those files change. Configure an external Envoy
configuration reload/restart mechanism to pick up renewed certificates, or
provide the files through a separately managed filesystem-watching SDS setup.
