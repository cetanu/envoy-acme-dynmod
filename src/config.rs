use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};

use serde::Deserialize;
use serde_valid::{Validate, validation::Error as ValidationError};

const LETS_ENCRYPT_PRODUCTION: &str = "https://acme-v02.api.letsencrypt.org/directory";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Validate)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[validate(min_items = 1, message = "domains must contain at least one name")]
    #[validate(unique_items, message = "domains must not contain duplicates")]
    #[validate(custom = validate_domains)]
    pub domains: Vec<String>,
    #[validate(custom = validate_contact_email)]
    pub contact_email: String,
    #[validate(custom = validate_storage_path)]
    pub storage_path: PathBuf,
    #[serde(default)]
    #[validate(custom = validate_optional_path)]
    pub certificate_path: Option<PathBuf>,
    #[serde(default)]
    #[validate(custom = validate_optional_path)]
    pub private_key_path: Option<PathBuf>,
    #[serde(default)]
    pub certificate_delivery: CertificateDelivery,
    #[serde(default)]
    #[validate(custom = validate_optional_sds_address)]
    pub sds_address: Option<String>,
    #[serde(default)]
    #[validate(custom = validate_optional_secret_name)]
    pub secret_name: Option<String>,
    #[serde(default = "default_directory_url")]
    #[validate(custom = validate_acme_directory_url)]
    pub acme_directory_url: String,
    #[serde(default = "default_renew_before_days")]
    #[validate(minimum = 1, message = "renew_before_days must be greater than zero")]
    pub renew_before_days: u64,
    #[serde(default = "default_check_interval_seconds")]
    #[validate(
        minimum = 1,
        message = "check_interval_seconds must be greater than zero"
    )]
    pub check_interval_seconds: u64,
}

impl Config {
    pub fn parse(json: &[u8]) -> Result<Self, String> {
        let mut config: Self = serde_json::from_slice(json)
            .map_err(|error| format!("invalid JSON configuration: {error}"))?;
        config
            .validate()
            .map_err(|error| format!("invalid configuration: {error}"))?;
        validate_delivery_config(&config)?;
        config.domains.sort();
        Ok(config)
    }

    pub fn sds_address(&self) -> SocketAddr {
        self.sds_address
            .as_deref()
            .expect("configuration was validated")
            .parse()
            .expect("configuration was validated")
    }

    pub fn certificate_path(&self) -> PathBuf {
        self.certificate_path
            .clone()
            .unwrap_or_else(|| self.storage_path.join("certificate.pem"))
    }

    pub fn private_key_path(&self) -> PathBuf {
        self.private_key_path
            .clone()
            .unwrap_or_else(|| self.storage_path.join("private-key.pem"))
    }

    pub fn renewal_window(&self) -> Duration {
        Duration::from_secs(self.renew_before_days.saturating_mul(24 * 60 * 60))
    }

    pub fn check_interval(&self) -> Duration {
        Duration::from_secs(self.check_interval_seconds)
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum CertificateDelivery {
    #[default]
    File,
    Grpc,
}

fn validate_domains(domains: &[String]) -> Result<(), ValidationError> {
    for domain in domains {
        if domain.is_empty()
            || domain.starts_with('.')
            || domain.ends_with('.')
            || domain.contains('*')
            || domain.bytes().any(|byte| byte.is_ascii_whitespace())
        {
            return Err(ValidationError::Custom(format!(
                "invalid HTTP-01 domain: {domain:?}"
            )));
        }
        if domain != &domain.to_ascii_lowercase() {
            return Err(ValidationError::Custom(format!(
                "domain must be lowercase: {domain:?}"
            )));
        }
    }
    Ok(())
}

fn validate_contact_email(contact_email: &str) -> Result<(), ValidationError> {
    if contact_email.trim().is_empty() || !contact_email.contains('@') {
        return Err(ValidationError::Custom(
            "contact_email must be an email address".into(),
        ));
    }
    Ok(())
}

fn validate_storage_path(storage_path: &Path) -> Result<(), ValidationError> {
    if !storage_path.is_absolute() {
        return Err(ValidationError::Custom(
            "storage_path must be absolute".into(),
        ));
    }
    Ok(())
}

fn validate_optional_path(path: &Option<PathBuf>) -> Result<(), ValidationError> {
    if let Some(path) = path
        && !path.is_absolute()
    {
        return Err(ValidationError::Custom(
            "certificate and private key paths must be absolute".into(),
        ));
    }
    Ok(())
}

fn validate_optional_sds_address(sds_address: &Option<String>) -> Result<(), ValidationError> {
    let Some(sds_address) = sds_address else {
        return Ok(());
    };
    let address = sds_address
        .parse::<SocketAddr>()
        .map_err(|error| ValidationError::Custom(format!("invalid sds_address: {error}")))?;
    if !address.ip().is_loopback() {
        return Err(ValidationError::Custom(
            "sds_address must use a loopback IP because SDS carries private keys".into(),
        ));
    }
    Ok(())
}

fn validate_optional_secret_name(secret_name: &Option<String>) -> Result<(), ValidationError> {
    if secret_name
        .as_deref()
        .is_some_and(|name| name.trim().is_empty())
    {
        return Err(ValidationError::Custom(
            "secret_name must not be empty".into(),
        ));
    }
    Ok(())
}

fn validate_delivery_config(config: &Config) -> Result<(), String> {
    if config.certificate_delivery == CertificateDelivery::Grpc {
        if config.sds_address.is_none() {
            return Err("sds_address is required when certificate_delivery is grpc".into());
        }
        if config.secret_name.is_none() {
            return Err("secret_name is required when certificate_delivery is grpc".into());
        }
    }
    if config.certificate_path() == config.private_key_path() {
        return Err("certificate_path and private_key_path must be different".into());
    }
    Ok(())
}

fn validate_acme_directory_url(acme_directory_url: &str) -> Result<(), ValidationError> {
    if !(acme_directory_url.starts_with("https://") || acme_directory_url.starts_with("http://")) {
        return Err(ValidationError::Custom(
            "acme_directory_url must be an HTTP(S) URL".into(),
        ));
    }
    Ok(())
}

fn default_directory_url() -> String {
    LETS_ENCRYPT_PRODUCTION.into()
}

const fn default_renew_before_days() -> u64 {
    30
}

const fn default_check_interval_seconds() -> u64 {
    12 * 60 * 60
}

#[cfg(test)]
mod tests {
    use super::Config;

    #[test]
    fn parses_minimal_config_and_applies_defaults() {
        let config = Config::parse(
            br#"{
                "domains": ["www.example.com", "example.com"],
                "contact_email": "ops@example.com",
                "storage_path": "/var/lib/envoy-acme"
            }"#,
        )
        .unwrap();

        assert_eq!(config.domains, ["example.com", "www.example.com"]);
        assert_eq!(config.renew_before_days, 30);
        assert_eq!(config.check_interval_seconds, 43_200);
        assert_eq!(
            config.certificate_delivery,
            super::CertificateDelivery::File
        );
        assert_eq!(
            config.certificate_path(),
            std::path::Path::new("/var/lib/envoy-acme/certificate.pem")
        );
        assert_eq!(
            config.private_key_path(),
            std::path::Path::new("/var/lib/envoy-acme/private-key.pem")
        );
    }

    #[test]
    fn rejects_wildcards_because_http01_cannot_validate_them() {
        let error = Config::parse(
            br#"{
                "domains": ["*.example.com"],
                "contact_email": "ops@example.com",
                "storage_path": "/tmp/acme",
                "sds_address": "127.0.0.1:50051",
                "secret_name": "certificate"
            }"#,
        )
        .unwrap_err();

        assert!(error.contains("invalid HTTP-01 domain"));
    }

    #[test]
    fn requires_sds_settings_for_grpc_delivery() {
        let error = Config::parse(
            br#"{
                "domains": ["example.com"],
                "contact_email": "ops@example.com",
                "storage_path": "/tmp/acme",
                "certificate_delivery": "grpc"
            }"#,
        )
        .unwrap_err();

        assert!(error.contains("sds_address is required"));
    }
}
