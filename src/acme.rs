use std::{
    error::Error,
    io,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use envoy_proxy_dynamic_modules_rust_sdk::{envoy_log_error, envoy_log_info, envoy_log_warn};
use instant_acme::{
    Account, AuthorizationStatus, ChallengeType, Identifier, NewAccount, NewOrder, OrderStatus,
    RetryPolicy,
};
use tokio::time::sleep;
use x509_parser::pem::parse_x509_pem;

use crate::{
    config::{CertificateDelivery, Config},
    state::{Certificate, ChallengeResponse, SharedState},
    storage::DiskStorage,
};

type BoxError = Box<dyn Error + Send + Sync>;

pub async fn run(config: Arc<Config>, state: Arc<SharedState>, storage: DiskStorage) {
    if let Err(error) = load_persisted_certificate(&config, &state, &storage).await {
        envoy_log_error!("failed to load persisted certificate: {error}");
    }

    loop {
        let delay = match renewal_cycle(&config, &state, &storage).await {
            Ok(()) => config.check_interval(),
            Err(error) => {
                envoy_log_error!("ACME renewal cycle failed: {error}");
                config.check_interval().min(Duration::from_secs(60))
            }
        };
        sleep(delay).await;
    }
}

async fn load_persisted_certificate(
    config: &Config,
    state: &SharedState,
    storage: &DiskStorage,
) -> Result<(), BoxError> {
    if let Some(certificate) = storage.load_certificate().await? {
        needs_renewal(&certificate.chain_pem, Duration::ZERO)?;
        publish_certificate(config, state, storage, certificate).await?;
    }
    Ok(())
}

async fn renewal_cycle(
    config: &Config,
    state: &SharedState,
    storage: &DiskStorage,
) -> Result<(), BoxError> {
    if let Some(certificate) = state.certificate() {
        match needs_renewal(&certificate.chain_pem, config.renewal_window()) {
            Ok(false) => return Ok(()),
            Ok(true) => {}
            Err(error) => {
                envoy_log_warn!("persisted certificate is invalid and will be replaced: {error}");
            }
        }
    }

    let account = match storage
        .load_account(&config.acme_directory_url, &config.contact_email)
        .await
    {
        Some(credentials) => Account::builder()?.from_credentials(credentials).await?,
        None => {
            let contact = format!("mailto:{}", config.contact_email);
            let (account, credentials) = Account::builder()?
                .create(
                    &NewAccount {
                        contact: &[contact.as_str()],
                        terms_of_service_agreed: true,
                        only_return_existing: false,
                    },
                    config.acme_directory_url.clone(),
                    None,
                )
                .await?;
            storage
                .save_account(
                    &config.acme_directory_url,
                    &config.contact_email,
                    credentials,
                )
                .await?;
            account
        }
    };

    envoy_log_info!(
        "requesting ACME certificate for {}",
        config.domains.join(", ")
    );
    let certificate = issue_certificate(&account, config, state).await?;
    storage.save_certificate(&certificate).await?;
    publish_certificate(config, state, storage, certificate).await?;
    match config.certificate_delivery {
        CertificateDelivery::File => envoy_log_info!("published renewed certificate files"),
        CertificateDelivery::Grpc => envoy_log_info!("published renewed SDS secret"),
    }
    Ok(())
}

async fn publish_certificate(
    config: &Config,
    state: &SharedState,
    storage: &DiskStorage,
    certificate: Certificate,
) -> Result<(), BoxError> {
    if config.certificate_delivery == CertificateDelivery::File {
        storage
            .save_certificate_files(
                &certificate,
                &config.certificate_path(),
                &config.private_key_path(),
            )
            .await?;
    }
    state.publish(certificate);
    Ok(())
}

async fn issue_certificate(
    account: &Account,
    config: &Config,
    state: &SharedState,
) -> Result<Certificate, BoxError> {
    let identifiers = config
        .domains
        .iter()
        .cloned()
        .map(Identifier::Dns)
        .collect::<Vec<_>>();
    let mut order = account.new_order(&NewOrder::new(&identifiers)).await?;
    let mut installed_tokens = Vec::new();

    let result = async {
        let mut authorizations = order.authorizations();
        while let Some(result) = authorizations.next().await {
            let mut authorization = result?;
            match authorization.status {
                AuthorizationStatus::Valid => continue,
                AuthorizationStatus::Pending => {}
                status => {
                    return Err(io::Error::other(format!(
                        "authorization for {} has unexpected status {status:?}",
                        authorization.identifier()
                    ))
                    .into());
                }
            }

            let authorization_domain = authorization.identifier().to_string();
            let mut challenge =
                authorization
                    .challenge(ChallengeType::Http01)
                    .ok_or_else(|| {
                        io::Error::other(format!(
                            "ACME server offered no HTTP-01 challenge for {authorization_domain}"
                        ))
                    })?;
            let token = challenge.token.clone();
            let domain = challenge.identifier().to_string().to_ascii_lowercase();
            let body = challenge.key_authorization().as_str().to_owned();
            state
                .challenges
                .insert(token.clone(), ChallengeResponse { domain, body });
            installed_tokens.push(token);
            challenge.set_ready().await?;
        }

        let status = order.poll_ready(&RetryPolicy::default()).await?;
        if status != OrderStatus::Ready {
            return Err(io::Error::other(format!(
                "ACME order reached unexpected status {status:?}"
            ))
            .into());
        }
        let private_key_pem = order.finalize().await?;
        let chain_pem = order.poll_certificate(&RetryPolicy::default()).await?;
        Ok(Certificate::new(chain_pem, private_key_pem))
    }
    .await;

    for token in installed_tokens {
        state.challenges.remove(&token);
    }
    result
}

fn needs_renewal(chain_pem: &str, renewal_window: Duration) -> Result<bool, BoxError> {
    let (_, pem) = parse_x509_pem(chain_pem.as_bytes())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
    let certificate = pem
        .parse_x509()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let renew_at = certificate
        .validity()
        .not_after
        .timestamp()
        .saturating_sub(i64::try_from(renewal_window.as_secs()).unwrap_or(i64::MAX));
    Ok(i64::try_from(now).unwrap_or(i64::MAX) >= renew_at)
}
