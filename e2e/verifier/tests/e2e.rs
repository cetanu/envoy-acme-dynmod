use std::{
    error::Error,
    fs, io,
    path::Path,
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

use reqwest::{StatusCode, blocking::Client, header::HOST};
use rustls::{
    RootCertStore, ServerConfig,
    client::{WebPkiServerVerifier, danger::ServerCertVerifier},
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime, pem::PemObject},
};
use serde::Deserialize;

const DOMAIN: &str = "acme.test";
const ENVOY_IP: &str = "10.30.50.4";
const PEBBLE_CA_PATH: &str = "/etc/pebble/pebble.minica.pem";
const PEBBLE_ROOT_URL: &str = "https://pebble:15000/roots/0";
const TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Deserialize)]
struct StoredCertificate {
    certificate_chain_pem: String,
    private_key_pem: String,
}

struct ProvisionedCertificate {
    chain: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
}

#[test]
fn pebble_http01_provisions_a_valid_certificate() -> Result<(), Box<dyn Error>> {
    wait_for_certificate_files()?;
    let certificate = verify_persistence()?;
    verify_certificate(&certificate.chain, certificate.private_key)?;
    verify_plain_http()?;
    verify_challenge_miss()?;

    println!(
        "E2E passed: Pebble validated HTTP-01 and provisioned a currently valid certificate for {DOMAIN}."
    );
    Ok(())
}

fn wait_for_certificate_files() -> Result<(), Box<dyn Error>> {
    let started = Instant::now();
    loop {
        let certificate_ready =
            fs::metadata("/state/certificate.pem").is_ok_and(|metadata| metadata.len() > 0);
        let private_key_ready =
            fs::metadata("/state/private-key.pem").is_ok_and(|metadata| metadata.len() > 0);
        if certificate_ready && private_key_ready {
            return Ok(());
        }
        if started.elapsed() >= TIMEOUT {
            return Err("timed out waiting for ACME issuance and certificate files".into());
        }
        thread::sleep(Duration::from_secs(1));
    }
}

fn verify_persistence() -> Result<ProvisionedCertificate, Box<dyn Error>> {
    require_nonempty_file("/state/account.json")?;
    require_nonempty_file("/state/certificate.json")?;

    let stored: StoredCertificate = serde_json::from_slice(&fs::read("/state/certificate.json")?)?;
    if stored.private_key_pem.trim().is_empty() {
        return Err("persisted private key is empty".into());
    }

    let certificate_file = fs::read_to_string("/state/certificate.pem")?;
    if certificate_file != stored.certificate_chain_pem {
        return Err("certificate.pem does not match persisted certificate".into());
    }
    let private_key_file = fs::read_to_string("/state/private-key.pem")?;
    if private_key_file != stored.private_key_pem {
        return Err("private-key.pem does not match persisted private key".into());
    }

    let certificate_chain = CertificateDer::pem_slice_iter(certificate_file.as_bytes())
        .collect::<Result<Vec<_>, _>>()?;
    if certificate_chain.is_empty() {
        return Err(invalid_data("certificate.pem contains no certificates").into());
    }
    let private_key = PrivateKeyDer::from_pem_slice(private_key_file.as_bytes())?;

    Ok(ProvisionedCertificate {
        chain: certificate_chain,
        private_key,
    })
}

fn verify_certificate(
    certificate_chain: &[CertificateDer<'static>],
    private_key: PrivateKeyDer<'static>,
) -> Result<(), Box<dyn Error>> {
    let api_ca = reqwest::Certificate::from_pem(&fs::read(PEBBLE_CA_PATH)?)?;
    let issuance_root_pem = Client::builder()
        .add_root_certificate(api_ca)
        .timeout(Duration::from_secs(10))
        .build()?
        .get(PEBBLE_ROOT_URL)
        .send()?
        .error_for_status()?
        .bytes()?;
    let issuance_root = CertificateDer::from_pem_slice(&issuance_root_pem)?;

    let mut roots = RootCertStore::empty();
    roots.add(issuance_root)?;

    let verifier = WebPkiServerVerifier::builder(Arc::new(roots)).build()?;
    verifier.verify_server_cert(
        &certificate_chain[0],
        &certificate_chain[1..],
        &ServerName::try_from(DOMAIN)?,
        &[],
        UnixTime::now(),
    )?;

    ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificate_chain.to_vec(), private_key)?;

    Ok(())
}

fn verify_plain_http() -> Result<(), Box<dyn Error>> {
    let response = Client::new()
        .get(format!("http://{ENVOY_IP}/"))
        .header(HOST, DOMAIN)
        .send()?
        .error_for_status()?
        .text()?;
    if response.trim() != "envoy-acme-http" {
        return Err(format!("unexpected plaintext response: {response:?}").into());
    }
    Ok(())
}

fn verify_challenge_miss() -> Result<(), Box<dyn Error>> {
    let status = Client::new()
        .get(format!(
            "http://{ENVOY_IP}/.well-known/acme-challenge/not-a-real-token"
        ))
        .header(HOST, DOMAIN)
        .send()?
        .status();
    if status != StatusCode::NOT_FOUND {
        return Err(format!("unknown challenge returned {status}, expected 404").into());
    }
    Ok(())
}

fn require_nonempty_file(path: impl AsRef<Path>) -> Result<(), Box<dyn Error>> {
    let path = path.as_ref();
    if fs::metadata(path)?.len() == 0 {
        return Err(format!("{} is empty", path.display()).into());
    }
    Ok(())
}

fn invalid_data(error: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.into())
}
