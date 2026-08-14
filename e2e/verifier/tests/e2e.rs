use std::{
    error::Error,
    fs, io,
    net::SocketAddr,
    path::Path,
    thread,
    time::{Duration, Instant},
};

use reqwest::{StatusCode, blocking::Client, header::HOST};
use serde::Deserialize;
use x509_parser::{extensions::GeneralName, pem::parse_x509_pem};

const DOMAIN: &str = "acme.test";
const ENVOY_IP: &str = "10.30.50.4";
const TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Deserialize)]
struct StoredCertificate {
    certificate_chain_pem: String,
    private_key_pem: String,
}

#[test]
fn pebble_http01_and_sds() -> Result<(), Box<dyn Error>> {
    let tls_client = Client::builder()
        .danger_accept_invalid_certs(true)
        .resolve(DOMAIN, SocketAddr::from(([10, 30, 50, 4], 443)))
        .build()?;

    wait_for_certificate(&tls_client)?;
    verify_persistence()?;
    verify_plain_http()?;
    verify_challenge_miss()?;

    println!(
        "E2E passed: Pebble validated HTTP-01 through the dynamic module and Envoy serves the SDS certificate."
    );
    Ok(())
}

fn wait_for_certificate(client: &Client) -> Result<(), Box<dyn Error>> {
    let started = Instant::now();
    loop {
        let ready = client
            .get(format!("https://{DOMAIN}/"))
            .send()
            .and_then(reqwest::blocking::Response::error_for_status)
            .and_then(reqwest::blocking::Response::text)
            .is_ok_and(|body| body.trim() == "envoy-acme-tls");
        if ready {
            return Ok(());
        }
        if started.elapsed() >= TIMEOUT {
            return Err("timed out waiting for ACME issuance and the Envoy TLS listener".into());
        }
        thread::sleep(Duration::from_secs(1));
    }
}

fn verify_persistence() -> Result<(), Box<dyn Error>> {
    require_nonempty_file("/state/account.json")?;
    require_nonempty_file("/state/certificate.json")?;

    let stored: StoredCertificate = serde_json::from_slice(&fs::read("/state/certificate.json")?)?;
    if stored.private_key_pem.trim().is_empty() {
        return Err("persisted private key is empty".into());
    }

    let (_, pem) = parse_x509_pem(stored.certificate_chain_pem.as_bytes())
        .map_err(|error| invalid_data(error.to_string()))?;
    let certificate = pem
        .parse_x509()
        .map_err(|error| invalid_data(error.to_string()))?;
    let san = certificate
        .subject_alternative_name()
        .map_err(|error| invalid_data(error.to_string()))?
        .ok_or_else(|| invalid_data("issued certificate has no subjectAltName"))?;
    let contains_domain = san
        .value
        .general_names
        .iter()
        .any(|name| matches!(name, GeneralName::DNSName(domain) if *domain == DOMAIN));
    if !contains_domain {
        return Err(format!("issued certificate does not contain DNS SAN {DOMAIN}").into());
    }
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
