use std::{
    error::Error,
    fs, io,
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
fn pebble_http01_and_file_delivery() -> Result<(), Box<dyn Error>> {
    wait_for_certificate_files()?;
    verify_persistence()?;
    verify_plain_http()?;
    verify_challenge_miss()?;

    println!("E2E passed: Pebble validated HTTP-01 and the module wrote the certificate files.");
    Ok(())
}

fn wait_for_certificate_files() -> Result<(), Box<dyn Error>> {
    let started = Instant::now();
    loop {
        let certificate_ready = fs::metadata("/state/certificate.pem")
            .is_ok_and(|metadata| metadata.len() > 0);
        let private_key_ready = fs::metadata("/state/private-key.pem")
            .is_ok_and(|metadata| metadata.len() > 0);
        if certificate_ready && private_key_ready {
            return Ok(());
        }
        if started.elapsed() >= TIMEOUT {
            return Err("timed out waiting for ACME issuance and certificate files".into());
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

    let certificate_file = fs::read_to_string("/state/certificate.pem")?;
    if certificate_file != stored.certificate_chain_pem {
        return Err("certificate.pem does not match persisted certificate".into());
    }
    let private_key_file = fs::read_to_string("/state/private-key.pem")?;
    if private_key_file != stored.private_key_pem {
        return Err("private-key.pem does not match persisted private key".into());
    }

    let (_, pem) = parse_x509_pem(certificate_file.as_bytes())
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
