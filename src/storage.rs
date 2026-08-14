use std::{
    io,
    path::{Path, PathBuf},
};

use instant_acme::AccountCredentials;
use serde::{Deserialize, Serialize};
use tokio::fs;

use crate::state::Certificate;

const ACCOUNT_FILE: &str = "account.json";
const CERTIFICATE_FILE: &str = "certificate.json";

#[derive(Clone)]
pub struct DiskStorage {
    root: PathBuf,
}

#[derive(Deserialize, Serialize)]
struct StoredCertificate {
    certificate_chain_pem: String,
    private_key_pem: String,
}

#[derive(Deserialize, Serialize)]
struct StoredAccount {
    directory_url: String,
    contact_email: String,
    credentials: AccountCredentials,
}

impl DiskStorage {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    pub async fn prepare(&self) -> io::Result<()> {
        fs::create_dir_all(&self.root).await?;
        set_owner_only_directory(&self.root).await
    }

    pub async fn load_account(
        &self,
        directory_url: &str,
        contact_email: &str,
    ) -> Option<AccountCredentials> {
        let path = self.root.join(ACCOUNT_FILE);
        let contents = fs::read(&path).await.ok()?;
        let account: StoredAccount = serde_json::from_slice(&contents).ok()?;
        if account.directory_url == directory_url && account.contact_email == contact_email {
            Some(account.credentials)
        } else {
            None
        }
    }

    pub async fn save_account(
        &self,
        directory_url: &str,
        contact_email: &str,
        credentials: AccountCredentials,
    ) -> io::Result<()> {
        let destination = self.root.join(ACCOUNT_FILE);
        let temporary = self.root.join(format!(".{}.tmp", ACCOUNT_FILE));
        let value = StoredAccount {
            directory_url: directory_url.to_owned(),
            contact_email: contact_email.to_owned(),
            credentials,
        };
        let contents = serde_json::to_vec_pretty(&value).map_err(io::Error::other)?;
        fs::write(&temporary, contents).await?;
        set_owner_only_file(&temporary).await?;
        fs::rename(&temporary, &destination).await
    }

    pub async fn load_certificate(&self) -> io::Result<Option<Certificate>> {
        let path = self.root.join(CERTIFICATE_FILE);
        let contents = match fs::read(&path).await {
            Ok(c) => c,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };

        let stored: StoredCertificate =
            serde_json::from_slice(&contents).map_err(io::Error::other)?;
        Ok(Some(Certificate::new(
            stored.certificate_chain_pem,
            stored.private_key_pem,
        )))
    }

    pub async fn save_certificate(&self, certificate: &Certificate) -> io::Result<()> {
        let destination = self.root.join(CERTIFICATE_FILE);
        let temporary = self.root.join(format!(".{}.tmp", CERTIFICATE_FILE));
        let value = StoredCertificate {
            certificate_chain_pem: certificate.chain_pem.clone(),
            private_key_pem: certificate.private_key_pem.clone(),
        };
        let contents = serde_json::to_vec_pretty(&value).map_err(io::Error::other)?;
        fs::write(&temporary, contents).await?;
        set_owner_only_file(&temporary).await?;
        fs::rename(&temporary, &destination).await
    }
}

#[cfg(unix)]
async fn set_owner_only_directory(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).await
}

#[cfg(not(unix))]
async fn set_owner_only_directory(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
async fn set_owner_only_file(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).await
}

#[cfg(not(unix))]
async fn set_owner_only_file(_path: &Path) -> io::Result<()> {
    Ok(())
}
