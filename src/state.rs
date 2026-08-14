use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    sync::Arc,
};

use dashmap::DashMap;
use tokio::sync::watch;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChallengeResponse {
    pub domain: String,
    pub body: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Certificate {
    pub chain_pem: String,
    pub private_key_pem: String,
    pub version: String,
}

impl Certificate {
    pub fn new(chain_pem: String, private_key_pem: String) -> Self {
        let mut hasher = DefaultHasher::new();
        chain_pem.hash(&mut hasher);
        private_key_pem.hash(&mut hasher);
        Self {
            chain_pem,
            private_key_pem,
            version: format!("{:016x}", hasher.finish()),
        }
    }
}

pub struct SharedState {
    pub challenges: DashMap<String, ChallengeResponse>,
    certificate_tx: watch::Sender<Option<Arc<Certificate>>>,
}

impl SharedState {
    pub fn new() -> Self {
        let (certificate_tx, _) = watch::channel(None);
        Self {
            challenges: DashMap::new(),
            certificate_tx,
        }
    }

    pub fn publish(&self, certificate: Certificate) {
        self.certificate_tx
            .send_replace(Some(Arc::new(certificate)));
    }

    pub fn certificate(&self) -> Option<Arc<Certificate>> {
        self.certificate_tx.borrow().clone()
    }

    pub fn subscribe(&self) -> watch::Receiver<Option<Arc<Certificate>>> {
        self.certificate_tx.subscribe()
    }
}
