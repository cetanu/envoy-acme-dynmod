use std::{pin::Pin, sync::Arc};

use prost::Message;
use tokio::sync::mpsc;
use tokio_stream::{Stream, wrappers::ReceiverStream};
use tonic::{Request, Response, Status, Streaming};

use crate::proto::envoy::{
    config::core::v3::{ControlPlane, DataSource, data_source},
    extensions::transport_sockets::tls::v3::{Secret, TlsCertificate, secret},
};
use crate::{
    proto::envoy::service::{
        discovery::v3::{
            DeltaDiscoveryRequest, DeltaDiscoveryResponse, DiscoveryRequest, DiscoveryResponse,
        },
        secret::v3::secret_discovery_service_server::SecretDiscoveryService,
    },
    state::{Certificate, SharedState},
};

pub const SECRET_TYPE_URL: &str =
    "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret";

type ResponseStream<T> = Pin<Box<dyn Stream<Item = Result<T, Status>> + Send>>;

pub struct SdsService {
    secret_name: String,
    state: Arc<SharedState>,
}

impl SdsService {
    pub fn new(secret_name: String, state: Arc<SharedState>) -> Self {
        Self { secret_name, state }
    }

    fn validate_request(&self, request: &DiscoveryRequest) -> Result<bool, Status> {
        if !request.type_url.is_empty() && request.type_url != SECRET_TYPE_URL {
            return Err(Status::invalid_argument(format!(
                "unsupported type_url {:?}",
                request.type_url
            )));
        }
        Ok(request.resource_names.is_empty()
            || request
                .resource_names
                .iter()
                .any(|name| name == &self.secret_name))
    }

    fn response(&self, certificate: &Certificate) -> DiscoveryResponse {
        discovery_response(&self.secret_name, certificate)
    }
}

#[tonic::async_trait]
impl SecretDiscoveryService for SdsService {
    type DeltaSecretsStream = ResponseStream<DeltaDiscoveryResponse>;
    type StreamSecretsStream = ResponseStream<DiscoveryResponse>;

    async fn delta_secrets(
        &self,
        _request: Request<Streaming<DeltaDiscoveryRequest>>,
    ) -> Result<Response<Self::DeltaSecretsStream>, Status> {
        Err(Status::unimplemented("delta SDS is not supported"))
    }

    async fn stream_secrets(
        &self,
        request: Request<Streaming<DiscoveryRequest>>,
    ) -> Result<Response<Self::StreamSecretsStream>, Status> {
        let mut requests = request.into_inner();
        let mut certificates = self.state.subscribe();
        let state = Arc::clone(&self.state);
        let secret_name = self.secret_name.clone();
        let (tx, rx) = mpsc::channel(8);

        tokio::spawn(async move {
            let service = Self::new(secret_name, state);
            let mut selected = false;
            let mut last_version = None;
            loop {
                tokio::select! {
                    request = requests.message() => match request {
                        Ok(Some(request)) => match service.validate_request(&request) {
                            Ok(is_selected) => {
                                selected = is_selected;
                                if let Some(error) = request.error_detail {
                                    envoy_proxy_dynamic_modules_rust_sdk::envoy_log_warn!(
                                        "Envoy rejected SDS version {}: {}",
                                        request.version_info,
                                        error.message
                                    );
                                }
                                let current_certificate = certificates.borrow().clone();
                                if selected
                                    && let Some(certificate) = current_certificate
                                    && last_version.as_deref() != Some(certificate.version.as_str())
                                {
                                    last_version = Some(certificate.version.clone());
                                    if tx.send(Ok(service.response(&certificate))).await.is_err() {
                                        break;
                                    }
                                }
                            }
                            Err(status) => {
                                let _ = tx.send(Err(status)).await;
                                break;
                            }
                        },
                        Ok(None) => break,
                        Err(status) => {
                            let _ = tx.send(Err(status)).await;
                            break;
                        }
                    },
                    changed = certificates.changed(), if selected => {
                        if changed.is_err() {
                            break;
                        }
                        let current_certificate = certificates.borrow().clone();
                        if let Some(certificate) = current_certificate
                            && last_version.as_deref() != Some(certificate.version.as_str())
                        {
                            last_version = Some(certificate.version.clone());
                            if tx.send(Ok(service.response(&certificate))).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            }
        });

        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }

    async fn fetch_secrets(
        &self,
        request: Request<DiscoveryRequest>,
    ) -> Result<Response<DiscoveryResponse>, Status> {
        if !self.validate_request(request.get_ref())? {
            return Err(Status::not_found("requested SDS secret does not exist"));
        }
        let certificate = self
            .state
            .certificate()
            .ok_or_else(|| Status::unavailable("certificate has not been issued yet"))?;
        Ok(Response::new(self.response(&certificate)))
    }
}

fn discovery_response(secret_name: &str, certificate: &Certificate) -> DiscoveryResponse {
    let secret = Secret {
        name: secret_name.to_owned(),
        r#type: Some(secret::Type::TlsCertificate(TlsCertificate {
            certificate_chain: Some(DataSource {
                watched_directory: None,
                specifier: Some(data_source::Specifier::InlineString(
                    certificate.chain_pem.clone(),
                )),
            }),
            private_key: Some(DataSource {
                watched_directory: None,
                specifier: Some(data_source::Specifier::InlineString(
                    certificate.private_key_pem.clone(),
                )),
            }),
            ..Default::default()
        })),
    };
    DiscoveryResponse {
        version_info: certificate.version.clone(),
        resources: vec![prost_types::Any {
            type_url: SECRET_TYPE_URL.to_owned(),
            value: secret.encode_to_vec(),
        }],
        canary: false,
        type_url: SECRET_TYPE_URL.to_owned(),
        nonce: certificate.version.clone(),
        control_plane: Some(ControlPlane {
            identifier: "envoy-acme-dynmod".into(),
        }),
        resource_errors: Vec::new(),
    }
}
