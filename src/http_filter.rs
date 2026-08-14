use std::sync::Arc;

use envoy_proxy_dynamic_modules_rust_sdk::{
    EnvoyHttpFilter, HttpFilter, HttpFilterConfig,
    abi::envoy_dynamic_module_type_on_http_filter_request_headers_status::{
        self as HeaderStatus, Continue, StopIteration,
    },
};

use crate::state::{ChallengeResponse, SharedState};

const CHALLENGE_PREFIX: &str = "/.well-known/acme-challenge/";

pub struct AcmeFilterConfig {
    state: Arc<SharedState>,
}

impl AcmeFilterConfig {
    pub fn new(state: Arc<SharedState>) -> Self {
        Self { state }
    }
}

impl<EHF: EnvoyHttpFilter> HttpFilterConfig<EHF> for AcmeFilterConfig {
    fn new_http_filter(&self, _envoy: &mut EHF) -> Box<dyn HttpFilter<EHF>> {
        Box::new(AcmeFilter {
            state: Arc::clone(&self.state),
        })
    }
}

struct AcmeFilter {
    state: Arc<SharedState>,
}

impl<EHF: EnvoyHttpFilter> HttpFilter<EHF> for AcmeFilter {
    fn on_request_headers(&mut self, envoy: &mut EHF, _end_of_stream: bool) -> HeaderStatus {
        let path = header(envoy, ":path").expect("Always contains a :path header");
        if !path.starts_with(CHALLENGE_PREFIX) {
            return Continue;
        }

        let method = header(envoy, ":method").unwrap_or_default();
        if method != "GET" && method != "HEAD" {
            envoy.send_response(
                405,
                &[("allow", b"GET, HEAD"), ("cache-control", b"no-store")],
                None,
                Some("acme_http01_method_not_allowed"),
            );
            return StopIteration;
        }
        let Some(token) = challenge_token(&path) else {
            envoy.send_response(
                404,
                &[("cache-control", b"no-store")],
                None,
                Some("acme_http01_challenge_not_found"),
            );
            return StopIteration;
        };

        let authority = header(envoy, ":authority").unwrap_or_default();
        let domain = authority_domain(&authority);
        let response = self
            .state
            .challenges
            .get(token)
            .filter(|response| response.domain == domain);
        match response.as_deref() {
            Some(ChallengeResponse { body, .. }) => {
                let response_body = (method == "GET").then_some(body.as_bytes());
                envoy.send_response(
                    200,
                    &[
                        ("content-type", b"text/plain"),
                        ("cache-control", b"no-store"),
                    ],
                    response_body,
                    Some("acme_http01_challenge"),
                );
            }
            None => envoy.send_response(
                404,
                &[("cache-control", b"no-store")],
                None,
                Some("acme_http01_challenge_not_found"),
            ),
        }
        StopIteration
    }
}

fn header<EHF: EnvoyHttpFilter>(envoy: &EHF, name: &str) -> Option<String> {
    let value = envoy.get_request_header_value(name)?;
    std::str::from_utf8(value.as_slice())
        .ok()
        .map(str::to_owned)
}

fn challenge_token(path: &str) -> Option<&str> {
    let token = path.strip_prefix(CHALLENGE_PREFIX)?;
    if token.is_empty() {
        return None;
    }
    if token.contains(['/', '?', '#']) {
        return None;
    }
    Some(token)
}

fn authority_domain(authority: &str) -> String {
    let authority = authority.to_ascii_lowercase();
    let without_port = match authority.rsplit_once(':') {
        Some((host, port)) if port.parse::<u16>().is_ok() => host,
        _ => authority.as_str(),
    };
    without_port.trim_end_matches('.').to_owned()
}
