mod acme;
mod config;
mod http_filter;
mod state;
mod storage;

use std::sync::{Arc, OnceLock};

use config::Config;
use envoy_proxy_dynamic_modules_rust_sdk::{
    EnvoyHttpFilter, EnvoyHttpFilterConfig, HttpFilterConfig, declare_init_functions,
};
use http_filter::AcmeFilterConfig;
use state::SharedState;
use storage::DiskStorage;
use tokio::runtime::Runtime;

static APP: OnceLock<Arc<App>> = OnceLock::new();

struct App {
    config: Arc<Config>,
    state: Arc<SharedState>,
    _runtime: Runtime,
}

impl App {
    fn start(config: Config) -> Result<Arc<Self>, String> {
        let runtime =
            Runtime::new().map_err(|error| format!("failed to start runtime: {error}"))?;
        let config = Arc::new(config);
        let state = Arc::new(SharedState::new());
        let storage = DiskStorage::new(config.storage_path.clone());

        runtime
            .block_on(storage.prepare())
            .map_err(|error| format!("failed to prepare storage: {error}"))?;

        runtime.spawn(acme::run(Arc::clone(&config), Arc::clone(&state), storage));

        Ok(Arc::new(Self {
            config,
            state,
            _runtime: runtime,
        }))
    }
}

declare_init_functions!(program_init, new_http_filter_config);

fn program_init() -> bool {
    true
}

fn new_http_filter_config<EC: EnvoyHttpFilterConfig, EHF: EnvoyHttpFilter>(
    _envoy: &mut EC,
    name: &str,
    json: &[u8],
) -> Option<Box<dyn HttpFilterConfig<EHF>>> {
    if name != "envoy_acme" {
        envoy_proxy_dynamic_modules_rust_sdk::envoy_log_error!(
            "unknown dynamic module filter name {name:?}; expected \"envoy_acme\""
        );
        return None;
    }
    let config = match Config::parse(json) {
        Ok(config) => config,
        Err(error) => {
            envoy_proxy_dynamic_modules_rust_sdk::envoy_log_error!(
                "invalid envoy_acme configuration: {error}"
            );
            return None;
        }
    };

    // Envoy invokes config factories on its main thread, as required by this SDK callback.
    if is_validation_mode() {
        return Some(Box::new(AcmeFilterConfig::new(
            Arc::new(SharedState::new()),
        )));
    }

    let app = match APP.get() {
        Some(app) if app.config.as_ref() == &config => Arc::clone(app),
        Some(_) => {
            envoy_proxy_dynamic_modules_rust_sdk::envoy_log_error!(
                "envoy_acme may only have one process-wide configuration"
            );
            return None;
        }
        None => {
            let app = match App::start(config) {
                Ok(app) => app,
                Err(error) => {
                    envoy_proxy_dynamic_modules_rust_sdk::envoy_log_error!(
                        "failed to initialize envoy_acme: {error}"
                    );
                    return None;
                }
            };
            if APP.set(Arc::clone(&app)).is_err() {
                envoy_proxy_dynamic_modules_rust_sdk::envoy_log_error!(
                    "envoy_acme was initialized concurrently"
                );
                return None;
            }
            app
        }
    };

    Some(Box::new(AcmeFilterConfig::new(Arc::clone(&app.state))))
}

fn is_validation_mode() -> bool {
    {
        unsafe { envoy_proxy_dynamic_modules_rust_sdk::is_validation_mode() }
    }
}
