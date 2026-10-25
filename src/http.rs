use std::sync::OnceLock;
use std::time::Duration;

use ureq::Agent;
use ureq::tls::{RootCerts, TlsConfig};

/// Shared HTTP agent. Uses the OS trust store (so corporate and sandbox
/// proxies with their own CA work) and honours HTTPS_PROXY / NO_PROXY.
/// Non-2xx statuses are returned as responses so callers can read Linear's
/// error bodies.
pub fn agent() -> &'static Agent {
    static AGENT: OnceLock<Agent> = OnceLock::new();
    AGENT.get_or_init(|| {
        Agent::config_builder()
            .http_status_as_error(false)
            .tls_config(
                TlsConfig::builder()
                    .root_certs(RootCerts::PlatformVerifier)
                    .build(),
            )
            .timeout_global(Some(Duration::from_secs(30)))
            .user_agent(concat!("lin/", env!("CARGO_PKG_VERSION")))
            .build()
            .into()
    })
}
