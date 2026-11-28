//! Pairing and the control-plane channel.
//!
//! A connector only ever *dials* the control plane, exactly like an agent: the
//! same gRPC port, the same TLS expectations (`https://` plus an optional CA
//! file, because the control plane's certificate is self-signed on first boot).

use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use wafred_proto::control_plane::{
    self as proto, control_plane_client::ControlPlaneClient as ProtoClient,
};
use tokio::sync::mpsc;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint};

use crate::socks5::Socks5Proxy;

use super::{ConnectorConfig, IngressEndpoint};
use crate::protocol::TunnelSettings;

/// Everything needed to redeem a pairing token.
#[derive(Debug, Clone)]
pub struct PairConfig {
    pub server_url: String,
    pub server_ca_cert: Option<String>,
    pub server_ca_pem: Option<String>,
    pub server_tls_name: Option<String>,
    pub pairing_token: String,
    pub hostname: String,
    pub version: String,
    pub os: String,
    /// Reached through this proxy when the host has no direct egress.
    pub socks5: Option<Socks5Proxy>,
}

/// What the control plane answered to a pairing request.
#[derive(Debug, Clone)]
pub struct PairOutcome {
    pub tunnel_id: String,
    pub name: String,
    pub credential: String,
    pub ingress: Vec<IngressEndpoint>,
    pub targets: Vec<String>,
    pub settings: TunnelSettings,
    /// Short-lived token for the edges, minted with the pairing.
    pub session_token: String,
    pub session_token_expires_at: i64,
}

/// Redeems a pairing token for a long-lived credential and the ingress list.
pub async fn pair(config: &PairConfig) -> Result<PairOutcome> {
    let channel = channel(
        &config.server_url,
        &config.server_ca_cert,
        &config.server_ca_pem,
        &config.server_tls_name,
        config.socks5.as_ref(),
    )
    .await?;
    let mut client = ProtoClient::new(channel);
    let response = client
        .pair_tunnel(proto::PairTunnelRequest {
            pairing_token: config.pairing_token.clone(),
            hostname: config.hostname.clone(),
            version: config.version.clone(),
            os_info: config.os.clone(),
        })
        .await
        .map_err(|status| {
            anyhow!(
                "the control plane refused the pairing: {}",
                status.message()
            )
        })?
        .into_inner();

    let settings = response.settings.unwrap_or_default();
    Ok(PairOutcome {
        tunnel_id: response.tunnel_id,
        name: response.name,
        credential: response.credential,
        ingress: response
            .ingress
            .into_iter()
            .filter(|entry| !entry.endpoint.is_empty())
            .map(|entry| IngressEndpoint {
                endpoint: entry.endpoint,
                fingerprints: entry.fingerprints,
            })
            .collect(),
        targets: response.targets,
        settings: TunnelSettings {
            max_streams: settings.max_streams,
            idle_timeout_secs: settings.idle_timeout_secs,
            heartbeat_secs: settings.heartbeat_secs,
        },
        session_token: response.session_token,
        session_token_expires_at: response.session_token_expires_at,
    })
}

/// An authenticated control-plane client for the connector's control stream.
pub struct ControlPlane {
    client: ProtoClient<Channel>,
}

impl ControlPlane {
    /// Opens the bidi control stream.
    ///
    /// The first message must be a `Hello`; the control plane answers with the
    /// current config (or a revocation).
    pub async fn control(
        &mut self,
        outbound: mpsc::Receiver<proto::TunnelConnectorMessage>,
    ) -> Result<tonic::Streaming<proto::TunnelConnectorCommand>> {
        let stream = futures::stream::unfold(outbound, |mut rx| async move {
            rx.recv().await.map(|message| (message, rx))
        });
        let response = self
            .client
            .tunnel_control(stream)
            .await
            .context("cannot open the tunnel control stream")?;
        Ok(response.into_inner())
    }
}

/// Connects to the control plane with the connector's stored configuration.
pub async fn connect(config: &ConnectorConfig) -> Result<ControlPlane> {
    let channel = channel(
        &config.server_url,
        &config.server_ca_cert,
        &config.server_ca_pem,
        &config.server_tls_name,
        config.socks5.as_ref(),
    )
    .await?;
    Ok(ControlPlane {
        client: ProtoClient::new(channel),
    })
}

async fn channel(
    server_url: &str,
    ca_cert_path: &Option<String>,
    ca_cert_pem: &Option<String>,
    tls_name: &Option<String>,
    socks5: Option<&Socks5Proxy>,
) -> Result<Channel> {
    let endpoint = Endpoint::from_shared(server_url.to_string())
        .map_err(|err| {
            anyhow!("invalid control-plane URL {server_url}: {err}")
        })?
        // The SOCKS5 handshake happens inside this budget, so it is larger
        // than a bare TCP connect would need.
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(300))
        .keep_alive_while_idle(true)
        .http2_keep_alive_interval(Duration::from_secs(30))
        .tcp_nodelay(true);
    let endpoint = apply_client_tls(
        endpoint,
        server_url,
        ca_cert_path,
        ca_cert_pem,
        tls_name,
    )?;

    // Without a proxy the default connector (direct TCP + TLS) is used. With
    // one, the same TLS configuration is layered over the stream this closure
    // dialed through SOCKS5: `connect_with_connector` applies the endpoint's
    // TLS on top of whatever the connector returns.
    let Some(proxy) = socks5.cloned() else {
        return endpoint.connect().await.with_context(|| {
            format!("cannot reach the control plane at {server_url}")
        });
    };
    let connector = tower::service_fn(move |uri: tonic::codegen::http::Uri| {
        let proxy = proxy.clone();
        async move {
            let host = uri
                .host()
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "the control-plane URL has no host",
                    )
                })?
                .trim_start_matches('[')
                .trim_end_matches(']')
                .to_string();
            let port = uri.port_u16().unwrap_or(443);
            proxy
                .connect(&host, port, Duration::from_secs(15))
                .await
                .map(hyper_util::rt::TokioIo::new)
                .map_err(|err| {
                    std::io::Error::other(format!(
                        "socks5 dial to {host}:{port} failed: {err}"
                    ))
                })
        }
    });
    endpoint
        .connect_with_connector(connector)
        .await
        .with_context(|| {
            format!(
                "cannot reach the control plane at {server_url} through the socks5 proxy"
            )
        })
}

/// Adds TLS to an endpoint for an `https://` URL.
///
/// Without the explicit configuration `Endpoint` would speak cleartext h2 into
/// a TLS port. Inline PEM (all-in-one) or a configured CA file is the only trust
/// anchor when present; otherwise the bundled webpki roots apply.
fn apply_client_tls(
    endpoint: Endpoint,
    server_url: &str,
    ca_cert_path: &Option<String>,
    ca_cert_pem: &Option<String>,
    tls_name: &Option<String>,
) -> Result<Endpoint> {
    if !has_scheme(server_url, "https://") {
        return Ok(endpoint);
    }
    let mut tls = ClientTlsConfig::new();
    if let Some(pem) = ca_cert_pem {
        tls = tls.ca_certificate(Certificate::from_pem(pem));
    } else if let Some(path) = ca_cert_path {
        let pem = std::fs::read_to_string(path).map_err(|err| {
            anyhow!("cannot read the control-plane CA {path}: {err}")
        })?;
        tls = tls.ca_certificate(Certificate::from_pem(pem));
    } else {
        tls = tls.with_enabled_roots();
    }
    if let Some(name) = tls_name {
        tls = tls.domain_name(name.clone());
    }
    endpoint
        .tls_config(tls)
        .map_err(|err| anyhow!("cannot configure control-plane TLS: {err}"))
}

fn has_scheme(url: &str, scheme: &str) -> bool {
    url.get(..scheme.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(scheme))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scheme_detection_is_case_insensitive() {
        assert!(has_scheme("https://cp:9090", "https://"));
        assert!(has_scheme("HTTPS://cp:9090", "https://"));
        assert!(!has_scheme("http://cp:9090", "https://"));
    }

    #[test]
    fn a_plaintext_endpoint_needs_no_tls_config() {
        let endpoint =
            Endpoint::from_shared("http://127.0.0.1:9090".to_string()).unwrap();
        assert!(
            apply_client_tls(
                endpoint,
                "http://127.0.0.1:9090",
                &None,
                &None,
                &None
            )
            .is_ok()
        );
    }

    #[test]
    fn a_missing_ca_file_is_an_error_not_a_silent_fallback() {
        let endpoint =
            Endpoint::from_shared("https://cp.example:9090".to_string())
                .unwrap();
        let result = apply_client_tls(
            endpoint,
            "https://cp.example:9090",
            &Some("/nonexistent/ca.pem".to_string()),
            &None,
            &None,
        );
        assert!(result.is_err());
    }
}
