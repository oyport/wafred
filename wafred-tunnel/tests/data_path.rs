//! End-to-end data-path test: origin → connector → edge bridge → client.
//!
//! Everything is in-process and uses the real code on both ends — the edge
//! acceptor, the loopback bridge and the production connector client — so this
//! covers what a unit test cannot: the TLS pin, the handshake, both directions
//! of yamux stream opening, and the byte pipe.

use std::time::Duration;

use ring::signature::{Ed25519KeyPair, KeyPair};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use wafred_tunnel::client::{Connector, ConnectorConfig, IngressEndpoint};
use wafred_tunnel::protocol::TunnelSettings;
use wafred_tunnel::registry::{TunnelPolicy, TunnelRegistry};
use wafred_tunnel::socks5::Socks5Proxy;
use wafred_tunnel::token::{self, SessionTokenClaims};
use wafred_tunnel::{TunnelAcceptor, TunnelCertificate};

/// A TCP echo server standing in for the internal origin.
async fn spawn_origin() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let (mut reader, mut writer) = socket.split();
                let _ = tokio::io::copy(&mut reader, &mut writer).await;
            });
        }
    });
    addr
}

fn provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// The signing key the control plane would hold; the edge only gets the
/// public half, exactly as in the rule bundle.
fn token_key() -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[3u8; 32]).unwrap()
}

fn public_key_hex() -> String {
    token::public_key_hex(token_key().public_key().as_ref())
}

/// A session token for `tunnel_id`, valid for ten minutes.
fn session_token(tunnel_id: &str) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let claims = SessionTokenClaims {
        tunnel_id: tunnel_id.to_string(),
        issued_at: now,
        expires_at: now + 600,
    };
    let signature = token_key().sign(&token::payload_bytes(&claims));
    token::encode(&claims, signature.as_ref())
}

#[tokio::test]
async fn the_edge_serves_an_internal_target_through_a_connector() {
    provider();
    let origin = spawn_origin().await;

    // ── Edge: one tunnel whose only target is the "internal" origin ──────────
    let cert = TunnelCertificate::generate(&["localhost".to_string()]).unwrap();
    let registry = TunnelRegistry::new();
    registry.apply_policies(vec![TunnelPolicy {
        tunnel_id: "tunnel-1".to_string(),
        name: "smoke".to_string(),
        enabled: true,
        session_public_key: public_key_hex(),
        targets: vec![origin.to_string()],
        settings: TunnelSettings::default(),
    }]);
    let acceptor = TunnelAcceptor::bind("127.0.0.1:0", &cert, registry.clone())
        .await
        .unwrap();
    let edge = acceptor.local_addr();
    let _acceptor = acceptor.spawn();

    // ── Connector: the production client, pointed at that edge ───────────────
    let connector = Connector::new(ConnectorConfig {
        tunnel_id: "tunnel-1".to_string(),
        credential: "control-plane-credential".to_string(),
        // No control plane in this test: the connector falls back to its
        // configured ingress and allowed targets, which is the documented
        // offline behaviour.
        server_url: "http://127.0.0.1:1".to_string(),
        server_ca_cert: None,
        server_ca_pem: None,
        server_tls_name: None,
        ingress: vec![IngressEndpoint {
            endpoint: edge.to_string(),
            fingerprints: vec![cert.fingerprint_sha256.clone()],
        }],
        allowed_targets: vec![origin.to_string()],
        version: "0.0.0-test".to_string(),
        hostname: "connector-test".to_string(),
        os: "test".to_string(),
        session_token: Some(session_token("tunnel-1")),
        socks5: None,
    });
    let runner = tokio::spawn(connector.run());

    for _ in 0..100 {
        if registry.session_count() == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(
        registry.session_count(),
        1,
        "the connector did not establish a session"
    );

    // ── The bridge the data plane would dial, carrying real bytes ────────────
    let bridge = registry
        .bridge_addr("tunnel-1", &origin.to_string())
        .expect("a live session must expose a bridge address");
    let mut socket = TcpStream::connect(bridge).await.unwrap();
    socket.write_all(b"hello tunnel").await.unwrap();
    socket.flush().await.unwrap();
    let mut buffer = [0u8; 12];
    tokio::time::timeout(
        Duration::from_secs(5),
        socket.read_exact(&mut buffer),
    )
    .await
    .expect("the round trip timed out")
    .expect("the bridge closed before echoing");
    assert_eq!(&buffer, b"hello tunnel");

    // A second, concurrent stream proves the session is multiplexed rather than
    // serialized: both connections are open at the same time.
    let mut second = TcpStream::connect(bridge).await.unwrap();
    second.write_all(b"second").await.unwrap();
    let mut buffer = [0u8; 6];
    tokio::time::timeout(
        Duration::from_secs(5),
        second.read_exact(&mut buffer),
    )
    .await
    .expect("the second round trip timed out")
    .expect("the second stream closed early");
    assert_eq!(&buffer, b"second");
    socket.write_all(b"still open").await.unwrap();
    let mut buffer = [0u8; 10];
    tokio::time::timeout(
        Duration::from_secs(5),
        socket.read_exact(&mut buffer),
    )
    .await
    .expect("the first stream was closed when the second opened")
    .expect("the first stream closed early");
    assert_eq!(&buffer, b"still open");

    // ── A wrong credential never reaches the bridge ──────────────────────────
    let wrong = Connector::new(ConnectorConfig {
        tunnel_id: "tunnel-1".to_string(),
        credential: "control-plane-credential".to_string(),
        server_url: "http://127.0.0.1:1".to_string(),
        server_ca_cert: None,
        server_ca_pem: None,
        server_tls_name: None,
        ingress: vec![IngressEndpoint {
            endpoint: edge.to_string(),
            fingerprints: vec![cert.fingerprint_sha256.clone()],
        }],
        allowed_targets: vec![origin.to_string()],
        version: "0.0.0-test".to_string(),
        hostname: "impostor".to_string(),
        os: "test".to_string(),
        // Signed by the same key, but for another tunnel: the edge must refuse
        // it even though the signature is valid.
        session_token: Some(session_token("other-tunnel")),
        socks5: None,
    });
    let wrong_runner = tokio::spawn(wrong.run());
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        registry.session_count(),
        1,
        "a connector with the wrong credential replaced the live session"
    );

    runner.abort();
    wrong_runner.abort();
}

#[tokio::test]
async fn a_disabled_tunnel_refuses_every_session() {
    provider();
    let origin = spawn_origin().await;
    let cert = TunnelCertificate::generate(&["localhost".to_string()]).unwrap();
    let registry = TunnelRegistry::new();
    registry.apply_policies(vec![TunnelPolicy {
        tunnel_id: "tunnel-1".to_string(),
        name: "disabled".to_string(),
        enabled: false,
        session_public_key: public_key_hex(),
        targets: vec![origin.to_string()],
        settings: TunnelSettings::default(),
    }]);
    let acceptor = TunnelAcceptor::bind("127.0.0.1:0", &cert, registry.clone())
        .await
        .unwrap();
    let edge = acceptor.local_addr();
    let _acceptor = acceptor.spawn();

    let connector = Connector::new(ConnectorConfig {
        tunnel_id: "tunnel-1".to_string(),
        credential: "control-plane-credential".to_string(),
        server_url: "http://127.0.0.1:1".to_string(),
        server_ca_cert: None,
        server_ca_pem: None,
        server_tls_name: None,
        ingress: vec![IngressEndpoint {
            endpoint: edge.to_string(),
            fingerprints: vec![cert.fingerprint_sha256.clone()],
        }],
        allowed_targets: vec![origin.to_string()],
        version: "0.0.0-test".to_string(),
        hostname: "connector-test".to_string(),
        os: "test".to_string(),
        session_token: Some(session_token("tunnel-1")),
        socks5: None,
    });
    let runner = tokio::spawn(connector.run());
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(registry.session_count(), 0);
    assert!(
        registry
            .bridge_addr("tunnel-1", &origin.to_string())
            .is_none()
    );
    runner.abort();
}

/// A forwarding SOCKS5 proxy: no authentication, and it connects to whatever
/// target the client asks for. This is the shape a jump host has, and it lets
/// the test drive the production connector through the real SOCKS5 client.
async fn spawn_socks5_proxy() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                // Greeting: read version + methods, answer "no auth".
                let mut head = [0u8; 2];
                if socket.read_exact(&mut head).await.is_err() {
                    return;
                }
                let mut methods = vec![0u8; head[1] as usize];
                if socket.read_exact(&mut methods).await.is_err() {
                    return;
                }
                if socket.write_all(&[0x05, 0x00]).await.is_err() {
                    return;
                }
                // CONNECT.
                let mut header = [0u8; 4];
                if socket.read_exact(&mut header).await.is_err() {
                    return;
                }
                let host = match header[3] {
                    0x01 => {
                        let mut ip = [0u8; 4];
                        if socket.read_exact(&mut ip).await.is_err() {
                            return;
                        }
                        format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
                    },
                    0x03 => {
                        let mut len = [0u8; 1];
                        if socket.read_exact(&mut len).await.is_err() {
                            return;
                        }
                        let mut domain = vec![0u8; len[0] as usize];
                        if socket.read_exact(&mut domain).await.is_err() {
                            return;
                        }
                        String::from_utf8_lossy(&domain).to_string()
                    },
                    _ => return,
                };
                let mut port = [0u8; 2];
                if socket.read_exact(&mut port).await.is_err() {
                    return;
                }
                let port = u16::from_be_bytes(port);
                let Ok(mut upstream) =
                    TcpStream::connect((host.as_str(), port)).await
                else {
                    let _ = socket
                        .write_all(&[0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                        .await;
                    return;
                };
                let _ = socket
                    .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
                    .await;
                let _ =
                    tokio::io::copy_bidirectional(&mut socket, &mut upstream)
                        .await;
            });
        }
    });
    addr
}

#[tokio::test]
async fn the_connector_reaches_the_edge_through_a_socks5_proxy() {
    provider();
    let origin = spawn_origin().await;
    let proxy_addr = spawn_socks5_proxy().await;

    // Edge: one tunnel whose target is the "internal" origin.
    let cert = TunnelCertificate::generate(&["localhost".to_string()]).unwrap();
    let registry = TunnelRegistry::new();
    registry.apply_policies(vec![TunnelPolicy {
        tunnel_id: "tunnel-1".to_string(),
        name: "smoke".to_string(),
        enabled: true,
        session_public_key: public_key_hex(),
        targets: vec![origin.to_string()],
        settings: TunnelSettings::default(),
    }]);
    let acceptor = TunnelAcceptor::bind("127.0.0.1:0", &cert, registry.clone())
        .await
        .unwrap();
    let edge = acceptor.local_addr();
    let _acceptor = acceptor.spawn();

    // The connector has no direct route: every dial goes through the proxy.
    let proxy =
        Socks5Proxy::parse(&proxy_addr.to_string(), None, None).unwrap();
    let connector = Connector::new(ConnectorConfig {
        tunnel_id: "tunnel-1".to_string(),
        credential: "control-plane-credential".to_string(),
        server_url: "http://127.0.0.1:1".to_string(),
        server_ca_cert: None,
        server_ca_pem: None,
        server_tls_name: None,
        ingress: vec![IngressEndpoint {
            endpoint: edge.to_string(),
            fingerprints: vec![cert.fingerprint_sha256.clone()],
        }],
        allowed_targets: vec![origin.to_string()],
        version: "0.0.0-test".to_string(),
        hostname: "connector-socks5".to_string(),
        os: "test".to_string(),
        session_token: Some(session_token("tunnel-1")),
        socks5: Some(proxy),
    });
    let runner = tokio::spawn(connector.run());

    for _ in 0..100 {
        if registry.session_count() == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(
        registry.session_count(),
        1,
        "the connector did not reach the edge through the socks5 proxy"
    );

    let bridge = registry
        .bridge_addr("tunnel-1", &origin.to_string())
        .expect("a live session must expose a bridge address");
    let mut socket = TcpStream::connect(bridge).await.unwrap();
    socket.write_all(b"through the proxy").await.unwrap();
    let mut buffer = [0u8; 17];
    tokio::time::timeout(
        Duration::from_secs(5),
        socket.read_exact(&mut buffer),
    )
    .await
    .expect("the round trip timed out")
    .expect("the bridge closed before echoing");
    assert_eq!(&buffer, b"through the proxy");

    runner.abort();
}
