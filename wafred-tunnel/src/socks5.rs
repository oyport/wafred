//! A small SOCKS5 client for connectors that have no direct egress.
//!
//! Some private networks only reach the internet through a SOCKS5 proxy (a
//! jump host, a corporate gateway, a bastion). The connector has to send both
//! its control-plane channel and its edge sessions through it, or it cannot
//! work at all there.
//!
//! Scope: SOCKS5 CONNECT only, which is all a TCP dial needs. Both address
//! forms a dial can use are supported, and **domain targets are sent as
//! domains** (ATYP 3) so the proxy resolves them — in the networks this exists
//! for, local DNS is usually the thing that does not work.
//!
//! Robustness is the point of this module, so every failure is a distinct,
//! actionable error: the proxy refused the method, the credentials were
//! rejected, the CONNECT was refused (with the reply code's meaning), the
//! proxy closed early, or the handshake timed out. There is no partial
//! success and no silent fallback to a direct dial.

use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Longest domain name a CONNECT request may carry.
const MAX_DOMAIN_LEN: usize = 255;

/// One SOCKS5 proxy endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Socks5Proxy {
    /// `host:port` of the proxy itself.
    pub addr: String,
    pub username: Option<String>,
    pub password: Option<String>,
}

impl Socks5Proxy {
    /// Parses a proxy description.
    ///
    /// Accepts `host:port`, `socks5://host:port` and `socks5h://host:port`
    /// (the two schemes mean the same thing here: the *target* host is always
    /// resolved by the proxy). Credentials may be embedded as
    /// `socks5://user:pass@host:port`; explicit `username`/`password` win over
    /// an embedded userinfo, which is how an operator can keep the password out
    /// of the config file.
    pub fn parse(
        raw: &str,
        username: Option<String>,
        password: Option<String>,
    ) -> Result<Self> {
        let raw = raw.trim();
        if raw.is_empty() {
            bail!("socks5 proxy address is empty");
        }
        if raw.chars().any(|c| c.is_control() || c.is_whitespace()) {
            bail!(
                "socks5 proxy address must not contain whitespace or control characters"
            );
        }
        let mut rest = raw;
        for scheme in ["socks5h://", "socks5://"] {
            if let Some(stripped) = rest.strip_prefix(scheme) {
                rest = stripped;
                break;
            }
        }
        let (userinfo, addr) = match rest.rsplit_once('@') {
            Some((userinfo, addr)) => (Some(userinfo), addr),
            None => (None, rest),
        };
        if addr.is_empty() || !addr.contains(':') {
            bail!("socks5 proxy address '{raw}' is not host:port");
        }
        let (host, port) = split_host_port(addr).ok_or_else(|| {
            anyhow!("socks5 proxy address '{addr}' is not host:port")
        })?;
        if host.is_empty() {
            bail!("socks5 proxy address '{addr}' has no host");
        }
        if port == 0 {
            bail!("socks5 proxy port must not be 0");
        }

        let mut username = username.filter(|value| !value.is_empty());
        let mut password = password.filter(|value| !value.is_empty());
        if let Some(userinfo) = userinfo {
            let (user, pass) =
                userinfo.split_once(':').unwrap_or((userinfo, ""));
            if username.is_none() && !user.is_empty() {
                username = Some(user.to_string());
            }
            if password.is_none() && !pass.is_empty() {
                password = Some(pass.to_string());
            }
        }
        if password.is_some() && username.is_none() {
            bail!("socks5 proxy has a password but no username");
        }

        Ok(Self {
            addr: addr.to_string(),
            username,
            password,
        })
    }

    pub fn uses_authentication(&self) -> bool {
        self.username.is_some()
    }

    /// Opens a TCP connection to `target_host:target_port` through the proxy.
    ///
    /// `timeout` bounds the whole handshake (dial, method negotiation, optional
    /// authentication and CONNECT), not each step: a proxy that stalls at any
    /// point fails the dial instead of hanging the caller.
    pub async fn connect(
        &self,
        target_host: &str,
        target_port: u16,
        timeout: Duration,
    ) -> Result<TcpStream> {
        match tokio::time::timeout(
            timeout,
            self.connect_inner(target_host, target_port),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(anyhow!(
                "socks5 handshake with {} timed out after {:?}",
                self.addr,
                timeout
            )),
        }
    }

    async fn connect_inner(
        &self,
        target_host: &str,
        target_port: u16,
    ) -> Result<TcpStream> {
        let mut stream =
            TcpStream::connect(&self.addr).await.with_context(|| {
                format!("cannot reach the socks5 proxy at {}", self.addr)
            })?;
        let _ = stream.set_nodelay(true);

        self.negotiate_method(&mut stream).await?;
        if self.uses_authentication() {
            self.authenticate(&mut stream).await?;
        }
        self.request_connect(&mut stream, target_host, target_port)
            .await?;
        Ok(stream)
    }

    /// Greeting + method selection.
    async fn negotiate_method(&self, stream: &mut TcpStream) -> Result<()> {
        // Offer "no auth" always (harmless when the proxy wants credentials)
        // and username/password when they are configured.
        let mut methods = vec![0x00u8];
        if self.uses_authentication() {
            methods.push(0x02);
        }
        let mut greeting = vec![0x05u8, methods.len() as u8];
        greeting.extend_from_slice(&methods);
        stream
            .write_all(&greeting)
            .await
            .context("cannot send the socks5 greeting")?;

        let mut reply = [0u8; 2];
        stream
            .read_exact(&mut reply)
            .await
            .context("the socks5 proxy closed during method negotiation")?;
        if reply[0] != 0x05 {
            bail!("the socks5 proxy answered with version {}", reply[0]);
        }
        match reply[1] {
            0x00 => Ok(()),
            0x02 if self.uses_authentication() => Ok(()),
            0xFF => bail!(
                "the socks5 proxy refused every authentication method offered"
            ),
            other => bail!(
                "the socks5 proxy selected method 0x{other:02x}, which was not offered"
            ),
        }
    }

    /// RFC 1929 username/password sub-negotiation.
    async fn authenticate(&self, stream: &mut TcpStream) -> Result<()> {
        let username = self.username.clone().unwrap_or_default();
        let password = self.password.clone().unwrap_or_default();
        if username.len() > 255 || password.len() > 255 {
            bail!("socks5 username/password must be at most 255 bytes");
        }
        let mut request =
            Vec::with_capacity(3 + username.len() + password.len());
        request.push(0x01);
        request.push(username.len() as u8);
        request.extend_from_slice(username.as_bytes());
        request.push(password.len() as u8);
        request.extend_from_slice(password.as_bytes());
        stream
            .write_all(&request)
            .await
            .context("cannot send the socks5 credentials")?;

        let mut reply = [0u8; 2];
        stream
            .read_exact(&mut reply)
            .await
            .context("the socks5 proxy closed during authentication")?;
        if reply[0] != 0x01 {
            bail!(
                "the socks5 proxy answered authentication with version {}",
                reply[0]
            );
        }
        if reply[1] != 0x00 {
            bail!("the socks5 proxy rejected the username/password");
        }
        Ok(())
    }

    /// CONNECT to the target and drain the reply.
    async fn request_connect(
        &self,
        stream: &mut TcpStream,
        target_host: &str,
        target_port: u16,
    ) -> Result<()> {
        let mut request = vec![0x05u8, 0x01, 0x00];
        write_target(&mut request, target_host, target_port)?;
        stream
            .write_all(&request)
            .await
            .context("cannot send the socks5 CONNECT request")?;

        let mut header = [0u8; 4];
        stream
            .read_exact(&mut header)
            .await
            .context("the socks5 proxy closed before answering CONNECT")?;
        if header[0] != 0x05 {
            bail!(
                "the socks5 proxy answered CONNECT with version {}",
                header[0]
            );
        }
        if header[1] != 0x00 {
            bail!(
                "the socks5 proxy refused CONNECT to {target_host}:{target_port}: {}",
                reply_message(header[1])
            );
        }
        // Drain BND.ADDR and BND.PORT so the stream is positioned at the
        // tunnel payload; an unknown address type cannot be skipped safely.
        match header[3] {
            0x01 => {
                let mut addr = [0u8; 4];
                stream.read_exact(&mut addr).await.context(
                    "the socks5 proxy closed while sending the bound address",
                )?;
            },
            0x04 => {
                let mut addr = [0u8; 16];
                stream.read_exact(&mut addr).await.context(
                    "the socks5 proxy closed while sending the bound address",
                )?;
            },
            0x03 => {
                let mut len = [0u8; 1];
                stream.read_exact(&mut len).await.context(
                    "the socks5 proxy closed while sending the bound address",
                )?;
                let mut addr = vec![0u8; len[0] as usize];
                stream.read_exact(&mut addr).await.context(
                    "the socks5 proxy closed while sending the bound address",
                )?;
            },
            other => bail!(
                "the socks5 proxy answered CONNECT with address type 0x{other:02x}"
            ),
        }
        let mut port = [0u8; 2];
        stream
            .read_exact(&mut port)
            .await
            .context("the socks5 proxy closed while sending the bound port")?;
        Ok(())
    }
}

/// Appends the target address to a CONNECT request in the right ATYP form.
fn write_target(request: &mut Vec<u8>, host: &str, port: u16) -> Result<()> {
    let host = host.trim();
    if host.is_empty() {
        bail!("socks5 target host is empty");
    }
    if host.chars().any(|c| c.is_control() || c.is_whitespace()) {
        bail!(
            "socks5 target host must not contain whitespace or control characters"
        );
    }
    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        request.push(0x01);
        request.extend_from_slice(&ip.octets());
    } else if let Ok(ip) = host.parse::<std::net::Ipv6Addr>() {
        request.push(0x04);
        request.extend_from_slice(&ip.octets());
    } else {
        if host.len() > MAX_DOMAIN_LEN {
            bail!("socks5 target host is longer than {MAX_DOMAIN_LEN} bytes");
        }
        request.push(0x03);
        request.push(host.len() as u8);
        request.extend_from_slice(host.as_bytes());
    }
    request.extend_from_slice(&port.to_be_bytes());
    Ok(())
}

/// Human-readable meaning of a CONNECT reply code (RFC 1928 §6).
fn reply_message(code: u8) -> &'static str {
    match code {
        0x01 => "general SOCKS server failure",
        0x02 => "connection not allowed by ruleset",
        0x03 => "network unreachable",
        0x04 => "host unreachable",
        0x05 => "connection refused",
        0x06 => "TTL expired",
        0x07 => "command not supported",
        0x08 => "address type not supported",
        _ => "unknown reply code",
    }
}

/// Splits `host:port`, brackets included for IPv6. `None` when malformed.
fn split_host_port(raw: &str) -> Option<(&str, u16)> {
    if let Some(rest) = raw.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        let port = tail.strip_prefix(':')?.parse().ok()?;
        return Some((host, port));
    }
    let (host, port) = raw.rsplit_once(':')?;
    if host.is_empty() || host.contains(':') {
        return None;
    }
    Some((host, port.parse().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    /// What the mock proxy should do for one connection.
    #[derive(Clone, Copy)]
    enum Behaviour {
        /// Accept without authentication and connect to the echo server.
        Accept,
        /// Demand username/password; the given pair is accepted.
        RequireAuth,
        /// Refuse CONNECT with this reply code.
        Refuse(u8),
        /// Accept the greeting, then close the connection.
        CloseAfterGreeting,
        /// Accept the greeting, then never answer CONNECT.
        Stall,
    }

    struct Mock {
        addr: std::net::SocketAddr,
        /// Domain the client asked for, when ATYP 3 was used.
        requested: tokio::sync::mpsc::UnboundedReceiver<String>,
    }

    async fn mock_proxy(
        behaviour: Behaviour,
        echo: std::net::SocketAddr,
        credentials: Option<(String, String)>,
    ) -> Mock {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                let tx = tx.clone();
                let credentials = credentials.clone();
                tokio::spawn(async move {
                    // Greeting.
                    let mut head = [0u8; 2];
                    if socket.read_exact(&mut head).await.is_err() {
                        return;
                    }
                    let mut methods = vec![0u8; head[1] as usize];
                    if socket.read_exact(&mut methods).await.is_err() {
                        return;
                    }
                    let method = match behaviour {
                        Behaviour::RequireAuth => 0x02,
                        _ => 0x00,
                    };
                    if socket.write_all(&[0x05, method]).await.is_err() {
                        return;
                    }
                    if matches!(behaviour, Behaviour::CloseAfterGreeting) {
                        return;
                    }
                    if method == 0x02 {
                        let mut auth_head = [0u8; 2];
                        if socket.read_exact(&mut auth_head).await.is_err() {
                            return;
                        }
                        let mut user = vec![0u8; auth_head[1] as usize];
                        if socket.read_exact(&mut user).await.is_err() {
                            return;
                        }
                        let mut plen = [0u8; 1];
                        if socket.read_exact(&mut plen).await.is_err() {
                            return;
                        }
                        let mut pass = vec![0u8; plen[0] as usize];
                        if socket.read_exact(&mut pass).await.is_err() {
                            return;
                        }
                        let ok = credentials.as_ref().is_some_and(|(u, p)| {
                            u.as_bytes() == user.as_slice()
                                && p.as_bytes() == pass.as_slice()
                        });
                        let status = if ok { 0x00 } else { 0x01 };
                        if socket.write_all(&[0x01, status]).await.is_err()
                            || !ok
                        {
                            return;
                        }
                    }
                    // CONNECT request.
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
                        0x04 => {
                            let mut ip = [0u8; 16];
                            if socket.read_exact(&mut ip).await.is_err() {
                                return;
                            }
                            "ipv6".to_string()
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
                    let _ = tx.send(host);
                    match behaviour {
                        Behaviour::Refuse(code) => {
                            let _ = socket
                                .write_all(&[
                                    0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0,
                                ])
                                .await;
                            return;
                        },
                        Behaviour::Stall => {
                            tokio::time::sleep(Duration::from_secs(30)).await;
                            return;
                        },
                        _ => {},
                    }
                    let _ = socket
                        .write_all(&[
                            0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0,
                        ])
                        .await;
                    // Bridge to the echo server.
                    let Ok(mut upstream) = TcpStream::connect(echo).await
                    else {
                        return;
                    };
                    let _ = tokio::io::copy_bidirectional(
                        &mut socket,
                        &mut upstream,
                    )
                    .await;
                });
            }
        });
        Mock {
            addr,
            requested: rx,
        }
    }

    async fn echo_server() -> std::net::SocketAddr {
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

    #[test]
    fn parsing_accepts_the_forms_an_operator_writes() {
        let plain = Socks5Proxy::parse("127.0.0.1:1080", None, None).unwrap();
        assert_eq!(plain.addr, "127.0.0.1:1080");
        assert!(!plain.uses_authentication());

        let with_scheme =
            Socks5Proxy::parse("socks5h://proxy.internal:1080", None, None)
                .unwrap();
        assert_eq!(with_scheme.addr, "proxy.internal:1080");

        let embedded = Socks5Proxy::parse(
            "socks5://alice:s3cret@proxy.internal:1080",
            None,
            None,
        )
        .unwrap();
        assert_eq!(embedded.username.as_deref(), Some("alice"));
        assert_eq!(embedded.password.as_deref(), Some("s3cret"));

        // Explicit credentials win over the embedded userinfo.
        let explicit = Socks5Proxy::parse(
            "socks5://alice:s3cret@proxy.internal:1080",
            Some("bob".to_string()),
            Some("hunter2".to_string()),
        )
        .unwrap();
        assert_eq!(explicit.username.as_deref(), Some("bob"));
        assert_eq!(explicit.password.as_deref(), Some("hunter2"));

        let v6 = Socks5Proxy::parse("[::1]:1080", None, None).unwrap();
        assert_eq!(v6.addr, "[::1]:1080");
    }

    #[test]
    fn parsing_rejects_malformed_descriptions() {
        for raw in [
            "",
            "proxy",
            "proxy:",
            ":1080",
            "proxy:0",
            "proxy:99999",
            "a b:1080",
        ] {
            assert!(Socks5Proxy::parse(raw, None, None).is_err(), "{raw}");
        }
        // A password without a username cannot be negotiated.
        assert!(
            Socks5Proxy::parse("proxy:1080", None, Some("p".to_string()))
                .is_err()
        );
    }

    #[tokio::test]
    async fn a_domain_target_is_sent_as_a_domain_and_the_tunnel_carries_bytes()
    {
        let echo = echo_server().await;
        let mut mock = mock_proxy(Behaviour::Accept, echo, None).await;
        let proxy =
            Socks5Proxy::parse(&mock.addr.to_string(), None, None).unwrap();
        let mut stream = proxy
            .connect("app.internal", 8443, Duration::from_secs(5))
            .await
            .unwrap();
        // The proxy resolved the domain itself: the request carried ATYP 3.
        assert_eq!(
            mock.requested.recv().await.as_deref(),
            Some("app.internal")
        );
        stream.write_all(b"hello").await.unwrap();
        let mut buffer = [0u8; 5];
        stream.read_exact(&mut buffer).await.unwrap();
        assert_eq!(&buffer, b"hello");
    }

    #[tokio::test]
    async fn an_ipv4_target_is_sent_as_an_address() {
        let echo = echo_server().await;
        let mut mock = mock_proxy(Behaviour::Accept, echo, None).await;
        let proxy =
            Socks5Proxy::parse(&mock.addr.to_string(), None, None).unwrap();
        let _stream = proxy
            .connect("10.0.0.5", 8080, Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(mock.requested.recv().await.as_deref(), Some("10.0.0.5"));
    }

    #[tokio::test]
    async fn username_password_authentication_works_and_a_wrong_pair_is_refused()
     {
        let echo = echo_server().await;
        let mut mock = mock_proxy(
            Behaviour::RequireAuth,
            echo,
            Some(("alice".to_string(), "s3cret".to_string())),
        )
        .await;
        let proxy = Socks5Proxy::parse(
            &mock.addr.to_string(),
            Some("alice".to_string()),
            Some("s3cret".to_string()),
        )
        .unwrap();
        let _stream = proxy
            .connect("app.internal", 80, Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(
            mock.requested.recv().await.as_deref(),
            Some("app.internal")
        );

        let wrong = Socks5Proxy::parse(
            &mock.addr.to_string(),
            Some("alice".to_string()),
            Some("wrong".to_string()),
        )
        .unwrap();
        let error = wrong
            .connect("app.internal", 80, Duration::from_secs(5))
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("rejected the username/password"), "{error}");
    }

    #[tokio::test]
    async fn a_refused_connect_reports_the_reply_code() {
        let echo = echo_server().await;
        let mock = mock_proxy(Behaviour::Refuse(0x05), echo, None).await;
        let proxy =
            Socks5Proxy::parse(&mock.addr.to_string(), None, None).unwrap();
        let error = proxy
            .connect("app.internal", 80, Duration::from_secs(5))
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("connection refused"), "{error}");
        assert!(error.contains("app.internal:80"), "{error}");
    }

    #[tokio::test]
    async fn a_proxy_that_closes_or_stalls_is_an_error_not_a_hang() {
        let echo = echo_server().await;
        let closing =
            mock_proxy(Behaviour::CloseAfterGreeting, echo, None).await;
        let proxy =
            Socks5Proxy::parse(&closing.addr.to_string(), None, None).unwrap();
        let error = proxy
            .connect("app.internal", 80, Duration::from_secs(5))
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("closed"), "{error}");

        let stalling = mock_proxy(Behaviour::Stall, echo, None).await;
        let proxy =
            Socks5Proxy::parse(&stalling.addr.to_string(), None, None).unwrap();
        let started = std::time::Instant::now();
        let error = proxy
            .connect("app.internal", 80, Duration::from_millis(300))
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("timed out"), "{error}");
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[tokio::test]
    async fn an_unreachable_proxy_is_reported_as_such() {
        // Port 1 on loopback: nothing listens there.
        let proxy = Socks5Proxy::parse("127.0.0.1:1", None, None).unwrap();
        let error = proxy
            .connect("app.internal", 80, Duration::from_secs(2))
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("cannot reach the socks5 proxy"), "{error}");
    }
}
