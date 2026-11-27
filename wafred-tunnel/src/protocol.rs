//! The wire protocol shared by the edge acceptor and the tunnel connector.
//!
//! One TLS connection carries one yamux session. The connector opens a single
//! *control stream* first (handshake, heartbeats, policy updates); the edge
//! opens one *data stream* per proxied connection. Both directions are framed
//! differently on purpose:
//!
//! * control frames are a 4-byte big-endian length followed by a JSON body
//!   (`ControlFrame`). They are rare, so the readability and the evolvability
//!   of a tagged JSON enum is worth more than the bytes;
//! * a data stream starts with a 2-byte big-endian length and the target
//!   `host:port` in UTF-8, and is a raw byte pipe after that. The preamble is
//!   tiny because it is paid once per proxied connection.

use std::io;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// ALPN protocol identifier. A peer that does not speak it is rejected during
/// the TLS handshake instead of after it.
pub const ALPN: &[u8] = b"wafred-tunnel/1";

/// Version of the control protocol. Bumped only for an incompatible change;
/// additive fields do not need it.
pub const PROTOCOL_VERSION: u32 = 1;

/// Upper bound for one control frame body.
pub const MAX_CONTROL_FRAME: usize = 64 * 1024;
/// Upper bound for a data-stream target preamble.
pub const MAX_TARGET_LEN: usize = 255;
/// Read buffer used when copying bytes between a socket and a stream.
pub const COPY_BUF: usize = 16 * 1024;

/// Error codes a peer can report. Serialized as a string so a future code is a
/// log line, not a decode failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// Credential missing, wrong, or no longer valid.
    Unauthenticated,
    /// The tunnel exists but is disabled.
    TunnelDisabled,
    /// The target is not in the policy (or in the connector's local allowlist).
    TargetDenied,
    /// The connector could not reach the target inside the private network.
    TargetUnreachable,
    /// A concurrency limit was hit.
    StreamLimit,
    /// The frame did not parse or violated the protocol.
    ProtocolError,
    /// The tunnel was revoked while the session was live.
    Revoked,
}

impl ErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::Unauthenticated => "unauthenticated",
            ErrorCode::TunnelDisabled => "tunnel_disabled",
            ErrorCode::TargetDenied => "target_denied",
            ErrorCode::TargetUnreachable => "target_unreachable",
            ErrorCode::StreamLimit => "stream_limit",
            ErrorCode::ProtocolError => "protocol_error",
            ErrorCode::Revoked => "revoked",
        }
    }
}

/// Limits the edge hands to the connector at handshake time.
///
/// The connector applies them to itself; they are not a security boundary (the
/// edge enforces its own copy), only a way to make the two ends agree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunnelSettings {
    pub max_streams: u32,
    pub idle_timeout_secs: u32,
    pub heartbeat_secs: u32,
}

impl Default for TunnelSettings {
    fn default() -> Self {
        Self {
            max_streams: 256,
            idle_timeout_secs: 300,
            heartbeat_secs: 20,
        }
    }
}

/// One control frame. Tagged so both ends can log an unknown variant instead of
/// failing the session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum ControlFrame {
    /// Connector → edge, first frame on the control stream.
    Hello {
        protocol: u32,
        tunnel_id: String,
        /// A short-lived session token signed by the control plane. The edge
        /// verifies it against the public key in its rule bundle; it never
        /// receives a reusable credential.
        token: String,
        version: String,
        hostname: String,
        os: String,
    },
    /// Edge → connector: the session is accepted.
    HelloOk {
        /// Monotonic policy revision; a mismatch on heartbeat triggers a
        /// `PolicyUpdate`.
        policy_version: u64,
        targets: Vec<String>,
        settings: TunnelSettings,
    },
    /// Edge → connector: the session is refused; the edge closes the
    /// connection right after writing it.
    Rejected { code: ErrorCode, message: String },
    /// Connector → edge, periodic.
    Heartbeat { streams_active: u32, rtt_ms: u32 },
    /// Edge → connector: answer to `Heartbeat`, carrying a fresh policy only
    /// when it changed.
    HeartbeatAck {
        policy_version: u64,
        targets: Option<Vec<String>>,
        settings: Option<TunnelSettings>,
    },
    /// Edge → connector: the policy changed (target list / limits).
    PolicyUpdate {
        policy_version: u64,
        targets: Vec<String>,
        settings: TunnelSettings,
    },
    /// Edge → connector: stop accepting new work, finish what is open, then
    /// exit (the edge is restarting or the session is being replaced).
    Drain { grace_secs: u32 },
    /// Edge → connector: the credential was revoked or the tunnel deleted.
    Revoked { message: String },
}

impl ControlFrame {
    /// Short name for logs. Never includes the credential.
    pub fn kind(&self) -> &'static str {
        match self {
            ControlFrame::Hello { .. } => "hello",
            ControlFrame::HelloOk { .. } => "hello_ok",
            ControlFrame::Rejected { .. } => "rejected",
            ControlFrame::Heartbeat { .. } => "heartbeat",
            ControlFrame::HeartbeatAck { .. } => "heartbeat_ack",
            ControlFrame::PolicyUpdate { .. } => "policy_update",
            ControlFrame::Drain { .. } => "drain",
            ControlFrame::Revoked { .. } => "revoked",
        }
    }
}

/// SHA-256 of a connector credential, lower-case hex.
///
/// The control plane stores this digest and hands it to the edges, so the
/// secret itself never has to reach a data plane or the database. The
/// credential is 32 random bytes, which is why a plain hash is enough here
/// (unlike a user password, there is nothing to guess).
pub fn credential_digest(secret: &str) -> String {
    hex::encode(Sha256::digest(secret.as_bytes()))
}

/// Constant-time comparison of a presented credential against a stored digest.
///
/// `expected_hex` is what the control plane put in the rule bundle; an empty or
/// malformed value never matches, so an unpaired tunnel cannot be opened.
pub fn credential_matches(presented: &str, expected_hex: &str) -> bool {
    let Some(expected) = decode_digest(expected_hex) else {
        return false;
    };
    let presented = Sha256::digest(presented.as_bytes());
    constant_time_eq(&presented, &expected)
}

fn decode_digest(raw: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(raw.trim()).ok()?;
    bytes.try_into().ok()
}

/// Compares two equal-length byte strings without an early exit.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Validates and normalizes a tunnel target (`host:port`).
///
/// The value is dialed by the connector inside the private network, so it is
/// parsed strictly: no scheme, no path, no userinfo, no whitespace, no control
/// characters, a non-zero port and a host that is either an IP literal or a
/// conservative DNS name. Anything else returns `None` and is refused rather
/// than handed to the dialer.
pub fn normalize_target(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() || raw.len() > MAX_TARGET_LEN {
        return None;
    }
    if raw.chars().any(|c| {
        c.is_control()
            || c.is_whitespace()
            || c == '/'
            || c == '@'
            || c == '?'
            || c == '#'
    }) {
        return None;
    }

    let (host, port) = if let Some(rest) = raw.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        (host, tail.strip_prefix(':')?)
    } else {
        let (host, port) = raw.rsplit_once(':')?;
        // A bare IPv6 address has more than one colon and no brackets; it is
        // not a valid target without them.
        if host.contains(':') {
            return None;
        }
        (host, port)
    };

    if host.is_empty() {
        return None;
    }
    let port: u16 = port.parse().ok()?;
    if port == 0 {
        return None;
    }

    if host.parse::<std::net::IpAddr>().is_ok() {
        return Some(raw.to_string());
    }
    if host.len() > 253 {
        return None;
    }
    let labels_ok = host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    });
    labels_ok.then(|| raw.to_string())
}

/// Normalizes a pool node address into a tunnel target.
///
/// A pool may store a bare host (`app.internal`), which the API accepts; the
/// tunnel target must still be a `host:port`, so the default port follows the
/// node's TLS flag — the same choice pingora makes for a direct origin. Both
/// the control plane (which derives the target list) and the edge (which looks
/// a bridge up by that target) go through this function, or the two would
/// disagree and the pool would silently have no upstream.
pub fn normalize_pool_target(raw: &str, tls: bool) -> Option<String> {
    let raw = raw.trim();
    if let Some(target) = normalize_target(raw) {
        return Some(target);
    }
    if raw.contains(':') || raw.starts_with('[') {
        // Looks like it carries a port already; a malformed one stays
        // malformed rather than getting a default appended.
        return None;
    }
    let port = if tls { 443 } else { 80 };
    normalize_target(&format!("{raw}:{port}"))
}

/// Writes one control frame.
pub async fn write_frame<W>(
    writer: &mut W,
    frame: &ControlFrame,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let body = serde_json::to_vec(frame)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    if body.len() > MAX_CONTROL_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "control frame exceeds the size limit",
        ));
    }
    let mut header = [0u8; 4];
    header.copy_from_slice(&(body.len() as u32).to_be_bytes());
    writer.write_all(&header).await?;
    writer.write_all(&body).await?;
    writer.flush().await
}

/// Reads one control frame.
pub async fn read_frame<R>(reader: &mut R) -> io::Result<ControlFrame>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; 4];
    reader.read_exact(&mut header).await?;
    let len = u32::from_be_bytes(header) as usize;
    if len == 0 || len > MAX_CONTROL_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "control frame length out of range",
        ));
    }
    let mut body = vec![0u8; len];
    reader.read_exact(&mut body).await?;
    serde_json::from_slice(&body)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}

/// Writes the target preamble that opens a data stream.
pub async fn write_open_target<W>(
    writer: &mut W,
    target: &str,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let bytes = target.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_TARGET_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "target length out of range",
        ));
    }
    let mut header = [0u8; 2];
    header.copy_from_slice(&(bytes.len() as u16).to_be_bytes());
    writer.write_all(&header).await?;
    writer.write_all(bytes).await?;
    writer.flush().await
}

/// Reads and validates the target preamble of a data stream.
pub async fn read_open_target<R>(reader: &mut R) -> io::Result<String>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; 2];
    reader.read_exact(&mut header).await?;
    let len = u16::from_be_bytes(header) as usize;
    if len == 0 || len > MAX_TARGET_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "target length out of range",
        ));
    }
    let mut body = vec![0u8; len];
    reader.read_exact(&mut body).await?;
    let raw = String::from_utf8(body)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    normalize_target(&raw).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "target is not a host:port")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_matches_only_the_same_credential() {
        let digest = credential_digest("secret-value");
        assert!(credential_matches("secret-value", &digest));
        assert!(!credential_matches("secret-value-2", &digest));
        assert!(!credential_matches("secret-value", ""));
        assert!(!credential_matches("secret-value", "not-hex"));
    }

    #[test]
    fn target_validation_accepts_host_and_port_forms() {
        for raw in [
            "127.0.0.1:8080",
            "10.0.0.5:80",
            "app.internal:8443",
            "app.internal.example.com:443",
            "[::1]:8080",
            "[2001:db8::1]:443",
            "_service._tcp.internal:8080",
        ] {
            assert_eq!(normalize_target(raw), Some(raw.to_string()), "{raw}");
        }
    }

    #[test]
    fn target_validation_rejects_everything_else() {
        for raw in [
            "",
            "app.internal",
            "app.internal:0",
            "app.internal:65536",
            "http://app.internal:80",
            "app.internal:80/path",
            "user@app.internal:22",
            "app.internal:80?x=1",
            "app.internal:80#frag",
            "app internal:80",
            "app.internal:80\u{0}",
            "::1:80",
            "-bad.example:80",
            "bad-.example:80",
            "bad..example:80",
        ] {
            assert_eq!(normalize_target(raw), None, "{raw:?}");
        }
    }

    #[test]
    fn pool_targets_get_the_default_port_of_their_tls_flag() {
        assert_eq!(
            normalize_pool_target("app.internal", false),
            Some("app.internal:80".to_string())
        );
        assert_eq!(
            normalize_pool_target("app.internal", true),
            Some("app.internal:443".to_string())
        );
        assert_eq!(
            normalize_pool_target("10.0.0.5:8080", false),
            Some("10.0.0.5:8080".to_string())
        );
        assert_eq!(normalize_pool_target("bad:port:here", false), None);
    }

    #[tokio::test]
    async fn control_frames_round_trip() {
        let frames = vec![
            ControlFrame::Hello {
                protocol: PROTOCOL_VERSION,
                tunnel_id: "t-1".to_string(),
                token: "v1.00.00".to_string(),
                version: "0.32.49".to_string(),
                hostname: "edge-1".to_string(),
                os: "linux".to_string(),
            },
            ControlFrame::HelloOk {
                policy_version: 7,
                targets: vec!["10.0.0.5:8080".to_string()],
                settings: TunnelSettings::default(),
            },
            ControlFrame::Rejected {
                code: ErrorCode::Unauthenticated,
                message: "bad credential".to_string(),
            },
            ControlFrame::Heartbeat {
                streams_active: 3,
                rtt_ms: 12,
            },
            ControlFrame::HeartbeatAck {
                policy_version: 8,
                targets: Some(vec!["10.0.0.6:80".to_string()]),
                settings: None,
            },
            ControlFrame::PolicyUpdate {
                policy_version: 9,
                targets: vec![],
                settings: TunnelSettings {
                    max_streams: 8,
                    idle_timeout_secs: 30,
                    heartbeat_secs: 5,
                },
            },
            ControlFrame::Drain { grace_secs: 10 },
            ControlFrame::Revoked {
                message: "rotated".to_string(),
            },
        ];

        let (mut a, mut b) = tokio::io::duplex(64 * 1024);
        for frame in &frames {
            write_frame(&mut a, frame).await.unwrap();
            let decoded = read_frame(&mut b).await.unwrap();
            assert_eq!(&decoded, frame);
        }
    }

    #[tokio::test]
    async fn data_stream_preamble_round_trips() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        write_open_target(&mut a, "app.internal:8443")
            .await
            .unwrap();
        assert_eq!(
            read_open_target(&mut b).await.unwrap(),
            "app.internal:8443"
        );
    }

    #[tokio::test]
    async fn data_stream_preamble_rejects_a_bad_target() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        let raw = b"http://evil/";
        let mut framed = Vec::new();
        framed.extend_from_slice(&(raw.len() as u16).to_be_bytes());
        framed.extend_from_slice(raw);
        a.write_all(&framed).await.unwrap();
        assert!(read_open_target(&mut b).await.is_err());
    }

    #[tokio::test]
    async fn an_oversized_control_frame_is_refused() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        let huge = ControlFrame::Revoked {
            message: "x".repeat(MAX_CONTROL_FRAME),
        };
        assert!(write_frame(&mut a, &huge).await.is_err());
        // Nothing was written: the peer must see EOF, not a truncated frame.
        drop(a);
        assert!(read_frame(&mut b).await.is_err());
    }
}
