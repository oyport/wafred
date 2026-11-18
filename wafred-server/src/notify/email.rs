//! SMTP e-mail sender for the notification system, on top of `lettre`.

use lettre::{
    message::Mailbox, transport::smtp::authentication::Credentials,
    AsyncSmtpTransport, AsyncTransport, Tokio1Executor,
};
use serde_json::Value;

use super::AlertEvent;

/// The channel `config` JSON object.
#[derive(Debug, Clone, PartialEq)]
pub struct EmailConfig {
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_user: String,
    pub smtp_pass: String,
    /// `ssl` (implicit TLS, usually port 465), `starttls` (usually 587) or
    /// `none` for a local relay without TLS.
    pub tls: String,
    pub from: String,
    pub to: Vec<String>,
}

impl EmailConfig {
    /// Parses and validates the stored channel config.
    pub fn from_json(config: &Value) -> Result<Self, String> {
        let get_str = |key: &str| {
            config
                .get(key)
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
        };
        let smtp_host = get_str("smtp_host")
            .ok_or("missing 'smtp_host' in the channel config")?;
        let smtp_port = config
            .get("smtp_port")
            .and_then(Value::as_u64)
            .unwrap_or(465);
        let smtp_port =
            u16::try_from(smtp_port).map_err(|_| "invalid 'smtp_port'")?;
        let from =
            get_str("from").ok_or("missing 'from' in the channel config")?;
        let to: Vec<String> = config
            .get("to")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        if to.is_empty() {
            return Err(
                "missing 'to' recipients in the channel config".to_string()
            );
        }
        Ok(Self {
            smtp_host,
            smtp_port,
            smtp_user: get_str("smtp_user").unwrap_or_default(),
            smtp_pass: get_str("smtp_pass").unwrap_or_default(),
            tls: get_str("tls").unwrap_or_else(|| "ssl".to_string()),
            from,
            to,
        })
    }
}

/// Sends the alert as a plain-text e-mail to every configured recipient.
pub async fn send(
    _http: &reqwest::Client,
    config: &Value,
    event: &AlertEvent,
) -> Result<(), String> {
    let config = EmailConfig::from_json(config)?;

    let from: Mailbox = config
        .from
        .parse()
        .map_err(|err| format!("invalid 'from' address: {err}"))?;
    // `Message` stamps the `Date` header itself when the builder omits it.
    let mut builder = lettre::message::Message::builder()
        .from(from)
        .subject(&event.title);
    for recipient in &config.to {
        let mailbox: Mailbox = recipient
            .parse()
            .map_err(|err| format!("invalid recipient '{recipient}': {err}"))?;
        builder = builder.to(mailbox);
    }
    let body = format!(
        "{}\n\nseverity: {}\ntime: {}\n\n-- \nSent by WAFred",
        event.message,
        event.severity,
        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC"),
    );
    let message = builder
        .body(body)
        .map_err(|err| format!("cannot build the e-mail: {err}"))?;

    let transport = build_transport(&config)?;
    transport
        .send(message)
        .await
        .map(|_| ())
        .map_err(|err| format!("SMTP delivery failed: {err}"))
}

/// Builds the SMTP transport for the configured TLS mode.
fn build_transport(
    config: &EmailConfig,
) -> Result<AsyncSmtpTransport<Tokio1Executor>, String> {
    let builder = match config.tls.as_str() {
        "starttls" => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(
            &config.smtp_host,
        )
        .map_err(|err| format!("cannot configure STARTTLS: {err}"))?,
        "none" => AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(
            &config.smtp_host,
        ),
        // Default and unknown values use the safe option: implicit TLS.
        _ => AsyncSmtpTransport::<Tokio1Executor>::relay(&config.smtp_host)
            .map_err(|err| format!("cannot configure TLS: {err}"))?,
    };
    let mut builder = builder.port(config.smtp_port);
    if !config.smtp_user.is_empty() {
        builder = builder.credentials(Credentials::new(
            config.smtp_user.clone(),
            config.smtp_pass.clone(),
        ));
    }
    Ok(builder.build())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;
    use tokio::time::{timeout, Duration};

    #[derive(Clone, Copy)]
    enum Reply {
        Accept,
        RejectData,
        RejectMessage,
        MalformedEhlo,
        InjectStartTlsReply,
    }

    #[derive(Default)]
    struct Exchange {
        commands: Vec<String>,
        message: String,
    }

    async fn mock_smtp(reply: Reply) -> (u16, JoinHandle<Exchange>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let (reader, mut writer) = socket.into_split();
            let mut reader = BufReader::new(reader);
            let mut exchange = Exchange::default();
            writer
                .write_all(b"220 localhost ESMTP ready\r\n")
                .await
                .unwrap();
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).await.unwrap() == 0 {
                    break;
                }
                let command = line.trim_end_matches(['\r', '\n']).to_string();
                exchange.commands.push(command.clone());
                if command.starts_with("EHLO ") {
                    match reply {
                        Reply::MalformedEhlo => {
                            writer
                                .write_all(b"250-  \r\n250 8BITMIME\r\n")
                                .await
                                .unwrap();
                        },
                        Reply::InjectStartTlsReply => {
                            writer
                                .write_all(b"250-localhost\r\n250 STARTTLS\r\n")
                                .await
                                .unwrap();
                        },
                        _ => {
                            writer
                                .write_all(b"250-localhost\r\n250 8BITMIME\r\n")
                                .await
                                .unwrap();
                        },
                    }
                } else if command == "STARTTLS" {
                    writer
                        .write_all(b"220 ready\r\n250 forged\r\n")
                        .await
                        .unwrap();
                    // Keep the socket open until the client closes or starts
                    // a TLS handshake; EOF must not be the reason for failure.
                    let mut probe = [0; 1024];
                    let _ = timeout(
                        Duration::from_secs(2),
                        reader.get_mut().read(&mut probe),
                    )
                    .await;
                    break;
                } else if command.starts_with("MAIL FROM:")
                    || command.starts_with("RCPT TO:")
                {
                    writer.write_all(b"250 accepted\r\n").await.unwrap();
                } else if command == "DATA" {
                    if matches!(reply, Reply::RejectData) {
                        writer.write_all(b"550 rejected\r\n").await.unwrap();
                        break;
                    }
                    writer.write_all(b"354 send message\r\n").await.unwrap();
                    loop {
                        let mut part = String::new();
                        assert_ne!(
                            reader.read_line(&mut part).await.unwrap(),
                            0
                        );
                        if part == ".\r\n" {
                            break;
                        }
                        exchange.message.push_str(&part);
                    }
                    let response: &[u8] =
                        if matches!(reply, Reply::RejectMessage) {
                            b"550 rejected message\r\n"
                        } else {
                            b"250 queued\r\n"
                        };
                    writer.write_all(response).await.unwrap();
                    break;
                } else {
                    writer.write_all(b"500 unsupported\r\n").await.unwrap();
                    break;
                }
            }
            exchange
        });
        (port, server)
    }

    fn config(port: u16, tls: &str) -> Value {
        json!({
            "smtp_host": "127.0.0.1",
            "smtp_port": port,
            "tls": tls,
            "from": "alerts@example.test",
            "to": ["\"local part\"@example.test", "other@example.test"],
        })
    }

    fn event() -> AlertEvent {
        AlertEvent {
            event_type: "test".to_string(),
            severity: "warning",
            title: "SMTP regression".to_string(),
            message:
                "first line\n.\nRCPT TO:<injected@example.test>\r\nlast line\r.\rRCPT TO:<injected-cr@example.test>\rfinal line"
                    .to_string(),
            details: None,
            dedup_key: None,
        }
    }

    async fn run(reply: Reply, tls: &str) -> (Result<(), String>, Exchange) {
        let (port, server) = mock_smtp(reply).await;
        let client = reqwest::Client::new();
        let result = timeout(
            Duration::from_secs(5),
            send(&client, &config(port, tls), &event()),
        )
        .await
        .expect("SMTP delivery timed out");
        let exchange = timeout(Duration::from_secs(5), server)
            .await
            .expect("mock SMTP server timed out")
            .expect("mock SMTP server failed");
        (result, exchange)
    }

    #[tokio::test]
    async fn sends_quoted_recipient_and_escapes_message_lines() {
        let (result, exchange) = run(Reply::Accept, "none").await;
        assert!(result.is_ok(), "SMTP delivery failed: {result:?}");
        assert!(exchange.commands.iter().any(|line| {
            line.starts_with("RCPT TO:")
                && line.contains("\"local part\"@example.test")
        }));
        assert_eq!(
            exchange
                .commands
                .iter()
                .filter(|line| line.starts_with("RCPT TO:"))
                .count(),
            2
        );
        assert!(exchange.message.contains("RCPT TO:<injected@example.test>"));
        assert!(exchange
            .message
            .contains("RCPT TO:<injected-cr@example.test>"));
        assert!(exchange.message.contains("\r\n..\r\n"));
        let bytes = exchange.message.as_bytes();
        for (index, &byte) in bytes.iter().enumerate() {
            if byte == b'.'
                && (index == 0 || matches!(bytes[index - 1], b'\r' | b'\n'))
            {
                assert_eq!(bytes.get(index + 1), Some(&b'.'));
            }
        }
        assert!(
            exchange.message.contains("\r..\r")
                || exchange.message.contains("=0D")
                || exchange
                    .message
                    .contains("\r\n..\r\nRCPT TO:<injected-cr@example.test>"),
            "bare CR must be escaped, encoded, or normalized and escaped"
        );
    }

    #[tokio::test]
    async fn rejects_failed_data_command() {
        let (result, exchange) = run(Reply::RejectData, "none").await;
        assert!(result.is_err());
        assert!(exchange.commands.iter().any(|line| line == "DATA"));
        assert!(exchange.message.is_empty());
    }

    #[tokio::test]
    async fn rejects_failure_after_message_body() {
        let (result, exchange) = run(Reply::RejectMessage, "none").await;
        assert!(result.is_err());
        assert!(!exchange.message.is_empty());
    }

    #[tokio::test]
    async fn rejects_non_ascii_whitespace_in_recipient() {
        let mut settings = config(9, "none");
        settings["to"] = json!(["bad\u{00a0}@example.test"]);
        let client = reqwest::Client::new();
        let event = event();
        let error =
            timeout(Duration::from_secs(5), send(&client, &settings, &event))
                .await
                .expect("SMTP address validation timed out")
                .expect_err("invalid recipient was accepted");
        assert!(error.starts_with("invalid recipient"));
    }

    #[tokio::test]
    async fn malformed_ehlo_does_not_panic() {
        let (_, exchange) = run(Reply::MalformedEhlo, "none").await;
        assert!(exchange
            .commands
            .iter()
            .any(|line| line.starts_with("EHLO ")));
    }

    #[tokio::test]
    async fn extra_plaintext_after_starttls_is_not_delivered() {
        let (result, exchange) =
            run(Reply::InjectStartTlsReply, "starttls").await;
        let error = result.expect_err("injected STARTTLS reply was accepted");
        assert!(
            error.contains("unexpected data after the STARTTLS reply"),
            "unexpected failure: {error}"
        );
        assert!(exchange.commands.iter().any(|line| line == "STARTTLS"));
        assert!(!exchange.commands.iter().any(|line| line == "DATA"));
    }
}
