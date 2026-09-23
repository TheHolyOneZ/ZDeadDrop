use std::time::Duration;

use crate::error::Result;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Channel {
    Email { address: String },

    Webhook { url: String },
}

impl Channel {
    pub fn parse(contact: &str) -> Option<Self> {
        if let Some(address) = contact.strip_prefix("mailto:") {
            return Some(Channel::Email {
                address: address.to_string(),
            });
        }
        if contact.starts_with("https://") || contact.starts_with("http://") {
            return Some(Channel::Webhook {
                url: contact.to_string(),
            });
        }

        if contact.contains('@') && !contact.contains(' ') {
            return Some(Channel::Email {
                address: contact.to_string(),
            });
        }
        None
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Channel::Email { .. } => "email",
            Channel::Webhook { .. } => "webhook",
        }
    }

    pub fn redacted(&self) -> String {
        match self {
            Channel::Email { address } => match address.split_once('@') {
                Some((local, domain)) => {
                    let head: String = local.chars().take(2).collect();
                    format!("{head}\u{2026}@{domain}")
                }
                None => "\u{2026}".to_string(),
            },
            Channel::Webhook { url } => url.split('/').nth(2).unwrap_or("\u{2026}").to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub enum Message {
    Reminder { days_quiet: u64, resume_url: String },

    TrusteePrompt { prompt_url: String },

    FinalCountdown { hours_left: u64, cancel_url: String },
}

impl Message {
    pub fn subject(&self) -> &'static str {
        match self {
            Message::Reminder { .. } => "Checking you are still there",
            Message::TrusteePrompt { .. } => "A question someone asked us to ask you",
            Message::FinalCountdown { .. } => "Please read this today",
        }
    }

    pub fn body(&self) -> String {
        match self {
            Message::Reminder {
                days_quiet,
                resume_url,
            } => format!(
                "You have not checked in for {days_quiet} days.\n\n\
                 If you are fine, open this and tap \"I'm here\":\n\n    {resume_url}\n\n\
                 Nothing has been sent to anyone. Nothing will be, for some time yet.\n\n\
                 If you did not expect this message, you can ignore it — but somebody \
                 set this up, and it will keep asking."
            ),
            Message::TrusteePrompt { prompt_url } => format!(
                "Someone asked us to check with you.\n\n\
                 They have not been in touch for a while, and they named you as \
                 somebody who would know whether that is a problem.\n\n\
                 There is one question, and it takes a moment:\n\n    {prompt_url}\n\n\
                 We are not asking you to do anything else, and you will not be told \
                 what this concerns."
            ),
            Message::FinalCountdown {
                hours_left,
                cancel_url,
            } => format!(
                "This is the last message before something you set up goes ahead.\n\n\
                 You have {hours_left} hours.\n\n\
                 To stop it:\n\n    {cancel_url}\n\n\
                 If you are reading this and you are fine, open that link now."
            ),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Sender {
    smtp: Option<SmtpConfig>,
    timeout: Duration,
}

#[derive(Debug, Clone)]
pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub from: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Delivery {
    Sent,

    NotConfigured(&'static str),
    Failed(String),
}

impl Delivery {
    pub fn succeeded(&self) -> bool {
        matches!(self, Delivery::Sent)
    }
}

impl Sender {
    pub fn from_env() -> Self {
        let smtp = match (
            std::env::var("ZDD_SMTP_HOST").ok(),
            std::env::var("ZDD_SMTP_FROM").ok(),
        ) {
            (Some(host), Some(from)) => Some(SmtpConfig {
                host,
                port: std::env::var("ZDD_SMTP_PORT")
                    .ok()
                    .and_then(|p| p.parse().ok())
                    .unwrap_or(587),
                username: std::env::var("ZDD_SMTP_USER").unwrap_or_default(),
                password: std::env::var("ZDD_SMTP_PASSWORD").unwrap_or_default(),
                from,
            }),
            _ => None,
        };

        Self {
            smtp,
            timeout: Duration::from_secs(20),
        }
    }

    pub fn has_email(&self) -> bool {
        self.smtp.is_some()
    }

    pub async fn send(&self, channel: &Channel, message: &Message) -> Delivery {
        match channel {
            Channel::Email { address } => self.send_email(address, message).await,
            Channel::Webhook { url } => self.send_webhook(url, message).await,
        }
    }

    async fn send_email(&self, to: &str, message: &Message) -> Delivery {
        let Some(config) = &self.smtp else {
            return Delivery::NotConfigured("no SMTP host is configured on this relay");
        };

        let built = lettre::Message::builder()
            .from(match config.from.parse() {
                Ok(m) => m,
                Err(e) => return Delivery::Failed(format!("bad from address: {e}")),
            })
            .to(match to.parse() {
                Ok(m) => m,
                Err(e) => return Delivery::Failed(format!("bad recipient address: {e}")),
            })
            .subject(message.subject())
            .body(message.body());

        let built = match built {
            Ok(m) => m,
            Err(e) => return Delivery::Failed(e.to_string()),
        };

        use lettre::AsyncTransport;
        let transport =
            lettre::AsyncSmtpTransport::<lettre::Tokio1Executor>::starttls_relay(&config.host);
        let transport = match transport {
            Ok(t) => t
                .port(config.port)
                .timeout(Some(self.timeout))
                .credentials(lettre::transport::smtp::authentication::Credentials::new(
                    config.username.clone(),
                    config.password.clone(),
                ))
                .build(),
            Err(e) => return Delivery::Failed(e.to_string()),
        };

        match transport.send(built).await {
            Ok(_) => Delivery::Sent,
            Err(e) => Delivery::Failed(e.to_string()),
        }
    }

    async fn send_webhook(&self, url: &str, message: &Message) -> Delivery {
        let client = match reqwest::Client::builder().timeout(self.timeout).build() {
            Ok(c) => c,
            Err(e) => return Delivery::Failed(e.to_string()),
        };

        let body = serde_json::json!({
            "title": message.subject(),
            "message": message.body(),
            "priority": match message {
                Message::FinalCountdown { .. } => 5,
                Message::Reminder { .. } => 4,
                Message::TrusteePrompt { .. } => 4,
            },
        });

        match client.post(url).json(&body).send().await {
            Ok(response) if response.status().is_success() => Delivery::Sent,
            Ok(response) => Delivery::Failed(format!("returned {}", response.status())),
            Err(e) => Delivery::Failed(e.to_string()),
        }
    }
}

pub fn record(
    conn: &rusqlite::Connection,
    vault: &str,
    channel: &Channel,
    message_kind: &str,
    outcome: &Delivery,
    now: u64,
) -> Result<()> {
    let (ok, detail) = match outcome {
        Delivery::Sent => (1, None),
        Delivery::NotConfigured(why) => (0, Some((*why).to_string())),
        Delivery::Failed(why) => (0, Some(why.clone())),
    };

    conn.execute(
        "INSERT INTO deliveries (vault, channel_kind, destination, message, ok, detail, at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        rusqlite::params![
            vault,
            channel.kind(),
            channel.redacted(),
            message_kind,
            ok,
            detail,
            now as i64
        ],
    )?;
    Ok(())
}

pub fn last_success(conn: &rusqlite::Connection, vault: &str) -> Result<Option<u64>> {
    use rusqlite::OptionalExtension;
    Ok(conn
        .query_row(
            "SELECT MAX(at) FROM deliveries WHERE vault = ?1 AND ok = 1",
            rusqlite::params![vault],
            |r| r.get::<_, Option<i64>>(0),
        )
        .optional()?
        .flatten()
        .map(|v| v as u64))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contacts_parse_into_the_right_channel() {
        assert_eq!(
            Channel::parse("mailto:alex@example.com"),
            Some(Channel::Email {
                address: "alex@example.com".into()
            })
        );
        assert_eq!(
            Channel::parse("https://ntfy.sh/my-topic"),
            Some(Channel::Webhook {
                url: "https://ntfy.sh/my-topic".into()
            })
        );

        assert_eq!(
            Channel::parse("alex@example.com"),
            Some(Channel::Email {
                address: "alex@example.com".into()
            })
        );
        assert_eq!(Channel::parse("not a contact"), None);
        assert_eq!(Channel::parse(""), None);
    }

    #[test]
    fn destinations_are_redacted_in_the_log() {
        let email = Channel::Email {
            address: "alexandra@example.com".into(),
        };
        let redacted = email.redacted();
        assert!(!redacted.contains("alexandra"), "{redacted}");
        assert!(
            redacted.contains("example.com"),
            "the domain is useful and not sensitive"
        );

        let hook = Channel::Webhook {
            url: "https://ntfy.sh/secret-topic-name".into(),
        };
        let redacted = hook.redacted();
        assert!(!redacted.contains("secret-topic-name"), "{redacted}");
        assert_eq!(redacted, "ntfy.sh");
    }

    #[test]
    fn messages_reveal_nothing_about_the_capsules() {
        let messages = [
            Message::Reminder {
                days_quiet: 40,
                resume_url: "https://r/x".into(),
            },
            Message::TrusteePrompt {
                prompt_url: "https://r/t".into(),
            },
            Message::FinalCountdown {
                hours_left: 72,
                cancel_url: "https://r/c".into(),
            },
        ];

        for message in &messages {
            let text = format!("{} {}", message.subject(), message.body());
            let lower = text.to_lowercase();
            for forbidden in ["capsule", "recipient", "vault", "secret", "key", "encrypt"] {
                assert!(
                    !lower.contains(forbidden),
                    "{:?} mentions {forbidden:?}: {text}",
                    message.subject()
                );
            }
        }
    }

    #[test]
    fn every_message_carries_its_link_and_says_what_it_does() {
        let reminder = Message::Reminder {
            days_quiet: 40,
            resume_url: "https://r/x".into(),
        };
        assert!(reminder.body().contains("https://r/x"));
        assert!(reminder.body().contains("40 days"));

        assert!(reminder.body().contains("Nothing has been sent"));

        let trustee = Message::TrusteePrompt {
            prompt_url: "https://r/t".into(),
        };
        assert!(trustee.body().contains("https://r/t"));
        assert!(trustee.body().contains("one question"));

        let final_call = Message::FinalCountdown {
            hours_left: 72,
            cancel_url: "https://r/c".into(),
        };
        assert!(final_call.body().contains("https://r/c"));
        assert!(final_call.body().contains("72 hours"));
    }

    #[test]
    fn the_trustee_prompt_gives_nothing_away() {
        let text = Message::TrusteePrompt {
            prompt_url: "https://r/t".into(),
        }
        .body();
        assert!(!text.to_lowercase().contains("died"));
        assert!(!text.to_lowercase().contains("death"));
        assert!(text.contains("you will not be told what this concerns"));
    }

    #[tokio::test]
    async fn an_unconfigured_email_channel_reports_rather_than_errors() {
        let sender = Sender {
            smtp: None,
            timeout: Duration::from_secs(1),
        };
        let outcome = sender
            .send(
                &Channel::Email {
                    address: "a@b.com".into(),
                },
                &Message::Reminder {
                    days_quiet: 1,
                    resume_url: "https://x".into(),
                },
            )
            .await;

        assert!(matches!(outcome, Delivery::NotConfigured(_)));
        assert!(!outcome.succeeded());
    }

    #[test]
    fn deliveries_are_recorded_and_the_last_success_is_findable() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE deliveries (vault TEXT, channel_kind TEXT, destination TEXT,
             message TEXT, ok INTEGER, detail TEXT, at INTEGER);",
        )
        .unwrap();

        let channel = Channel::Email {
            address: "alex@example.com".into(),
        };
        record(
            &conn,
            "v1",
            &channel,
            "reminder",
            &Delivery::Failed("smtp down".into()),
            100,
        )
        .unwrap();
        assert_eq!(last_success(&conn, "v1").unwrap(), None);

        record(&conn, "v1", &channel, "reminder", &Delivery::Sent, 200).unwrap();
        assert_eq!(last_success(&conn, "v1").unwrap(), Some(200));

        let stored: String = conn
            .query_row("SELECT destination FROM deliveries LIMIT 1", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert!(
            !stored.contains("alex@"),
            "the log kept the full address: {stored}"
        );
    }
}
