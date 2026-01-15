use anyhow::{Context, Result};
use lettre::message::Mailbox;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, Message, Tokio1Executor};

use crate::config::Config;

pub async fn send_admin_alert(cfg: &Config, subject: &str, body: &str) -> Result<()> {
    let Some(host) = cfg.smtp_host.as_deref() else {
        tracing::info!("SMTP_HOST not set; skipping email alert");
        return Ok(());
    };

    if cfg.smtp_to.is_empty() {
        tracing::info!("SMTP_TO not set; skipping email alert");
        return Ok(());
    }

    let from_addr = cfg
        .smtp_from
        .as_deref()
        .unwrap_or("ipmanager@localhost")
        .parse::<Mailbox>()
        .context("SMTP_FROM is invalid")?;

    let mut builder = Message::builder().from(from_addr).subject(subject);
    for to in &cfg.smtp_to {
        let mailbox = to.parse::<Mailbox>().context("SMTP_TO is invalid")?;
        builder = builder.to(mailbox);
    }
    let message = builder.body(body.to_string()).context("failed to build email")?;

    let mut transport = if cfg.smtp_use_starttls {
        AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(host)
            .context("failed to create SMTP transport")?
    } else {
        AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(host).build()
    };

    if let (Some(user), Some(pass)) = (cfg.smtp_username.as_deref(), cfg.smtp_password.as_deref()) {
        transport = transport.credentials(Credentials::new(user.to_string(), pass.to_string()));
    }
    if let Some(port) = cfg.smtp_port {
        transport = transport.port(port);
    }

    transport
        .send(message)
        .await
        .context("failed to send email")?;
    Ok(())
}
