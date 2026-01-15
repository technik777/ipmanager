use anyhow::{Context, Result};
use lettre::message::Mailbox;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

use crate::config::Config;

pub async fn send_admin_alert(cfg: &Config, subject: &str, body: &str) -> Result<()> {
    let Some(host) = cfg.smtp_host.as_deref() else {
        tracing::info!("SMTP_HOST not set; skipping email alert");
        return Ok(());
    };

    let from_addr = cfg
        .smtp_from
        .as_deref()
        .unwrap_or("ipmanager@localhost")
        .parse::<Mailbox>()
        .context("SMTP_FROM is invalid")?;

    let recipients: Vec<String> = if let Some(admin) = cfg.admin_email.as_deref() {
        vec![admin.to_string()]
    } else {
        cfg.smtp_to.clone()
    };

    if recipients.is_empty() {
        tracing::info!("ADMIN_EMAIL/SMTP_TO not set; skipping email alert");
        return Ok(());
    }

    let mut builder = Message::builder().from(from_addr).subject(subject);
    for to in &recipients {
        let mailbox = to.parse::<Mailbox>().context("SMTP_TO is invalid")?;
        builder = builder.to(mailbox);
    }
    let message = builder.body(body.to_string()).context("failed to build email")?;

    let mut builder = if cfg.smtp_use_starttls {
        AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(host)
            .context("failed to create SMTP transport")?
    } else {
        AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(host)
    };

    if let (Some(user), Some(pass)) = (cfg.smtp_username.as_deref(), cfg.smtp_password.as_deref()) {
        builder = builder.credentials(Credentials::new(user.to_string(), pass.to_string()));
    }
    if let Some(port) = cfg.smtp_port {
        builder = builder.port(port);
    }

    let transport = builder.build();
    transport
        .send(message)
        .await
        .context("failed to send email")?;
    Ok(())
}
