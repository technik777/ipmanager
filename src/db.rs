use std::time::Duration;

use anyhow::{Context, Result};
use bcrypt::{hash, DEFAULT_COST};
use sqlx::{postgres::PgPoolOptions, PgPool};

use crate::config::Config;

pub async fn connect(cfg: &Config) -> Result<PgPool> {
    let pool = PgPoolOptions::new()
        .max_connections(cfg.db_max_connections)
        .min_connections(cfg.db_min_connections)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&cfg.database_url)
        .await
        .context("failed to connect to postgres (check DATABASE_URL)")?;

    // Quick sanity check
    sqlx::query_scalar::<_, i32>("select 1")
        .fetch_one(&pool)
        .await
        .context("postgres ping failed")?;

    Ok(pool)
}

pub async fn ensure_initial_admin(cfg: &Config, pool: &PgPool) -> Result<()> {
    let existing: Option<String> =
        sqlx::query_scalar("select username from users where username = $1 limit 1")
            .bind(&cfg.initial_admin_user)
            .fetch_optional(pool)
            .await
            .context("failed to query existing admin user")?;

    if existing.is_some() {
        tracing::info!(user = %cfg.initial_admin_user, "initial admin already exists");
        return Ok(());
    }

    let password_hash = hash(&cfg.initial_admin_password, DEFAULT_COST)
        .context("failed to bcrypt-hash initial admin password")?;

    sqlx::query(
        "insert into users (username, password_hash, role, is_active)
         values ($1, $2, 'admin', true)",
    )
    .bind(&cfg.initial_admin_user)
    .bind(password_hash)
    .execute(pool)
    .await
    .context("failed to insert initial admin user")?;

    tracing::info!(user = %cfg.initial_admin_user, "initial admin created");
    Ok(())
}
