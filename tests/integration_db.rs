use sqlx::migrate::Migrator;
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row};
use uuid::Uuid;

static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

async fn test_pool() -> anyhow::Result<Option<PgPool>> {
    let url = match std::env::var("TEST_DATABASE_URL") {
        Ok(v) if !v.trim().is_empty() => v,
        _ => return Ok(None),
    };

    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await?;

    MIGRATOR.run(&pool).await?;
    Ok(Some(pool))
}

#[tokio::test]
async fn host_duplicate_is_rejected() -> anyhow::Result<()> {
    let Some(pool) = test_pool().await? else {
        eprintln!("skipping integration test: TEST_DATABASE_URL not set");
        return Ok(());
    };

    let mut tx = pool.begin().await?;

    let subnet_id: Uuid =
        sqlx::query("insert into subnets (name, cidr) values ($1, $2) returning id")
            .bind("s-integration")
            .bind("192.0.2.0/24")
            .map(|row: sqlx::postgres::PgRow| row.get(0))
            .fetch_one(&mut *tx)
            .await?;

    sqlx::query("insert into hosts (hostname, ip, mac, subnet_id) values ($1, $2, $3, $4)")
        .bind("host-a")
        .bind("192.0.2.10")
        .bind("aa:bb:cc:dd:ee:01")
        .bind(subnet_id)
        .execute(&mut *tx)
        .await?;

    let err =
        sqlx::query("insert into hosts (hostname, ip, mac, subnet_id) values ($1, $2, $3, $4)")
            .bind("host-a") // duplicate hostname
            .bind("192.0.2.11")
            .bind("aa:bb:cc:dd:ee:02")
            .bind(subnet_id)
            .execute(&mut *tx)
            .await
            .expect_err("duplicate hostname should fail");

    let code = err
        .as_database_error()
        .and_then(|e| e.code())
        .map(|c| c.as_ref().to_string());
    assert_eq!(code.as_deref(), Some("23505"));

    tx.rollback().await?;
    Ok(())
}

#[tokio::test]
async fn host_invalid_subnet_is_rejected() -> anyhow::Result<()> {
    let Some(pool) = test_pool().await? else {
        eprintln!("skipping integration test: TEST_DATABASE_URL not set");
        return Ok(());
    };

    let mut tx = pool.begin().await?;

    let bogus_subnet = Uuid::new_v4();
    let err =
        sqlx::query("insert into hosts (hostname, ip, mac, subnet_id) values ($1, $2, $3, $4)")
            .bind("host-bad-subnet")
            .bind("192.0.2.50")
            .bind("aa:bb:cc:dd:ee:03")
            .bind(bogus_subnet)
            .execute(&mut *tx)
            .await
            .expect_err("FK violation expected for missing subnet");

    let code = err
        .as_database_error()
        .and_then(|e| e.code())
        .map(|c| c.as_ref().to_string());
    assert_eq!(code.as_deref(), Some("23503")); // foreign_key_violation

    tx.rollback().await?;
    Ok(())
}
