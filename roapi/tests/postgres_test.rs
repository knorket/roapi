mod helpers;

use tokio_postgres::NoTls;

#[tokio::test]
async fn test_postgres_count() {
    let json_table = helpers::get_spacex_table();
    let (app, _) = helpers::test_api_app_with_tables(vec![json_table]).await;
    let addr = app.postgres_addr();
    tokio::spawn(app.run_until_stopped());

    let conn_str = format!("host={} port={}", addr.ip(), addr.port());
    let (client, connection) = tokio_postgres::connect(&conn_str, NoTls).await.unwrap();

    // The connection object performs the actual communication with the database,
    // so spawn it off to run on its own.
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("connection error: {e}");
        }
    });

    let rows = client
        .simple_query("SELECT COUNT(*) FROM spacex_launches")
        .await
        .unwrap();

    match &rows[0] {
        tokio_postgres::SimpleQueryMessage::RowDescription(_) => {}
        _ => {
            panic!("expect row description from query result.");
        }
    }

    match &rows[1] {
        tokio_postgres::SimpleQueryMessage::Row(row) => {
            assert_eq!(row.get(0).unwrap(), "132");
        }
        _ => {
            panic!("expect row from query result.");
        }
    }

    match &rows[2] {
        tokio_postgres::SimpleQueryMessage::CommandComplete(modified) => {
            assert_eq!(modified, &1);
        }
        _ => {
            panic!("expect command complete from query result.");
        }
    }

    assert_eq!(rows.len(), 3);
}

// --- Authentication Tests ---

// Helper to create a Config for auth tests
fn auth_test_config(
    pg_auth_enabled: Option<bool>,
    pg_auth_username: Option<String>,
    pg_auth_password: Option<String>,
    tables: Vec<roapi::config::TableSource>,
) -> roapi::config::Config {
    roapi::config::Config {
        tables,
        pg_auth_enabled,
        pg_auth_username,
        pg_auth_password,
        ..Default::default()
    }
}

async fn attempt_pg_connection(
    addr: std::net::SocketAddr,
    user: Option<&str>,
    pass: Option<&str>,
) -> Result<(tokio_postgres::Client, tokio_postgres::Connection<tokio_postgres::Socket, tokio_postgres::tls::NoTlsStream>), tokio_postgres::Error>
{
    let mut conn_str_parts = vec![
        format!("host={}", addr.ip()),
        format!("port={}", addr.port()),
    ];
    if let Some(u) = user {
        conn_str_parts.push(format!("user={}", u));
    }
    if let Some(p) = pass {
        conn_str_parts.push(format!("password={}", p));
    }
    // Add a default dbname if not specified, as some drivers/servers require it.
    if !conn_str_parts.iter().any(|s| s.starts_with("dbname=")) {
        conn_str_parts.push("dbname=roapi_test".to_string());
    }

    let conn_str = conn_str_parts.join(" ");
    tokio_postgres::connect(&conn_str, NoTls).await
}

#[tokio::test]
async fn test_postgres_auth_enabled_correct_credentials() {
    let table = helpers::get_spacex_table();
    let config = auth_test_config(
        Some(true),
        Some("roapi_user".to_string()),
        Some("roapi_pass".to_string()),
        vec![table],
    );
    let (app, _) = helpers::test_api_app_with_config(config).await; // Assuming this helper exists or can be made
    let addr = app.postgres_addr();
    tokio::spawn(app.run_until_stopped());

    let result = attempt_pg_connection(addr, Some("roapi_user"), Some("roapi_pass")).await;
    assert!(result.is_ok(), "Connection failed with correct credentials: {:?}", result.err());
    if let Ok((client, connection)) = result {
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                eprintln!("connection error: {e}");
            }
        });
        // Optional: Perform a simple query to ensure connection is fully established
        assert!(client.simple_query("SELECT 1").await.is_ok());
    }
}

#[tokio::test]
async fn test_postgres_auth_enabled_incorrect_password() {
    let table = helpers::get_spacex_table();
    let config = auth_test_config(
        Some(true),
        Some("roapi_user".to_string()),
        Some("roapi_pass".to_string()),
        vec![table],
    );
    let (app, _) = helpers::test_api_app_with_config(config).await;
    let addr = app.postgres_addr();
    tokio::spawn(app.run_until_stopped());

    let result = attempt_pg_connection(addr, Some("roapi_user"), Some("wrong_pass")).await;
    assert!(result.is_err(), "Connection succeeded with incorrect password");
}

#[tokio::test]
async fn test_postgres_auth_enabled_incorrect_username() {
    let table = helpers::get_spacex_table();
    let config = auth_test_config(
        Some(true),
        Some("roapi_user".to_string()),
        Some("roapi_pass".to_string()),
        vec![table],
    );
    let (app, _) = helpers::test_api_app_with_config(config).await;
    let addr = app.postgres_addr();
    tokio::spawn(app.run_until_stopped());

    let result = attempt_pg_connection(addr, Some("wrong_user"), Some("roapi_pass")).await;
    assert!(result.is_err(), "Connection succeeded with incorrect username");
}

#[tokio::test]
async fn test_postgres_auth_enabled_no_credentials_provided() {
    let table = helpers::get_spacex_table();
    let config = auth_test_config(
        Some(true),
        Some("roapi_user".to_string()),
        Some("roapi_pass".to_string()),
        vec![table],
    );
    let (app, _) = helpers::test_api_app_with_config(config).await;
    let addr = app.postgres_addr();
    tokio::spawn(app.run_until_stopped());

    let result = attempt_pg_connection(addr, None, None).await;
    assert!(result.is_err(), "Connection succeeded with no credentials when auth is enabled");
}

#[tokio::test]
async fn test_postgres_auth_disabled_no_credentials() {
    let table = helpers::get_spacex_table();
    let config = auth_test_config(
        Some(false), // Auth disabled
        Some("roapi_user".to_string()), // Credentials configured but auth disabled
        Some("roapi_pass".to_string()),
        vec![table],
    );
    let (app, _) = helpers::test_api_app_with_config(config).await;
    let addr = app.postgres_addr();
    tokio::spawn(app.run_until_stopped());

    let result = attempt_pg_connection(addr, None, None).await;
    assert!(result.is_ok(), "Connection failed with auth disabled and no credentials: {:?}", result.err());
     if let Ok((client, connection)) = result {
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                eprintln!("connection error: {e}");
            }
        });
        assert!(client.simple_query("SELECT 1").await.is_ok());
    }
}

#[tokio::test]
async fn test_postgres_auth_not_set_no_credentials() {
    // Test default behavior: if pg_auth_enabled is None, auth should be off
    let table = helpers::get_spacex_table();
     let config = auth_test_config(
        None, // Auth not explicitly set
        None, // No username configured
        None, // No password configured
        vec![table],
    );
    let (app, _) = helpers::test_api_app_with_config(config).await;
    let addr = app.postgres_addr();
    tokio::spawn(app.run_until_stopped());

    let result = attempt_pg_connection(addr, None, None).await;
     assert!(result.is_ok(), "Connection failed with auth not set and no credentials: {:?}", result.err());
    if let Ok((client, connection)) = result {
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                eprintln!("connection error: {e}");
            }
        });
        assert!(client.simple_query("SELECT 1").await.is_ok());
    }
}
