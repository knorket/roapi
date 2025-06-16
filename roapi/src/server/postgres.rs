// Wire protocol reference:
// https://www.postgresql.org/docs/current/protocol-message-formats.html
// https://beta.pgcon.org/2014/schedule/attachments/330_postgres-for-the-wire.pdf

use async_trait::async_trait;
use std::sync::Arc;

use columnq::datafusion::dataframe::DataFrame;
use columnq::datafusion::error::DataFusionError;
use convergence::engine::{Engine, Portal};
use convergence::protocol::{ErrorResponse, FieldDescription, SqlState};
use convergence::protocol_ext::DataRowBatch;
use convergence::sqlparser::ast::Statement;
use convergence_arrow::table::{record_batch_to_rows, schema_to_field_desc};
use log::info;
use snafu::{whatever, Whatever};
use tokio::net::TcpListener;

use pgwire::api::auth::{StartupHandler, CleartextPasswordAuth};
use pgwire::api::ClientInfo;
use pgwire::error::{PgWireError, PgWireResult};

use crate::config::Config;
use crate::context::RoapiContext;
use crate::server::RunnableServer;

// Comment out or remove the old hardcoded credentials
// const ROAPI_USER: &str = "roapi_user";
// const ROAPI_PASSWORD: &str = "roapi_password";

pub struct RoapiStartupHandler {
    pg_auth_enabled: Option<bool>,
    pg_auth_username: Option<String>,
    pg_auth_password: Option<String>,
}

#[async_trait]
impl StartupHandler for RoapiStartupHandler {
    async fn on_startup(
        &self,
        _client: &mut ClientInfo,
        message: &pgwire::api::msgs::startup::StartupMessage,
    ) -> PgWireResult<()> {
        // If auth is not enabled, or username/password is not configured, allow.
        if !self.pg_auth_enabled.unwrap_or(false)
            || self.pg_auth_username.is_none()
            || self.pg_auth_password.is_none()
        {
            return Ok(());
        }

        // Auth is enabled and configured, proceed with username check.
        let configured_username = self.pg_auth_username.as_ref().unwrap();
        if let Some(message_user) = message.user() {
            if message_user == configured_username {
                return Ok(());
            }
        }
        Err(PgWireError::AuthenticationFailed)
    }
}

impl CleartextPasswordAuth for RoapiStartupHandler {
    async fn check_password(&self, _user: &str, provided_pass: &str) -> PgWireResult<()> {
        // If auth is not enabled, or username/password is not configured, allow.
        // This check might seem redundant if on_startup already handled it,
        // but it's good for defense in depth, in case the client somehow
        // tries password auth directly.
        if !self.pg_auth_enabled.unwrap_or(false)
            || self.pg_auth_username.is_none()
            || self.pg_auth_password.is_none()
        {
            return Ok(());
        }

        let configured_password = self.pg_auth_password.as_ref().unwrap();
        if provided_pass == configured_password {
            Ok(())
        } else {
            Err(PgWireError::AuthenticationFailed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pgwire::api::auth::StartupHandler; // Ensure StartupHandler trait is in scope
    use pgwire::api::msgs::startup::StartupMessage;
    use pgwire::api::ClientInfo;
    use std::collections::HashMap;

    fn mock_startup_message(user: Option<&str>) -> StartupMessage {
        let mut parameters = HashMap::new();
        if let Some(u) = user {
            parameters.insert("user".to_string(), u.to_string());
        }
        StartupMessage::new(None, parameters)
    }

    fn mock_client_info() -> ClientInfo {
        // ClientInfo::new is not public, and there's no trivial default.
        // However, for these tests, _client is not used by on_startup.
        // So we can pass a "default" like structure if needed, or handle it if
        // the pgwire crate offers a testing utility for it.
        // For now, assuming it can be created or isn't strictly needed for the handler logic.
        // This might need adjustment based on pgwire's specific API for ClientInfo construction.
        // Let's assume for now we can create a dummy one or it's not vital.
        // If ClientInfo construction is complex/private, we might need to use a test double
        // or focus tests on parts of the handler that don't interact with ClientInfo.
        // For RoapiStartupHandler, _client is unused in on_startup.
        ClientInfo::new("127.0.0.1:12345".parse().unwrap(), false, None)
    }

    #[tokio::test]
    async fn auth_enabled_correct_credentials() {
        let handler = RoapiStartupHandler {
            pg_auth_enabled: Some(true),
            pg_auth_username: Some("testuser".to_string()),
            pg_auth_password: Some("testpass".to_string()),
        };
        let mut client_info = mock_client_info();
        let msg = mock_startup_message(Some("testuser"));

        assert!(handler.on_startup(&mut client_info, &msg).await.is_ok());
        assert!(handler
            .check_password("testuser", "testpass")
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn auth_enabled_incorrect_username() {
        let handler = RoapiStartupHandler {
            pg_auth_enabled: Some(true),
            pg_auth_username: Some("testuser".to_string()),
            pg_auth_password: Some("testpass".to_string()),
        };
        let mut client_info = mock_client_info();
        let msg = mock_startup_message(Some("wronguser"));

        assert!(handler.on_startup(&mut client_info, &msg).await.is_err());
        // check_password might not be called if on_startup fails, but good to test its logic independently
        assert!(handler
            .check_password("wronguser", "testpass")
            .await
            .is_ok()); // check_password itself doesn't check username
    }

    #[tokio::test]
    async fn auth_enabled_incorrect_password() {
        let handler = RoapiStartupHandler {
            pg_auth_enabled: Some(true),
            pg_auth_username: Some("testuser".to_string()),
            pg_auth_password: Some("testpass".to_string()),
        };
        let mut client_info = mock_client_info();
        let msg = mock_startup_message(Some("testuser"));

        assert!(handler.on_startup(&mut client_info, &msg).await.is_ok());
        assert!(handler
            .check_password("testuser", "wrongpass")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn auth_disabled_allows_any_user_pass() {
        let handler = RoapiStartupHandler {
            pg_auth_enabled: Some(false),
            pg_auth_username: Some("testuser".to_string()), // Configured but disabled
            pg_auth_password: Some("testpass".to_string()), // Configured but disabled
        };
        let mut client_info = mock_client_info();
        let msg_any_user = mock_startup_message(Some("any_user"));
        let msg_no_user = mock_startup_message(None);

        assert!(handler
            .on_startup(&mut client_info, &msg_any_user)
            .await
            .is_ok());
        assert!(handler
            .on_startup(&mut client_info, &msg_no_user)
            .await
            .is_ok());
        assert!(handler
            .check_password("any_user", "any_password")
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn auth_enabled_but_no_creds_configured_allows_any() {
        let handler_no_user = RoapiStartupHandler {
            pg_auth_enabled: Some(true),
            pg_auth_username: None, // Not configured
            pg_auth_password: Some("testpass".to_string()),
        };
        let handler_no_pass = RoapiStartupHandler {
            pg_auth_enabled: Some(true),
            pg_auth_username: Some("testuser".to_string()),
            pg_auth_password: None, // Not configured
        };
        let handler_no_creds = RoapiStartupHandler {
            pg_auth_enabled: Some(true),
            pg_auth_username: None,
            pg_auth_password: None,
        };

        let mut client_info = mock_client_info();
        let msg_any_user = mock_startup_message(Some("any_user"));

        // Test with username not configured
        assert!(handler_no_user
            .on_startup(&mut client_info, &msg_any_user)
            .await
            .is_ok());
        assert!(handler_no_user
            .check_password("any_user", "any_password")
            .await
            .is_ok());

        // Test with password not configured
        assert!(handler_no_pass
            .on_startup(&mut client_info, &msg_any_user)
            .await
            .is_ok());
        assert!(handler_no_pass
            .check_password("any_user", "any_password")
            .await
            .is_ok());

        // Test with no credentials configured
        assert!(handler_no_creds
            .on_startup(&mut client_info, &msg_any_user)
            .await
            .is_ok());
        assert!(handler_no_creds
            .check_password("any_user", "any_password")
            .await
            .is_ok());
    }

     #[tokio::test]
    async fn auth_not_explicitly_enabled_allows_any() {
        // This covers the case where pg_auth_enabled is None
        let handler = RoapiStartupHandler {
            pg_auth_enabled: None,
            pg_auth_username: Some("testuser".to_string()),
            pg_auth_password: Some("testpass".to_string()),
        };
        let mut client_info = mock_client_info();
        let msg_any_user = mock_startup_message(Some("any_user"));

        assert!(handler.on_startup(&mut client_info, &msg_any_user).await.is_ok());
        assert!(handler.check_password("any_user", "any_password").await.is_ok());
    }
}

fn df_err_to_sql(err: DataFusionError) -> ErrorResponse {
    ErrorResponse::error(SqlState::DataException, err.to_string())
}

/// A portal built using a logical DataFusion query plan.
pub struct DataFusionPortal {
    df: DataFrame,
}

#[async_trait]
impl Portal for DataFusionPortal {
    async fn fetch(&mut self, batch: &mut DataRowBatch) -> Result<(), ErrorResponse> {
        let arrow_batches = self.df.clone().collect().await.map_err(df_err_to_sql)?;
        for arrow_batch in arrow_batches {
            record_batch_to_rows(&arrow_batch, batch)?;
        }
        Ok(())
    }
}

pub struct RoapiContextEngine<H: RoapiContext> {
    pub ctx: Arc<H>,
}

impl<H: RoapiContext> RoapiContextEngine<H> {
    fn ignored_statement(statement: &Statement) -> bool {
        !matches!(
            statement,
            Statement::Query { .. }
                | Statement::Analyze { .. }
                | Statement::Fetch { .. }
                | Statement::ShowFunctions { .. }
                | Statement::ShowVariable { .. }
                | Statement::ShowVariables { .. }
                | Statement::ShowCollation { .. }
                | Statement::Assert { .. }
                | Statement::ExplainTable { .. }
                | Statement::Explain { .. }
                | Statement::ShowColumns { .. }
                | Statement::ShowTables { .. }
        )
    }
}

#[async_trait]
impl<H: RoapiContext> Engine for RoapiContextEngine<H> {
    type PortalType = DataFusionPortal;

    async fn prepare(
        &mut self,
        statement: &Statement,
    ) -> Result<Vec<FieldDescription>, ErrorResponse> {
        if RoapiContextEngine::<H>::ignored_statement(statement) {
            return Ok(vec![]);
        }
        let query = statement.to_string();
        info!("preparing query: {}", &query);
        let df = self.ctx.sql_to_df(&query).await.map_err(df_err_to_sql)?;
        schema_to_field_desc(&df.schema().clone().into())
    }

    async fn create_portal(
        &mut self,
        statement: &Statement,
    ) -> Result<Self::PortalType, ErrorResponse> {
        if RoapiContextEngine::<H>::ignored_statement(statement) {
            Ok(DataFusionPortal {
                df: self
                    .ctx
                    .sql_to_df("SELECT 1 WHERE 1 = 2")
                    .await
                    .map_err(df_err_to_sql)?,
            })
        } else {
            let query = statement.to_string();
            let df = self.ctx.sql_to_df(&query).await.map_err(df_err_to_sql)?;
            Ok(DataFusionPortal { df })
        }
    }
}

pub struct PostgresServer<H: RoapiContext> {
    pub ctx: Arc<H>,
    pub addr: std::net::SocketAddr,
    pub listener: TcpListener,
    // Store config for auth handler
    pub config: Arc<Config>,
}

impl<H: RoapiContext> PostgresServer<H> {
    pub async fn new(ctx: Arc<H>, config: Arc<Config>, default_host: String) -> Self {
        let default_addr = format!("{default_host}:5432");

        let addr = config
            .addr
            .postgres
            .clone()
            .unwrap_or_else(|| default_addr.to_string());

        let listener = TcpListener::bind(addr)
            .await
            .expect("Failed to bind address for Postgres server");
        Self {
            ctx,
            addr: listener
                .local_addr()
                .expect("Failed to get address from listener"),
            listener,
            config,
        }
    }
}

#[async_trait]
impl<H: RoapiContext> RunnableServer for PostgresServer<H> {
    fn addr(&self) -> std::net::SocketAddr {
        self.addr
    }

    async fn run(&self) -> Result<(), Whatever> {
        use convergence::connection::Connection;

        loop {
            let (stream, _) = whatever!(
                self.listener.accept().await,
                "Failed to create postgres TCP listener"
            );
            let engine = RoapiContextEngine {
                ctx: self.ctx.clone(),
            };
            let engine = RoapiContextEngine {
                ctx: self.ctx.clone(),
            };
            let handler_config = self.config.clone();
            tokio::spawn(async move {
                let authenticator = Arc::new(RoapiStartupHandler {
                    pg_auth_enabled: handler_config.pg_auth_enabled,
                    pg_auth_username: handler_config.pg_auth_username.clone(),
                    pg_auth_password: handler_config.pg_auth_password.clone(),
                });
                let mut conn = Connection::new(engine).with_authenticator(authenticator);
                conn.run(stream).await.unwrap();
            });
        }
    }
}
