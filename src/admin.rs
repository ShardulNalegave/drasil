
// ===== Imports =====
use anyhow::Result;
use axum::{routing::get, Router};
use tokio::net::TcpListener;
// ===================

pub async fn run_admin() -> Result<()> {
  let router = Router::new()
    .route("/", get(root));

  let lis = TcpListener::bind("0.0.0.0:7000").await?;
  axum::serve(lis, router).await?;

  Ok(())
}

async fn root() -> &'static str {
  "Hello, Drasil!"
}