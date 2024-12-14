
// ===== Imports =====
use std::sync::Arc;
use anyhow::Result;
use axum::{routing::get, Router};
use tokio::{net::TcpListener, sync::{broadcast::Receiver, RwLock}};
use crate::config;
// ===================

pub async fn run_admin(
  mut shutdown_rx: Receiver<()>,
  cfg: Arc<RwLock<config::Config>>,
) -> Result<()> {
  let (host, port) = {
    let cfg_read = cfg.read().await;
    let host = cfg_read.admin.host.clone()
      .expect("No HOST provided for admin");
    let port = cfg_read.admin.port
      .expect("No PORT provided for admin");
    (host, port)
  };

  let router = Router::new()
    .route("/", get(index));

  info!("Admin server listening at {}:{}", host, port);

  let lis = TcpListener::bind((host, port)).await?;
  axum::serve(lis, router)
    .with_graceful_shutdown(async move {
      let _ = shutdown_rx.recv().await;
    })
    .await?;

    info!("Admin server shut down");
  Ok(())
}

async fn index() -> &'static str {
  "Hello, Drasil!"
}