
pub mod config;
pub mod server;
pub mod admin;

// ===== Imports =====
#[macro_use] extern crate log;
#[macro_use] extern crate merge;
#[macro_use] extern crate clap;
#[macro_use] extern crate serde;
use std::sync::Arc;
use anyhow::{Context, Result};
use clap::Parser;
use merge::Merge;
use tokio::{signal::unix::{signal, SignalKind}, sync::{broadcast, RwLock}};
// ===================

#[tokio::main]
async fn main() -> Result<()> {
  pretty_env_logger::init_custom_env("DRASIL_LOG_LEVEL");
  let _args = config::Args::parse();

  let cfg = {
    let mut cfg: config::Config = confy::load::<config::Config>("drasil", Some("config"))
      .context("Failed to load config file")?;
    cfg.merge(config::Config::default()); // Merge default values

    Arc::new(RwLock::new(cfg))
  };

  // Broadcast channel to send shutdown signal
  let (shutdown_tx, _) = broadcast::channel::<()>(1);

  let admin_task = tokio::spawn(
    admin::run_admin(shutdown_tx.subscribe(), cfg.clone()),
  ); // Thread running admin webserver

  let udp_server_task = tokio::spawn(
    server::udp::run_udp(shutdown_tx.subscribe(), cfg.clone()),
  ); // Thread running DNS resolver (UDP)

  // On the main thread, wait for a SIGINT signal to know when to shutdown
  let mut signal_task = signal(SignalKind::interrupt())?;
  signal_task.recv().await;

  // Inform all threads
  shutdown_tx.send(())?;
  admin_task.await??;
  udp_server_task.await??;

  Ok(())
}