
pub mod config;
pub mod server;
pub mod admin;
pub mod utils;

// ===== Imports =====
#[macro_use] extern crate log;
#[macro_use] extern crate merge;
#[macro_use] extern crate clap;
#[macro_use] extern crate serde;
use anyhow::Result;
use clap::Parser;
use merge::Merge;
use tokio::{signal::unix::{signal, SignalKind}, sync::broadcast};
// ===================

#[tokio::main]
async fn main() -> Result<()> {
  pretty_env_logger::init_custom_env("DRASIL_LOG_LEVEL");

  let _args = config::Args::parse();

  let mut cfg: config::Config = confy::load::<config::Config>("drasil", Some("config"))?;
  cfg.merge(config::Config::default()); // Merge default values

  let (
    close_broadcast_tx,
    close_broadcast_rx,
  ) = broadcast::channel::<bool>(1);

  let _admin_task = tokio::spawn(admin::run_admin());
  let _udp_server_task = tokio::spawn(server::udp::run_udp());

  let mut signal_task = signal(SignalKind::interrupt())?;
  signal_task.recv().await;

  close_broadcast_tx.send(true)?;
  Ok(())
}