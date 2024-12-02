
pub mod config;
pub mod admin;
pub mod server;

// ===== Imports =====
#[macro_use] extern crate log;
#[macro_use] extern crate merge;
#[macro_use] extern crate clap;
#[macro_use] extern crate serde;
use anyhow::Result;
use clap::Parser;
use merge::Merge;
// ===================

#[tokio::main]
async fn main() -> Result<()> {
  pretty_env_logger::init_custom_env("DRASIL_LOG_LEVEL");

  let mut cfg = config::Config::parse();
  let cfg_file = confy::load::<config::Config>("drasil", Some("config"))?;
  cfg.merge(cfg_file);                  // Merge config file
  cfg.merge(config::Config::default()); // Merge default values

  let _ = tokio::join!(
    admin::run_admin(),
    server::udp::run_udp(),
    server::tcp::run_tcp(),
  );

  Ok(())
}
