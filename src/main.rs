
pub mod config;

// ===== Imports =====
#[macro_use] extern crate log;
#[macro_use] extern crate merge;
#[macro_use] extern crate clap;
#[macro_use] extern crate serde;
use anyhow::{Context, Result};
use clap::Parser;
use merge::Merge;
// ===================

#[tokio::main]
async fn main() -> Result<()> {
  pretty_env_logger::init_custom_env("DRASIL_LOG_LEVEL");
  let _args = config::Args::parse();

  let _cfg: config::Config = {
    let mut cfg: config::Config = confy::load::<config::Config>("drasil", Some("config"))
      .context("Failed to load config file")?;
    cfg.merge(config::Config::default()); // Merge default values
    cfg
  };

  Ok(())
}