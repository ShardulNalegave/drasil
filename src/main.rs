
pub mod config;
pub mod constants;

// ===== Imports =====
#[macro_use] extern crate log;
#[macro_use] extern crate merge;
#[macro_use] extern crate clap;
#[macro_use] extern crate serde;
use anyhow::Result;
use clap::Parser;
use merge::Merge;
use tokio::net::UdpSocket;
// ===================

#[tokio::main]
async fn main() -> Result<()> {
  pretty_env_logger::init_custom_env("DRASIL_LOG_LEVEL");

  let mut cfg = config::Config::parse();
  let cfg_file = confy::load::<config::Config>("drasil", Some("config"))?;
  cfg.merge(cfg_file);                  // Merge config file
  cfg.merge(config::Config::default()); // Merge default values

  let host = cfg.host.expect("No host address provided");
  let port = cfg.port.expect("No port provided");

  info!("Listening at {}:{}", host, port);

  let lis = UdpSocket::bind((host, port)).await?;
  loop {
    let mut buff = [0; 512];
    let (_len, _from) = lis.recv_from(&mut buff).await?;
    let packet = drasil_dns::packet::Packet::parse(buff);
    println!("{:#?}", packet);
  }
}
