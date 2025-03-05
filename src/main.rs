
pub mod config;
pub mod cache;

// ===== Imports =====
#[macro_use] extern crate log;
#[macro_use] extern crate clap;
#[macro_use] extern crate serde;
use anyhow::{Context, Result};
use clap::Parser;
use tokio::net::UdpSocket;
// ===================

#[tokio::main]
async fn main() -> Result<()> {
  pretty_env_logger::init_custom_env("DRASIL_LOG_LEVEL");
  let _args = config::Args::parse();

  // let cfg: config::Config = confy::load::<config::Config>("drasil", Some("config"))
  //   .context("Failed to load config file")?;

  // info!("Listening at {}:{}", cfg.resolver.host, cfg.resolver.port);
  // let sock = UdpSocket::bind((cfg.resolver.host, cfg.resolver.port)).await?;

  // loop {
  //   let mut buff = [0; 512];
  //   let (_len, from) = sock.recv_from(&mut buff).await?;
  //   let mut packet = drasil_dns::packet::Packet::parse(&buff)?;
  //   println!("{:#?}", packet);

  //   packet.answers.push(drasil_dns::Record::A {
  //     domain: vec!["google".to_string(), "com".to_string()],
  //     addr: "1.2.3.4".parse()?,
  //     ttl: 60,
  //     class: drasil_dns::RecordClass::IN,
  //   });

  //   packet.header.is_recursion_available = true;
  //   packet.header.request_kind = drasil_dns::RequestKind::Response;
  //   packet.header.answer_count = 1;

  //   println!("{:#?}", packet);

  //   let byts = packet.to_bytes()?;
  //   sock.send_to(&byts, from).await?;
  // }

  let server = ("8.8.8.8", 53);
  let socket = UdpSocket::bind(("0.0.0.0", 43210)).await?;

  let packet = drasil_dns::PacketBuilder::new(12345)
    .recursion_desired()
    .add_question(drasil_dns::Question {
      name: vec!["google".to_string(), "com".to_string()],
      record_type: drasil_dns::RecordType::A,
      record_class: drasil_dns::RecordClass::IN,
    }).build();

  socket.send_to(&packet.to_bytes()?, server).await?;

  let mut buff = [0; 512];
  let (_len, _from) = socket.recv_from(&mut buff).await?;
  let res_packet = drasil_dns::packet::Packet::parse(&buff)?;

  println!("{:#?}", res_packet);
  Ok(())
}