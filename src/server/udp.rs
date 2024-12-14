
// ===== Imports =====
use std::{sync::{atomic::{AtomicBool, Ordering}, Arc}, time::Duration};
use anyhow::Result;
use tokio::{net::UdpSocket, sync::{broadcast::Receiver, RwLock}, time::timeout};
use crate::config;
// ===================

pub async fn run_udp(
  mut shutdown_rx: Receiver<()>,
  cfg: Arc<RwLock<config::Config>>,
) -> Result<()> {
  let (host, port) = {
    let cfg_read = cfg.read().await;
    let host = cfg_read.resolver.host.clone()
      .expect("No HOST provided for resolver");
    let port = cfg_read.resolver.port
      .expect("No PORT provided for resolver");
    (host, port)
  };

  info!("UDP server listening at {}:{}", host, port);
  let sock: UdpSocket = UdpSocket::bind((host, port)).await?;

  let shutdown_flag = Arc::new(AtomicBool::new(false));
  let shutdown_flag_clone = shutdown_flag.clone();

  tokio::spawn(async move {
    let _ = shutdown_rx.recv().await;
    shutdown_flag_clone.store(true, Ordering::SeqCst);
  });

  while !shutdown_flag.load(Ordering::SeqCst) {
    let mut buff = [0; 512];
    match timeout(Duration::from_secs(5), sock.recv_from(&mut buff)).await {
      Err(_) => {
        continue;
      },

      Ok(Err(_)) => {
        error!("Error while reading from UDP socket");
        continue;
      },

      Ok(Ok((_len, _addr))) => {},
    }

    let packet = drasil_dns::Packet::parse(&buff)?;
    println!("{:#?}", packet);
  }

  info!("UDP server was gracefully shut down.");
  Ok(())
}