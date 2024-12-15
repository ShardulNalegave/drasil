
// ===== Imports =====
use std::{sync::{atomic::{AtomicBool, Ordering}, Arc}, time::Duration};
use anyhow::Result;
use tokio::{net::UdpSocket, sync::{broadcast::Receiver, RwLock}, time::{self, timeout}};
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

  info!("Starting UDP server at {}:{}", host, port);
  let sock = get_udp_socket_with_retries_and_delay(&host, port, 5, Duration::from_secs(2)).await;
  if let None = sock {
    error!("Failed to create UDP socket");
  } else if let Some(sock) = sock {
    info!("UDP server running");

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
  }

  Ok(())
}

async fn get_udp_socket_with_retries_and_delay(host: &str, port: u16, max_retries: u8, delay: Duration) -> Option<UdpSocket> {
  let mut try_num = 0;
  while try_num <= max_retries {
    if try_num != 0 {
      info!("Retrying creation of UDP socket ({}/{})", try_num, max_retries);
    }

    match UdpSocket::bind((host, port)).await {
      Err(e) => {
        error!("Error while creating the UDP socket:\n{}", e);
        try_num += 1;
      },
      Ok(s) => return Some(s),
    }

    time::sleep(delay).await;
  }

  None
}