
// ===== Imports =====
use anyhow::Result;
use tokio::sync::broadcast::Receiver;
// ===================

pub async fn retry_task_till_close_requested(
  mut close_broadcast: Receiver<bool>,
) -> Result<()> {
  tokio::select! {
    _ = close_broadcast.recv() => {
      Ok(())
    }
  }
}