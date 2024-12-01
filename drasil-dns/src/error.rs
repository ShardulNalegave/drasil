
// ===== Imports =====
use thiserror::Error;
// ===================

/// Error type for Drasil-DNS
#[derive(Error, Debug)]
pub enum DrasilDNSError {
  #[error("unknown error")]
  Unknown,
  #[error("invalid packet size (expected: 512 bytes, received: {size})")]
  InvalidPacketSize { size: usize },
  #[error("too many jumps encountered in label sequence (max 5 allowed)")]
  TooManyJumpsInLabelSequence,
  #[error("label size exceeds 63 characters")]
  LabelTooLarge,
  #[error("reached the end while parsing the packet, please ensure packet data is correct")]
  EOF,
  #[error("encountered an OPT record used for eDNS. Currently, we don't have support for eDNS")]
  OPTRecordEncountered,
}