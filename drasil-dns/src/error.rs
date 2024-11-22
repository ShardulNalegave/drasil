
// ===== Imports =====
use thiserror::Error;
// ===================

#[derive(Error, Debug)]
pub enum DrasilDNSError {
  #[error("unknown error")]
  Unknown,
  #[error("couldn't parse header section")]
  CouldntParseHeader,
  #[error("too many jumps encountered in label sequence (max 5 allowed)")]
  TooManyJumpsInLabelSequence,
}