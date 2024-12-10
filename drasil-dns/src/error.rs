
// ===== Imports =====
use thiserror::Error;
// ===================

/// Error type for Drasil-DNS
#[derive(Error, Debug)]
pub enum DrasilDNSError {
  #[error("unknown error")]
  Unknown,
  #[error("too many jumps encountered in label sequence (max 5 allowed)")]
  TooManyJumpsInLabelSequence,
  #[error("label size exceeds 63 characters (size: {size})")]
  LabelTooLarge { size: u8 },
  #[error("reached the end while parsing the packet, please ensure packet data is correct")]
  EOF,
  #[error("invalid source netmask provided (family: {family}, max: {max}, provided: {provided})")]
  InvalidSourceNetmask { family: u16, max: u8, provided: u8 },
  #[error("invalid scope netmask provided (family: {family}, max: {max}, provided: {provided})")]
  InvalidScopeNetmask { family: u16, max: u8, provided: u8 },
  #[error("unknown network family (value: {family})")]
  InvalidNetworkFamily { family: u16 },
  #[error("invalid EDNS(0) option length (option-type: {option_type}, size: {size})")]
  InvalidEDNSOptionLength { option_type: u16, size: u16 },
  #[error("invalid data: {msg}")]
  InvalidData { msg: String },
}