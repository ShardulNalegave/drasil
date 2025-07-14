
pub(crate) mod buffer;
pub mod types;

/// Provides error type for the crate
pub mod error;

/// Provides the `Header` struct
pub mod header;

/// Provides the `Question` struct
pub mod question;

/// Provides the `Record` enum
pub mod record;

/// Provides the `Packet` struct
pub mod packet;

pub use crate::{
  error::DrasilDNSError,
  types::{
    RecordType,
    RecordClass,
    dnssec::{DNSSECAlgorithm, DNSSECDigestType},
  },
  packet::{
    Packet,
    builder::PacketBuilder,
  },
  header::{
    Header,
    RequestKind,
    ResponseCode,
  },
  question::Question,
  record::{
    Record,
    edns::{EDNSOption, EDNSOptionType},
  },
};