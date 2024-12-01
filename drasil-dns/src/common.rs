
/// # Record Class
/// Enum representing record class value in records and questions
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u16)]
pub enum RecordClass {
  Unknown(u16),
  IN = 1,
}

impl Into<u16> for RecordClass {
  fn into(self) -> u16 {
    match self {
      Self::IN => 1,
      Self::Unknown(v) => v,
    }
  }
}

impl From<u16> for RecordClass {
  fn from(value: u16) -> Self {
    match value {
      1 => Self::IN,
      v => Self::Unknown(v),
    }
  }
}

/// # Record Type
/// Enum representing record type value in records and questions
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u16)]
pub enum RecordType {
  Unknown(u16),
  A = 1,
  NS = 2,
  CNAME = 5,
  MX = 15,
  AAAA = 28,
  OPT = 41, // used for eDNS
}

impl Into<u16> for RecordType {
  fn into(self) -> u16 {
    match self {
      Self::A => 1,
      Self::NS => 2,
      Self::CNAME => 5,
      Self::MX => 15,
      Self::AAAA => 28,
      Self::OPT => 41,
      Self::Unknown(v) => v,
    }
  }
}

impl From<u16> for RecordType {
  fn from(value: u16) -> Self {
    match value {
      1 => Self::A,
      2 => Self::NS,
      5 => Self::CNAME,
      15 => Self::MX,
      28 => Self::AAAA,
      41 => Self::OPT,
      v => Self::Unknown(v),
    }
  }
}