
pub mod dnssec;

// ===== Imports =====
use std::collections::HashSet;
use crate::{buffer::Buffer, error::DrasilDNSError};
// ===================

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u16)]
pub enum RecordType {
  Unknown(u16),
  A = 1,
  NS = 2,
  CNAME = 5,
  MX = 15,
  AAAA = 28,
  OPT = 41, // used for eDNS
  DS = 43,
  RRSIG = 46,
  NSEC = 47,
  DNSKEY = 48,
  NSEC3 = 50,
  NSEC3PARAM = 51,
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
      Self::DS => 43,
      Self::RRSIG => 46,
      Self::NSEC => 47,
      Self::DNSKEY => 48,
      Self::NSEC3 => 50,
      Self::NSEC3PARAM => 51,
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
      43 => Self::DS,
      46 => Self::RRSIG,
      47 => Self::NSEC,
      48 => Self::DNSKEY,
      50 => Self::NSEC3,
      51 => Self::NSEC3PARAM,
      v => Self::Unknown(v),
    }
  }
}

impl RecordType {
  pub fn is_unknown(&self) -> bool {
    if let Self::Unknown(_) = self {
      return true;
    }
    return false;
  }

  pub(crate) fn parse_type_bitmaps(mut buff: Buffer) -> Result<HashSet<RecordType>, DrasilDNSError> {
    let mut recs = HashSet::new();

    while !buff.is_eof() {
      let window = buff.read_u8()?;
      let len = buff.read_u8()?;
      let bitmap = buff.read_bytes(len as usize)?;
      let window_offset = window as u16 * 256;

      for (byte_offset, &byte) in bitmap.iter().enumerate() {
        if byte == 0 {
          continue;
        }

        let byte_offset = byte_offset as u16 * 8;
        let mut pos = 1;

        while pos <= 8 {
          if (byte >> (8 - pos)) & 0b1 == 0b1 {
            let rec: RecordType = RecordType::from(window_offset + byte_offset + pos);
            if !rec.is_unknown() {
              recs.insert(rec);
            }
          }
          pos += 1;
        }
      }
    }

    Ok(recs)
  }

  pub(crate) fn into_type_bitmaps(set: &HashSet<RecordType>) -> Result<Buffer, DrasilDNSError> {
    let mut buff = Buffer::with_capacity(0);
    buff.set_expandable(true);

    let mut windows: Vec<Vec<u8>> = vec![vec![]];

    for &rec in set {
      let rec_val: u16 = rec.into();
      let window = ((rec_val - 1) / 256) as usize;
      let offset = ((rec_val - 1) % 256) as usize;
      let byte_offset = offset / 8;
      let byte_pos = offset % 8;

      if windows.get(window).is_none() {
        windows.push(vec![]);
      }

      if windows[window].get(byte_offset).is_none() {
        windows[window].resize(byte_offset + 1, 0);
      }

      windows[window][byte_offset] |= 1 << (7 - byte_pos);
    }

    for (window, bitmap) in windows.iter().enumerate() {
      if !bitmap.is_empty() {
        buff.write_u8(window as u8)?;
        buff.write_u8(bitmap.len() as u8)?;
        buff.write_bytes(&bitmap)?;
      }
    }

    Ok(buff)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn record_type_set_to_type_bitmaps() {
    let mut set = HashSet::new();
    set.insert(RecordType::A);
    set.insert(RecordType::CNAME);
    set.insert(RecordType::NSEC3PARAM);

    let ans: Vec<u8> = vec![
      0, 7, 0b1000_1000, 0, 0, 0, 0, 0, 0b00100000,
    ];

    let buff = RecordType::into_type_bitmaps(&set).expect("Failed at into_type_bitmaps");
    let buff_bytes: Vec<u8> = buff.into();
    assert_eq!(buff_bytes, ans, "RecordType set to Type-Bitmaps conversion failed");
  }

  #[test]
  fn type_bitmaps_to_record_type_set() {
    let data = [
      0, 1, 0b1000_1000,
    ];

    let buff: Buffer = data[..].into();
    let set = RecordType::parse_type_bitmaps(buff).expect("Failed at parse_type_bitmaps");

    assert!(set.contains(&RecordType::A), "set doesn't contain type A which is set");
    assert!(set.contains(&RecordType::CNAME), "set doesn't contain type CNAME which is set");
  }
}