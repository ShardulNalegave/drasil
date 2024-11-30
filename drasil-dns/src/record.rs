
// ===== Imports =====
use std::net::{Ipv4Addr, Ipv6Addr};
use crate::{buffer::Buffer, common::{RecordClass, RecordType}, error::DrasilDNSError};
// ===================

/// # Record
/// Enum for representing various kinds of DNS records that exist.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Record {
  Unknown {
    domain: Vec<String>,
    ttl: u32,
    len: u32,
    record_type: u16,
    class: RecordClass,
  }, // 0
  A {
    domain: Vec<String>,
    addr: Ipv4Addr,
    ttl: u32,
    class: RecordClass,
  }, // 1
  NS {
    domain: Vec<String>,
    host: Vec<String>,
    ttl: u32,
    class: RecordClass,
  }, // 2
  CNAME {
    domain: Vec<String>,
    host: Vec<String>,
    ttl: u32,
    class: RecordClass,
  }, // 5
  MX {
    domain: Vec<String>,
    priority: u16,
    host: Vec<String>,
    ttl: u32,
    class: RecordClass,
  }, // 15
  AAAA {
    domain: Vec<String>,
    addr: Ipv6Addr,
    ttl: u32,
    class: RecordClass,
  }, // 28
}

impl Record {
  pub fn parse(buff: &mut Buffer) -> Result<Self, DrasilDNSError> {
    let domain = buff.read_labels()?;
    let record_type = RecordType::from(buff.get_u16()?);
    let class = RecordClass::from(buff.get_u16()?);
    let ttl = buff.get_u32()?;
    let len = buff.get_u32()?;

    Ok(match record_type {
      RecordType::Unknown(v) => Self::Unknown {
        domain,
        ttl,
        len,
        record_type: v,
        class,
      },
      RecordType::A => {
        let addr = Ipv4Addr::from_bits(buff.get_u32()?);
        Self::A { domain, class, ttl, addr }
      },
      RecordType::NS => {
        let host = buff.read_labels()?;
        Self::NS { domain, host, ttl, class }
      },
      RecordType::CNAME => {
        let host = buff.read_labels()?;
        Self::NS { domain, host, ttl, class }
      },
      RecordType::MX => {
        let priority = buff.get_u16()?;
        let host = buff.read_labels()?;
        Self::MX { domain, priority, host, ttl, class }
      },
      RecordType::AAAA => {
        let addr = Ipv6Addr::from_bits(buff.get_u128()?);
        Self::AAAA { domain, class, ttl, addr }
      },
    })
  }
}
