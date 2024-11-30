
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
    data: Vec<u8>,
  }, // 0

  /// `A` record maps domain names to IPv4 addresses
  A {
    domain: Vec<String>,
    addr: Ipv4Addr,
    ttl: u32,
    class: RecordClass,
  }, // 1

  /// `NS` record tells which nameserver is responsible for the asked domain
  NS {
    domain: Vec<String>,
    host: Vec<String>,
    ttl: u32,
    class: RecordClass,
  }, // 2

  /// `CNAME` record maps one domain name to another one
  CNAME {
    domain: Vec<String>,
    host: Vec<String>,
    ttl: u32,
    class: RecordClass,
  }, // 5

  /// `MX` (Mail Exchange) record specifies where to deliver emails for a specific domain
  MX {
    domain: Vec<String>,
    priority: u16,
    host: Vec<String>,
    ttl: u32,
    class: RecordClass,
  }, // 15

  /// `AAAA` record maps domains to IPv6 addresses
  AAAA {
    domain: Vec<String>,
    addr: Ipv6Addr,
    ttl: u32,
    class: RecordClass,
  }, // 28
}

impl Record {
  pub(crate) fn parse(buff: &mut Buffer) -> Result<Self, DrasilDNSError> {
    let domain = buff.read_labels()?;
    let record_type = RecordType::from(buff.get_u16()?);
    let class = RecordClass::from(buff.get_u16()?);
    let ttl = buff.get_u32()?;
    let len = buff.get_u32()?;

    Ok(match record_type {
      RecordType::Unknown(v) => {
        let data = buff.get_range(buff.get_pos(), len as usize)?;
        Self::Unknown {
          domain,
          ttl,
          len,
          record_type: v,
          class,
          data: data.to_vec(),
        }
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

  pub(crate) fn write_bytes(&self, buff: &mut Buffer) -> Result<(), DrasilDNSError> {
    match self {
      Record::Unknown {
        domain,
        ttl,
        len,
        record_type,
        class,
        data,
      } => {
        buff.write_labels(domain)?;
        buff.write_u16(*record_type)?;
        buff.write_u16((*class).into())?;
        buff.write_u32(*ttl)?;
        buff.write_u32(*len)?;
        buff.write_vec(data)?;
      },

      Record::A {
        domain,
        addr,
        ttl,
        class,
      } => {
        buff.write_labels(domain)?;
        buff.write_u16(RecordType::A.into())?;
        buff.write_u16((*class).into())?;
        buff.write_u32(*ttl)?;
        buff.write_u16(4)?;
        buff.write_u32(addr.to_bits())?;
      },

      Record::NS {
        domain,
        host,
        ttl,
        class,
      } => {
        buff.write_labels(domain)?;
        buff.write_u16(RecordType::NS.into())?;
        buff.write_u16((*class).into())?;
        buff.write_u32(*ttl)?;

        let pos = buff.get_pos();
        buff.write_u16(0)?;

        buff.write_labels(host)?;

        buff.set_u16(pos, (buff.get_pos() - (pos + 2)) as u16)?;
      },

      Record::CNAME {
        domain,
        host,
        ttl,
        class,
      } => {
        buff.write_labels(domain)?;
        buff.write_u16(RecordType::CNAME.into())?;
        buff.write_u16((*class).into())?;
        buff.write_u32(*ttl)?;
        
        let pos = buff.get_pos();
        buff.write_u16(0)?;

        buff.write_labels(host)?;

        buff.set_u16(pos, (buff.get_pos() - (pos + 2)) as u16)?;
      },

      Record::MX {
        domain,
        priority,
        host,
        ttl,
        class,
      } => {
        buff.write_labels(domain)?;
        buff.write_u16(RecordType::MX.into())?;
        buff.write_u16((*class).into())?;
        buff.write_u32(*ttl)?;
        
        let pos = buff.get_pos();
        buff.write_u16(0)?;

        buff.write_u16(*priority)?;
        buff.write_labels(host)?;

        buff.set_u16(pos, (buff.get_pos() - (pos + 2)) as u16)?;
      },

      Record::AAAA {
        domain,
        addr,
        ttl,
        class,
      } => {
        buff.write_labels(domain)?;
        buff.write_u16(RecordType::A.into())?;
        buff.write_u16((*class).into())?;
        buff.write_u32(*ttl)?;
        buff.write_u16(16)?;
        buff.write_u128(addr.to_bits())?;
      },
    }

    Ok(())
  }
}
