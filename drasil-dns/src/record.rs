
/// Provides eDNS types
pub mod edns;

// ===== Imports =====
use std::net::{Ipv4Addr, Ipv6Addr};
use crate::{buffer::Buffer, common::{RecordClass, RecordType}, error::DrasilDNSError, record::edns::EDNSOption};
// ===================

/// # Record
/// Enum for representing various kinds of DNS records that exist.
#[derive(Debug, Clone, PartialEq, Eq)]
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

  OPT {
    udp_payload_size: u16,
    extended_rcode: u8,
    version: u8,
    dnssec_ok: bool,
    options: Vec<EDNSOption>,
  }, // 41
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

      RecordType::OPT => {
        buff.seek(buff.get_pos() - 10);

        let udp_payload_size = buff.get_u16()?;
        let extended_rcode = buff.get_u8()?;
        let version = buff.get_u8()?;

        let reserved = buff.get_u16()?;
        let dnssec_ok = (reserved & 0x8000) >> 15 == 1;

        let data_length = buff.get_u16()?;
        println!("{}", data_length);

        let pos = buff.get_pos();
        let mut options = vec![];

        loop {
          let opt = EDNSOption::parse(buff)?;
          options.push(opt);

          if buff.get_pos() - pos >= (data_length as usize) {
            break;
          }
        }

        Self::OPT { udp_payload_size, extended_rcode, version, dnssec_ok, options }
      }

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

      Record::OPT {
        udp_payload_size,
        extended_rcode,
        version,
        dnssec_ok,
        options,
      } => {
        buff.write_u8(0)?; // set domain to empty (0)
        buff.write_u16(RecordType::OPT.into())?;
        buff.write_u16(*udp_payload_size)?;
        buff.write_u8(*extended_rcode)?;
        buff.write_u8(*version)?;
        buff.write_u16(if *dnssec_ok { 0x8000 } else { 0x0000 })?;
        
        let pos = buff.get_pos();
        buff.write_u16(0)?;

        for opt in options {
          opt.write_bytes(buff)?;
        }

        buff.set_u16(pos, (buff.get_pos() - (pos + 2)) as u16)?;
      }

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
