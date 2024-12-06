
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

  RRSIG {
    domain: Vec<String>,
    class: RecordClass,
    ttl: u32,
    type_covered: u16,
    algorithm: u8,
    labels: u8,
    original_ttl: u32,
    signature_expiration: u32,
    signature_inception: u32,
    key_tag: u16,
    signer_name: Vec<String>,
    signature: Vec<u8>,
  }, // 46

  DNSKEY {
    domain: Vec<String>,
    class: RecordClass,
    ttl: u32,
    is_secure_entry_point: bool,
    is_zone_key: bool,
    protocol: u8,
    algorithm: u8,
    public_key: Vec<u8>,
  }, // 48
}

impl Record {
  pub(crate) fn parse(buff: &mut Buffer) -> Result<Self, DrasilDNSError> {
    let (_, domain) = buff.read_labels()?;
    let record_type = RecordType::from(buff.read_u16()?);
    let class = RecordClass::from(buff.read_u16()?);
    let ttl = buff.read_u32()?;
    let len = buff.read_u32()?;

    Ok(match record_type {
      RecordType::Unknown(v) => {
        let data = buff.read_bytes(len as usize)?;
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
        buff.seek(buff.pos() - 10);

        let udp_payload_size = buff.read_u16()?;
        let extended_rcode = buff.read_u8()?;
        let version = buff.read_u8()?;

        let reserved = buff.read_u16()?;
        let dnssec_ok: bool = (reserved & 0x8000) >> 15 == 1;

        let data_length = buff.read_u16()?;

        let pos = buff.pos();
        let mut options = vec![];

        loop {
          let opt = EDNSOption::parse(buff)?;
          options.push(opt);

          if buff.pos() - pos >= (data_length as usize) {
            break;
          }
        }

        Self::OPT { udp_payload_size, extended_rcode, version, dnssec_ok, options }
      }

      RecordType::A => {
        let addr = Ipv4Addr::from_bits(buff.read_u32()?);
        Self::A { domain, class, ttl, addr }
      },

      RecordType::NS => {
        let (_, host) = buff.read_labels()?;
        Self::NS { domain, host, ttl, class }
      },

      RecordType::CNAME => {
        let (_, host) = buff.read_labels()?;
        Self::NS { domain, host, ttl, class }
      },

      RecordType::MX => {
        let priority = buff.read_u16()?;
        let (_, host) = buff.read_labels()?;
        Self::MX { domain, priority, host, ttl, class }
      },

      RecordType::AAAA => {
        let addr = Ipv6Addr::from_bits(buff.read_u128()?);
        Self::AAAA { domain, class, ttl, addr }
      },

      RecordType::RRSIG => {
        let type_covered = buff.read_u16()?;
        let algorithm = buff.read_u8()?;
        let labels = buff.read_u8()?;
        let original_ttl = buff.read_u32()?;
        let signature_expiration = buff.read_u32()?;
        let signature_inception = buff.read_u32()?;
        let key_tag = buff.read_u16()?;

        let (signer_name_len, signer_name) = buff.read_labels()?;

        let signature_length = len as usize - (18 + signer_name_len);
        let signature = buff.read_bytes(signature_length)?.to_vec();

        Self::RRSIG {
          domain,
          class,
          ttl,
          type_covered,
          algorithm,
          labels,
          original_ttl,
          signature_expiration,
          signature_inception,
          key_tag,
          signer_name,
          signature,
        }
      },

      RecordType::DNSKEY => {
        let flags = buff.read_u16()?;
        let protocol = buff.read_u8()?;
        let algorithm = buff.read_u8()?;

        let is_zone_key = (flags >> 7) & 0b1 == 1;
        let is_secure_entry_point = (flags >> 15) & 0b1 == 1;

        let public_key = buff.read_bytes(len as usize - 4)?.to_vec();

        Self::DNSKEY { domain, class, ttl, is_secure_entry_point, is_zone_key, public_key, protocol, algorithm }
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
        let mut b = Buffer::with_capacity(0);
        b.set_expandable(true);

        b.write_labels(domain)?;
        b.write_u16(*record_type)?;
        b.write_u16((*class).into())?;
        b.write_u32(*ttl)?;
        b.write_u32(*len)?;
        b.write_bytes(&data)?;

        buff.write_buffer(&b)?;
      },

      Record::OPT {
        udp_payload_size,
        extended_rcode,
        version,
        dnssec_ok,
        options,
      } => {
        let mut b = Buffer::with_capacity(0);
        b.set_expandable(true);

        b.write_u8(0)?; // set domain to empty (0)
        b.write_u16(RecordType::OPT.into())?;
        b.write_u16(*udp_payload_size)?;
        b.write_u8(*extended_rcode)?;
        b.write_u8(*version)?;
        b.write_u16(if *dnssec_ok { 0x8000 } else { 0x0000 })?;
        
        let pos = b.pos();
        b.write_u16(0)?;

        for opt in options {
          opt.write_bytes(&mut b)?;
        }

        let len = (b.pos() - (pos + 2)) as u16;
        b.set_bytes(pos, &len.to_be_bytes())?;

        buff.write_buffer(&b)?;
      },

      Record::A {
        domain,
        addr,
        ttl,
        class,
      } => {
        let mut b = Buffer::with_capacity(0);
        b.set_expandable(true);

        b.write_labels(domain)?;
        b.write_u16(RecordType::A.into())?;
        b.write_u16((*class).into())?;
        b.write_u32(*ttl)?;
        b.write_u32(4)?;
        b.write_u32(addr.to_bits())?;

        buff.write_buffer(&b)?;
      },

      Record::NS {
        domain,
        host,
        ttl,
        class,
      } => {
        let mut b = Buffer::with_capacity(0);
        b.set_expandable(true);

        b.write_labels(domain)?;
        b.write_u16(RecordType::NS.into())?;
        b.write_u16((*class).into())?;
        b.write_u32(*ttl)?;

        let pos = b.pos();
        b.write_u32(0)?;

        let len = b.write_labels(host)? as u32;
        b.set_bytes(pos, &len.to_be_bytes())?;

        buff.write_buffer(&b)?;
      },

      Record::CNAME {
        domain,
        host,
        ttl,
        class,
      } => {
        let mut b = Buffer::with_capacity(0);
        b.set_expandable(true);

        b.write_labels(domain)?;
        b.write_u16(RecordType::CNAME.into())?;
        b.write_u16((*class).into())?;
        b.write_u32(*ttl)?;

        let pos = b.pos();
        b.write_u32(0)?;

        let len = b.write_labels(host)? as u32;
        b.set_bytes(pos, &len.to_be_bytes())?;

        buff.write_buffer(&b)?;
      },

      Record::MX {
        domain,
        priority,
        host,
        ttl,
        class,
      } => {
        let mut b = Buffer::with_capacity(0);
        b.set_expandable(true);

        b.write_labels(domain)?;
        b.write_u16(RecordType::MX.into())?;
        b.write_u16((*class).into())?;
        b.write_u32(*ttl)?;
        
        let pos = b.pos();
        b.write_u32(0)?;

        b.write_u16(*priority)?;
        let len = b.write_labels(host)? as u32;

        b.set_bytes(pos, &(len + 2).to_be_bytes())?;

        buff.write_buffer(&b)?;
      },

      Record::AAAA {
        domain,
        addr,
        ttl,
        class,
      } => {
        let mut b = Buffer::with_capacity(0);
        b.set_expandable(true);

        b.write_labels(domain)?;
        b.write_u16(RecordType::A.into())?;
        b.write_u16((*class).into())?;
        b.write_u32(*ttl)?;
        b.write_u32(16)?;
        b.write_u128(addr.to_bits())?;

        buff.write_buffer(&b)?;
      },

      Record::RRSIG {
        domain,
        class,
        ttl,
        type_covered,
        algorithm,
        labels,
        original_ttl,
        signature_expiration,
        signature_inception,
        key_tag,
        signer_name,
        signature,
      } => {
        let mut b = Buffer::with_capacity(0);
        b.set_expandable(true);

        b.write_labels(domain)?;
        b.write_u16(RecordType::RRSIG.into())?;
        b.write_u16((*class).into())?;
        b.write_u32(*ttl)?;

        let pos = b.pos();
        b.write_u32(0)?;

        b.write_u16(*type_covered)?;
        b.write_u8(*algorithm)?;
        b.write_u8(*labels)?;
        b.write_u32(*original_ttl)?;
        b.write_u32(*signature_expiration)?;
        b.write_u32(*signature_inception)?;
        b.write_u16(*key_tag)?;
        b.write_labels(signer_name)?;
        b.write_bytes(&signature)?;

        let len = b.pos() - (pos + 4);
        b.set_bytes(pos, &len.to_be_bytes())?;

        buff.write_buffer(&b)?;
      },

      Record::DNSKEY {
        domain,
        class,
        ttl,
        is_secure_entry_point,
        is_zone_key,
        protocol,
        algorithm,
        public_key,
      } => {
        let mut flags = 0b0;
        if *is_zone_key {
          flags |= 0b1 << 7;
        }
        if *is_secure_entry_point {
          flags |= 0b1 << 15;
        }

        let mut b = Buffer::with_capacity(0);
        b.set_expandable(true);

        b.write_labels(domain)?;
        b.write_u16(RecordType::DNSKEY.into())?;
        b.write_u16((*class).into())?;
        b.write_u32(*ttl)?;
        b.write_u32(4 + public_key.len() as u32)?;
        b.write_u16(flags)?;
        b.write_u8(*protocol)?;
        b.write_u8(*algorithm)?;
        b.write_bytes(public_key)?;

        buff.write_buffer(&b)?;
      },
    }

    Ok(())
  }
}
