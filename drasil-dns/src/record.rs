
/// Provides eDNS types
pub mod edns;

// ===== Imports =====
use std::{collections::HashSet, net::{Ipv4Addr, Ipv6Addr}};
use crate::{buffer::Buffer, error::DrasilDNSError, record::edns::EDNSOption, types::{dnssec::{DNSSECAlgorithm, DNSSECDigestType}, RecordClass, RecordType}};
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

  DS {
    domain: Vec<String>,
    class: RecordClass,
    ttl: u32,
    key_tag: u16,
    algorithm: DNSSECAlgorithm,
    digest_type: DNSSECDigestType,
    digest: Vec<u8>,
  }, // 43

  RRSIG {
    domain: Vec<String>,
    class: RecordClass,
    ttl: u32,
    type_covered: u16,
    algorithm: DNSSECAlgorithm,
    labels: u8,
    original_ttl: u32,
    signature_expiration: u32,
    signature_inception: u32,
    key_tag: u16,
    signer_name: Vec<String>,
    signature: Vec<u8>,
  }, // 46

  NSEC {
    domain: Vec<String>,
    class: RecordClass,
    ttl: u32,
    next_domain_name: Vec<String>,
    record_types: HashSet<RecordType>,
  }, // 47

  DNSKEY {
    domain: Vec<String>,
    class: RecordClass,
    ttl: u32,
    is_secure_entry_point: bool,
    is_zone_key: bool,
    protocol: u8,
    algorithm: DNSSECAlgorithm,
    public_key: Vec<u8>,
  }, // 48

  NSEC3 {
    domain: Vec<String>,
    class: RecordClass,
    ttl: u32,
    hash_algorithm: u8,
    opt_out: bool,
    iterations: u16,
    salt_length: u8,
    salt: Vec<u8>,
    hash_length: u8,
    next_hashed_owner_name: Vec<u8>,
    record_types: HashSet<RecordType>,
  }, // 50

  NSEC3PARAM {
    domain: Vec<String>,
    class: RecordClass,
    ttl: u32,
    hash_algorithm: u8,
    flags: u8,
    iterations: u16,
    salt_length: u8,
    salt: Vec<u8>,
  }, // 51
}

impl Record {
  pub(crate) fn parse(buff: &mut Buffer) -> Result<Option<Self>, DrasilDNSError> {
    buff.read_transaction(|buff| {
      let (_, domain) = buff.read_labels(true)?;
      let record_type = RecordType::from(buff.read_u16()?);
      let class = RecordClass::from(buff.read_u16()?);
      let ttl = buff.read_u32()?;
      let len = buff.read_u32()?;

      Ok(Some(match record_type {
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
          let (_, host) = buff.read_labels(true)?;
          Self::NS { domain, host, ttl, class }
        },

        RecordType::CNAME => {
          let (_, host) = buff.read_labels(true)?;
          Self::NS { domain, host, ttl, class }
        },

        RecordType::MX => {
          let priority = buff.read_u16()?;
          let (_, host) = buff.read_labels(true)?;
          Self::MX { domain, priority, host, ttl, class }
        },

        RecordType::AAAA => {
          let addr = Ipv6Addr::from_bits(buff.read_u128()?);
          Self::AAAA { domain, class, ttl, addr }
        },

        RecordType::DS => {
          let key_tag = buff.read_u16()?;
          let algorithm = buff.read_u8()?.into();
          let digest_type = buff.read_u8()?.into();
          let digest = buff.read_bytes(len as usize - 4)?.to_vec();

          Self::DS { domain, class, ttl, key_tag, algorithm, digest_type, digest }
        },

        RecordType::RRSIG => {
          let type_covered = buff.read_u16()?;
          let algorithm = buff.read_u8()?.into();
          let labels = buff.read_u8()?;
          let original_ttl = buff.read_u32()?;
          let signature_expiration = buff.read_u32()?;
          let signature_inception = buff.read_u32()?;
          let key_tag = buff.read_u16()?;

          let (signer_name_len, signer_name) = buff.read_labels(false)?;

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

        RecordType::NSEC => {
          let (ndn_len, next_domain_name) = buff.read_labels(false)?;

          let type_bitmaps = buff.read_bytes(len as usize - ndn_len)?;
          let record_types = RecordType::parse_type_bitmaps(type_bitmaps.into())?;

          Self::NSEC { domain, class, ttl, next_domain_name, record_types }
        },

        RecordType::DNSKEY => {
          let flags = buff.read_u16()?;
          let protocol = buff.read_u8()?;
          let algorithm = buff.read_u8()?.into();

          let is_zone_key = (flags >> 7) & 0b1 == 1;
          let is_secure_entry_point = (flags >> 15) & 0b1 == 1;

          let public_key = buff.read_bytes(len as usize - 4)?.to_vec();

          Self::DNSKEY { domain, class, ttl, is_secure_entry_point, is_zone_key, public_key, protocol, algorithm }
        },

        RecordType::NSEC3 => {
          let hash_algorithm = buff.read_u8()?;

          let flags = buff.read_u8()?;
          let opt_out = (flags >> 7) == 1;

          let iterations = buff.read_u16()?;
          let salt_length = buff.read_u8()?;
          let salt = buff.read_bytes(salt_length as usize)?.to_vec();
          let hash_length = buff.read_u8()?;
          let next_hashed_owner_name = buff.read_bytes(hash_length as usize)?.to_vec();

          let type_bitmaps_length = len as usize - 6 - (salt_length + hash_length) as usize;
          let type_bitmaps = buff.read_bytes(type_bitmaps_length)?;
          let record_types = RecordType::parse_type_bitmaps(type_bitmaps.into())?;

          Self::NSEC3 { domain, class, ttl, hash_algorithm, opt_out, iterations, salt_length, salt, hash_length, next_hashed_owner_name, record_types }
        },

        RecordType::NSEC3PARAM => {
          let hash_algorithm = buff.read_u8()?;
          let flags = buff.read_u8()?;
          let iterations = buff.read_u16()?;
          let salt_length = buff.read_u8()?;
          let salt = buff.read_bytes(salt_length as usize)?.to_vec();

          if flags != 0 {
            return Ok(None); // if flags is not set to 0 then this record should be ignored
          }

          Self::NSEC3PARAM { domain, class, ttl, hash_algorithm, flags, iterations, salt_length, salt }
        },
      }))
    })
  }

  pub(crate) fn write_bytes(&self, buff: &mut Buffer) -> Result<(), DrasilDNSError> {
    let mut b = Buffer::with_capacity(0);
    b.set_expandable(true);

    match self {
      Record::Unknown {
        domain,
        ttl,
        len,
        record_type,
        class,
        data,
      } => {
        b.write_labels(domain)?;
        b.write_u16(*record_type)?;
        b.write_u16((*class).into())?;
        b.write_u32(*ttl)?;
        b.write_u32(*len)?;
        b.write_bytes(&data)?;
      },

      Record::OPT {
        udp_payload_size,
        extended_rcode,
        version,
        dnssec_ok,
        options,
      } => {
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
      },

      Record::A {
        domain,
        addr,
        ttl,
        class,
      } => {
        b.write_labels(domain)?;
        b.write_u16(RecordType::A.into())?;
        b.write_u16((*class).into())?;
        b.write_u32(*ttl)?;
        b.write_u32(4)?;
        b.write_u32(addr.to_bits())?;
      },

      Record::NS {
        domain,
        host,
        ttl,
        class,
      } => {
        b.write_labels(domain)?;
        b.write_u16(RecordType::NS.into())?;
        b.write_u16((*class).into())?;
        b.write_u32(*ttl)?;

        let pos = b.pos();
        b.write_u32(0)?;

        let len = b.write_labels(host)? as u32;
        b.set_bytes(pos, &len.to_be_bytes())?;
      },

      Record::CNAME {
        domain,
        host,
        ttl,
        class,
      } => {
        b.write_labels(domain)?;
        b.write_u16(RecordType::CNAME.into())?;
        b.write_u16((*class).into())?;
        b.write_u32(*ttl)?;

        let pos = b.pos();
        b.write_u32(0)?;

        let len = b.write_labels(host)? as u32;
        b.set_bytes(pos, &len.to_be_bytes())?;
      },

      Record::MX {
        domain,
        priority,
        host,
        ttl,
        class,
      } => {
        b.write_labels(domain)?;
        b.write_u16(RecordType::MX.into())?;
        b.write_u16((*class).into())?;
        b.write_u32(*ttl)?;
        
        let pos = b.pos();
        b.write_u32(0)?;

        b.write_u16(*priority)?;
        let len = b.write_labels(host)? as u32;

        b.set_bytes(pos, &(len + 2).to_be_bytes())?;
      },

      Record::AAAA {
        domain,
        addr,
        ttl,
        class,
      } => {
        b.write_labels(domain)?;
        b.write_u16(RecordType::A.into())?;
        b.write_u16((*class).into())?;
        b.write_u32(*ttl)?;
        b.write_u32(16)?;
        b.write_u128(addr.to_bits())?;
      },

      Record::DS {
        domain,
        class,
        ttl,
        key_tag,
        algorithm,
        digest_type,
        digest,
      } => {
        b.write_labels(domain)?;
        b.write_u16(RecordType::DS.into())?;
        b.write_u16((*class).into())?;
        b.write_u32(*ttl)?;
        b.write_u32(4 + digest.len() as u32)?;
        b.write_u16(*key_tag)?;
        b.write_u8((*algorithm).into())?;
        b.write_u8((*digest_type).into())?;
        b.write_bytes(digest)?;
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
        b.write_labels(domain)?;
        b.write_u16(RecordType::RRSIG.into())?;
        b.write_u16((*class).into())?;
        b.write_u32(*ttl)?;

        let pos = b.pos();
        b.write_u32(0)?;

        b.write_u16(*type_covered)?;
        b.write_u8((*algorithm).into())?;
        b.write_u8(*labels)?;
        b.write_u32(*original_ttl)?;
        b.write_u32(*signature_expiration)?;
        b.write_u32(*signature_inception)?;
        b.write_u16(*key_tag)?;
        b.write_labels(signer_name)?;
        b.write_bytes(&signature)?;

        let len = b.pos() - (pos + 4);
        b.set_bytes(pos, &len.to_be_bytes())?;
      },

      Record::NSEC {
        domain,
        class,
        ttl,
        next_domain_name,
        record_types,
      } => {
        let type_bitmaps = RecordType::into_type_bitmaps(record_types)?;

        b.write_labels(domain)?;
        b.write_u16(RecordType::NSEC.into())?;
        b.write_u16((*class).into())?;
        b.write_u32(*ttl)?;

        let pos = b.pos();
        b.write_u32(0)?;

        b.write_labels(next_domain_name)?;
        b.write_buffer(&type_bitmaps)?;

        b.set_bytes(pos, &(pos + 4).to_be_bytes())?;
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

        b.write_labels(domain)?;
        b.write_u16(RecordType::DNSKEY.into())?;
        b.write_u16((*class).into())?;
        b.write_u32(*ttl)?;
        b.write_u32(4 + public_key.len() as u32)?;
        b.write_u16(flags)?;
        b.write_u8(*protocol)?;
        b.write_u8((*algorithm).into())?;
        b.write_bytes(public_key)?;
      },

      Self::NSEC3 {
        domain,
        class,
        ttl,
        hash_algorithm,
        opt_out,
        iterations,
        salt_length,
        salt,
        hash_length,
        next_hashed_owner_name,
        record_types,
      } => {
        let type_bitmaps = RecordType::into_type_bitmaps(record_types)?;

        b.write_labels(domain)?;
        b.write_u16(RecordType::NSEC3.into())?;
        b.write_u16((*class).into())?;
        b.write_u32(*ttl)?;

        let pos = b.pos();
        b.write_u32(0)?;

        b.write_u8(*hash_algorithm)?;
        b.write_u8(if *opt_out { 0b1000_0000 } else { 0 })?;
        b.write_u16(*iterations)?;
        b.write_u8(*salt_length)?;
        b.write_bytes(salt)?;
        b.write_u8(*hash_length)?;
        b.write_bytes(&next_hashed_owner_name)?;
        b.write_buffer(&type_bitmaps)?;

        b.set_bytes(pos, &(pos + 4).to_be_bytes())?;
      },

      Self::NSEC3PARAM {
        domain,
        class,
        ttl,
        hash_algorithm,
        flags,
        iterations,
        salt_length,
        salt,
      } => {
        if *flags == 0 {
          return Ok(()); // flag should be equal to 0 else ignore this record
        }

        b.write_labels(domain)?;
        b.write_u16(RecordType::NSEC3PARAM.into())?;
        b.write_u16((*class).into())?;
        b.write_u32(*ttl)?;
        b.write_u8(*hash_algorithm)?;
        b.write_u8(*flags)?;
        b.write_u16(*iterations)?;
        b.write_u8(*salt_length)?;
        b.write_bytes(salt)?;
      },
    }

    buff.write_buffer(&b)?;
    Ok(())
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn record_rw() {
    let records: Vec<Record> = vec![
      Record::A {
        domain: vec!["google".to_string(), "com".to_string()],
        addr: Ipv4Addr::from_bits(0x10101010),
        ttl: 60,
        class: RecordClass::IN,
      },

      Record::OPT {
        udp_payload_size: 1024,
        extended_rcode: 0,
        version: 1,
        dnssec_ok: true,
        options: vec![
          EDNSOption::Cookie { client: 100, server: None },
          EDNSOption::Cookie { client: 100, server: Some(150) },
          EDNSOption::ClientSubnet { family: 2, source_netmask: 75, scope_netmask: 0, addr: 0x10101010 },
        ],
      },
    ];

    let mut b = Buffer::with_capacity(0);
    b.set_expandable(true);

    for record in &records {
      record.write_bytes(&mut b).expect("Failed at record write");
    }

    b.seek(0);
    let mut records_after_read = vec![];

    for _ in 0..records.len() {
      records_after_read.push(
        Record::parse(&mut b)
          .expect("Failed at record read")
          .expect("Record skipped unnecessarily"),
      );
    }

    assert_eq!(records, records_after_read, "Records not equals after write+read");
  }
}