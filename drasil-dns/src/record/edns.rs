
// ===== Imports =====
use crate::{buffer::Buffer, error::DrasilDNSError};
// ===================

/// Enum for EDNS(0) option types
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u16)]
pub enum EDNSOptionType {
  Unknown(u16),
  NSID = 3,
  ClientSubnet = 8,
  Cookie = 10,
  KeepAlive = 11,
  Padding = 12,
  ChainQuery = 13,
  KeyTag = 14,
  EDE = 15,
  ECS = 16,
}

impl Into<u16> for EDNSOptionType {
  fn into(self) -> u16 {
    match self {
      EDNSOptionType::Unknown(v) => v,
      EDNSOptionType::NSID => 3,
      EDNSOptionType::ClientSubnet => 8,
      EDNSOptionType::Cookie => 10,
      EDNSOptionType::KeepAlive => 11,
      EDNSOptionType::Padding => 12,
      EDNSOptionType::ChainQuery => 13,
      EDNSOptionType::KeyTag => 14,
      EDNSOptionType::EDE => 15,
      EDNSOptionType::ECS => 16,
    }
  }
}

impl From<u16> for EDNSOptionType {
  fn from(value: u16) -> Self {
    match value {
      3 => Self::NSID,
      8 => Self::ClientSubnet,
      10 => Self::Cookie,
      11 => Self::KeepAlive,
      12 => Self::Padding,
      13 => Self::ChainQuery,
      14 => Self::KeyTag,
      15 => Self::EDE,
      16 => Self::ECS,
      v => Self::Unknown(v),
    }
  }
}

/// # EDNS(0) Option
/// Enum for representing all EDNS(0) options.
/// Options are the {attribute, value} pairs stored in the RDATA section of OPT RR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EDNSOption {
  Unknown {
    code: u16,
    len: u16,
    data: Vec<u8>,
  },

  // Name-Server Identification
  NSID {
    data: String,
  }, // 3

  ClientSubnet {
    family: u16,
    source_netmask: u8,
    scope_netmask: u8,
    addr: u128,
  }, // 8

  Cookie {
    client: u64,
    server: Option<u64>,
  }, // 10

  KeepAlive {
    timeout: u16,
  }, // 11

  Padding {
    len: u16,
  }, // 12

  ChainQuery {
    flags: u16,
    qname_min_length: u16,
  }, // 13

  KeyTag {
    tags: Vec<u16>,
  }, // 14

  // Extended DNS Error
  EDE {
    info_code: u16,
    extra_text: String,
  }, // 15

  EcsIPv4 {
    source_netmask: u8,
    scope_netmask: u8,
    addr: u32,
  }, // 16 - ipv4

  EcsIPv6 {
    source_netmask: u8,
    scope_netmask: u8,
    addr: u128,
  }, // 16 - ipv4
}

impl EDNSOption {
  pub(crate) fn parse(buff: &mut Buffer) -> Result<EDNSOption, DrasilDNSError> {
    buff.read_transaction(|buff| {
      let code = buff.read_u16()?;
      let len = buff.read_u16()?;

      Ok(match code {
        3 => {
          let data = buff.read_bytes(len as usize - 2)?;
          Self::NSID { data: String::from_utf8_lossy(&data).to_string() }
        },

        8 => {
          let family = buff.read_u16()?;
          let source_netmask = buff.read_u8()?;
          let scope_netmask = buff.read_u8()?;
          let mut addr = 0_u128;

          if family == 1 { // ipv4
            if source_netmask > 32 {
              return Err(DrasilDNSError::InvalidSourceNetmask { family, max: 32, provided: source_netmask })
            }
            if scope_netmask > 32 {
              return Err(DrasilDNSError::InvalidScopeNetmask { family, max: 32, provided: source_netmask })
            }
          } else if family == 2 { // ipv6
            if source_netmask > 128 {
              return Err(DrasilDNSError::InvalidSourceNetmask { family, max: 128, provided: source_netmask })
            }
            if scope_netmask > 128 {
              return Err(DrasilDNSError::InvalidScopeNetmask { family, max: 128, provided: source_netmask })
            }
          } else {
            return Err(DrasilDNSError::InvalidNetworkFamily { family });
          }

          if source_netmask <= 8 {
            addr = buff.read_u8()? as u128;
          } else if source_netmask <= 16 {
            addr = buff.read_u16()? as u128;
          } else if source_netmask <= 32 {
            addr = buff.read_u32()? as u128;
          } else if source_netmask <= 64 {
            addr = buff.read_u64()? as u128;
          } else if source_netmask <= 128 {
            addr = buff.read_u128()? as u128;
          }

          Self::ClientSubnet { family, source_netmask, scope_netmask, addr }
        },

        10 => {
          if len != 8 && len != 16 {
            return Err(DrasilDNSError::InvalidEDNSOptionLength { option_type: 10, size: len });
          }

          let client = buff.read_u64()?;
          let mut server = None;
          if len == 16 {
            server = Some(buff.read_u64()?);
          }

          Self::Cookie { client, server }
        },

        11 => {
          if len != 2 {
            return Err(DrasilDNSError::InvalidEDNSOptionLength { option_type: 11, size: len });
          }

          let timeout = buff.read_u16()?;
          Self::KeepAlive { timeout }
        },

        12 => {
          buff.seek(buff.pos() + (len as usize));
          Self::Padding { len }
        },

        13 => {
          if len != 4 {
            return Err(DrasilDNSError::InvalidEDNSOptionLength { option_type: 13, size: len });
          }

          let flags = buff.read_u16()?;
          let qname_min_length = buff.read_u16()?;

          Self::ChainQuery { flags, qname_min_length }
        },

        14 => {
          if len % 2 != 0 {
            return Err(DrasilDNSError::InvalidEDNSOptionLength { option_type: 14, size: len });
          }

          let mut tags = vec![];
          for _ in 0..(len % 2) {
            tags.push(buff.read_u16()?);
          }

          Self::KeyTag { tags }
        },

        15 => {
          let info_code = buff.read_u16()?;
          let extra_text = buff.read_bytes(len as usize - 2)?;

          Self::EDE { info_code, extra_text: String::from_utf8_lossy(extra_text).to_string() }
        },

        16 => {
          let family = buff.read_u16()?;
          let source_netmask = buff.read_u8()?;
          let scope_netmask = buff.read_u8()?;

          if family == 1 { // ipv4
            if source_netmask > 32 {
              return Err(DrasilDNSError::InvalidSourceNetmask { family, max: 32, provided: source_netmask })
            }

            if scope_netmask > 32 {
              return Err(DrasilDNSError::InvalidScopeNetmask { family, max: 32, provided: source_netmask })
            }

            let addr = buff.read_u32()?;
            Self::EcsIPv4 { source_netmask, scope_netmask, addr }

          } else if family == 2 { // ipv6
            if source_netmask > 128 {
              return Err(DrasilDNSError::InvalidSourceNetmask { family, max: 128, provided: source_netmask })
            }

            if scope_netmask > 128 {
              return Err(DrasilDNSError::InvalidScopeNetmask { family, max: 128, provided: source_netmask })
            }

            let addr = buff.read_u128()?;
            Self::EcsIPv6 { source_netmask, scope_netmask, addr }
          } else {
            return Err(DrasilDNSError::InvalidNetworkFamily { family });
          }
        },
        
        code => {
          let data = buff.read_bytes(len as usize)?.to_vec();
          Self::Unknown { code, len, data }
        },
      })
    })
  }

  pub(crate) fn write_bytes(&self, buff: &mut Buffer) -> Result<(), DrasilDNSError> {
    match self {
      EDNSOption::Unknown {
        code,
        len,
        data,
      } => {
        let mut b = Buffer::with_capacity(4 + *len as usize);
        b.write_u16(*code)?;
        b.write_u16(*len)?;
        b.write_bytes(&data)?;
        buff.write_buffer(&b)?;
      },

      EDNSOption::NSID { data } => {
        let len = data.len() as u16;

        let mut b = Buffer::with_capacity(4 + len as usize);
        b.write_u16(EDNSOptionType::NSID.into())?;
        b.write_u16(len)?;
        b.write_bytes(data.as_bytes())?;
        buff.write_buffer(&b)?;
      },

      EDNSOption::ClientSubnet { family, source_netmask, scope_netmask, addr } => {
        if !(1..=2).contains(family) {
          return Err(DrasilDNSError::InvalidNetworkFamily { family: *family });
        }

        if *family == 1 { // ipv4
          if *source_netmask > 32 {
            return Err(DrasilDNSError::InvalidSourceNetmask { family: *family, max: 32, provided: *source_netmask })
          }
          if *scope_netmask > 32 {
            return Err(DrasilDNSError::InvalidScopeNetmask { family: *family, max: 32, provided: *source_netmask })
          }
        } else if *family == 2 { // ipv6
          if *source_netmask > 128 {
            return Err(DrasilDNSError::InvalidSourceNetmask { family: *family, max: 128, provided: *source_netmask })
          }
          if *scope_netmask > 128 {
            return Err(DrasilDNSError::InvalidScopeNetmask { family: *family, max: 128, provided: *source_netmask })
          }
        } else {
          return Err(DrasilDNSError::InvalidNetworkFamily { family: *family });
        }

        let mut b = Buffer::with_capacity(0);
        b.set_expandable(true);

        b.write_u16(EDNSOptionType::ClientSubnet.into())?;
        
        let pos = b.pos();
        b.write_u16(0)?;

        b.write_u16(*family)?;
        b.write_u8(*source_netmask)?;
        b.write_u8(*scope_netmask)?;

        if *source_netmask <= 8 {
          b.write_u8(*addr as u8)?;
        } else if *source_netmask <= 16 {
          b.write_u16(*addr as u16)?;
        } else if *source_netmask <= 32 {
          b.write_u32(*addr as u32)?;
        } else if *source_netmask <= 64 {
          b.write_u64(*addr as u64)?;
        } else if *source_netmask <= 128 {
          b.write_u128(*addr)?;
        }

        let len = (b.pos() - (pos + 2)) as u16;
        b.set_bytes(pos, &len.to_be_bytes())?;
        buff.write_buffer(&b)?;
      },

      EDNSOption::Cookie { client, server } => {
        let len = if server.is_some() { 16 } else { 8 };
        let mut b = Buffer::with_capacity(4 + len as usize);

        b.write_u16(EDNSOptionType::Cookie.into())?;
        b.write_u16(len)?;
        b.write_u64(*client)?;
        if let Some(server) = server {
          b.write_u64(*server)?;
        }

        buff.write_buffer(&b)?;
      },

      EDNSOption::KeepAlive { timeout } => {
        let mut b = Buffer::with_capacity(6);
        b.write_u16(EDNSOptionType::KeepAlive.into())?;
        b.write_u16(2)?;
        b.write_u16(*timeout)?;
        buff.write_buffer(&b)?;
      },

      EDNSOption::Padding { len } => {
        let mut b = Buffer::with_capacity(4 + *len as usize);
        b.write_u16(EDNSOptionType::Padding.into())?;
        b.write_u16(*len)?;
        
        for _ in 0..(*len) {
          b.write_u8(0)?;
        }

        buff.write_buffer(&b)?;
      },

      EDNSOption::ChainQuery { flags, qname_min_length } => {
        let mut b = Buffer::with_capacity(8);
        b.write_u16(EDNSOptionType::ChainQuery.into())?;
        b.write_u16(4)?;
        b.write_u16(*flags)?;
        b.write_u16(*qname_min_length)?;
        buff.write_buffer(&b)?;
      },

      EDNSOption::KeyTag { tags } => {
        let len = 2 * tags.len() as u16;
        let mut b = Buffer::with_capacity(4 + len as usize);

        b.write_u16(EDNSOptionType::KeyTag.into())?;
        b.write_u16(len)?;

        for tag in tags {
          b.write_u16(*tag)?;
        }

        buff.write_buffer(&b)?;
      },
      
      EDNSOption::EDE { info_code, extra_text } => {
        let len = 2 + extra_text.len() as u16;
        let mut b = Buffer::with_capacity(4 + len as usize);

        b.write_u16(EDNSOptionType::EDE.into())?;
        b.write_u16(len)?;
        b.write_u16(*info_code)?;
        b.write_bytes(extra_text.as_bytes())?;
        
        buff.write_buffer(&b)?;
      },

      EDNSOption::EcsIPv4 { source_netmask, scope_netmask, addr } => {
        let mut b = Buffer::with_capacity(14);

        b.write_u16(EDNSOptionType::ECS.into())?;
        b.write_u16(10)?;
        b.write_u16(1)?;
        b.write_u8(*source_netmask)?;
        b.write_u8(*scope_netmask)?;
        b.write_u32(*addr)?;

        buff.write_buffer(&b)?;
      },

      EDNSOption::EcsIPv6 { source_netmask, scope_netmask, addr } => {
        let mut b = Buffer::with_capacity(24);

        b.write_u16(EDNSOptionType::ECS.into())?;
        b.write_u16(20)?;
        b.write_u16(2)?;
        b.write_u8(*source_netmask)?;
        b.write_u8(*scope_netmask)?;
        b.write_u128(*addr)?;

        buff.write_buffer(&b)?;
      },
    }

    Ok(())
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn edns_rw() {
    let mut b = Buffer::with_capacity(0);
    b.set_expandable(true);

    let options: Vec<EDNSOption> = vec![
      EDNSOption::Cookie { client: 100, server: None },
      EDNSOption::Cookie { client: 100, server: Some(150) },

      EDNSOption::ClientSubnet { family: 1, source_netmask: 24, scope_netmask: 0, addr: 0x10101010 },
    ];

    for option in &options {
      option.write_bytes(&mut b).expect("Failed to write EDNS option");
    }

    b.seek(0);

    let mut options_after_read = vec![];
    for _ in 0..options.len() {
      options_after_read.push(EDNSOption::parse(&mut b).expect("Failed to read EDNS option"));
    }

    assert_eq!(options, options_after_read, "EDNS Options unequal after write+read");
  }
}