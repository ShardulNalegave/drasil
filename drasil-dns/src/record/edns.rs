
// ===== Imports =====
use crate::{buffer::Buffer, error::DrasilDNSError};
// ===================

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
    let code = buff.get_u16()?;
    let len = buff.get_u16()?;

    Ok(match code {
      3 => {
        let mut data = vec![];
        for _ in 0..(len - 2) {
          data.push(buff.get_u8()?);
        }

        Self::NSID { data: String::from_utf8_lossy(&data).to_string() }
      },

      8 => {
        let family = buff.get_u16()?;
        let source_netmask = buff.get_u8()?;
        let scope_netmask = buff.get_u8()?;
        let mut addr = 0_u128;

        if family == 1 { // ipv4
          assert!(source_netmask <= 128, "invalid source netmask in OPT");
          assert!(scope_netmask <= 128, "invalid scope netmask in OPT");
        } else if family == 2 { // ipv6
          assert!(source_netmask <= 128, "invalid source netmask in OPT");
          assert!(scope_netmask <= 128, "invalid scope netmask in OPT");
        }

        if source_netmask <= 8 {
          addr = buff.get_u8()? as u128;
        } else if source_netmask <= 16 {
          addr = buff.get_u16()? as u128;
        } else if source_netmask <= 32 {
          addr = buff.get_u32()? as u128;
        } else if source_netmask <= 64 {
          addr = buff.get_u64()? as u128;
        } else if source_netmask <= 128 {
          addr = buff.get_u128()? as u128;
        }

        Self::ClientSubnet { family, source_netmask, scope_netmask, addr }
      },

      10 => {
        assert!(len == 8 || len == 16, "Cookie option length should be 8 or 16");

        let client = buff.get_u64()?;
        let mut server = None;
        if len == 16 {
          server = Some(buff.get_u64()?);
        }

        Self::Cookie { client, server }
      },

      11 => {
        assert!(len == 2, "KeepAlive option length should be 2");

        let timeout = buff.get_u16()?;
        Self::KeepAlive { timeout }
      },

      12 => {
        buff.seek(buff.get_pos() + (len as usize));
        Self::Padding { len }
      },

      13 => {
        assert!(len == 4, "ChainQuery option length should be 4");

        let flags = buff.get_u16()?;
        let qname_min_length = buff.get_u16()?;

        Self::ChainQuery { flags, qname_min_length }
      },

      14 => {
        assert!(len % 2 == 0, "KeyTag option length should be a multiple of 2");

        let mut tags = vec![];
        for _ in 0..(len % 2) {
          tags.push(buff.get_u16()?);
        }

        Self::KeyTag { tags }
      },

      15 => {
        let info_code = buff.get_u16()?;
        let mut extra_text = vec![];
 
        for _ in 0..(len - 2) {
          extra_text.push(buff.get_u8()?);
        }

        Self::EDE { info_code, extra_text: String::from_utf8_lossy(&extra_text).to_string() }
      },

      16 => {
        let family = buff.get_u16()?;
        let source_netmask = buff.get_u8()?;
        let scope_netmask = buff.get_u8()?;

        if family == 1 { // ipv4
          assert!(source_netmask <= 128, "invalid source netmask in OPT");
          assert!(scope_netmask <= 128, "invalid scope netmask in OPT");

          let addr = buff.get_u32()?;
          Self::EcsIPv4 { source_netmask, scope_netmask, addr }

        } else if family == 2 { // ipv6
          assert!(source_netmask <= 128, "invalid source netmask in OPT");
          assert!(scope_netmask <= 128, "invalid scope netmask in OPT");

          let addr = buff.get_u128()?;
          Self::EcsIPv6 { source_netmask, scope_netmask, addr }
        } else {
          unreachable!()
        }
      },
      
      code => {
        let data = buff.get_range(buff.get_pos(), len as usize)?.to_vec();
        buff.seek(buff.get_pos() + (len as usize));
        Self::Unknown { code, len, data }
      },
    })
  }

  pub(crate) fn write_bytes(&self, buff: &mut Buffer) -> Result<(), DrasilDNSError> {
    match self {
      EDNSOption::Unknown {
        code,
        len,
        data,
      } => {
        buff.write_u16(*code)?;
        buff.write_u16(*len)?;
        buff.write_vec(data)?;
      },

      EDNSOption::NSID { data } => {
        let len = data.len() as u16;

        buff.write_u16(EDNSOptionType::NSID.into())?;
        buff.write_u16(len)?;
        buff.write_vec(&data.as_bytes().to_vec())?;
      },

      EDNSOption::ClientSubnet { family, source_netmask, scope_netmask, addr } => {
        buff.write_u16(EDNSOptionType::ClientSubnet.into())?;

        let mut len = 4;
        let len_pos = buff.get_pos();
        buff.write_u16(0)?;

        buff.write_u16(*family)?;
        buff.write_u8(*source_netmask)?;
        buff.write_u8(*scope_netmask)?;

        if *source_netmask <= 8 {
          buff.write_u8(*addr as u8)?;
          len += 1;
        } else if *source_netmask <= 16 {
          buff.write_u16(*addr as u16)?;
          len += 2;
        } else if *source_netmask <= 32 {
          buff.write_u32(*addr as u32)?;
          len += 4;
        } else if *source_netmask <= 64 {
          buff.write_u64(*addr as u64)?;
          len += 8;
        } else if *source_netmask <= 128 {
          buff.write_u128(*addr)?;
          len += 16;
        }

        buff.set_u16(len_pos, len)?;
      },

      EDNSOption::Cookie { client, server } => {
        buff.write_u16(EDNSOptionType::Cookie.into())?;
        buff.write_u16(if server.is_some() { 16 } else { 8 })?;
        buff.write_u64(*client)?;
        if let Some(server) = server {
          buff.write_u64(*server)?;
        }
      },

      EDNSOption::KeepAlive { timeout } => {
        buff.write_u16(EDNSOptionType::KeepAlive.into())?;
        buff.write_u16(2)?;
        buff.write_u16(*timeout)?;
      },

      EDNSOption::Padding { len } => {
        buff.write_u16(EDNSOptionType::Padding.into())?;
        buff.write_u16(*len)?;
        
        for _ in 0..(*len) {
          buff.write_u8(0)?;
        }
      },

      EDNSOption::ChainQuery { flags, qname_min_length } => {
        buff.write_u16(EDNSOptionType::ChainQuery.into())?;
        buff.write_u16(4)?;
        buff.write_u16(*flags)?;
        buff.write_u16(*qname_min_length)?;
      },

      EDNSOption::KeyTag { tags } => {
        buff.write_u16(EDNSOptionType::KeyTag.into())?;
        buff.write_u16(2 * tags.len() as u16)?;

        for tag in tags {
          buff.write_u16(*tag)?;
        }
      },
      
      EDNSOption::EDE { info_code, extra_text } => {
        let len = 2 + extra_text.len() as u16;

        buff.write_u16(EDNSOptionType::EDE.into())?;
        buff.write_u16(len)?;
        buff.write_u16(*info_code)?;
        buff.write_vec(&extra_text.as_bytes().to_vec())?;
      },

      EDNSOption::EcsIPv4 { source_netmask, scope_netmask, addr } => {
        buff.write_u16(EDNSOptionType::ECS.into())?;
        buff.write_u16(10)?;
        buff.write_u16(1)?;
        buff.write_u8(*source_netmask)?;
        buff.write_u8(*scope_netmask)?;
        buff.write_u32(*addr)?;
      },

      EDNSOption::EcsIPv6 { source_netmask, scope_netmask, addr } => {
        buff.write_u16(EDNSOptionType::ECS.into())?;
        buff.write_u16(20)?;
        buff.write_u16(2)?;
        buff.write_u8(*source_netmask)?;
        buff.write_u8(*scope_netmask)?;
        buff.write_u128(*addr)?;
      },
    }

    Ok(())
  }
}