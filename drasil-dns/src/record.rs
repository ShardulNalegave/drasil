
// ===== Imports =====
use crate::{common::{read_name, RecordClass, RecordType}, error::DrasilDNSError};
// ===================

#[derive(Debug, Clone)]
pub struct Record {
  pub name: String,
  pub record_type: RecordType,
  pub class: RecordClass,
  pub time_to_live: u32,
  pub len: u16,
  pub ip: u32,
}

impl Record {
  pub fn parse(packet_data: &[u8; 512], pos: &mut usize) -> Result<Self, DrasilDNSError> {
    let name = read_name(packet_data, pos)?;
    
    let record_type = u16::from_be_bytes([
      packet_data[*pos],
      packet_data[*pos+1]
    ]).into();
    *pos += 2;

    let class = u16::from_be_bytes([
      packet_data[*pos],
      packet_data[*pos+1]
    ]).into();
    *pos += 2;

    let time_to_live = u32::from_be_bytes([
      packet_data[*pos],
      packet_data[*pos+1],
      packet_data[*pos+2],
      packet_data[*pos+3],
    ]);
    *pos += 4;

    let len = u16::from_be_bytes([
      packet_data[*pos],
      packet_data[*pos+1]
    ]);
    *pos += 2;

    let ip = u32::from_be_bytes([
      packet_data[*pos],
      packet_data[*pos+1],
      packet_data[*pos+2],
      packet_data[*pos+3],
    ]);
    *pos += 4;

    Ok(Self { name, record_type, class, time_to_live, len, ip })
  }
}