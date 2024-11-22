
// ===== Imports =====
use crate::{common::{read_name, RecordClass, RecordType}, error::DrasilDNSError};
// ===================

#[derive(Debug, Clone)]
pub struct Question {
  pub name: String,
  pub record_type: RecordType,
  pub class: RecordClass,
}

impl Question {
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

    Ok(Self { name, record_type, class })
  }
}