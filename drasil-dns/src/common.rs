
// ===== Imports =====
use crate::error::DrasilDNSError;
// ===================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordType {
  A = 1,
}

impl From<u16> for RecordType {
  fn from(value: u16) -> Self {
    match value {
      1 => Self::A,
      v => panic!("No RecordType of value {} exists", v),
    }
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordClass {
  IN = 1,
}

impl From<u16> for RecordClass {
  fn from(value: u16) -> Self {
    match value {
      1 => Self::IN,
      v => panic!("No RecordClass of value {} exists", v),
    }
  }
}

pub fn read_name(packet_data: &[u8; 512], pos: &mut usize) -> Result<String, DrasilDNSError> {
  let mut res = String::new();
  let mut i: usize = *pos;
  
  let mut jumps = 0;
  let max_jumps = 5;
  let mut delim = "";

  loop {
    let len = packet_data[i];

    if (len & 0b11000000) == 0b11000000 { // jump
      if jumps >= max_jumps {
        return Err(DrasilDNSError::TooManyJumpsInLabelSequence);
      }

      if jumps == 0 {
        *pos += 2;
      }

      let low = packet_data[i+1] as u16;
      let offset = (((len as u16) ^ 0b11000000) << 8) | low;
      i = offset as usize;

      jumps += 1;
      continue;
    } else {
      i += 1;
      if len == 0 {
        break;
      }

      let mut buff = vec![];
      for j in i..(i+(len as usize)) {
        buff.push(packet_data[j]);
      }

      res.push_str(delim);
      res.push_str(&String::from_utf8_lossy(&buff).to_lowercase());

      delim = ".";
      i += len as usize;
    }
  }

  if jumps == 0 {
    *pos = i;
  }

  Ok(res)
}