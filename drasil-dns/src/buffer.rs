
// ===== Imports =====
use crate::error::DrasilDNSError;
// ===================

pub(crate) struct Buffer {
  pos: usize,
  size: usize,
  data: Vec<u8>,
}

impl Default for Buffer {
  fn default() -> Self {
    Self { pos: 0, size: 512, data: vec![0; 512] }
  }
}

impl Buffer {
  pub fn new(data: Vec<u8>) -> Self {
    Self { pos: 0, size: data.len(), data }
  }

  pub fn get_data(&self) -> &[u8] {
    &self.data
  }

  pub fn get_pos(&self) -> usize {
    self.pos
  }

  pub fn seek(&mut self, pos: usize) {
    self.pos = pos;
  }

  pub fn get_range(&mut self, from: usize, len: usize) -> Result<&[u8], DrasilDNSError> {
    if (from + len) > self.size {
      return Err(DrasilDNSError::EOF);
    }

    Ok(&self.data[from..(from + len)])
  }

  pub fn get_u8(&mut self) -> Result<u8, DrasilDNSError> {
    if self.pos > self.size {
      return Err(DrasilDNSError::EOF);
    }

    let byte = self.data[self.pos];
    self.pos += 1;

    Ok(byte)
  }

  pub fn get_u16(&mut self) -> Result<u16, DrasilDNSError> {
    let high = self.get_u8()?;
    let low = self.get_u8()?;
    Ok(u16::from_be_bytes([high, low]))
  }

  pub fn get_u32(&mut self) -> Result<u32, DrasilDNSError> {
    let mut bytes = [0; 4];
    for i in 0..4 {
      bytes[i] = self.get_u8()?;
    }
    Ok(u32::from_be_bytes(bytes))
  }

  pub fn get_u64(&mut self) -> Result<u64, DrasilDNSError> {
    let mut bytes = [0; 8];
    for i in 0..8 {
      bytes[i] = self.get_u8()?;
    }
    Ok(u64::from_be_bytes(bytes))
  }

  pub fn get_u128(&mut self) -> Result<u128, DrasilDNSError> {
    let mut bytes = [0; 16];
    for i in 0..16 {
      bytes[i] = self.get_u8()?;
    }
    Ok(u128::from_be_bytes(bytes))
  }

  pub fn write_u8(&mut self, val: u8) -> Result<(), DrasilDNSError> {
    if self.pos > self.size {
      return Err(DrasilDNSError::EOF);
    }

    self.data[self.pos] = val;
    self.pos += 1;

    Ok(())
  }

  pub fn write_u16(&mut self, val: u16) -> Result<(), DrasilDNSError> {
    let [high, low] = val.to_be_bytes();
    self.write_u8(high)?;
    self.write_u8(low)?;
    Ok(())
  }

  pub fn write_u32(&mut self, val: u32) -> Result<(), DrasilDNSError> {
    for byte in val.to_be_bytes() {
      self.write_u8(byte)?;
    }
    Ok(())
  }

  pub fn write_u64(&mut self, val: u64) -> Result<(), DrasilDNSError> {
    for byte in val.to_be_bytes() {
      self.write_u8(byte)?;
    }
    Ok(())
  }

  pub fn write_u128(&mut self, val: u128) -> Result<(), DrasilDNSError> {
    for byte in val.to_be_bytes() {
      self.write_u8(byte)?;
    }
    Ok(())
  }

  pub fn write_vec(&mut self, data: &Vec<u8>) -> Result<(), DrasilDNSError> {
    for b in data {
      self.write_u8(*b)?;
    }
    Ok(())
  }

  pub fn set_u16(&mut self, pos: usize, val: u16) -> Result<(), DrasilDNSError> {
    if pos > self.size {
      return Err(DrasilDNSError::EOF);
    }

    let old_pos = self.pos;
    self.pos = pos;
    let res = self.write_u16(val);
    self.pos = old_pos;
    res
  }

  pub fn read_labels(&mut self) -> Result<Vec<String>, DrasilDNSError> {
    let mut labels = vec![];
    let mut i: usize = self.pos;
    
    let mut jumps = 0;
    let max_jumps = 5;

    loop {
      let len = self.data[i];

      if (len & 0b11000000) == 0b11000000 { // jump
        if jumps >= max_jumps {
          return Err(DrasilDNSError::TooManyJumpsInLabelSequence);
        }

        if jumps == 0 {
          self.seek(i + 2);
        }

        let low = self.data[i+1] as u16;
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
          buff.push(self.data[j]);
        }

        labels.push(String::from_utf8_lossy(&buff).to_lowercase());
        i += len as usize;
      }
    }

    if jumps == 0 {
      self.seek(i);
    }

    Ok(labels)
  }

  pub fn write_labels(&mut self, labels: &Vec<String>) -> Result<(), DrasilDNSError> {
    for label in labels {
      let len = label.len() as u8;
      if len > 63 {
        return Err(DrasilDNSError::LabelTooLarge);
      }

      self.write_u8(len)?;
      for b in label.as_bytes() {
        self.write_u8(*b)?;
      }
    }

    self.write_u8(0)?;
    Ok(())
  }
}