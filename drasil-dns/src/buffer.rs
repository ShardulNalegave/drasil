
// ===== Imports =====
use crate::error::DrasilDNSError;
// ===================

/// # Buffer
/// Custom reader and writer for byte buffers.
/// All operations are atomic for both reads and writes.
pub(crate) struct Buffer {
  pos: usize,
  capacity: usize,
  data: Vec<u8>,
  expandable: bool,
}

impl Default for Buffer {
  fn default() -> Self {
    Self { pos: 0, capacity: 512, data: vec![0; 512], expandable: false } // DNS packet size is 512 bytes acc. to original spec
  }
}

impl From<&[u8]> for Buffer {
  fn from(data: &[u8]) -> Self {
    Self { pos: 0, capacity: data.len(), data: data.to_vec(), expandable: false }
  }
}

impl From<Vec<u8>> for Buffer {
  fn from(data: Vec<u8>) -> Self {
    Self { pos: 0, capacity: data.len(), data, expandable: false }
  }
}

impl Into<Vec<u8>> for Buffer {
  fn into(self) -> Vec<u8> {
    self.data
  }
}

impl Buffer {
  /// Creates a new `Buffer` with given capacity
  pub fn with_capacity(capacity: usize) -> Self {
    Self { pos: 0, capacity, data: vec![0; capacity], expandable: false }
  }

  /// Used to set the expandable nature of the `Buffer`
  pub fn set_expandable(&mut self, expandable: bool) {
    self.expandable = expandable;
  }

  /// Tells whether or not `Buffer` is expandable
  pub fn expandable(&self) -> bool {
    self.expandable
  }

  /// Tells whether `Buffer` is at EOF position
  pub fn is_eof(&self) -> bool {
    self.pos >= self.capacity
  }

  /// Returns current position of the buffer
  pub fn pos(&self) -> usize {
    self.pos
  }

  /// Returns the capacity of `Buffer`
  pub fn capacity(&self) -> usize {
    self.capacity
  }

  /// Sets current position of the buffer
  pub fn seek(&mut self, pos: usize) {
    self.pos = pos;
  }

  /// Sets given slice data in the buffer from the provided position.
  /// This is an atomic operation, in case the write fails at any point the position and half-written data will be reset.
  pub fn set_bytes(&mut self, at: usize, bytes: &[u8]) -> Result<(), DrasilDNSError> {
    if (at + bytes.len()) > self.capacity {
      if self.expandable {
        let extra = self.capacity - (at + bytes.len());
        self.capacity = extra;
        self.data.append(&mut vec![0; extra]);
      } else {
        return Err(DrasilDNSError::EOF);
      }
    }

    for b in bytes {
      if let Err(err) = self.write_u8(*b) {
        let i = self.pos - at;
        self.set_bytes(at, &vec![0; i])?;
        self.pos -= i;

        return Err(DrasilDNSError::WriteFailed { error: Box::new(err) });
      }
    }

    Ok(())
  }

  /// Sets the given buffer's data in the current buffer from the provided position
  pub fn set_buffer(&mut self, at: usize, buff: &Buffer) -> Result<(), DrasilDNSError> {
    self.set_bytes(at, &buff.data)?;
    Ok(())
  }

  /// Reads `len` number of bytes from the current position.
  pub fn read_bytes(&mut self, len: usize) -> Result<&[u8], DrasilDNSError> {
    if (self.pos + len) > self.capacity {
      return Err(DrasilDNSError::EOF);
    }

    let bytes = &self.data[self.pos..(self.pos+len)];
    self.pos += len;
    Ok(bytes)
  }

  /// Write given bytes starting from current position
  pub fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), DrasilDNSError> {
    self.set_bytes(self.pos, bytes)?;
    Ok(())
  }

  /// Writes the given buffer from current position
  pub fn write_buffer(&mut self, buff:& Buffer) -> Result<(), DrasilDNSError> {
    self.set_buffer(self.pos, buff)?;
    Ok(())
  }

  /// Reads a single byte
  pub fn read_u8(&mut self) -> Result<u8, DrasilDNSError> {
    if self.pos > self.capacity {
      return Err(DrasilDNSError::EOF);
    }

    let byte = self.data[self.pos];
    self.pos += 1;

    Ok(byte)
  }

  /// Reads a `u16`
  pub fn read_u16(&mut self) -> Result<u16, DrasilDNSError> {
    let bytes: [u8; 2] = self.read_bytes(2)?.try_into().unwrap(); // is safe because returned slice's length is already known
    Ok(u16::from_be_bytes(bytes))
  }

  /// Reads a `u32`
  pub fn read_u32(&mut self) -> Result<u32, DrasilDNSError> {
    let bytes: [u8; 4] = self.read_bytes(4)?.try_into().unwrap(); // is safe because returned slice's length is already known
    Ok(u32::from_be_bytes(bytes))
  }

  /// Reads a `u64`
  pub fn read_u64(&mut self) -> Result<u64, DrasilDNSError> {
    let bytes: [u8; 8] = self.read_bytes(8)?.try_into().unwrap(); // is safe because returned slice's length is already known
    Ok(u64::from_be_bytes(bytes))
  }

  /// Reads a `u128`
  pub fn read_u128(&mut self) -> Result<u128, DrasilDNSError> {
    let bytes: [u8; 16] = self.read_bytes(16)?.try_into().unwrap(); // is safe because returned slice's length is already known
    Ok(u128::from_be_bytes(bytes))
  }

  /// Writes a single byte
  pub fn write_u8(&mut self, val: u8) -> Result<(), DrasilDNSError> {
    if self.pos > self.capacity {
      if self.expandable {
        self.capacity += 1;
        self.data.push(0);
      } else {
        return Err(DrasilDNSError::EOF);
      }
    }

    self.data[self.pos] = val;
    self.pos += 1;

    Ok(())
  }

  /// Writes a `u16`
  pub fn write_u16(&mut self, val: u16) -> Result<(), DrasilDNSError> {
    let bytes = val.to_be_bytes();
    self.write_bytes(&bytes)?;
    Ok(())
  }

  /// Writes a `u32`
  pub fn write_u32(&mut self, val: u32) -> Result<(), DrasilDNSError> {
    let bytes = val.to_be_bytes();
    self.write_bytes(&bytes)?;
    Ok(())
  }

  /// Writes a `u64`
  pub fn write_u64(&mut self, val: u64) -> Result<(), DrasilDNSError> {
    let bytes = val.to_be_bytes();
    self.write_bytes(&bytes)?;
    Ok(())
  }

  /// Writes a `u128`
  pub fn write_u128(&mut self, val: u128) -> Result<(), DrasilDNSError> {
    let bytes = val.to_be_bytes();
    self.write_bytes(&bytes)?;
    Ok(())
  }

  /// Reads series of labels stored in buffer starting from current position.
  /// Returns the number of bytes read and the labels.
  pub fn read_labels(&mut self, use_jumps: bool) -> Result<(usize, Vec<String>), DrasilDNSError> {
    let initial_pos = self.pos;

    let mut labels = vec![];
    let mut i: usize = self.pos;
    
    let mut jumps = 0;
    let max_jumps = 5;

    loop {
      let len = match self.data.get(i) {
        Some(len) => *len,
        None => {
          self.pos = initial_pos;
          return Err(DrasilDNSError::EOF);
        },
      };

      if (len & 0b11000000) == 0b11000000 && use_jumps { // jump
        if jumps >= max_jumps {
          return Err(DrasilDNSError::TooManyJumpsInLabelSequence);
        }

        if jumps == 0 {
          self.seek(i + 2);
        }

        let low = match self.data.get(i+1) {
          Some(b) => *b,
          None => {
            self.pos = initial_pos;
            return Err(DrasilDNSError::EOF);
          },
        } as u16;
        let offset = (((len as u16) ^ 0b11000000) << 8) | low;
        i = offset as usize;

        jumps += 1;
        continue;
      } else {
        i += 1;
        if len == 0 {
          break;
        } else if len > 63 {
          self.pos = initial_pos;
          return Err(DrasilDNSError::LabelTooLarge);
        }

        let mut buff = vec![];
        for j in i..(i+(len as usize)) {
          buff.push(match self.data.get(j) {
            Some(b) => *b,
            None => {
              self.pos = initial_pos;
              return Err(DrasilDNSError::EOF)
            },
          });
        }

        labels.push(String::from_utf8_lossy(&buff).to_lowercase());
        i += len as usize;
      }
    }

    if jumps == 0 {
      self.seek(i);
    }

    Ok((self.pos - initial_pos, labels))
  }

  /// Writes the provided labels to the buffer
  pub fn write_labels(&mut self, labels: &Vec<String>) -> Result<usize, DrasilDNSError> {
    let initial_pos = self.pos;
    let mut b = Buffer::with_capacity(0);
    b.set_expandable(true);

    for label in labels {
      let label_bytes = label.as_bytes();
      let len = label_bytes.len() as u8;

      if len > 63 {
        return Err(DrasilDNSError::LabelTooLarge);
      }

      b.write_u8(len)?;
      b.write_bytes(label_bytes)?;
    }

    b.write_u8(0)?;

    self.write_buffer(&b)?;
    Ok(self.pos - initial_pos)
  }
}