
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestKind {
  Query = 0,
  Response = 1,
}

impl From<u8> for RequestKind {
  fn from(value: u8) -> Self {
    match value {
      0 => RequestKind::Query,
      1 => RequestKind::Response,
      _ => unreachable!(),
    }
  }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ResponseCode {
  NOERROR = 0,
  FORMERR = 1,
  SERVFAIL = 2,
  NXDOMAIN = 3,
  NOTIMP = 4,
  REFUSED = 5,
}

impl From<u8> for ResponseCode {
  fn from(value: u8) -> Self {
    match value {
      1 => ResponseCode::FORMERR,
      2 => ResponseCode::SERVFAIL,
      3 => ResponseCode::NXDOMAIN,
      4 => ResponseCode::NOTIMP,
      5 => ResponseCode::REFUSED,
      0 | _ => ResponseCode::NOERROR,
    }
  }
}

#[derive(Debug, Copy, Clone)]
pub struct Header {
  pub id: u16,
  pub request_kind: RequestKind,
  pub opcode: u8,
  pub is_authoritative_answer: bool,
  pub is_truncated_message: bool,
  pub is_recursion_desired: bool,
  pub is_recursion_available: bool,
  pub reserved: u8,
  pub response_code: ResponseCode,
  pub question_count: u16,
  pub answer_count: u16,
  pub authority_count: u16,
  pub additional_count: u16,
}

impl From<[u8; 12]> for Header {
  fn from(data: [u8; 12]) -> Self {
    let id = u16::from_be_bytes([
      data[0],
      data[1],
    ]);

    let request_kind = {
      RequestKind::from(data[2] >> 7)
    };

    let opcode = {
      let byte = data[2] & 0b01111000;
      byte >> 3
    };

    let is_authoritative_answer = {
      let byte = data[2] & 0b00000100;
      (byte >> 2) == 1
    };

    let is_truncated_message = {
      let byte = data[2] & 0b00000010;
      (byte >> 1) == 1
    };

    let is_recursion_desired = {
      let byte = data[2] & 0b00000001;
      byte == 1
    };

    let is_recursion_available = {
      (data[3] >> 7) == 1
    };

    let reserved = {
      let byte = data[3] & 0b01110000;
      byte >> 4
    };

    let response_code = {
      ResponseCode::from(data[3] & 0b00001111)
    };

    let question_count = u16::from_be_bytes([
      data[4],
      data[5],
    ]);

    let answer_count = u16::from_be_bytes([
      data[6],
      data[7],
    ]);

    let authority_count = u16::from_be_bytes([
      data[8],
      data[9],
    ]);

    let additional_count = u16::from_be_bytes([
      data[10],
      data[11],
    ]);
    
    Self {
      id,
      request_kind,
      opcode,
      is_authoritative_answer,
      is_truncated_message,
      is_recursion_desired,
      is_recursion_available,
      reserved,
      response_code,
      question_count,
      answer_count,
      authority_count,
      additional_count,
    }
  }
}

impl Into<[u8; 12]> for Header {
  fn into(self) -> [u8; 12] {
    let mut buff = [0; 12];
    buff[0..2].copy_from_slice(&self.id.to_be_bytes());

    let mut flags = 0_u16;
    
    flags |= (self.request_kind as u16) << 15;
    flags |= (self.opcode as u16) << 14;

    if self.is_authoritative_answer {
      flags |= 0b00000100_00000000;
    }

    if self.is_truncated_message {
      flags |= 0b00000010_00000000;
    }

    if self.is_recursion_desired {
      flags |= 0b00000001_00000000;
    }

    if self.is_recursion_available {
      flags |= 0b00000000_10000000;
    }

    flags |= (self.reserved as u16) << 4;
    flags |= self.response_code as u16;

    buff[2..4].copy_from_slice(&flags.to_be_bytes());

    buff[4..6].copy_from_slice(&self.question_count.to_be_bytes());
    buff[6..8].copy_from_slice(&self.answer_count.to_be_bytes());
    buff[8..10].copy_from_slice(&self.authority_count.to_be_bytes());
    buff[10..12].copy_from_slice(&self.additional_count.to_be_bytes());

    buff
  }
}