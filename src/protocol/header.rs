
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RequestKind {
  Query = 0,
  Response = 1,
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
  pub response_code: u8,
  pub question_count: u16,
  pub answer_count: u16,
  pub authority_count: u16,
  pub additional_count: u16,
}

impl Header {
  pub fn parse(data: [u8; 12]) -> Self {
    let id = {
      let high = data[0] as u16;
      let low = data[1] as u16;
      (high << 8) + low
    };

    let request_kind = {
      let byte = data[2];
      match byte >> 7 {
        0 => RequestKind::Query,
        1 => RequestKind::Response,
        _ => unreachable!()
      }
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
      data[3] & 0b00001111
    };

    let question_count = {
      let high = data[4] as u16;
      let low = data[5] as u16;
      (high << 8) + low
    };

    let answer_count = {
      let high = data[6] as u16;
      let low = data[7] as u16;
      (high << 8) + low
    };

    let authority_count = {
      let high = data[8] as u16;
      let low = data[9] as u16;
      (high << 8) + low
    };

    let additional_count = {
      let high = data[10] as u16;
      let low = data[11] as u16;
      (high << 8) + low
    };
    
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