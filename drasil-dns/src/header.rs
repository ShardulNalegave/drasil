
// ===== Imports =====
use crate::{buffer::Buffer, error::DrasilDNSError};
// ===================

/// # Request Kind
/// Flag in packet's header. Helps differentiate between queries and its responses.
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
      _ => panic!("invalid value ({}) for RequestKind", value),
    }
  }
}

/// # Response Code
/// Flag representing packet's response.
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

/// # Header
/// Struct representing DNS packet header.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Header {
  pub id: u16,
  pub request_kind: RequestKind,
  pub opcode: u8,
  pub is_authoritative_answer: bool,
  pub is_truncated_message: bool,
  pub is_recursion_desired: bool,
  pub is_recursion_available: bool,
  pub response_code: ResponseCode,
  pub question_count: u16,
  pub answer_count: u16,
  pub authority_count: u16,
  pub additional_count: u16,
}

impl Header {
  pub(crate) fn parse(buff: &mut Buffer) -> Result<Header, DrasilDNSError> {
    buff.read_transaction(|buff| {
      let id = buff.read_u16()?;
      let [flag_high, flag_low] = buff.read_u16()?.to_be_bytes();
      let question_count = buff.read_u16()?;
      let answer_count = buff.read_u16()?;
      let authority_count = buff.read_u16()?;
      let additional_count = buff.read_u16()?;

      let request_kind = RequestKind::from(flag_high >> 7);
      let opcode = (flag_high & 0b01111000) >> 3;

      let is_authoritative_answer = ((flag_high & 0b00000100) >> 2) == 1;
      let is_truncated_message = ((flag_high & 0b00000010) >> 1) == 1;
      let is_recursion_desired = (flag_high & 0b00000001) == 1;
      let is_recursion_available = (flag_low >> 7) == 1;

      let _ = (flag_low & 0b01110000) >> 4; // reserved section
      let response_code = ResponseCode::from(flag_low & 0b00001111);

      Ok(Self {
        id,
        request_kind,
        opcode,
        is_authoritative_answer,
        is_truncated_message,
        is_recursion_desired,
        is_recursion_available,
        response_code,
        question_count,
        answer_count,
        authority_count,
        additional_count,
      })
    })
  }

  pub(crate) fn write_bytes(&self, buff: &mut Buffer) -> Result<(), DrasilDNSError> {
    let mut b = Buffer::with_capacity(12);

    let mut flag_high = 0_u8;
    let mut flag_low = 0_u8;

    flag_high |= (self.request_kind as u8) << 7;
    flag_high |= (self.opcode as u8) << 3;

    if self.is_authoritative_answer {
      flag_high |= 0b00000100;
    }

    if self.is_truncated_message {
      flag_high |= 0b00000010;
    }

    if self.is_recursion_desired {
      flag_high |= 0b00000001;
    }

    if self.is_recursion_available {
      flag_low |= 0b10000000;
    }

    flag_low |= self.response_code as u8;

    b.write_u16(self.id)?;
    b.write_u16(u16::from_be_bytes([flag_high, flag_low]))?;
    b.write_u16(self.question_count)?;
    b.write_u16(self.answer_count)?;
    b.write_u16(self.authority_count)?;
    b.write_u16(self.additional_count)?;

    buff.write_buffer(&b)?;
    Ok(())
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn header_rw() {
    let header = Header {
      id: 100,
      request_kind: RequestKind::Query,
      opcode: 10,
      is_authoritative_answer: false,
      is_truncated_message: false,
      is_recursion_desired: true,
      is_recursion_available: false,
      response_code: ResponseCode::NOERROR,
      question_count: 1,
      answer_count: 0,
      authority_count: 0,
      additional_count: 0,
    };

    let mut b = Buffer::with_capacity(12);
    header.write_bytes(&mut b).expect("Failed at header write");

    b.seek(0);
    let header_after_write = Header::parse(&mut b)
      .expect("Failed at header read");

    assert_eq!(header, header_after_write, "Header is not equal after write+read");
  }
}