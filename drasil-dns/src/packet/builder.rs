
// ===== Imports =====
use crate::{
  header::{Header, RequestKind, ResponseCode}, packet::Packet, question::Question, record::Record
};
// ===================

/// # Packet Builder
/// Utility struct to construct DNS packets.
pub struct PacketBuilder {
  id: u16,
  request_kind: RequestKind,
  opcode: u8,
  is_authoritative_answer: bool,
  is_truncated_message: bool,
  is_recursion_desired: bool,
  is_recursion_available: bool,
  reserved: u8,
  response_code: ResponseCode,

  questions: Vec<Question>,
  answers: Vec<Record>,
  authority: Vec<Record>,
  additional: Vec<Record>,
}

impl PacketBuilder {
  /// Create a new builder with the provided ID.
  pub fn new(id: u16) -> Self {
    Self {
      id,
      request_kind: RequestKind::Query,
      opcode: 0,
      is_authoritative_answer: false,
      is_truncated_message: false,
      is_recursion_desired: false,
      is_recursion_available: false,
      response_code: ResponseCode::NOERROR,
      reserved: 0,
      questions: vec![],
      answers: vec![],
      authority: vec![],
      additional: vec![],
    }
  }

  /// Build a new packet from the specified options.
  pub fn build(self) -> Packet {
    Packet {
      header: Header {
        id: self.id,
        request_kind: self.request_kind,
        opcode: self.opcode,
        is_authoritative_answer: self.is_authoritative_answer,
        is_truncated_message: self.is_truncated_message,
        is_recursion_desired: self.is_recursion_desired,
        is_recursion_available: self.is_recursion_available,
        reserved: self.reserved,
        response_code: self.response_code,
        question_count: self.questions.len() as u16,
        answer_count: self.answers.len() as u16,
        authority_count: self.authority.len() as u16,
        additional_count: self.additional.len() as u16,
      },
      questions: self.questions,
      answers: self.answers,
      authority: self.authority,
      additional: self.additional,
    }
  }

  /// Specify the request kind for the packet
  pub fn with_request_kind(mut self, kind: RequestKind) -> Self {
    self.request_kind = kind;
    self
  }

  /// Set opcode for the packet
  pub fn with_opcode(mut self, opcode: u8) -> Self {
    self.opcode = opcode & 0b00001111;
    self
  }

  /// Sets authoritative answer flag to true
  pub fn authoritative_answer(mut self) -> Self {
    self.is_authoritative_answer = true;
    self
  }

  /// Sets truncated message flag to true
  pub fn truncated_message(mut self) -> Self {
    self.is_truncated_message = true;
    self
  }

  /// Sets recursion desired flag to true
  pub fn recursion_desired(mut self) -> Self {
    self.is_recursion_desired = true;
    self
  }

  /// Sets recursion available flag to true
  pub fn recursion_available(mut self) -> Self {
    self.is_recursion_available = true;
    self
  }

  /// Add a new question to the packet
  pub fn add_question(mut self, question: Question) -> Self {
    self.questions.push(question);
    self
  }

  /// Add a new answer record to the packet
  pub fn add_answer(mut self, record: Record) -> Self {
    self.answers.push(record);
    self
  }

  /// Add a new authority record to the packet
  pub fn add_authority(mut self, record: Record) -> Self {
    self.authority.push(record);
    self
  }

  /// Add a new additional record to the packet
  pub fn add_additional(mut self, record: Record) -> Self {
    self.additional.push(record);
    self
  }
}