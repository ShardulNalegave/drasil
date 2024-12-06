
/// Provides a builder struct for Packet
pub mod builder;

// ===== Imports =====
use crate::{
  buffer::Buffer,
  error::DrasilDNSError,
  header::Header,
  question::Question,
  record::Record,
};
// ===================

/// # Packet
/// Struct representing a single DNS packet.
#[derive(Debug, Clone)]
pub struct Packet {
  pub header: Header,
  pub questions: Vec<Question>,
  pub answers: Vec<Record>,
  pub authority: Vec<Record>,
  pub additional: Vec<Record>,
}

impl Packet {
  /// Get a DNS packet from bytes.
  pub fn parse(data: &[u8]) -> Result<Self, DrasilDNSError> {
    let mut buff: Buffer = data.into();

    let header = Header::parse(&mut buff)?;

    let mut questions = vec![];
    let mut answers = vec![];
    let mut authority = vec![];
    let mut additional = vec![];

    for _ in 0..header.question_count {
      let q = Question::parse(&mut buff)?;
      questions.push(q);
    }

    for _ in 0..header.answer_count {
      let r = Record::parse(&mut buff)?;
      answers.push(r);
    }

    for _ in 0..header.authority_count {
      let r = Record::parse(&mut buff)?;
      authority.push(r);
    }

    for _ in 0..header.additional_count {
      let r = Record::parse(&mut buff)?;
      additional.push(r);
    }

    Ok(Self {
      header,
      questions,
      answers,
      authority,
      additional,
    })
  }

  /// Convert a DNS packet into bytes
  pub fn to_bytes(&self) -> Result<Vec<u8>, DrasilDNSError> {
    let mut buff = Buffer::default();
    self.header.write_bytes(&mut buff)?;

    for q in &self.questions {
      q.write_bytes(&mut buff)?;
    }

    for r in &self.answers {
      r.write_bytes(&mut buff)?;
    }

    for r in &self.authority {
      r.write_bytes(&mut buff)?;
    }

    for r in &self.additional {
      r.write_bytes(&mut buff)?;
    }

    Ok(buff.into())
  }
}