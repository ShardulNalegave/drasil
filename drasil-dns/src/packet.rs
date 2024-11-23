
pub mod builder;

// ===== Imports =====
use crate::{
  error::DrasilDNSError,
  header::Header,
  question::Question,
  record::Record,
};
// ===================

#[derive(Debug, Clone)]
pub struct Packet {
  pub header: Header,
  pub questions: Vec<Question>,
  pub answers: Vec<Record>,
  pub authority: Vec<Record>,
  pub additional: Vec<Record>,
}

impl Packet {
  pub fn parse(data: [u8; 512]) -> Result<Self, DrasilDNSError> {
    let header_buff: [u8; 12] = data[0..12]
      .try_into()
      .map_err(|_| DrasilDNSError::CouldntParseHeader)?;
    let header: Header = header_buff.into();

    let mut questions = vec![];
    let mut answers = vec![];
    let mut authority = vec![];
    let mut additional = vec![];

    let mut pos = 12;

    for _ in 0..header.question_count {
      let q = Question::parse(&data, &mut pos)?;
      questions.push(q);
    }

    for _ in 0..header.answer_count {
      let r = Record::parse(&data, &mut pos)?;
      answers.push(r);
    }

    for _ in 0..header.authority_count {
      let r = Record::parse(&data, &mut pos)?;
      authority.push(r);
    }

    for _ in 0..header.additional_count {
      let r = Record::parse(&data, &mut pos)?;
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
}