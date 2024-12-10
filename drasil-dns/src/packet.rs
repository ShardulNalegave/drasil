
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
#[derive(Debug, Clone, PartialEq, Eq)]
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
      match Record::parse(&mut buff)? {
        None => {},
        Some(r) => answers.push(r),
      }
    }

    for _ in 0..header.authority_count {
      match Record::parse(&mut buff)? {
        None => {},
        Some(r) => authority.push(r),
      }
    }

    for _ in 0..header.additional_count {
      match Record::parse(&mut buff)? {
        None => {},
        Some(r) => additional.push(r),
      }
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

    let mut data: Vec<u8> = buff.into();
    if data.len() < 512 { // DNS packets are at minimum 512 bytes long
      data.resize(512, 0);
    }

    Ok(data)
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::net::Ipv4Addr;
  use crate::{
    header::{RequestKind, ResponseCode},
    types::{RecordClass, RecordType},
    record::edns::EDNSOption,
  };

  #[test]
  fn packet_rw() {
    let packet = Packet {
      header: Header {
        id: 100,
        request_kind: RequestKind::Query,
        opcode: 10,
        is_authoritative_answer: false,
        is_truncated_message: false,
        is_recursion_desired: true,
        is_recursion_available: false,
        response_code: ResponseCode::NOERROR,
        question_count: 1,
        answer_count: 1,
        authority_count: 0,
        additional_count: 1,
      },
      questions: vec![
        Question {
          name: vec!["google".to_string(), "com".to_string()],
          record_type: RecordType::A,
          record_class: RecordClass::IN,
        }
      ],
      answers: vec![
        Record::A {
          domain: vec!["google".to_string(), "com".to_string()],
          addr: Ipv4Addr::from_bits(0x10101010),
          ttl: 60,
          class: RecordClass::IN,
        },
      ],
      authority: vec![],
      additional: vec![
        Record::OPT {
          udp_payload_size: 1024,
          extended_rcode: 0,
          version: 1,
          dnssec_ok: true,
          options: vec![
            EDNSOption::Cookie { client: 100, server: None },
            EDNSOption::Cookie { client: 100, server: Some(150) },
            EDNSOption::ClientSubnet { family: 2, source_netmask: 75, scope_netmask: 0, addr: 0x10101010 },
          ],
        },
      ],
    };

    let mut b = Buffer::with_capacity(0);
    b.set_expandable(true);

    let data= packet.to_bytes()
      .expect("Failed to write packet");
    assert!(data.len() >= 512, "DNS packet is less than minimum size of 512 bytes");

    let packet_after_read = Packet::parse(&data)
      .expect("Failed to read packet");

    assert_eq!(packet, packet_after_read, "Packet not equal after write+read");
  }
}