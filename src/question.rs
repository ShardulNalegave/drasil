
// ===== Imports =====
use crate::{buffer::Buffer, types::{RecordClass, RecordType}, error::DrasilDNSError};
// ===================

/// # Question
/// Struct representing a question record
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
  pub name: Vec<String>,
  pub record_type: RecordType,
  pub record_class: RecordClass,
}

impl Question {
  pub(crate) fn parse(buff: &mut Buffer) -> Result<Self, DrasilDNSError> {
    buff.read_transaction(|buff| {
      let (_, name) = buff.read_labels(true)?;
      let record_type = buff.read_u16()?.into();
      let record_class = buff.read_u16()?.into();

      Ok(Self { name, record_type, record_class })
    })
  }

  pub(crate) fn write_bytes(&self, buff: &mut Buffer) -> Result<(), DrasilDNSError> {
    let mut b = Buffer::with_capacity(0);
    b.set_expandable(true);

    b.write_labels(&self.name)?;
    b.write_u16(self.record_type.into())?;
    b.write_u16(self.record_class.into())?;

    buff.write_buffer(&b)?;
    Ok(())
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn question_rw() {
    let question = Question {
      name: vec!["google".to_string(), "com".to_string()],
      record_type: RecordType::A,
      record_class: RecordClass::IN,
    };

    let mut b = Buffer::with_capacity(0);
    b.set_expandable(true);

    question.write_bytes(&mut b).expect("Failed to write question");
    
    b.seek(0);
    let question_after_read = Question::parse(&mut b)
      .expect("Failed to read question");

    assert_eq!(question, question_after_read, "Question not equal after write+read");
  }
}