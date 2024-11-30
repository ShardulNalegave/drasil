
// ===== Imports =====
use crate::{buffer::Buffer, common::{RecordClass, RecordType}, error::DrasilDNSError};
// ===================

#[derive(Debug, Clone)]
pub struct Question {
  pub name: Vec<String>,
  pub record_type: RecordType,
  pub record_class: RecordClass,
}

impl Question {
  pub fn parse(buff: &mut Buffer) -> Result<Self, DrasilDNSError> {
    let name = buff.read_labels()?;
    let record_type = RecordType::from(buff.get_u16()?);
    let record_class = RecordClass::from(buff.get_u16()?);

    Ok(Self { name, record_type, record_class })
  }

  pub fn write_bytes(&self, buff: &mut Buffer) -> Result<(), DrasilDNSError> {
    buff.write_labels(&self.name)?;
    buff.write_u16(self.record_type.into())?;
    buff.write_u16(self.record_class.into())?;
    Ok(())
  }
}