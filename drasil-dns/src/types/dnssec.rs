
/// # DNSSEC Algorithm
/// According to RFC4034 :-
/// 
/// > The DNSKEY, RRSIG, and DS RRs use an 8-bit number to identify the
/// > security algorithm being used.  These values are stored in the
/// > "Algorithm number" field in the resource record RDATA.
/// > 
/// > Some algorithms are usable only for zone signing (DNSSEC), some only
/// > for transaction security mechanisms (SIG(0) and TSIG), and some for
/// > both.  Those usable for zone signing may appear in DNSKEY, RRSIG, and
/// > DS RRs.  Those usable for transaction security would be present in
/// > SIG(0) and KEY RRs, as described in RFC2931.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum DNSSECAlgorithm {
  Unknown(u8),
  RSAMD5 = 1, // RSA MD5
  DH = 2, // Diffie-Hellman
  DSA = 3, // DSA/SH-1
  ECC = 4, // Elliptic Curve
  RSASHA1 = 5, // RSA SHA-1
  INDIRECT = 252,
  PRIVATEDNS = 253,
  PRIVATEOID = 254,
}

impl Into<u8> for DNSSECAlgorithm {
  fn into(self) -> u8 {
    match self {
      Self::RSAMD5 => 1,
      Self::DH => 2,
      Self::DSA => 3,
      Self::ECC => 4,
      Self::RSASHA1 => 5,
      Self::INDIRECT => 252,
      Self::PRIVATEDNS => 253,
      Self::PRIVATEOID => 254,
      Self::Unknown(val) => val,
    }
  }
}

impl From<u8> for DNSSECAlgorithm {
  fn from(value: u8) -> Self {
    match value {
      1 => Self::RSAMD5,
      2 => Self::DH,
      3 => Self::DSA,
      4 => Self::ECC,
      5 => Self::RSASHA1,
      252 => Self::INDIRECT,
      253 => Self::PRIVATEDNS,
      254 => Self::PRIVATEOID,
      val => Self::Unknown(val),
    }
  }
}

/// # DNSSEC Digest Type
/// According to RFC4034 :-
/// > A "Digest Type" field in the DS resource record types identifies the
/// > cryptographic digest algorithm used by the resource record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum DNSSECDigestType {
  Unknown(u8),
  SHA1 = 1, // SHA-1
}

impl Into<u8> for DNSSECDigestType {
  fn into(self) -> u8 {
    match self {
      Self::SHA1 => 1,
      Self::Unknown(v) => v,
    }
  }
}

impl From<u8> for DNSSECDigestType {
  fn from(value: u8) -> Self {
    match value {
      1 => Self::SHA1,
      v => Self::Unknown(v),
    }
  }
}