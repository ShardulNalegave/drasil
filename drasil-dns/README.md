
# drasil-dns
drasil-dns is a Rust-based DNS library designed for parsing and handling DNS packets with an emphasis on correctness.
It supports modern DNS features like EDNS (Extension Mechanisms for DNS) and is able to parse DNSSEC (Domain Name System Security Extensions) related data.

## Features
- **EDNS(0):**
  - Has support for EDNS(0) i.e. Extensions for DNS.
  - Properly processes EDNS-specific fields like OPT records, extended flags, and larger packet sizes.
  - Implementation is based on [RFC2671](https://datatracker.ietf.org/doc/html/rfc2671) and [RFC6891](https://datatracker.ietf.org/doc/html/rfc6891)
- **DNSSEC:**
  - Has support for DNSSEC i.e. DNS Security Extensions.
  - Properly processes DNSSEC records like RRSIG, DNSKEY, NEC, NEC3, NEC3PARAM, etc.
  - Implementation is based on [RFC4034](https://datatracker.ietf.org/doc/html/rfc4034), [RFC4035](https://datatracker.ietf.org/doc/html/rfc4035) and [RFC5155](https://datatracker.ietf.org/doc/html/rfc5155)
- **Error Types:** The library provides its own error-types to give useful context in case of errors.

## Installation
Add **drasil-dns** to your project by including it in your `Cargo.toml` file:
```toml
[dependencies]
drasil-dns = "x" # Replace with the latest version
```

## Usage

### Parsing a DNS Packet
```rust
use drasil_dns::{Packet, DrasilDNSError};

let data: &[u8] = &[ ... ]; // Packet data
let res: Result<Packet, DrasilDNSError> = Packet::parse(data);

match res {
  Err(e) => eprintln!("Failed to parse packet: {:?}", e), // Handle errors
  Ok(packet) => println!("{:#?}", packet),
}
```

### Building a new DNS Packet
```rust
use drasil_dns::PacketBuilder;

// Create packets using the builder utility
let builder: PacketBuilder = PacketBuilder::new(5)
  .with_request_kind(RequestKind::Query)
  .recursion_desired()
  .add_question(Question {
    name: vec!["google".into(), "com".into()],
    record_type: RecordType::A,
    record_class: RecordClass::IN,
  })
  .build();
```

## License
This project is licensed under the MIT License. See the `LICENSE` file for details.