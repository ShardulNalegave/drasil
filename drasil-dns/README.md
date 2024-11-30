
# Drasil-DNS
Rust crate to easily serialize and deserialize DNS packets.

```rust

// Create packets using the builder utility
let packet1: Packet = PacketBuilder::new(5)
  .with_request_kind(RequestKind::Query)
  .recursion_desired()
  .add_question(Question {
    name: vec!["google".into(), "com".into()],
    record_type: RecordType::A,
    record_class: RecordClass::IN,
  }).build();

// Or just parse a slice of bytes
let data: &[u8] = &[ ... ];
let packet2: Packet = Packet::parse(data).unwrap();

let bytes1: [u8; 512] = packet1.to_bytes().unwrap();
let bytes2: [u8; 512] = packet2.to_bytes().unwrap();

```
