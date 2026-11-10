//! pcap-parser: from-scratch, dependency-free market data capture parsing.
//!
//! The library is organized as a pipeline of independent layers; each layer
//! only depends on the ones above it, and the last layer is pluggable:
//!
//! ```text
//! .zst file ──zstd──▶ pcap bytes ──pcap──▶ packet records ──feeds──▶ events
//! ```
//!
//! - [`zstd`]: decompression (RFC 8878, implemented from scratch)
//! - [`pcap`]: global header + packet records (classic libpcap format)
//! - [`net`]: Ethernet/VLAN/IPv4/UDP dissection
//! - [`feeds`]: pluggable market-data protocol parsers ([`feeds::PacketParser`];
//!   XDP today, ITCH and others can be added without touching the layers
//!   above)
//!
//! # Example
//!
//! Decompress a capture, walk its records, and feed every packet through a
//! selectable parser:
//!
//! ```
//! use pcap_parser::feeds::{self, PacketParser};
//! use pcap_parser::pcap::GlobalHeader;
//!
//! // Build an in-memory "capture": pcap global header + one record
//! // holding a 58-byte XDP heartbeat frame (Ethernet/IPv4/UDP).
//! let mut buf = Vec::new();
//! buf.extend_from_slice(&[0x4d, 0x3c, 0xb2, 0xa1]); // nanosecond, LE
//! buf.extend_from_slice(&2u16.to_le_bytes());       // version 2.4
//! buf.extend_from_slice(&4u16.to_le_bytes());
//! buf.extend_from_slice(&0i32.to_le_bytes());       // thiszone
//! buf.extend_from_slice(&0u32.to_le_bytes());       // sigfigs
//! buf.extend_from_slice(&262_144u32.to_le_bytes()); // snaplen
//! buf.extend_from_slice(&1u32.to_le_bytes());       // linktype: Ethernet
//!
//! let mut pkt = Vec::new();
//! pkt.extend_from_slice(&[0x01, 0x00, 0x5e, 0x7d, 0x3b, 0xc3]); // dst
//! pkt.extend_from_slice(&[0xd4, 0xaf, 0xf7, 0xca, 0xe5, 0x05]); // src
//! pkt.extend_from_slice(&[0x08, 0x00]);                         // IPv4
//! // IP header: v4 ihl5, total 44, proto 17 (UDP)
//! pkt.extend_from_slice(&[0x45, 0x00, 0x00, 0x2c, 0, 0, 0, 0, 64, 17, 0, 0]);
//! pkt.extend_from_slice(&[10, 0, 0, 1, 233, 125, 89, 195]);
//! // UDP header: 23503 -> 23503, len 24
//! pkt.extend_from_slice(&[0x5b, 0xcf, 0x5b, 0xcf, 0x00, 0x18, 0, 0]);
//! // XDP packet header: 16-byte heartbeat, no messages
//! pkt.extend_from_slice(&16u16.to_le_bytes());
//! pkt.push(1); // DeliveryFlag: heartbeat
//! pkt.push(0); // NumberMsgs
//! pkt.extend_from_slice(&1u32.to_le_bytes()); // SeqNum
//! pkt.extend_from_slice(&0u32.to_le_bytes()); // SendTime
//! pkt.extend_from_slice(&0u32.to_le_bytes()); // SendTimeNS
//!
//! for field in [0u32, 0u32] {
//!     buf.extend_from_slice(&field.to_le_bytes()); // ts_sec, ts_frac
//! }
//! buf.extend_from_slice(&(pkt.len() as u32).to_le_bytes()); // incl_len
//! buf.extend_from_slice(&(pkt.len() as u32).to_le_bytes()); // orig_len
//! buf.extend_from_slice(&pkt);
//!
//! // 1. pcap layer (the data would normally come from `zstd::frame::decompress`)
//! let header = GlobalHeader::parse(&buf).unwrap();
//!
//! // 2. pick a feed parser by name and 3. run it over every packet
//! let mut parser = feeds::parser_by_name("xdp").unwrap();
//! parser.begin(&header);
//! let mut packets = 0;
//! for rec in header.records(&buf) {
//!     let events = parser.parse_packet(rec.unwrap().data).unwrap();
//!     for ev in events {
//!         println!("{ev}");
//!     }
//!     packets += 1;
//! }
//! assert_eq!(packets, 1);
//! assert!(parser.summarize().contains("heartbeat"));
//! ```

#![forbid(unsafe_code)]

pub mod feeds;
pub mod net;
pub mod pcap;
pub mod zstd;
