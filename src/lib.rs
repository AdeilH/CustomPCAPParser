//! pcap-parser library: from-scratch zstd decompression and pcap parsing.
//!
//! Standard library only — no external crates.

#![forbid(unsafe_code)]

pub mod net;
pub mod pcap;
pub mod xdp;
pub mod zstd;
