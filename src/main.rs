//! pcap-parser: decompresses zstd-compressed pcap captures and parses them.
//!
//! Built step by step on top of the standard library only; see README.md for
//! the roadmap.

#![forbid(unsafe_code)]

mod zstd;

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 1 {
        eprintln!("usage: pcap-parser <capture.pcap.zst>");
        return ExitCode::from(2);
    }
    let path = &args[0];
    println!("pcap-parser: skeleton ({path})");
    ExitCode::SUCCESS
}
