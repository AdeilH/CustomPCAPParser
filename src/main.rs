//! pcap-parser CLI: decompresses zstd-compressed pcap captures and parses
//! them. Built step by step on the standard library only; see README.md.

use pcap_parser::pcap::GlobalHeader;
use pcap_parser::zstd::frame;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("usage: pcap-parser <capture.pcap.zst> [output]");
        return ExitCode::from(2);
    }
    let path = &args[0];

    let raw = match std::fs::read(path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: cannot read {path}: {e}");
            return ExitCode::FAILURE;
        }
    };

    let start = std::time::Instant::now();
    let decompressed = match frame::decompress(&raw) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("error: zstd decompression failed: {e}");
            return ExitCode::FAILURE;
        }
    };
    let elapsed = start.elapsed();

    println!("decompressed {} bytes in {:?}", decompressed.len(), elapsed);

    let header = match GlobalHeader::parse(&decompressed) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("error: invalid pcap global header: {e}");
            return ExitCode::FAILURE;
        }
    };
    println!("pcap global header:");
    println!("  format:  {}", header.magic);
    println!("  version: {}.{}", header.version_major, header.version_minor);
    println!("  snaplen: {} bytes", header.snaplen);
    println!("  link:    {}", header.network);

    if let Some(out_path) = args.get(1) {
        if let Err(e) = std::fs::write(out_path, &decompressed) {
            eprintln!("error: cannot write {out_path}: {e}");
            return ExitCode::FAILURE;
        }
        println!("wrote {out_path}");
    }

    ExitCode::SUCCESS
}
