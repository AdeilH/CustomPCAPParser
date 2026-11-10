//! pcap-parser CLI: decompresses zstd-compressed pcap captures and parses
//! them. Built step by step on the standard library only; see README.md.

use pcap_parser::pcap::{timestamp_string, GlobalHeader};
use pcap_parser::zstd::frame;
use std::process::ExitCode;

/// How many sample records to print.
const SAMPLE_RECORDS: usize = 5;

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

    // Walk the packet records.
    let mut records = header.records(&decompressed);
    let mut count: u64 = 0;
    let mut captured_bytes: u64 = 0;
    let mut wire_bytes: u64 = 0;
    let mut first_ts: Option<(u32, u32)> = None;
    let mut last_ts: Option<(u32, u32)> = None;
    let mut samples: Vec<String> = Vec::new();
    for rec in &mut records {
        let rec = match rec {
            Ok(r) => r,
            Err(e) => {
                eprintln!(
                    "error: corrupt record after {} records ({} bytes into record data): {e}",
                    count,
                    records.consumed()
                );
                return ExitCode::FAILURE;
            }
        };
        if (count as usize) < SAMPLE_RECORDS {
            samples.push(format!(
                "  #{:<5} {}  captured {}/{} bytes",
                count + 1,
                rec.header.timestamp_string(header.magic),
                rec.header.incl_len,
                rec.header.orig_len
            ));
        }
        captured_bytes += rec.header.incl_len as u64;
        wire_bytes += rec.header.orig_len as u64;
        first_ts.get_or_insert((rec.header.ts_sec, rec.header.ts_frac));
        last_ts = Some((rec.header.ts_sec, rec.header.ts_frac));
        count += 1;
    }

    println!("packet records:");
    println!("  count:   {count}");
    println!("  captured: {captured_bytes} bytes ({} on wire)", wire_bytes);
    if let (Some(first), Some(last)) = (first_ts, last_ts) {
        println!(
            "  span:    {} .. {}",
            timestamp_string(first.0, first.1, header.magic),
            timestamp_string(last.0, last.1, header.magic),
        );
    }
    for line in &samples {
        println!("{line}");
    }

    if let Some(out_path) = args.get(1) {
        if let Err(e) = std::fs::write(out_path, &decompressed) {
            eprintln!("error: cannot write {out_path}: {e}");
            return ExitCode::FAILURE;
        }
        println!("wrote {out_path}");
    }

    ExitCode::SUCCESS
}
