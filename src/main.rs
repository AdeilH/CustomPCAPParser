//! pcap-parser CLI: decompresses zstd-compressed pcap captures and parses
//! them. Built step by step on the standard library only; see README.md.

use pcap_parser::pcap::{timestamp_string, GlobalHeader};
use pcap_parser::xdp;
use pcap_parser::zstd::frame;
use std::collections::HashMap;
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

    // Walk the packet records, dissecting the XDP payload on the way.
    let mut records = header.records(&decompressed);
    let mut count: u64 = 0;
    let mut captured_bytes: u64 = 0;
    let mut wire_bytes: u64 = 0;
    let mut first_ts: Option<(u32, u32)> = None;
    let mut last_ts: Option<(u32, u32)> = None;
    let mut samples: Vec<String> = Vec::new();

    let mut xdp_packets: u64 = 0;
    let mut other_frames: u64 = 0;
    let mut xdp_messages: u64 = 0;
    let mut delivery_hist: HashMap<u8, u64> = HashMap::new();
    let mut type_hist: HashMap<u16, u64> = HashMap::new();
    let mut sample_add_order: Option<String> = None;
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

        // XDP dissection (Ethernet -> VLAN -> IPv4 -> UDP -> XDP).
        match xdp::udp_payload_of(rec.data) {
            Ok(payload) => {
                let (pkt, msgs) = match xdp::PacketHeader::parse(payload) {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("error: XDP packet header at record {}: {e}", count + 1);
                        return ExitCode::FAILURE;
                    }
                };
                xdp_packets += 1;
                *delivery_hist.entry(pkt.delivery_flag).or_default() += 1;
                for m in msgs {
                    let (hdr, body) = match m {
                        Ok(m) => m,
                        Err(e) => {
                            eprintln!("error: XDP message at record {}: {e}", count + 1);
                            return ExitCode::FAILURE;
                        }
                    };
                    let msg = match xdp::decode(hdr, body) {
                        Ok(m) => m,
                        Err(e) => {
                            eprintln!("error: XDP message decode at record {}: {e}", count + 1);
                            return ExitCode::FAILURE;
                        }
                    };
                    if sample_add_order.is_none() {
                        if let xdp::Message::AddOrder { symbol_index, symbol_seq_num, price, volume, side, .. } = &msg
                        {
                            sample_add_order = Some(format!(
                                "Add Order sym#{} seq {} price {} vol {} side {}",
                                symbol_index, symbol_seq_num, price, volume,
                                *side as char
                            ));
                        }
                    }
                    *type_hist.entry(msg.msg_type()).or_default() += 1;
                    xdp_messages += 1;
                }
            }
            Err(_) => other_frames += 1,
        }

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

    println!("xdp payload:");
    println!(
        "  packets:  {xdp_packets} ({other_frames} non-XDP frames)"
    );
    let mut flags: Vec<_> = delivery_hist.iter().collect();
    flags.sort_by_key(|(_, n)| std::cmp::Reverse(**n));
    let flag_str = flags
        .iter()
        .map(|(f, n)| format!("{} {} ({})", n, xdp::delivery_name(**f), f))
        .collect::<Vec<_>>()
        .join(", ");
    println!("  delivery: {flag_str}");
    println!("  messages: {xdp_messages}");
    let mut types: Vec<_> = type_hist.iter().collect();
    types.sort_by_key(|(t, _)| **t);
    for (t, n) in types {
        println!(
            "    {:>5} {:<24} {}",
            t,
            xdp::msg_type_name(*t),
            n
        );
    }
    if let Some(s) = sample_add_order {
        println!("  first market message: {s}");
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
