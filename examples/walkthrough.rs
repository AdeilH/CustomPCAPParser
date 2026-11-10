//! End-to-end walkthrough of the library pipeline, the way an external
//! program uses it:
//!
//! ```text
//! .zst ──zstd──▶ pcap bytes ──pcap──▶ records ──feeds::PacketParser──▶ typed messages
//! ```
//!
//! Run against a capture:
//!
//! ```sh
//! cargo run --release --example walkthrough -- data/ny4-xase-pillar-b-20230822T130000.pcap.zst
//! ```

use std::collections::HashMap;

use pcap_parser::feeds::{self, Event};
use pcap_parser::feeds::xdp;
use pcap_parser::pcap::GlobalHeader;
use pcap_parser::zstd::frame;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .expect("usage: walkthrough <capture.pcap.zst>");

    // ---- Layer 1: zstd --------------------------------------------------
    // Decompresses all frames, verifies XXH64 content checksums, skips
    // skippable frames.
    let decoded = frame::decompress(&std::fs::read(path)?)?;

    // ---- Layer 2: pcap --------------------------------------------------
    let header = GlobalHeader::parse(&decoded)?;
    println!(
        "capture: pcap v{}.{} ({}) snaplen {} link {}",
        header.version_major, header.version_minor, header.magic, header.snaplen, header.network
    );

    // ---- Layer 3: feeds (pluggable) --------------------------------------
    // Registry-selected, run as a trait object: the code below does not know
    // which protocol it is driving beyond the `Event` enum.
    let mut parser = feeds::parser_by_name("xdp").expect("'xdp' is registered");
    parser.begin(&header);

    let mut packets = 0u64;
    let mut buy_orders = 0u64;
    let mut sell_orders = 0u64;
    let mut orders_shown = 0u32;
    let mut trades: HashMap<u32, u64> = HashMap::new(); // price -> volume
    let mut symbols = HashMap::new(); // symbol index -> name

    for rec in header.records(&decoded) {
        let rec = rec?;
        packets += 1;
        for ev in parser.parse_packet(rec.data)? {
            let Event::Xdp(msg) = ev;
            match msg {
                xdp::Message::SymbolIndexMapping { symbol_index, symbol, .. } => {
                    symbols.insert(symbol_index, symbol.to_string());
                }
                xdp::Message::AddOrder { side, price, volume, symbol_index, .. } => {
                    match side {
                        b'B' => buy_orders += 1,
                        b'S' => sell_orders += 1,
                        _ => {}
                    }
                    if orders_shown < 5 {
                        orders_shown += 1;
                        let name = symbols
                            .get(&symbol_index)
                            .map(String::as_str)
                            .unwrap_or("?");
                        println!("add: {name} side {} price {price} vol {volume}", side as char);
                    }
                }
                xdp::Message::Execution { price, volume, .. }
                | xdp::Message::NonDisplayedTrade { price, volume, .. } => {
                    *trades.entry(price).or_default() += volume as u64;
                }
                _ => {}
            }
        }
    }

    // ---- Programmatic statistics (public parser fields) -----------------
    println!(
        "{} packets; orders B/S {}/{}; executed shares {} across {} price levels",
        packets,
        buy_orders,
        sell_orders,
        trades.values().sum::<u64>(),
        trades.len()
    );

    // The parser also renders a human-readable report.
    print!("{}", parser.summarize());
    Ok(())
}
