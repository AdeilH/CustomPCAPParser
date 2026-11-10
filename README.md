# pcap-parser

A market-data capture parser for NYSE Pillar (XASE) feeds, written in pure
Rust with **no external crates** (standard library only, `#![forbid(unsafe_code)]`).
It decompresses zstd captures, parses pcap structure, dissects
Ethernet/VLAN/IPv4/UDP, and decodes the NYSE **XDP** protocol — with the
protocol layer pluggable so other feeds (e.g. NASDAQ ITCH) can be added
without touching the layers below.

Everything is implemented from scratch against the specifications:

- **zstd decompression** — [RFC 8878]: frame/block parsing, Huffman literals,
  FSE sequence decoding, XXH64 content-checksum verification. Byte-identical
  to the reference `zstd` CLI on the full capture set.
- **pcap parsing** — classic `libpcap` format: global header, per-packet
  records, microsecond and nanosecond variants, both byte orders.
- **XDP payload decoding** — [NYSE XDP Common Client Specification] (packet
  header, delivery flags, message framing, common messages) plus the
  [NYSE Pillar Integrated Feed Client Specification] (order/trade messages).

```text
.zst file ──zstd──▶ pcap bytes ──pcap──▶ packet records ──feeds──▶ typed events
            from scratch     global hdr + records    pluggable protocol parsers
```

The crate builds a **library** (`pcap_parser`) with a thin CLI on top. Each
layer depends only on the ones above it.

## Getting started

Use it from another program with a path dependency:

```toml
[dependencies]
pcap-parser = { path = "/home/Adeel/Projects/Trading/PcapParser" }
```

or a git dependency once this repo is pushed:

```toml
pcap-parser = { git = "https://github.com/you/pcap-parser.git", branch = "main" }
```

(MSRV ≈ 1.73. The name `pcap-parser` is taken on crates.io, so publishing
publicly would require a rename.)

A complete runnable consumer lives in [`examples/walkthrough.rs`](examples/walkthrough.rs):

```sh
cargo run --release --example walkthrough -- data/ny4-xase-pillar-b-20230822T130000.pcap.zst
```

## API

### Layer 1 — `pcap_parser::zstd` (decompression)

```rust
use pcap_parser::zstd::frame;

let decoded: Vec<u8> = frame::decompress(&std::fs::read("capture.pcap.zst")?)?;
```

- `frame::decompress(data) -> Result<Vec<u8>, ZstdError>` — decompresses a
  concatenation of zstd frames (skippable frames are skipped), verifying the
  XXH64 content checksum of every frame that declares one.
- `frame::decompress_frame(data) -> Result<(Vec<u8>, usize)>` — one frame;
  returns its content and consumed byte count.
- `frame::parse_frame_header(data) -> Result<FrameHeader>` — inspect
  `frame_content_size`, `window_size`, `dictionary_id`, `has_checksum`,
  `single_segment` before decoding.
- `zstd::xxhash::xxh64(data, seed)` — the from-scratch XXH64, in case you
  need the hash itself.

The decoder covers the full format: Raw/RLE/Compressed blocks, Huffman
literals (direct + FSE-compressed weights), FSE sequences (predefined, RLE,
compressed, repeat modes), repeat offsets. Dictionary frames are rejected as
`ZstdError::Unsupported`.

### Layer 2 — `pcap_parser::pcap` (capture structure)

```rust
use pcap_parser::pcap::GlobalHeader;

let header = GlobalHeader::parse(&decoded)?;

for rec in header.records(&decoded) {
    let rec = rec?;                                  // PacketRecord
    println!("{} {} bytes",
        rec.header.timestamp_string(header.magic), rec.header.incl_len);
}
```

- `GlobalHeader::parse(data) -> Result<GlobalHeader, PcapError>` — the
  24-byte file header; `PcapError::BadMagic` carries the offending bytes.
- `GlobalHeader` fields: `magic` (`PcapMagic`: micro/nanosecond × LE/BE,
  `is_big_endian()`, `resolution()`), `version_major/minor`, `thiszone`,
  `sigfigs`, `snaplen`, `network` (`LinkType`, e.g. `LinkType::ETHERNET`).
- `header.records(&data)` — iterator over `PacketRecord { header, data }`;
  the iteration ends cleanly at EOF and surfaces truncated headers/data or
  trailing junk as errors. `incl_len > orig_len` is rejected as corrupt.
- `PacketRecordHeader` — `ts_sec`, `ts_frac` (resolution per the magic),
  `incl_len`, `orig_len`; `timestamp_string(magic)` renders e.g.
  `2023-08-22 13:00:00.000945411 UTC`. A free function
  `pcap::timestamp_string(ts_sec, ts_frac, magic)` formats raw values.

### Layer 3 — `pcap_parser::net` (transport dissection)

```rust
use pcap_parser::net;

let frame = net::parse_ethernet(record_data)?;   // VLAN tags peeled off
let ip = net::parse_ipv4(frame.payload)?;        // bounds from total_length
let udp = net::parse_udp(ip.payload)?;           // bounds from UDP length
udp.payload                                      // the datagram payload
```

`EthFrame { dst, src, ethertype, vlans, payload }`,
`Ipv4Packet { src, dst, protocol, payload }`,
`UdpDatagram { src_port, dst_port, payload }`. Ethernet padding is excluded
(lengths are field-authoritative, not slice-authoritative).

### Layer 4 — `pcap_parser::feeds` (pluggable protocol parsers)

The seam between capture plumbing and a market-data protocol.

```rust
use pcap_parser::feeds::{self, PacketParser};

let mut parser = feeds::parser_by_name("xdp").expect("'xdp' is registered");
parser.begin(&header);                       // once, with the pcap header
for rec in header.records(&decoded) {
    for ev in parser.parse_packet(rec?.data)? {
        println!("{ev}");                    // Event implements Display
    }
}
print!("{}", parser.summarize());            // end-of-capture report
```

- `PacketParser` — the trait: `name()`, `describe()`, `begin(&GlobalHeader)`,
  `parse_packet(&[u8]) -> Result<Vec<Event>, FeedError>`, `summarize()`.
  Parsers are stateful (they own their statistics) and may be used as
  `Box<dyn PacketParser>`.
- `feeds::parser_by_name(name) -> Option<Box<dyn PacketParser>>` /
  `feeds::PARSER_NAMES` — the registry. Registered today: `"xdp"`,
  `"none"` (a counting-only parser that doubles as the minimal template).
- `Event` — decoded items; `Event::Xdp(xdp::Message)` today. New feeds add
  a variant.

#### The XDP feed (`feeds::xdp`)

`XdpParser` dissects Ethernet/VLAN/IPv4/UDP down to the XDP packet header,
decodes every message, and accumulates statistics. Non-IP frames on the same
capture are tolerated (`non_feed_packets`); protocol corruption is a hard
error.

Beyond the trait, the public struct exposes the statistics programmatically:

```rust
let parser: feeds::xdp::XdpParser = /* ... */;
parser.packets;             // XDP packets parsed
parser.messages;            // messages decoded
parser.delivery;            // HashMap<DeliveryFlag, count>
parser.types;               // HashMap<message type, count>
parser.first_add_order;     // Option<String>, a rendered sample
```

Typed access to decoded messages (all fields little-endian per the spec):

```rust
match ev {
    feeds::Event::Xdp(xdp::Message::AddOrder { symbol_index, order_id, price, volume, side, .. }) => {
        // build/track book state; side is b'B' or b'S'
    }
    feeds::Event::Xdp(xdp::Message::Execution { trade_id, price, volume, printable, .. }) => {
        // trades
    }
    _ => {}
}
```

Decoded message types: common — Sequence Number Reset (1), Source Time
Reference (2), Symbol Index Mapping (3, incl. symbol/market/price scale),
Security Status (34), Refresh Header (35, full + short forms); Pillar
Integrated — Add Order (100), Modify (101), Delete (102), Execution (103),
Replace (104), Imbalance (105), Add Order Refresh (106), Non-Displayed Trade
(110). Unknown types pass through as `Message::Other`. `msg_type_name()` and
`delivery_name()` map the numeric values to spec names.

**Prices** are raw integer numerators per the spec: divide by
`10^PriceScaleCode` from the symbol's Symbol Index Mapping message
(e.g. `21380000` at scale 6 ⇒ $21.38).

For lower-level control the module also exposes the free functions the
parser is built on: `xdp::PacketHeader::parse(payload)` (header + message
iterator), `xdp::decode(header, body) -> Message`, and
`xdp::udp_payload_of(record_data)` (Ethernet→IPv4→UDP in one call).

#### Errors

`FeedError::Transport(net::NetError)` — L2-L4 failure;
`FeedError::Application(String)` — feed decode failure;
`FeedError::Corrupted(&str)` — structural violations. All library error
types implement `std::error::Error`, so `?` with `Box<dyn Error>` (or
`anyhow`) just works.

### Writing your own feed (e.g. NASDAQ ITCH)

1. Create `src/feeds/itch.rs` with an `ItchParser` implementing
   `PacketParser` (`name()` = `"itch"`). Dissect the packet in
   `parse_packet` — reuse `net::` for transport if the feed is UDP-framed —
   and add an `Itch(..)` variant to `feeds::Event`.
2. Register it in `feeds::parser_by_name` and `PARSER_NAMES`.
3. Nothing above the feed layer changes; the zstd, pcap, and record
   machinery stay untouched.

## CLI usage

```sh
cargo run --release -- --feed xdp data/ny4-xase-pillar-a-20230822T002000.pcap.zst
cargo run --release -- --feed none data/capture.pcap.zst   # count packets only
cargo run --release -- --list-feeds
cargo run --release -- data/capture.pcap.zst out.pcap      # also write decoded pcap
```

Capture files in `data/` (~3.8 GB) are deliberately not tracked by git; the
e2e tests skip themselves when they are absent.

## Status / roadmap

Work proceeds step by step, one commit per step:

1. [x] Project skeleton (std-only cargo project)
2. [x] zstd: XXH64 checksum
3. [x] zstd: reverse bit reader (entropy streams)
4. [x] zstd: FSE table description + decoding
5. [x] zstd: Huffman tree description + literal decoding
6. [x] zstd: frame/block headers, Raw & RLE blocks
7. [x] zstd: sequences section + compressed blocks
8. [x] zstd: end-to-end decompression, verified against `zstd` CLI + XXH64
9. [x] pcap: global header parsing (one capture, `data/`)
10. [x] pcap: per-packet record headers
11. [x] XDP: packet payload parsing
12. [x] Build as a library — layered public API with pluggable feed parsers
13. [ ] ITCH (or other feed) parser following the recipe above
14. [ ] Streaming/incremental interfaces (avoid buffering whole captures)

## References

- [RFC 8878] — Zstandard compression
- [NYSE XDP Common Client Specification]
- [NYSE Pillar Integrated Feed Client Specification]

[RFC 8878]: https://www.rfc-editor.org/rfc/rfc8878.html
[NYSE XDP Common Client Specification]: https://www.nyse.com/publicdocs/nyse/data/XDP_Common_Client_Specification_v2.1f.pdf
[NYSE Pillar Integrated Feed Client Specification]: https://www.nyse.com/publicdocs/nyse/data/NYSE_Pillar_Integrated_Feed_Client_Specification.pdf
