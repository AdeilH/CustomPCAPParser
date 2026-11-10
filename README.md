# pcap-parser

A pcap capture parser for NYSE Pillar (XASE) market data, written in pure Rust
with **no external crates** (standard library only).

Everything is implemented from scratch, following the relevant specifications:

- **zstd decompression** — implemented from scratch per [RFC 8878]
  (frame/block parsing, Huffman literals, FSE sequence decoding, XXH64 content
  checksum verification).
- **pcap parsing** — per the classic `libpcap` file format (magic, global
  header, per-packet records, both microsecond and nanosecond variants).
- **XDP payload parsing** — per the [NYSE XDP Common Client Specification]
  (packet header, delivery flags, message framing, common messages) and the
  [NYSE Pillar Integrated Feed Client Specification] (Add/Modify/Delete/
  Execution/Replace/Imbalance/Refresh order messages). Ethernet/VLAN/IPv4/UDP
  dissection down to the XDP payload is included.

## Library layout

The crate is a library (`pcap_parser`) with a thin CLI on top. The pipeline
is layered; each layer depends only on the ones above it, and the last one
is pluggable:

```text
.zst file ──zstd──▶ pcap bytes ──pcap──▶ packet records ──feeds──▶ events
            (from scratch)   (global hdr + records)   (pluggable parsers)
```

- `pcap_parser::zstd` — decompression
- `pcap_parser::pcap` — global header, record iteration
- `pcap_parser::net` — Ethernet/VLAN/IPv4/UDP dissection
- `pcap_parser::feeds` — the seam where market-data protocols plug in:
  implement the `PacketParser` trait, return your parser from
  `feeds::parser_by_name`, and it composes with everything above (see the
  crate docs for a complete working example)

```sh
cargo run --release -- --feed xdp data/ny4-xase-pillar-a-20230822T002000.pcap.zst
cargo run --release -- --list-feeds
```

### Adding a feed module (e.g. NASDAQ ITCH)

1. Create `src/feeds/itch.rs` with an `ItchParser` that implements
   `feeds::PacketParser` (`name()` = `"itch"`, `parse_packet()` dissecting
   the packet — reuse `net::` for transport, add an `Itch` variant to
   `feeds::Event`).
2. Register it in `feeds::parser_by_name` and `PARSER_NAMES`.
3. Nothing above the feed layer changes: the zstd, pcap, and record
   machinery stay untouched.

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
    (`feeds::PacketParser`; XDP registered, ITCH/other feeds follow the
    recipe above without touching the zstd/pcap layers)

## Usage

```sh
cargo run --release -- data/ny4-xase-pillar-a-20230822T002000.pcap.zst
```

The capture files in `data/` (~3.8 GB) are deliberately not tracked by git.

[RFC 8878]: https://www.rfc-editor.org/rfc/rfc8878.html
[NYSE XDP Common Client Specification]: https://www.nyse.com/publicdocs/nyse/data/XDP_Common_Client_Specification_v2.1f.pdf
[NYSE Pillar Integrated Feed Client Specification]: https://www.nyse.com/publicdocs/nyse/data/NYSE_Pillar_Integrated_Feed_Client_Specification.pdf
