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
12. [ ] Build as a library — restructure the crate so the parsing layers
    (zstd, pcap, net, xdp) expose a clean public API for external consumers
    (binary stays a thin wrapper). **Planned next; not started yet.**

## Usage

```sh
cargo run --release -- data/ny4-xase-pillar-a-20230822T002000.pcap.zst
```

The capture files in `data/` (~3.8 GB) are deliberately not tracked by git.

[RFC 8878]: https://www.rfc-editor.org/rfc/rfc8878.html
[NYSE XDP Common Client Specification]: https://www.nyse.com/publicdocs/nyse/data/XDP_Common_Client_Specification_v2.1f.pdf
[NYSE Pillar Integrated Feed Client Specification]: https://www.nyse.com/publicdocs/nyse/data/NYSE_Pillar_Integrated_Feed_Client_Specification.pdf
