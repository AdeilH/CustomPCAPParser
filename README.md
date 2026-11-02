# pcap-parser

A pcap capture parser for NYSE Pillar (XASE) market data, written in pure Rust
with **no external crates** (standard library only).

Everything is implemented from scratch, following the relevant specifications:

- **zstd decompression** — implemented from scratch per [RFC 8878]
  (frame/block parsing, Huffman literals, FSE sequence decoding, XXH64 content
  checksum verification).
- **pcap parsing** — per the classic `libpcap` file format (magic, global
  header, per-packet records, both microsecond and nanosecond variants).
- **XDP packet parsing** — planned; the packets in the captures are
  XDP-produced frames.

## Status / roadmap

Work proceeds step by step, one commit per step:

1. [x] Project skeleton (std-only cargo project)
2. [ ] zstd: XXH64 checksum
3. [ ] zstd: reverse bit reader (entropy streams)
4. [ ] zstd: FSE table description + decoding
5. [ ] zstd: Huffman tree description + literal decoding
6. [ ] zstd: frame/block headers, Raw & RLE blocks
7. [ ] zstd: sequences section + compressed blocks
8. [ ] zstd: end-to-end decompression, verified against `zstd` CLI + XXH64
9. [ ] pcap: global header parsing (one capture, `data/`)
10. [ ] pcap: per-packet record headers
11. [ ] XDP: packet payload parsing

## Usage

```sh
cargo run --release -- data/ny4-xase-pillar-a-20230822T002000.pcap.zst
```

The capture files in `data/` (~3.8 GB) are deliberately not tracked by git.

[RFC 8878]: https://www.rfc-editor.org/rfc/rfc8878.html
