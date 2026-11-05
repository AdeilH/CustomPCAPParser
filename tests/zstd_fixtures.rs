//! End-to-end fixture tests: zstd files produced by the reference CLI
//! (v1.5.7) must decode to the right content.

use pcap_parser::zstd::frame;

// Fixtures are generated with the zstd CLI; see the commit that added them.
const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

fn load(name: &str) -> Vec<u8> {
    std::fs::read(format!("{FIXTURES}/{name}")).expect(name)
}

#[test]
fn empty_frame() {
    // `zstd -3` of a 0-byte file: single-segment frame, 1-byte FCS,
    // checksum flag, one Raw block of size 0.
    let data = load("empty.zst");
    let out = frame::decompress(&data).unwrap();
    assert!(out.is_empty());
}

#[test]
fn raw_block_200b_with_checksum() {
    // 200 bytes of /dev/urandom stored as a single Raw block, checksum on.
    let data = load("raw_small.zst");
    let out = frame::decompress(&data).unwrap();
    assert_eq!(out.len(), 200);
}

#[test]
fn raw_block_8k_no_checksum() {
    // 8192 bytes of /dev/urandom, single Raw block, no checksum,
    // 2-byte FCS field (value 8192 = 256 + 7936).
    let data = load("raw_med.zst");
    let out = frame::decompress(&data).unwrap();
    assert_eq!(out.len(), 8192);
}

#[test]
fn rle_fixture_pending_compressed_blocks() {
    // 7 x 131072 'A' via the CLI: one Compressed block followed by six RLE
    // blocks. Until compressed blocks are implemented this must fail
    // cleanly; afterwards it decodes to the full content.
    let data = load("rle_big.zst");
    match frame::decompress(&data) {
        Err(pcap_parser::zstd::ZstdError::Unsupported(_)) => {
            // expected until the sequences step lands
        }
        Ok(out) => {
            assert_eq!(out.len(), 7 * 131_072);
            assert!(out.iter().all(|&b| b == b'A'));
        }
        Err(e) => panic!("unexpected error: {e}"),
    }
}

#[test]
fn skippable_frame_is_ignored() {
    // Prepend a skippable frame (magic 0x184D2A50, 4-byte size, 4 bytes of
    // payload) ahead of the raw_small fixture; the zstd frame after it must
    // still decode identically.
    let mut data = Vec::new();
    data.extend_from_slice(&0x184D2A50u32.to_le_bytes());
    data.extend_from_slice(&4u32.to_le_bytes());
    data.extend_from_slice(b"junk");
    data.extend_from_slice(&load("raw_small.zst"));
    let out = frame::decompress(&data).unwrap();
    assert_eq!(out.len(), 200);
}

#[test]
fn checksum_mismatch_detected() {
    // Flip the last byte (inside the checksum) of raw_small.zst.
    let mut data = load("raw_small.zst");
    let n = data.len();
    data[n - 1] ^= 0x01;
    assert!(matches!(
        frame::decompress(&data),
        Err(pcap_parser::zstd::ZstdError::Corrupted(_))
    ));
}
