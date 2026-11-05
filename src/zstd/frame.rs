//! Frame-level zstd decoding: frame headers, blocks, skippable frames,
//! content checksum verification (RFC 8878, Sections 3.1.1 / 3.1.2).

use super::block;
use super::fse;
use super::huffman;
use super::xxhash::xxh64;
use super::{read_u24_le, read_u32_le, Result, ZstdError};

pub const MAGIC_ZSTD: u32 = 0xFD2FB528;
/// Skippable frames use magics 0x184D2A50 through 0x184D2A5F.
const MAGIC_SKIPPABLE_MIN: u32 = 0x184D2A50;
const MAGIC_SKIPPABLE_MAX: u32 = 0x184D2A5F;

const BLOCK_MAX_UNCOMPRESSED: u64 = 128 * 1024;

/// Parsed frame header.
#[derive(Debug, Clone)]
pub struct FrameHeader {
    /// Declared uncompressed size, if present.
    pub frame_content_size: Option<u64>,
    /// Minimum buffer guarantee; offsets must stay within it.
    pub window_size: u64,
    pub dictionary_id: Option<u32>,
    pub has_checksum: bool,
    pub single_segment: bool,
    /// Total bytes of the frame header (magic included).
    pub size: usize,
}

/// Parse the frame header at the start of `data` (which begins with the
/// 4-byte magic number).
pub fn parse_frame_header(data: &[u8]) -> Result<FrameHeader> {
    if data.len() < 5 {
        return Err(ZstdError::UnexpectedEof("frame header descriptor"));
    }
    let fhd = data[4];
    let fcs_flag = fhd >> 6;
    let single_segment = (fhd >> 5) & 1 != 0;
    if (fhd >> 3) & 1 != 0 {
        return Err(ZstdError::Corrupted("frame descriptor reserved bit set"));
    }
    let has_checksum = (fhd >> 2) & 1 != 0;
    let did_flag = fhd & 3;

    let mut pos = 5usize;

    // Window descriptor (absent when single_segment).
    let window_size: u64;
    if single_segment {
        window_size = 0; // filled from FCS below
    } else {
        if data.len() <= pos {
            return Err(ZstdError::UnexpectedEof("window descriptor"));
        }
        let wd = data[pos];
        pos += 1;
        let window_log = 10 + (wd >> 3) as u64;
        let window_base = 1u64 << window_log;
        let window_add = (window_base / 8) * (wd & 7) as u64;
        window_size = window_base + window_add;
    }

    // Dictionary ID.
    let did_size = match did_flag {
        0 => 0,
        1 => 1,
        2 => 2,
        _ => 4,
    };
    let dictionary_id = if did_size > 0 {
        if data.len() < pos + did_size {
            return Err(ZstdError::UnexpectedEof("dictionary id"));
        }
        let mut id: u32 = 0;
        for i in 0..did_size {
            id |= (data[pos + i] as u32) << (8 * i);
        }
        pos += did_size;
        Some(id)
    } else {
        None
    };

    // Frame content size.
    let fcs_size = match fcs_flag {
        0 => {
            if single_segment {
                1
            } else {
                0
            }
        }
        1 => 2,
        2 => 4,
        _ => 8,
    };
    if data.len() < pos + fcs_size {
        return Err(ZstdError::UnexpectedEof("frame content size"));
    }
    let frame_content_size = match fcs_size {
        0 => None,
        1 => Some(data[pos] as u64),
        2 => Some(u16::from_le_bytes([data[pos], data[pos + 1]]) as u64 + 256),
        4 => Some(u32::from_le_bytes([
            data[pos],
            data[pos + 1],
            data[pos + 2],
            data[pos + 3],
        ]) as u64),
        _ => Some(u64::from_le_bytes([
            data[pos],
            data[pos + 1],
            data[pos + 2],
            data[pos + 3],
            data[pos + 4],
            data[pos + 5],
            data[pos + 6],
            data[pos + 7],
        ])),
    };
    pos += fcs_size;

    let mut header = FrameHeader {
        frame_content_size,
        window_size,
        dictionary_id,
        has_checksum,
        single_segment,
        size: pos,
    };
    if single_segment {
        // Window size equals the frame content size.
        header.window_size = header.frame_content_size.ok_or(ZstdError::Corrupted(
            "single segment frame without content size",
        ))?;
    }
    Ok(header)
}

/// Incremental per-frame decoder state: output so far plus the tables and
/// repeat offsets carried across compressed blocks.
pub(crate) struct FrameDecoder<'a> {
    pub data: &'a [u8],
    /// Cursor into `data`, pointing just past the last consumed block.
    pub pos: usize,
    pub header: FrameHeader,
    /// Decompressed bytes of this frame so far.
    pub output: Vec<u8>,
    /// Huffman tree from the previous Compressed_Literals_Block.
    pub huffman: Option<huffman::HuffmanTable>,
    /// Previous sequence FSE tables (for Repeat_Mode), per symbol type.
    pub prev_ll: Option<fse::FseTable>,
    pub prev_of: Option<fse::FseTable>,
    pub prev_ml: Option<fse::FseTable>,
    /// Recent offsets (most recent first); RFC 8878 Section 3.1.1.5.
    pub rep_offsets: [u64; 3],
    pub done: bool,
}

impl<'a> FrameDecoder<'a> {
    fn new(data: &'a [u8], header: FrameHeader) -> Self {
        let pos = header.size;
        let capacity = header.frame_content_size.unwrap_or(0).min(1 << 30) as usize;
        FrameDecoder {
            data,
            pos,
            header,
            output: Vec::with_capacity(capacity),
            huffman: None,
            prev_ll: None,
            prev_of: None,
            prev_ml: None,
            rep_offsets: [1, 4, 8],
            done: false,
        }
    }

    /// Largest block payload this frame may produce.
    fn block_max(&self) -> u64 {
        // Window size bounds block size too (single-segment frames: the
        // content size is the window).
        self.header.window_size.min(BLOCK_MAX_UNCOMPRESSED)
    }

    /// Decode blocks until the last-block flag; returns total bytes consumed
    /// for the frame (header + blocks, checksum excluded).
    fn run(&mut self) -> Result<()> {
        let mut saw_block = false;
        while !self.done {
            let hdr = read_u24_le(self.data, self.pos)?;
            self.pos += 3;
            let last = hdr & 1 != 0;
            let btype = (hdr >> 1) & 3;
            let bsize = (hdr >> 3) as usize;

            match btype {
                0 => {
                    // Raw block: literal copy.
                    if bsize as u64 > self.block_max() {
                        return Err(ZstdError::Corrupted("raw block larger than block maximum"));
                    }
                    if self.pos + bsize > self.data.len() {
                        return Err(ZstdError::UnexpectedEof("raw block content"));
                    }
                    self.output.extend_from_slice(&self.data[self.pos..self.pos + bsize]);
                    self.pos += bsize;
                }
                1 => {
                    // RLE block: one byte, repeated `bsize` times.
                    if bsize as u64 > self.block_max() {
                        return Err(ZstdError::Corrupted("RLE block larger than block maximum"));
                    }
                    if self.pos >= self.data.len() {
                        return Err(ZstdError::UnexpectedEof("RLE block content"));
                    }
                    let byte = self.data[self.pos];
                    self.pos += 1;
                    self.output.resize(self.output.len() + bsize, byte);
                }
                2 => {
                    block::decompress_compressed(self, bsize)?;
                }
                _ => return Err(ZstdError::Corrupted("reserved block type")),
            }
            saw_block = true;
            self.done = last;
        }
        if !saw_block {
            return Err(ZstdError::Corrupted("frame without blocks"));
        }
        Ok(())
    }
}

/// Decompress a single zstd frame starting at `data[0..4] == magic`.
/// Returns the frame content and the total number of input bytes consumed
/// (header + blocks + optional checksum).
pub fn decompress_frame(data: &[u8]) -> Result<(Vec<u8>, usize)> {
    let magic = read_u32_le(data, 0)?;
    if magic != MAGIC_ZSTD {
        return Err(ZstdError::BadMagic { expected: MAGIC_ZSTD, got: magic });
    }
    let header = parse_frame_header(data)?;
    let mut dec = FrameDecoder::new(data, header.clone());
    dec.run()?;

    let mut end = dec.pos;
    if dec.header.has_checksum {
        let stored = read_u32_le(data, end)?;
        end += 4;
        let computed = xxh64(&dec.output, 0) as u32;
        if computed != stored {
            return Err(ZstdError::Corrupted("content checksum mismatch"));
        }
    }
    Ok((dec.output, end))
}

/// Decompress a concatenation of zstd and skippable frames.
pub fn decompress(data: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    let mut frames = 0usize;
    while pos < data.len() {
        let magic = read_u32_le(data, pos)?;
        if (MAGIC_SKIPPABLE_MIN..=MAGIC_SKIPPABLE_MAX).contains(&magic) {
            if data.len() < pos + 8 {
                return Err(ZstdError::UnexpectedEof("skippable frame header"));
            }
            let size = read_u32_le(data, pos + 4)? as usize;
            if data.len() < pos + 8 + size {
                return Err(ZstdError::UnexpectedEof("skippable frame content"));
            }
            pos += 8 + size;
            continue;
        }
        let (content, used) = decompress_frame(&data[pos..])?;
        out.extend_from_slice(&content);
        pos += used;
        frames += 1;
    }
    if frames == 0 {
        return Err(ZstdError::Corrupted("input contains no zstd frames"));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hand-built pure-RLE frame: 200000 × 'A' as two RLE blocks, 4-byte
    /// FCS, no checksum. Header verified against RFC 8878 by construction.
    #[test]
    fn hand_built_rle_frame() {
        let mut data = Vec::new();
        data.extend_from_slice(&MAGIC_ZSTD.to_le_bytes());
        // Descriptor: FCS flag 2 (4 bytes), single segment (bit 5), no
        // checksum -> 0b1010_0000.
        data.push(0b1010_0000);
        data.extend_from_slice(&200_000u32.to_le_bytes()); // FCS
        // Block 1: not last, RLE, 131072 bytes.
        let hdr1 = (131_072u32 << 3) | (1 << 1) | 0;
        data.extend_from_slice(&hdr1.to_le_bytes()[..3]);
        data.push(b'A');
        // Block 2: last, RLE, 68928 bytes.
        let hdr2 = (68_928u32 << 3) | (1 << 1) | 1;
        data.extend_from_slice(&hdr2.to_le_bytes()[..3]);
        data.push(b'A');

        let (out, used) = decompress_frame(&data).unwrap();
        assert_eq!(used, data.len());
        assert_eq!(out.len(), 200_000);
        assert!(out.iter().all(|&b| b == b'A'));
    }

    #[test]
    fn rejects_bad_magic() {
        assert!(matches!(
            decompress_frame(b"\x00\x00\x00\x00"),
            Err(ZstdError::BadMagic { .. })
        ));
    }

    #[test]
    fn rejects_reserved_descriptor_bit() {
        let mut data = Vec::new();
        data.extend_from_slice(&MAGIC_ZSTD.to_le_bytes());
        data.push(0b0000_1000); // reserved bit 3 set
        assert!(decompress_frame(&data).is_err());
    }

    #[test]
    fn parses_all_fcs_widths() {
        // (fcs_flag, bytes) -> value
        let cases: Vec<(u8, Vec<u8>, Option<u64>)> = vec![
            (0, vec![0], Some(0)),                    // single segment, 1 byte
            (1, vec![0x00, 0x00], Some(256)),         // 2 bytes, stored value + 256
            (2, vec![0x40, 0x42, 0x0F, 0x00], Some(1_000_000)),
            (
                3,
                (70_000_000_000u64).to_le_bytes().to_vec(),
                Some(70_000_000_000),
            ),
        ];
        for (flag, bytes, value) in cases {
            let mut data = Vec::new();
            data.extend_from_slice(&MAGIC_ZSTD.to_le_bytes());
            // Single segment (bit 5) + FCS flag in the top two bits.
            data.push(0b0010_0000 | (flag << 6));
            data.extend_from_slice(&bytes);
            let hdr = parse_frame_header(&data).unwrap();
            assert_eq!(hdr.frame_content_size, value);
            assert_eq!(hdr.size, data.len());
        }
    }

    #[test]
    fn window_descriptor_formula() {
        // RFC 8878 Section 3.1.1.1.2: windowLog = 10 + Exponent etc.
        let mut data = Vec::new();
        data.extend_from_slice(&MAGIC_ZSTD.to_le_bytes());
        data.push(0x00); // no FCS, not single segment, no checksum
        data.push(0x58); // exponent 11, mantissa 0 -> 2 MiB
        let hdr = parse_frame_header(&data).unwrap();
        assert_eq!(hdr.window_size, 2 * 1024 * 1024);
        // Mantissa adds base/8 per unit.
        let mut data = data.clone();
        data[5] = 0x5F; // exponent 11, mantissa 7
        let hdr = parse_frame_header(&data).unwrap();
        assert_eq!(hdr.window_size, 2 * 1024 * 1024 + (2 * 1024 * 1024 / 8) * 7);
    }
}
