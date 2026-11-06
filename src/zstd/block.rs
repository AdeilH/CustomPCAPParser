//! Compressed block decoding: literals section, sequences section, and
//! sequence execution (RFC 8878, Sections 3.1.1.3 / 3.1.1.4 / 3.1.1.5).

use super::bitreader::BitReader;
use super::frame::FrameDecoder;
use super::fse::{self, FseTable};
use super::huffman;
use super::{Result, ZstdError};

/// Literals-length baseline / extra-bit tables (RFC 8878 Table 16).
const LL_BASELINE: [u32; 36] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, //
    16, 18, 20, 22, 24, 28, 32, 40, 48, 64, 128, 256, 512, 1024, 2048, 4096, //
    8192, 16384, 32768, 65536,
];
const LL_BITS: [u32; 36] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //
    1, 1, 1, 1, 2, 2, 3, 3, 4, 6, 7, 8, 9, 10, 11, 12, //
    13, 14, 15, 16,
];

/// Match-length baseline / extra-bit tables (RFC 8878 Table 17).
const ML_BASELINE: [u32; 53] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, //
    19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, //
    35, 37, 39, 41, 43, 47, 51, 59, 67, 83, 99, 131, 259, 515, 1027, 2051, //
    4099, 8195, 16387, 32771, 65539,
];
const ML_BITS: [u32; 53] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //
    1, 1, 1, 1, 2, 2, 3, 3, 4, 4, 5, 7, 8, 9, 10, 11, //
    12, 13, 14, 15, 16,
];

/// Symbol-type bounds for sequence tables: (max symbol, max accuracy log).
const LL_LIMITS: (usize, u32) = (35, 9);
const OF_LIMITS: (usize, u32) = (31, 8);
const ML_LIMITS: (usize, u32) = (52, 9);

#[derive(Clone, Copy, PartialEq)]
#[repr(u8)]
enum LiteralsType {
    Raw = 0,
    Rle = 1,
    Compressed = 2,
    Treeless = 3,
}

/// Decode one Compressed_Block of `block_size` payload bytes.
///
/// Advances `dec.pos` past the block and appends the decompressed bytes to
/// `dec.output`. Updates the carried Huffman tree, sequence tables, and
/// repeat offsets.
pub(crate) fn decompress_compressed(
    dec: &mut FrameDecoder,
    block_size: usize,
) -> Result<()> {
    let block_start = dec.pos;
    let block_end = block_start + block_size;
    if block_end > dec.data.len() {
        return Err(ZstdError::UnexpectedEof("compressed block content"));
    }
    let data = dec.data;
    let out_before = dec.output.len();

    let (literals, lit_section_size, huffman_update) =
        parse_literals_section(dec, &data[block_start..block_end])?;

    let seq_start = block_start + lit_section_size;
    let seq_data = &data[seq_start..block_end];
    decode_sequences(dec, seq_data, &literals)?;

    if let Some(table) = huffman_update {
        dec.huffman = Some(table);
    }

    let produced = dec.output.len() - out_before;
    if produced as u64 > dec.block_max() {
        return Err(ZstdError::Corrupted("block decompressed size exceeds maximum"));
    }
    dec.pos = block_end;
    Ok(())
}

/// Parse the literals section at the start of `block`; returns the
/// regenerated literals, the section's total size, and (when the section
/// carried a new tree) the Huffman table to carry forward.
fn parse_literals_section(
    dec: &FrameDecoder,
    block: &[u8],
) -> Result<(Vec<u8>, usize, Option<huffman::HuffmanTable>)> {
    if block.is_empty() {
        return Err(ZstdError::UnexpectedEof("literals section header"));
    }
    let b0 = block[0];
    let ltype = match b0 & 3 {
        0 => LiteralsType::Raw,
        1 => LiteralsType::Rle,
        2 => LiteralsType::Compressed,
        _ => LiteralsType::Treeless,
    };
    let size_format = (b0 >> 2) & 3;

    let (regen, header_size): (usize, usize);
    let compressed_size: usize;
    match ltype {
        LiteralsType::Raw | LiteralsType::Rle => {
            // Size formats 00/10: 1 byte; 01: 2 bytes; 11: 3 bytes.
            match size_format {
                0 | 2 => {
                    regen = (b0 >> 3) as usize;
                    header_size = 1;
                }
                1 => {
                    if block.len() < 2 {
                        return Err(ZstdError::UnexpectedEof("literals header"));
                    }
                    regen = ((b0 >> 4) as usize) | ((block[1] as usize) << 4);
                    header_size = 2;
                }
                _ => {
                    if block.len() < 3 {
                        return Err(ZstdError::UnexpectedEof("literals header"));
                    }
                    regen = ((b0 >> 4) as usize)
                        | ((block[1] as usize) << 4)
                        | ((block[2] as usize) << 12);
                    header_size = 3;
                }
            }
            compressed_size = match ltype {
                LiteralsType::Raw => regen,
                _ => 1,
            };
        }
        LiteralsType::Compressed | LiteralsType::Treeless => {
            // Size formats: 00 (1 stream, 10/10 bits, 3-byte header),
            // 01 (4 streams, 10/10), 10 (4 streams, 14/14, 4-byte),
            // 11 (4 streams, 18/18, 5-byte).
            let (width, streams, header_size_h): (u32, usize, usize) = match size_format {
                0 => (10, 1, 3),
                1 => (10, 4, 3),
                2 => (14, 4, 4),
                _ => (18, 4, 5),
            };
            if block.len() < header_size_h {
                return Err(ZstdError::UnexpectedEof("literals header"));
            }
            let mut v: u64 = 0;
            for (i, &b) in block[..header_size_h].iter().enumerate() {
                v |= (b as u64) << (8 * i);
            }
            regen = ((v >> 4) as usize) & ((1 << width) - 1);
            compressed_size = ((v >> (4 + width)) as usize) & ((1 << width) - 1);
            header_size = header_size_h;
            let _ = streams; // used below via size_format
        }
    }

    if regen > dec.block_max() as usize {
        return Err(ZstdError::Corrupted("literals size exceeds block maximum"));
    }
    let section_size = header_size + compressed_size;
    if section_size > block.len() {
        return Err(ZstdError::Corrupted("literals section overruns block"));
    }

    let mut literals = Vec::with_capacity(regen);
    let mut huffman_update = None;

    match ltype {
        LiteralsType::Raw => {
            literals.extend_from_slice(&block[header_size..header_size + regen]);
        }
        LiteralsType::Rle => {
            literals.resize(regen, block[header_size]);
        }
        LiteralsType::Compressed | LiteralsType::Treeless => {
            let mut cursor = header_size;
            // The table the streams decode with: freshly parsed for
            // Compressed blocks, carried for Treeless ones.
            let tree = if ltype == LiteralsType::Compressed {
                let (table, used) =
                    huffman::read_tree_description(&block[cursor..cursor + compressed_size])?;
                cursor += used;
                huffman_update = Some(table.clone());
                table
            } else {
                match dec.huffman.as_ref() {
                    Some(t) => t.clone(),
                    None => {
                        return Err(ZstdError::Corrupted(
                            "treeless literals block without a previous Huffman tree",
                        ))
                    }
                }
            };

            // The streams region: `compressed_size` bytes minus any tree.
            let streams = &block[cursor..header_size + compressed_size];
            let streams_total = streams.len();
            if size_format == 0 {
                // Single stream covering everything.
                let mut br = BitReader::new(streams)?;
                tree.decode_stream(&mut br, regen, &mut literals)?;
            } else {
                // Four streams behind a 6-byte jump table.
                if streams_total < 6 {
                    return Err(ZstdError::Corrupted("literals jump table truncated"));
                }
                let s1 = u16::from_le_bytes([streams[0], streams[1]]) as usize;
                let s2 = u16::from_le_bytes([streams[2], streams[3]]) as usize;
                let s3 = u16::from_le_bytes([streams[4], streams[5]]) as usize;
                let used = 6 + s1 + s2 + s3;
                if used > streams_total {
                    return Err(ZstdError::Corrupted("literals stream sizes overflow region"));
                }
                if regen < 6 {
                    return Err(ZstdError::Corrupted("4-stream literals too small"));
                }
                let seg = (regen + 3) / 4;
                let sizes = [seg, seg, seg, regen - 3 * seg];
                let mut off = 6;
                for (i, &count) in sizes.iter().enumerate() {
                    let end = if i == 3 { streams_total } else { off + [s1, s2, s3][i] };
                    let stream = &streams[off..end];
                    off = end;
                    let mut br = BitReader::new(stream)?;
                    tree.decode_stream(&mut br, count, &mut literals)?;
                }
            }
        }
    }

    debug_assert_eq!(literals.len(), regen);
    Ok((literals, section_size, huffman_update))
}

/// Parse the three sequence FSE tables per Symbol_Compression_Modes and
/// execute the sequences (RFC 8878, Sections 3.1.1.3.2 / 3.1.1.4 / 3.1.1.5).
fn decode_sequences(dec: &mut FrameDecoder, seq: &[u8], literals: &[u8]) -> Result<()> {
    if seq.is_empty() {
        return Err(ZstdError::UnexpectedEof("sequences section"));
    }

    // Number_of_Sequences: 1, 2 or 3 bytes.
    let mut pos: usize;
    let b0 = seq[0];
    let nb_sequences: usize = if b0 == 0 {
        return append_remaining_literals(dec, literals);
    } else if b0 < 128 {
        pos = 1;
        b0 as usize
    } else if b0 < 255 {
        if seq.len() < 2 {
            return Err(ZstdError::UnexpectedEof("sequence count"));
        }
        pos = 2;
        (((b0 - 128) as usize) << 8) + seq[1] as usize
    } else {
        if seq.len() < 3 {
            return Err(ZstdError::UnexpectedEof("sequence count"));
        }
        pos = 3;
        (seq[1] as usize) + ((seq[2] as usize) << 8) + 0x7F00
    };

    // Symbol_Compression_Modes.
    if seq.len() <= pos {
        return Err(ZstdError::UnexpectedEof("symbol compression modes"));
    }
    let modes = seq[pos];
    pos += 1;
    if modes & 3 != 0 {
        return Err(ZstdError::Corrupted("symbol compression modes reserved bits set"));
    }
    let ll_mode = (modes >> 6) & 3;
    let of_mode = (modes >> 4) & 3;
    let ml_mode = (modes >> 2) & 3;

    // Tables in order: LL, OF, ML. Predefined/RLE/FSE update the carried
    // tables; Repeat reuses them without updating.
    let ll_table = read_sequence_table(dec, ll_mode, LL_LIMITS, &mut pos, seq)?;
    let of_table = read_sequence_table(dec, of_mode, OF_LIMITS, &mut pos, seq)?;
    let ml_table = read_sequence_table(dec, ml_mode, ML_LIMITS, &mut pos, seq)?;

    if pos > seq.len() {
        return Err(ZstdError::Corrupted("sequence tables overrun section"));
    }
    let mut br = BitReader::new(&seq[pos..])?;

    // Initial states: Literals_Length, then Offset, then Match_Length.
    let mut ll_state = br.read(ll_table.accuracy_log) as usize;
    let mut of_state = br.read(of_table.accuracy_log) as usize;
    let mut ml_state = br.read(ml_table.accuracy_log) as usize;

    let mut lit_cursor = 0usize;
    for i in 0..nb_sequences {
        let ll_code = ll_table.symbol(ll_state) as usize;
        let of_code = of_table.symbol(of_state) as usize;
        let ml_code = ml_table.symbol(ml_state) as usize;
        if ll_code > LL_LIMITS.0 || of_code > OF_LIMITS.0 || ml_code > ML_LIMITS.0 {
            return Err(ZstdError::Corrupted("sequence code out of range"));
        }

        // Extra bits are read offset-first, then match length, then literals
        // length (RFC 8878, Section 3.1.1.3.2.1.2).
        let offset_value = (1u64 << of_code) + br.read(of_code as u32);
        let match_length = ML_BASELINE[ml_code] as u64 + br.read(ML_BITS[ml_code]);
        let literals_length = LL_BASELINE[ll_code] as u64 + br.read(LL_BITS[ll_code]);

        if i + 1 < nb_sequences {
            ll_state = ll_table.next_state(ll_state, &mut br);
            ml_state = ml_table.next_state(ml_state, &mut br);
            of_state = of_table.next_state(of_state, &mut br);
        }

        let offset = resolve_offset(dec, offset_value, literals_length as usize)?;
        let ll = literals_length as usize;
        let ml = match_length as usize;

        // Literal copy.
        if lit_cursor + ll > literals.len() {
            return Err(ZstdError::Corrupted("sequence consumes more literals than present"));
        }
        dec.output.extend_from_slice(&literals[lit_cursor..lit_cursor + ll]);
        lit_cursor += ll;

        // Match copy: `offset` bytes back from the current position,
        // overlapping-safe.
        let out_len = dec.output.len();
        if offset as usize > out_len {
            return Err(ZstdError::Corrupted("match offset beyond decoded output"));
        }
        let start = out_len - offset as usize;
        if offset >= match_length {
            // Non-overlapping match: bulk copy.
            dec.output.extend_from_within(start..start + ml);
        } else {
            // Overlapping match: byte-by-byte (RLE-style run).
            for i in 0..ml {
                let b = dec.output[start + i];
                dec.output.push(b);
            }
        }
    }

    // Remaining literals are appended verbatim (RFC 8878, Section 3.1.1.3.2).
    if lit_cursor > literals.len() {
        return Err(ZstdError::Corrupted("literals cursor overrun"));
    }
    dec.output.extend_from_slice(&literals[lit_cursor..]);

    // The bitstream must be exactly consumed (RFC 8878, Section 3.1.1.3.2.1.2).
    if !br.fully_consumed() {
        return Err(ZstdError::Corrupted("sequences bitstream not fully consumed"));
    }
    Ok(())
}

fn append_remaining_literals(dec: &mut FrameDecoder, literals: &[u8]) -> Result<()> {
    dec.output.extend_from_slice(literals);
    Ok(())
}

/// Resolve the sequence's offset from `offset_value` and update the
/// recent-offset history (RFC 8878, Sections 3.1.1.4 / 3.1.1.5).
fn resolve_offset(
    dec: &mut FrameDecoder,
    offset_value: u64,
    literals_length: usize,
) -> Result<u64> {
    if offset_value > 3 {
        let offset = offset_value - 3;
        let rep = &mut dec.rep_offsets;
        *rep = [offset, rep[0], rep[1]];
        return Ok(offset);
    }

    // Repeat codes; shifted by one when the sequence has no literals.
    let ll0 = literals_length == 0;
    let rep = dec.rep_offsets;
    let (offset, new): (u64, [u64; 3]) = match (offset_value, ll0) {
        (1, false) => (rep[0], rep),                        // most recent, unchanged
        (1, true) => (rep[1], [rep[1], rep[0], rep[2]]),    // second most recent
        (2, false) => (rep[1], [rep[1], rep[0], rep[2]]),
        (2, true) => (rep[2], [rep[2], rep[0], rep[1]]),    // third most recent
        (3, false) => (rep[2], [rep[2], rep[0], rep[1]]),
        (3, true) => {
            // rep1 - 1 with a history shift (RFC 8878 Section 3.1.1.5).
            let offset = rep[0].checked_sub(1).ok_or(ZstdError::Corrupted(
                "repeat offset 3 with literals_length 0 would produce offset 0",
            ))?;
            if offset == 0 {
                return Err(ZstdError::Corrupted("zero repeat offset"));
            }
            (offset, [offset, rep[0], rep[1]])
        }
        _ => unreachable!(),
    };
    dec.rep_offsets = new;
    Ok(offset)
}

/// Read one sequence table description per its compression mode; advances
/// `pos` and updates the carried table unless in Repeat_Mode.
fn read_sequence_table(
    dec: &mut FrameDecoder,
    mode: u8,
    limits: (usize, u32),
    pos: &mut usize,
    seq: &[u8],
) -> Result<FseTable> {
    let (table, store): (FseTable, bool) = match mode {
        0 => (predefined_table(limits)?, true),
        1 => {
            if *pos >= seq.len() {
                return Err(ZstdError::UnexpectedEof("RLE mode table symbol"));
            }
            let symbol = seq[*pos] as usize;
            if symbol > limits.0 {
                return Err(ZstdError::Corrupted("RLE table symbol out of range"));
            }
            *pos += 1;
            (
                FseTable {
                    accuracy_log: 0,
                    symbols: vec![symbol as u8],
                    nb_bits: vec![0],
                    baseline: vec![0],
                },
                true,
            )
        }
        2 => {
            let (counts, accuracy_log, used) =
                fse::read_normalized_counts(&seq[*pos..], limits.0, limits.1)?;
            let table = fse::build_table(&counts, accuracy_log)?;
            *pos += used;
            (table, true)
        }
        _ => {
            // Repeat_Mode: reuse the previous table of this symbol type.
            let prev = match limits {
                LL_LIMITS => dec.prev_ll.as_ref(),
                OF_LIMITS => dec.prev_of.as_ref(),
                _ => dec.prev_ml.as_ref(),
            };
            match prev {
                Some(t) => (t.clone(), false),
                None => {
                    return Err(ZstdError::Corrupted(
                        "repeat mode without a previous sequence table",
                    ))
                }
            }
        }
    };
    if store {
        match limits {
            LL_LIMITS => dec.prev_ll = Some(table.clone()),
            OF_LIMITS => dec.prev_of = Some(table.clone()),
            _ => dec.prev_ml = Some(table.clone()),
        }
    }
    Ok(table)
}

/// Build the predefined table for a symbol type (RFC 8878 Section 3.1.1.3.2.2).
fn predefined_table(limits: (usize, u32)) -> Result<FseTable> {
    match limits {
        LL_LIMITS => fse::predefined_ll(),
        OF_LIMITS => fse::predefined_of(),
        _ => fse::predefined_ml(),
    }
}
