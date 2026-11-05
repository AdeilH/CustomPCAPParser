//! Huffman decoding for zstd literals, per RFC 8878 Section 4.2.
//!
//! The tree is described as per-symbol *weights* (either stored directly as
//! 4-bit fields or compressed with FSE); the last symbol's weight is deduced
//! by completing the sum of `2^(weight-1)` to the next power of two. Weights
//! are then converted to a flat prefix decoding table of `1 << max_bits`
//! entries.

use super::bitreader::BitReader;
use super::fse;
use super::{Result, ZstdError};

/// Maximum Huffman code length allowed by the format.
const MAX_CODE_BITS: u32 = 11;
/// Maximum stored weight (implies max_bits <= 12 pre-completion checks).
const MAX_WEIGHT: u8 = 12;

/// Flat prefix-code decoding table with `1 << max_bits` entries.
#[derive(Debug, Clone)]
pub struct HuffmanTable {
    max_bits: u32,
    /// Symbol per table index.
    symbols: Vec<u8>,
    /// Code length per table index (the number of bits to consume).
    nb_bits: Vec<u8>,
}

impl HuffmanTable {
    pub fn max_bits(&self) -> u32 {
        self.max_bits
    }

    /// Decode one symbol: peek `max_bits`, look up, consume the code length.
    #[inline]
    pub fn decode_symbol(&self, br: &mut BitReader) -> u8 {
        let idx = br.peek(self.max_bits) as usize;
        let sym = self.symbols[idx];
        br.read(self.nb_bits[idx] as u32);
        sym
    }

    /// Decode exactly `count` symbols into `out`. The stream must be exactly
    /// consumed afterwards (RFC 8878, Section 4.2.2).
    pub fn decode_stream(&self, br: &mut BitReader, count: usize, out: &mut Vec<u8>) -> Result<()> {
        out.reserve(count.saturating_sub(out.len()));
        for _ in 0..count {
            if br.overflowed() {
                return Err(ZstdError::Corrupted("Huffman stream over-read"));
            }
            out.push(self.decode_symbol(br));
        }
        if !br.fully_consumed() {
            return Err(ZstdError::Corrupted("Huffman stream not fully consumed"));
        }
        Ok(())
    }

    /// Build the table from a complete weight list (one entry per symbol,
    /// including the deduced last weight).
    fn from_weights(weights: &[u8]) -> Result<HuffmanTable> {
        // Complete to the next power of two: total = sum of 2^(w-1).
        let mut total: u32 = 0;
        for &w in weights {
            if w > MAX_WEIGHT {
                return Err(ZstdError::Corrupted("Huffman weight too large"));
            }
            if w != 0 {
                total += 1 << (w - 1);
            }
        }
        if total == 0 {
            return Err(ZstdError::Corrupted("Huffman tree has no symbols"));
        }
        // max_bits is chosen so that 2^max_bits > total.
        let max_bits = 31 - total.leading_zeros() + 1;
        if max_bits > MAX_CODE_BITS {
            return Err(ZstdError::Corrupted("Huffman tree too deep"));
        }
        // The last symbol's weight completes the tree; `rest` must be a
        // power of two.
        let rest = (1u32 << max_bits) - total;
        if rest == 0 || (rest & (rest - 1)) != 0 {
            return Err(ZstdError::Corrupted(
                "Huffman weights do not complete to a power of two",
            ));
        }
        let last_weight = (31 - rest.leading_zeros() + 1) as u8;

        let mut weights = weights.to_vec();
        weights.push(last_weight);

        // Number of bits per symbol: max_bits + 1 - weight (0 = absent).
        let nb_of: Vec<u8> = weights
            .iter()
            .map(|&w| if w == 0 { 0 } else { max_bits as u8 + 1 - w })
            .collect();

        // Rank counts and starting positions per weight, ascending.
        let mut rank = vec![0u32; max_bits as usize + 2];
        for &w in &weights {
            if w != 0 {
                rank[w as usize] += 1;
            }
        }
        let mut next_pos: Vec<usize> = vec![0; max_bits as usize + 2];
        let mut acc = 0usize;
        for w in 1..=max_bits as usize {
            next_pos[w] = acc;
            // A weight-w symbol (code length max_bits+1-w) covers
            // 2^(w-1) table slots.
            acc += (rank[w] as usize) << (w - 1);
        }
        if acc != 1usize << max_bits {
            return Err(ZstdError::Corrupted("Huffman tree weight mismatch"));
        }

        let table_size = 1usize << max_bits;
        let mut symbols = vec![0u8; table_size];
        let mut nb_bits = vec![0u8; table_size];
        let mut filled = 0usize;
        // Symbols sorted by weight (ascending), ties by symbol value.
        for s in 0..weights.len() {
            let w = weights[s];
            if w == 0 {
                continue;
            }
            let nb = nb_of[s] as usize;
            let span = 1usize << (w as usize - 1);
            let start = next_pos[w as usize];
            let end = start + span;
            if end > table_size {
                return Err(ZstdError::Corrupted("Huffman table overflow"));
            }
            for slot in &mut symbols[start..end] {
                *slot = s as u8;
            }
            for slot in &mut nb_bits[start..end] {
                *slot = nb as u8;
            }
            next_pos[w as usize] = end;
            filled += span;
        }
        debug_assert_eq!(filled, table_size);

        Ok(HuffmanTable { max_bits, symbols, nb_bits })
    }
}

/// Parse a Huffman tree description; returns the table and the number of
/// bytes consumed (needed to locate the literal streams that follow).
pub fn read_tree_description(data: &[u8]) -> Result<(HuffmanTable, usize)> {
    if data.is_empty() {
        return Err(ZstdError::UnexpectedEof("Huffman tree header"));
    }
    let header = data[0];

    let weights: Vec<u8> = if header < 128 {
        // FSE-compressed weights: `header` bytes of backward bitstream
        // follow the embedded FSE table description.
        let stream_len = header as usize;
        if 1 + stream_len > data.len() {
            return Err(ZstdError::UnexpectedEof("FSE-compressed Huffman weights"));
        }
        let (counts, accuracy_log, table_bytes) =
            fse::read_normalized_counts(&data[1..1 + stream_len], 255, 6)?;
        if table_bytes > stream_len {
            return Err(ZstdError::Corrupted("Huffman weight FSE table overruns stream"));
        }
        let table = fse::build_table(&counts, accuracy_log)?;
        let stream = &data[1 + table_bytes..1 + stream_len];
        let mut br = BitReader::new(stream)?;

        // Two interleaved states share one table; state1 decodes the
        // even-indexed weights, state2 the odd-indexed ones. Termination
        // follows the reference decoder: when a state update would need
        // more bits than remain, its bits are assumed zero and the other
        // state's pending symbol is flushed (RFC 8878, Section 4.2.1.2).
        let mut state1 = br.read(accuracy_log) as usize;
        let mut state2 = br.read(accuracy_log) as usize;
        let mut weights = Vec::new();
        loop {
            weights.push(table.symbol(state1));
            state1 = table.next_state(state1, &mut br);
            if br.overflowed() {
                weights.push(table.symbol(state2));
                break;
            }
            weights.push(table.symbol(state2));
            state2 = table.next_state(state2, &mut br);
            if br.overflowed() {
                weights.push(table.symbol(state1));
                break;
            }
            // Weights cover symbols 0..255; the last is deduced, so at most
            // 255 can be listed.
            if weights.len() > 255 {
                return Err(ZstdError::Corrupted("too many Huffman weights"));
            }
        }
        weights
    } else {
        // Direct representation: 4-bit weights, two per byte, high nibble
        // first; count = header - 127 (the last symbol's weight is deduced).
        let n = (header - 127) as usize;
        let bytes = n.div_ceil(2);
        if 1 + bytes > data.len() {
            return Err(ZstdError::UnexpectedEof("direct Huffman weights"));
        }
        let mut weights = Vec::with_capacity(n);
        for i in 0..n {
            let b = data[1 + i / 2];
            weights.push(if i % 2 == 0 { b >> 4 } else { b & 0xF });
        }
        weights
    };

    let table = HuffmanTable::from_weights(&weights)?;
    let used = if header < 128 { 1 + header as usize } else { 1 + ((header - 127) as usize).div_ceil(2) };
    Ok((table, used))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The RFC 8878 Section 4.2.1 example tree: weights for symbols 0..4 are
    /// [4, 3, 2, 0, 1]; symbol 5's weight (1) is deduced.
    fn rfc_example_table() -> HuffmanTable {
        // Direct representation: 5 weights -> header 127+5 = 132, packed
        // 4,3 | 2,0 | 1,? — 5 nibbles => 3 bytes with a trailing pad nibble.
        // We use the internal constructor instead to avoid pad-nibble edges.
        HuffmanTable::from_weights(&[4, 3, 2, 0, 1]).unwrap()
    }

    #[test]
    fn rfc_example_table_layout() {
        // Table 25: sym4 "0000", sym5 "0001", sym2 "001", sym1 "01", sym0 "1".
        let t = rfc_example_table();
        assert_eq!(t.max_bits(), 4);
        assert_eq!(t.symbols.len(), 16);
        let expect: [(u8, u8); 16] = [
            // index: (symbol, nb_bits)
            (4, 4), (5, 4), (2, 3), (2, 3), (1, 2), (1, 2), (1, 2), (1, 2), //
            (0, 1), (0, 1), (0, 1), (0, 1), (0, 1), (0, 1), (0, 1), (0, 1),
        ];
        for i in 0..16 {
            assert_eq!((t.symbols[i], t.nb_bits[i]), expect[i], "index {i}");
        }
    }

    #[test]
    fn rfc_example_tree_roundtrip() {
        // Note: the RFC 8878 Section 4.2.2 worked example is internally
        // inconsistent (its Table 26 swaps the codes of symbols 4 and 5
        // relative to Table 25). We follow Table 25 / the reference
        // implementation: within a weight, ascending symbol order gets
        // ascending code values. This test encodes literals "0145" with a
        // mini encoder mirroring the reference compressor (codes written in
        // reverse symbol order, each codeword value LSB-first) and verifies
        // our decoder reproduces the literals exactly.
        let t = rfc_example_table();

        // Codeword value per symbol: first table index holding the symbol,
        // shifted back up to a max_bits-wide value.
        let code_of = |sym: u8| -> (u64, u32) {
            let idx = t.symbols.iter().position(|&s| s == sym).unwrap();
            let shift = t.max_bits - t.nb_bits[idx] as u32;
            ((idx as u64) >> shift, t.nb_bits[idx] as u32)
        };

        let literals = [0u8, 1, 4, 5];
        let total_bits: usize = literals.iter().map(|&s| code_of(s).1 as usize).sum();
        let marker_pos = total_bits;
        let len = (marker_pos + 8) / 8;
        let mut data = vec![0u8; len];
        let mut put = |pos: usize, bit: u64| data[pos / 8] |= ((bit & 1) << (pos % 8)) as u8;
        put(marker_pos, 1); // final marker
        let mut pos = 0usize;
        // Encoder writes symbols in reverse order, codeword LSB at the
        // lowest position of its span.
        for &sym in literals.iter().rev() {
            let (code, nb) = code_of(sym);
            for i in 0..nb as usize {
                put(pos + i, (code >> i) & 1);
            }
            pos += nb as usize;
        }

        let mut br = BitReader::new(&data).unwrap();
        let mut out = Vec::new();
        t.decode_stream(&mut br, literals.len(), &mut out).unwrap();
        assert_eq!(out, literals.to_vec());
    }

    #[test]
    fn direct_weights_description() {
        // header 132 = 127 + 5 stored weights [4, 3, 2, 0, 1]; the pad
        // nibble in the last byte must be ignored.
        let data = [132, 0x43, 0x20, 0x10];
        let (t, used) = read_tree_description(&data).unwrap();
        assert_eq!(used, 4);
        assert_eq!(t.max_bits(), 4);
        assert_eq!(t.symbols[8], 0); // "1xxx" -> symbol 0
        assert_eq!(t.symbols[0], 4); // "0000" -> symbol 4
    }

    #[test]
    fn direct_weights_reject_bad_completion() {
        // Weights [3, 1]: total = 4 + 1 = 5 -> max_bits 3, rest = 8 - 5 = 3,
        // which is not a power of two -> the last weight cannot be deduced.
        let data = [129, 0x31];
        assert!(read_tree_description(&data).is_err());
    }

    #[test]
    fn single_weight_pair_tree() {
        // [1] -> total 1 -> max_bits 1, last weight 1: two 1-bit symbols.
        let t = HuffmanTable::from_weights(&[1]).unwrap();
        assert_eq!(t.max_bits(), 1);
        assert_eq!(t.symbols, vec![0, 1]);
        assert_eq!(t.nb_bits, vec![1, 1]);
    }

    #[test]
    fn rejects_degenerate_trees() {
        assert!(HuffmanTable::from_weights(&[0, 0, 0]).is_err()); // no symbols
        assert!(HuffmanTable::from_weights(&[13]).is_err()); // weight too large
    }
}
