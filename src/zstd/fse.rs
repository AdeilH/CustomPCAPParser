//! FSE (Finite State Entropy) decoding, per RFC 8878 Section 4.1.
//!
//! An FSE decoding table maps a state to `(symbol, nb_bits, baseline)`:
//! the symbol is emitted, `nb_bits` bits are consumed and added to
//! `baseline` to form the next state. Tables come either from an embedded
//! "normalized counts" description (read from a *forward* LSB-first
//! bitstream) or from the predefined distributions in Section 3.1.1.3.2.2.

use super::bitreader::BitReader;
use super::{Result, ZstdError};

/// Maximum supported accuracy log across all contexts (sequences tables).
/// The format allows up to 9 for literals/match length and 8 for offsets;
/// Huffman-weight tables are capped at 6. We accept up to 9 and let callers
/// pass stricter bounds where the spec requires them.
pub const MAX_ACCURACY_LOG: u32 = 9;

/// A built FSE decoding table of `1 << accuracy_log` states.
#[derive(Debug, Clone)]
pub struct FseTable {
    pub accuracy_log: u32,
    /// Symbol emitted in each state.
    pub symbols: Vec<u8>,
    /// Bits to consume when leaving each state.
    pub nb_bits: Vec<u8>,
    /// Baseline added to the consumed bits to form the next state.
    pub baseline: Vec<u16>,
}

impl FseTable {
    pub fn state_count(&self) -> usize {
        self.symbols.len()
    }

    /// Symbol decoded in `state`.
    #[inline]
    pub fn symbol(&self, state: usize) -> u8 {
        self.symbols[state]
    }

    /// Advance from `state`: consume the state's bits from `br` and return
    /// the next state.
    #[inline]
    pub fn next_state(&self, state: usize, br: &mut BitReader) -> usize {
        let bits = self.nb_bits[state] as u32;
        (self.baseline[state] as u64 + br.read(bits)) as usize
    }
}

/// Forward (LSB-first from byte 0) bit reader, used only for the
/// FSE table description bitstream, which — unlike entropy streams — is
/// read front to back (RFC 8878, Section 4.1.1).
struct ForwardBitReader<'a> {
    data: &'a [u8],
    pos: usize, // bit position
}

impl<'a> ForwardBitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        ForwardBitReader { data, pos: 0 }
    }

    fn read(&mut self, n: u32) -> u64 {
        let v = self.peek(n);
        self.pos += n as usize;
        v
    }

    fn peek(&self, n: u32) -> u64 {
        debug_assert!((1..=32).contains(&n));
        if n == 0 {
            return 0;
        }
        let n = n as usize;
        let byte = self.pos / 8;
        let off = self.pos % 8;
        // Load up to 8 bytes from `byte`, little-endian, zero-padded.
        let mut container = 0u64;
        for k in 0..8usize {
            if let Some(&b) = self.data.get(byte + k) {
                container |= (b as u64) << (8 * k);
            }
        }
        (container >> off) & ((1u64 << n) - 1)
    }
}

/// Decode a normalized-counts table description.
///
/// Returns the per-symbol probabilities (entries may be -1 meaning "less
/// than 1"), the accuracy log, and the number of bytes the description
/// consumed (the description always ends on a byte boundary).
///
/// `max_symbol` bounds the number of symbols (LL: 35, ML: 52, OF: 31,
/// Huffman weights: 255); `max_accuracy_log` bounds the accuracy (LL/ML: 9,
/// OF: 8, weights: 6).
pub fn read_normalized_counts(
    data: &[u8],
    max_symbol: usize,
    max_accuracy_log: u32,
) -> Result<(Vec<i16>, u32, usize)> {
    let mut br = ForwardBitReader::new(data);
    if data.is_empty() {
        return Err(ZstdError::UnexpectedEof("FSE table description"));
    }
    let accuracy_log = br.read(4) as u32 + 5;
    if accuracy_log > max_accuracy_log {
        return Err(ZstdError::Corrupted("FSE accuracy log out of range"));
    }
    let table_size = 1usize << accuracy_log;

    // "Remaining probabilities + 1"; counts down to 1 when the distribution
    // is fully allocated. `threshold` is the size of the current field
    // (halved whenever remaining drops below it).
    let mut remaining: i32 = table_size as i32 + 1;
    let mut threshold: i32 = table_size as i32;
    let mut counts: Vec<i16> = Vec::new();
    let mut previous_was_zero = false;

    while remaining > 1 {
        if previous_was_zero {
            // Run of zero-probability symbols, encoded in 2-bit flags;
            // a flag of 3 means "three more zeros, and read another flag".
            loop {
                if br.pos + 2 > data.len() * 8 {
                    return Err(ZstdError::UnexpectedEof("FSE zero-run flags"));
                }
                let flag = br.read(2) as usize;
                for _ in 0..flag {
                    counts.push(0);
                }
                if flag < 3 {
                    break;
                }
            }
            previous_was_zero = false;
            if counts.len() > max_symbol + 1 {
                return Err(ZstdError::Corrupted("FSE table has too many symbols"));
            }
            if remaining <= 1 {
                break;
            }
        }

        // Number of bits in this field: log2(threshold), with the "small
        // value costs one bit less" scheme of RFC 8878 Table 20.
        let max = (2 * threshold - 1) - remaining;
        let k = (31 - threshold.unsigned_abs().leading_zeros()) as u32; // log2(threshold), threshold = 2^k
        if br.pos + k as usize > data.len() * 8 {
            return Err(ZstdError::UnexpectedEof("FSE table description"));
        }
        let value: i32;
        let low = br.peek(k) as i32;
        if low < max {
            br.read(k);
            value = low;
        } else {
            // Wide field: re-read including one more bit (RFC 8878 Table 20).
            if br.pos + k as usize + 1 > data.len() * 8 {
                return Err(ZstdError::UnexpectedEof("FSE table description"));
            }
            let full = br.peek(k + 1) as i32;
            br.read(k + 1);
            value = if full < threshold { full } else { full - max };
        }

        let prob = value - 1; // "extra accuracy": decoded value 0 is probability -1
        remaining -= prob.abs();
        if remaining < 1 {
            return Err(ZstdError::Corrupted("FSE distribution oversubscribed"));
        }
        counts.push(prob as i16);
        if counts.len() > max_symbol + 1 {
            return Err(ZstdError::Corrupted("FSE table has too many symbols"));
        }
        previous_was_zero = prob == 0;

        while remaining < threshold && threshold > 1 {
            threshold >>= 1;
        }
    }

    if remaining != 1 {
        return Err(ZstdError::Corrupted("FSE distribution undersubscribed"));
    }

    let bytes_used = br.pos.div_ceil(8);
    Ok((counts, accuracy_log, bytes_used))
}

/// Build a decoding table from normalized counts (RFC 8878, Section 4.1.1).
pub fn build_table(counts: &[i16], accuracy_log: u32) -> Result<FseTable> {
    let size = 1usize << accuracy_log;
    let total: i32 = counts.iter().map(|&p| p.unsigned_abs() as i32).sum();
    if total != size as i32 {
        return Err(ZstdError::Corrupted("FSE counts do not sum to table size"));
    }
    if counts.iter().filter(|&&p| p != 0).count() < 2 {
        return Err(ZstdError::Corrupted(
            "FSE table needs two or more symbols with nonzero probability",
        ));
    }

    let mut symbols = vec![0u8; size];
    let mut nb_bits = vec![0u8; size];
    let mut baseline = vec![0u16; size];
    // next-state counters: how many of this symbol's states have been
    // numbered so far (states are numbered 1..=prob in cell order).
    let mut next = vec![0u32; counts.len()];

    // "Less than 1" probability symbols occupy single cells from the end of
    // the table backwards, with a full state reset (accuracy_log bits, base 0).
    let mut high: isize = size as isize - 1;
    for (s, &p) in counts.iter().enumerate() {
        match p {
            0 => {}
            -1 => {
                symbols[high as usize] = s as u8;
                next[s] = 1;
                high -= 1;
            }
            p if p > 0 => next[s] = p as u32,
            _ => return Err(ZstdError::Corrupted("FSE probability below -1")),
        }
    }

    // Spread remaining symbols across free cells.
    let step = (size >> 1) + (size >> 3) + 3;
    let mask = size - 1;
    let mut position = 0usize;
    for (s, &p) in counts.iter().enumerate() {
        for _ in 0..p.max(0) {
            symbols[position] = s as u8;
            loop {
                position = (position + step) & mask;
                if (position as isize) <= high {
                    break;
                }
            }
        }
    }

    // Assign nb_bits / baseline: the symbol's states, in increasing order,
    // get successively numbered next-states 1..=prob. The lowest
    // `next_pow2 - prob` states need one bit more than the rest.
    for u in 0..size {
        let s = symbols[u] as usize;
        let nstate = next[s];
        next[s] += 1;
        let hbits = 31 - nstate.leading_zeros(); // highbit
        if hbits > accuracy_log {
            return Err(ZstdError::Corrupted("FSE state numbering out of range"));
        }
        let nb = accuracy_log - hbits;
        nb_bits[u] = nb as u8;
        baseline[u] = ((nstate << nb) - size as u32) as u16;
    }

    Ok(FseTable { accuracy_log, symbols, nb_bits, baseline })
}

/// Predefined distributions (RFC 8878, Section 3.1.1.3.2.2).

const LL_DEFAULT_DISTRIBUTION: [i16; 36] = [
    4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, //
    2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1, 1, 1, //
    -1, -1, -1, -1,
];

const ML_DEFAULT_DISTRIBUTION: [i16; 53] = [
    1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, //
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, //
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, //
    -1, -1, -1, -1, -1,
];

const OF_DEFAULT_DISTRIBUTION: [i16; 29] = [
    1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, //
    1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1,
];

/// Predefined literals-length table (accuracy log 6).
pub fn predefined_ll() -> Result<FseTable> {
    build_table(&LL_DEFAULT_DISTRIBUTION, 6)
}

/// Predefined match-length table (accuracy log 6).
pub fn predefined_ml() -> Result<FseTable> {
    build_table(&ML_DEFAULT_DISTRIBUTION, 6)
}

/// Predefined offset-code table (accuracy log 5).
pub fn predefined_of() -> Result<FseTable> {
    build_table(&OF_DEFAULT_DISTRIBUTION, 5)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 8878 Appendix A predefined decoding tables (state 0's bogus
    /// nb_bits=0 duplicate row from the erratum is dropped by the extractor).
    mod appendix {
        include!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/appendix_tables.rs"));
    }

    #[test]
    fn predefined_tables_match_appendix_a() {
        let cases = [
            (predefined_ll().unwrap(), &appendix::APPENDIX_LL[..]),
            (predefined_ml().unwrap(), &appendix::APPENDIX_ML[..]),
            (predefined_of().unwrap(), &appendix::APPENDIX_OF[..]),
        ];
        for (table, expected) in cases {
            assert_eq!(table.state_count(), expected.len());
            for (state, &(sym, nb, base)) in expected.iter().enumerate() {
                assert_eq!(
                    (table.symbols[state], table.nb_bits[state], table.baseline[state]),
                    (sym, nb, base),
                    "state {state}"
                );
            }
        }
    }

    #[test]
    fn rfc_table21_five_state_example() {
        // RFC 8878 Section 4.1.1, Table 21: a symbol with probability 5 in an
        // accuracy_log 7 table owns states whose (nb_bits, baseline) are
        // (5,32) (5,64) (5,96) (4,0) (4,16) in state order.
        let mut counts = vec![5i16];
        counts.push(123); // partner symbol filling the rest of the 128 states
        let table = build_table(&counts, 7).unwrap();
        let mine: Vec<(u8, u16)> = (0..table.state_count())
            .filter(|&u| table.symbols[u] == 0)
            .map(|u| (table.nb_bits[u], table.baseline[u]))
            .collect();
        assert_eq!(mine, vec![(5, 32), (5, 64), (5, 96), (4, 0), (4, 16)]);
    }

    /// Minimal encoder for normalized-counts descriptions, mirroring the
    /// decoder's field scheme (used only to construct test vectors).
    fn encode_normalized_counts(counts: &[i16], accuracy_log: u32) -> Vec<u8> {
        let mut out = Vec::new();
        let mut acc: u64 = 0;
        let mut nbits = 0usize;
        let mut write = |value: u64, n: usize, acc: &mut u64, nbits: &mut usize| {
            *acc |= value << *nbits;
            *nbits += n;
            while *nbits >= 8 {
                out.push((*acc & 0xFF) as u8);
                *acc >>= 8;
                *nbits -= 8;
            }
        };
        write((accuracy_log - 5) as u64, 4, &mut acc, &mut nbits);

        let table_size = 1i32 << accuracy_log;
        let mut remaining: i32 = table_size + 1;
        let mut threshold: i32 = table_size;
        let mut previous_zero = false;
        let mut idx = 0usize;
        while remaining > 1 {
            if previous_zero {
                // Count consecutive zeros starting at the current position;
                // emit 2-bit flags.
                let mut zeros = 0usize;
                while idx + zeros < counts.len() && counts[idx + zeros] == 0 {
                    zeros += 1;
                }
                idx += zeros;
                let mut z = zeros;
                // Each flag adds up to 3 zeros; a flag of 3 chains.
                while z >= 3 {
                    write(3, 2, &mut acc, &mut nbits);
                    z -= 3;
                }
                write(z as u64, 2, &mut acc, &mut nbits);
                if remaining <= 1 {
                    break;
                }
            }
            let prob = counts[idx];
            idx += 1;
            let max = (2 * threshold - 1) - remaining;
            let value = prob as i32 + 1; // extra accuracy
            let k = (31 - threshold.unsigned_abs().leading_zeros()) as usize;
            if value < max {
                write(value as u64, k, &mut acc, &mut nbits);
            } else {
                let encoded = if value >= threshold { value + max } else { value };
                write(encoded as u64, k + 1, &mut acc, &mut nbits);
            }
            remaining -= prob.unsigned_abs() as i32;
            previous_zero = prob == 0;
            while remaining < threshold && threshold > 1 {
                threshold >>= 1;
            }
        }
        if nbits > 0 {
            out.push((acc & 0xFF) as u8);
        }
        out
    }

    #[test]
    fn normalized_counts_roundtrip() {
        let cases: Vec<(Vec<i16>, u32)> = vec![
            (LL_DEFAULT_DISTRIBUTION.to_vec(), 6),
            (ML_DEFAULT_DISTRIBUTION.to_vec(), 6),
            (OF_DEFAULT_DISTRIBUTION.to_vec(), 5),
            // Explicit FSE_Compressed_Mode-style distributions, incl. -1s,
            // zeros and long zero runs. Each must sum to 1 << accuracy_log
            // (with -1 counting 1), as the format requires.
            (vec![2, 2, 0, 0, 0, 5, 1, -1, 20, -1], 5),  // 2+2+5+1+1+20+1 = 32
            (vec![0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 27], 5), // 1+4+27 = 32
            (vec![1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 14, 17], 5), // 32
        ];
        for (counts, al) in cases {
            assert_eq!(
                counts.iter().map(|&p| p.unsigned_abs() as u32).sum::<u32>(),
                1 << al,
                "test vector must be a valid distribution"
            );
            let encoded = encode_normalized_counts(&counts, al);
            let (decoded, decoded_al, used) =
                read_normalized_counts(&encoded, counts.len() + 8, al).unwrap();
            assert_eq!(decoded_al, al);
            // Trailing zeros may be dropped by the decoder's early exit.
            let trimmed_len = decoded.len();
            assert_eq!(&decoded[..], &counts[..trimmed_len], "counts {counts:?}");
            assert!(trimmed_len <= counts.len());
            // All nonzero entries and their positions must match exactly.
            for (i, (&d, &c)) in decoded.iter().zip(counts.iter()).enumerate() {
                assert_eq!(d, c, "symbol {i}");
            }
            assert_eq!(used, encoded.len(), "byte consumption");
        }
    }

    #[test]
    fn normalized_counts_rejects_bad_accuracy() {
        // accuracy nibble 15 -> accuracy log 20 > max 9
        let data = [0x0F, 0x00, 0x00, 0x00];
        assert!(read_normalized_counts(&data, 255, MAX_ACCURACY_LOG).is_err());
    }

    #[test]
    fn build_rejects_wrong_totals() {
        assert!(build_table(&[4, 4, 4], 6).is_err()); // sums to 12, not 64
        assert!(build_table(&[64], 6).is_err()); // single symbol
    }

    #[test]
    fn decode_walk_is_in_range() {
        // Symbolic walk: from any start state, transitions must stay in
        // range and consume the announced bit count.
        let table = predefined_of().unwrap();
        let data = [0xFFu8; 64]; // all ones
        let mut br = BitReader::new(&data).unwrap();
        let mut state = br.read(table.accuracy_log) as usize;
        for _ in 0..1000 {
            let bits = table.nb_bits[state] as u32;
            let sym = table.symbol(state);
            assert!(sym <= 31);
            state = table.baseline[state] as usize + br.read(bits) as usize;
            assert!(state < table.state_count(), "state {state} out of range");
            if br.overflowed() {
                break;
            }
        }
    }
}
