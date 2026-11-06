//! Bit reader for zstd entropy streams (Huffman literals, FSE sequences).
//!
//! zstd entropy bitstreams are written *forward* by the compressor (bit
//! position `p` lives in byte `p/8`, bit `p%8`, LSB-first within a byte) and
//! read *backward* by the decompressor: after the payload, the compressor
//! writes a final 1-bit marker followed by zero padding up to the byte
//! boundary. The decoder therefore starts just *below* that marker, at the
//! highest payload bit, and reads downward.
//!
//! Reading `n` bits yields an `n`-bit value whose MSB is the first bit read
//! (the highest payload position) and whose LSB is the last one; this is the
//! convention the format calls "reading bits as a little-endian value"
//! (RFC 8878, Section 4.1 / 4.2.2). When a read crosses the bottom of the
//! stream, the missing bits are zero — mirrors the reference decoder, which
//! treats bits past the start as zero until an explicit overflow is reported.
//!
//! The stream is fully consumed when exactly `payload_bits()` bits have been
//! read; reading more than that sets the overflow condition.

use super::{Result, ZstdError};

#[derive(Debug)]
pub struct BitReader<'a> {
    data: &'a [u8],
    /// Number of payload bits: the global position of the final 1-bit marker
    /// (positions `0..bits` are payload; `bits` itself is the marker).
    bits: usize,
    /// Payload bits consumed so far. The next bit to read is at position
    /// `bits - 1 - consumed`.
    consumed: usize,
}

impl<'a> BitReader<'a> {
    /// Wrap a bitstream region (e.g. a Huffman stream or a sequences bitstream).
    /// The last byte must contain the 1-bit marker and therefore be nonzero.
    pub fn new(data: &'a [u8]) -> Result<Self> {
        let len = data.len();
        if len == 0 {
            return Err(ZstdError::UnexpectedEof("bitstream (empty)"));
        }
        let last = data[len - 1];
        if last == 0 {
            // The marker guarantees the final byte is nonzero.
            return Err(ZstdError::Corrupted("entropy bitstream ends with a zero byte"));
        }
        // Position of the marker bit = (len-1)*8 + highbit(last); the number
        // of payload bits equals that position.
        let bits = (len - 1) * 8 + (7 - last.leading_zeros() as usize);
        Ok(BitReader { data, bits, consumed: 0 })
    }

    /// Payload bits still unread (saturating; over-reads do not wrap).
    pub fn remaining(&self) -> usize {
        self.bits.saturating_sub(self.consumed)
    }

    /// Payload bits consumed so far.
    #[allow(dead_code)] // used by later steps
    pub fn consumed(&self) -> usize {
        self.consumed
    }

    /// True once more bits have been requested than the payload holds.
    /// Reads that overflow return zero bits (the format's "assume zero" rule).
    pub fn overflowed(&self) -> bool {
        self.consumed > self.bits
    }

    /// True when every payload bit has been consumed — the strict end
    /// condition for well-formed streams (RFC 8878, Section 4.2.2).
    pub fn fully_consumed(&self) -> bool {
        self.consumed == self.bits
    }

    /// Read `n` bits (1..=32), consuming them. Returns the value with the
    /// first-read bit as its MSB. Zero-padded past the start of the stream.
    pub fn read(&mut self, n: u32) -> u64 {
        let v = self.peek(n);
        self.consumed += n as usize;
        v
    }

    /// Like [`read`](Self::read) without consuming.
    pub fn peek(&self, n: u32) -> u64 {
        debug_assert!(n <= 32, "peek supports 0..=32 bits");
        if n == 0 {
            return 0;
        }
        let n = n as usize;
        // Position of the next bit to read (it becomes the value's MSB).
        let q_i = self.bits as isize - 1 - self.consumed as isize;
        if q_i < 0 {
            return 0; // entirely past the start of the stream
        }
        let q = q_i as usize;
        let top_byte = q / 8; // byte holding position q
        let r = q % 8;

        // Load an 8-byte window anchored at `top_byte`: data[top_byte] lands
        // in the container's byte 7 (bits 56..63), data[top_byte-1] in byte 6,
        // and so on. Bytes before index 0 (over-read) or past the end of the
        // buffer stay zero. Positions descend as container bits descend, so
        // the n wanted bits sit at container bits [56+r-n+1 .. 56+r].
        let mut container = 0u64;
        for k in 0..8usize {
            let idx_i = top_byte as isize - k as isize;
            if idx_i >= 0 {
                let idx = idx_i as usize;
                if idx < self.data.len() {
                    container |= (self.data[idx] as u64) << (8 * (7 - k));
                }
            }
        }

        let shift = 56 + r - (n - 1);
        debug_assert!(shift + n <= 64);
        (container >> shift) & ((1u64 << n) - 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a stream from a sequence of (n_bits, value) reads, mirroring how
    /// an encoder lays out codes: the first read's MSB goes at the highest
    /// payload position, positions descend from there. Appends the 1-bit
    /// marker plus zero padding.
    fn build_stream(reads: &[(u32, u64)]) -> Vec<u8> {
        let total: usize = reads.iter().map(|(n, _)| *n as usize).sum();
        let marker_pos = total; // positions 0..total-1 are payload
        let len = (marker_pos + 1 + 7) / 8;
        let mut data = vec![0u8; len];
        let mut put = |pos: usize, bit: u64| {
            data[pos / 8] |= ((bit & 1) << (pos % 8)) as u8;
        };
        put(marker_pos, 1); // final marker
        let mut cursor = total; // next position to hand out (descending)
        for &(n, v) in reads {
            let n = n as usize;
            // value bit (n-1-i) lands at position cursor-1-i
            for i in 0..n {
                put(cursor - 1 - i, (v >> (n - 1 - i)) & 1);
            }
            cursor -= n;
        }
        assert_eq!(cursor, 0);
        data
    }

    #[test]
    fn rfc_huffman_example() {
        // RFC 8878 Section 4.2.2: literals "0145" with the example tree
        // (0:"1", 1:"01", 4:"0001", 5:"0000") produce bytes [0x10, 0x0D].
        // Peeking 4 bits at a time must yield values that decode to
        // symbols 0, 1, 4, 5 with widths 1, 2, 4, 4.
        let data = [0x10u8, 0x0D];
        let mut br = BitReader::new(&data).unwrap();
        assert_eq!(br.remaining(), 11);

        // Decode via a mini lookup: value -> (symbol, nb_bits).
        let lookup = |v: u64| -> (u8, u32) {
            match v {
                8..=15 => (0, 1),   // "1xxx"
                4..=7 => (1, 2),    // "01xx"
                1 => (4, 4),        // "0001"
                0 => (5, 4),        // "0000"
                _ => panic!("invalid prefix {v}"),
            }
        };
        let mut symbols = Vec::new();
        while !br.overflowed() {
            let v = br.peek(4);
            let (sym, nb) = lookup(v);
            br.read(nb);
            symbols.push(sym);
            if br.fully_consumed() {
                break;
            }
        }
        assert_eq!(symbols, vec![0, 1, 4, 5]);
        assert!(br.fully_consumed());
        assert!(!br.overflowed());
    }

    #[test]
    fn roundtrip_reads() {
        // A sequence of reads must reconstruct the values the builder laid in,
        // and consume the stream exactly.
        let reads = vec![
            (5u32, 0b10101u64),
            (1, 1),
            (7, 0b1110001),
            (3, 0b000),
            (12, 0b1011_0100_1101),
            (2, 0b11),
        ];
        let data = build_stream(&reads);
        let mut br = BitReader::new(&data).unwrap();
        assert_eq!(br.remaining(), reads.iter().map(|r| r.0 as usize).sum::<usize>());
        for &(n, v) in &reads {
            assert_eq!(br.peek(n), v, "peek {n} bits");
            assert_eq!(br.read(n), v, "read {n} bits");
        }
        assert!(br.fully_consumed());
        assert_eq!(br.remaining(), 0);
    }

    #[test]
    fn overread_is_zero_and_flags_overflow() {
        // One single payload bit + marker.
        let data = build_stream(&[(1, 1)]);
        let mut br = BitReader::new(&data).unwrap();
        assert_eq!(br.read(1), 1);
        assert!(br.fully_consumed());
        // Reads past the end return zeros and flag overflow.
        assert_eq!(br.read(4), 0);
        assert!(br.overflowed());
        assert_eq!(br.remaining(), 0);
    }

    #[test]
    fn single_byte_stream() {
        let data = build_stream(&[(3, 0b101), (2, 0b01)]);
        assert_eq!(data.len(), 1);
        let mut br = BitReader::new(&data).unwrap();
        assert_eq!(br.read(3), 0b101);
        assert_eq!(br.read(2), 0b01);
        assert!(br.fully_consumed());
    }

    #[test]
    fn multi_byte_stream_crosses_windows() {
        // > 8 bytes so reads straddle container windows repeatedly.
        let reads: Vec<(u32, u64)> = (0..40)
            .map(|i| (5u32, (i as u64 * 21 + 7) & 0x1F))
            .collect();
        let data = build_stream(&reads);
        assert!(data.len() > 8);
        let mut br = BitReader::new(&data).unwrap();
        for &(n, v) in &reads {
            assert_eq!(br.read(n), v);
        }
        assert!(br.fully_consumed());
    }

    #[test]
    fn zero_last_byte_rejected() {
        assert!(BitReader::new(&[0x00]).is_err());
        assert!(BitReader::new(&[]).is_err());
    }
}
