//! XXH64 hash (used by zstd for frame content checksums).
//!
//! Implemented from the xxHash specification; zstd stores the low 32 bits of
//! the digest of the *decompressed* content (seed 0) at the end of each frame
//! when the Content_Checksum_Flag is set (RFC 8878, Section 3.1.1).

const P1: u64 = 0x9E37_79B1_85EB_CA87;
const P2: u64 = 0xC2B2_AE3D_27D4_EB4F;
const P3: u64 = 0x1656_67B1_9E37_79F9;
const P4: u64 = 0x85EB_CA77_C2B2_AE63;
const P5: u64 = 0x27D4_EB2F_1656_67C5;

#[inline]
fn read_u64_le(data: &[u8], pos: usize) -> u64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&data[pos..pos + 8]);
    u64::from_le_bytes(buf)
}

#[inline]
fn round(acc: u64, input: u64) -> u64 {
    acc.wrapping_add(input.wrapping_mul(P2))
        .rotate_left(31)
        .wrapping_mul(P1)
}

#[inline]
fn merge_round(mut acc: u64, val: u64) -> u64 {
    acc ^= round(0, val);
    acc.wrapping_mul(P1).wrapping_add(P4)
}

/// One-shot XXH64 of `data` with `seed`.
pub fn xxh64(data: &[u8], seed: u64) -> u64 {
    let len = data.len();
    let mut h: u64;
    let mut pos = 0usize;

    if len >= 32 {
        let mut v1 = seed.wrapping_add(P1).wrapping_add(P2);
        let mut v2 = seed.wrapping_add(P2);
        let mut v3 = seed;
        let mut v4 = seed.wrapping_sub(P1);

        while pos + 32 <= len {
            v1 = round(v1, read_u64_le(data, pos));
            v2 = round(v2, read_u64_le(data, pos + 8));
            v3 = round(v3, read_u64_le(data, pos + 16));
            v4 = round(v4, read_u64_le(data, pos + 24));
            pos += 32;
        }

        h = v1.rotate_left(1)
            .wrapping_add(v2.rotate_left(7))
            .wrapping_add(v3.rotate_left(12))
            .wrapping_add(v4.rotate_left(18));
        h = merge_round(h, v1);
        h = merge_round(h, v2);
        h = merge_round(h, v3);
        h = merge_round(h, v4);
    } else {
        h = seed.wrapping_add(P5);
    }

    h = h.wrapping_add(len as u64);

    while pos + 8 <= len {
        let k1 = round(0, read_u64_le(data, pos));
        h ^= k1;
        h = h.rotate_left(27).wrapping_mul(P1).wrapping_add(P4);
        pos += 8;
    }
    if pos + 4 <= len {
        let lane = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as u64;
        h ^= lane.wrapping_mul(P1);
        h = h.rotate_left(23).wrapping_mul(P2).wrapping_add(P3);
        pos += 4;
    }
    while pos < len {
        h ^= (data[pos] as u64).wrapping_mul(P5);
        h = h.rotate_left(11).wrapping_mul(P1);
        pos += 1;
    }

    h ^= h >> 33;
    h = h.wrapping_mul(P2);
    h ^= h >> 29;
    h = h.wrapping_mul(P3);
    h ^= h >> 32;
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pattern(n: usize) -> Vec<u8> {
        // Deterministic byte pattern exercising all hash paths.
        (0..n).map(|i| (i.wrapping_mul(31).wrapping_add(i / 251)) as u8).collect()
    }

    #[test]
    fn empty_input() {
        // Well-known XXH64("", seed=0) value from the xxHash specification.
        assert_eq!(xxh64(b"", 0), 0xEF46_DB37_51D8_E999);
    }

    #[test]
    fn stripe_boundary_lengths_are_stable() {
        // Sizes around the 32-byte stripe threshold and every remainder class.
        // The exact digest is not asserted here (no local reference tool);
        // correctness is pinned end-to-end by the zstd frame checksum test in
        // src/zstd/frame.rs once real frames are decoded.
        let hashes: Vec<u64> = (0..100).map(|n| xxh64(&pattern(n), 0)).collect();
        // Distinct inputs must (overwhelmingly) produce distinct digests.
        let mut sorted = hashes.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), hashes.len());
    }

    #[test]
    fn seed_changes_digest() {
        assert_ne!(xxh64(&pattern(64), 0), xxh64(&pattern(64), 1));
    }
}
