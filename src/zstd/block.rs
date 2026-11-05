//! Compressed block decoding: literals section, sequences section, and
//! sequence execution (RFC 8878, Section 3.1.1.3 / 3.1.1.4 / 3.1.1.5).

use super::frame::FrameDecoder;
use super::{Result, ZstdError};

/// Decode one Compressed_Block of `block_size` payload bytes.
///
/// Advances `dec.pos` past the block and appends the decompressed bytes to
/// `dec.output`. Updates the carried Huffman tree, sequence tables, and
/// repeat offsets.
pub(crate) fn decompress_compressed(
    dec: &mut FrameDecoder,
    block_size: usize,
) -> Result<()> {
    // Implemented step by step; raw and RLE blocks work already.
    let _ = block_size;
    Err(ZstdError::Unsupported("compressed blocks are not implemented yet"))
}
