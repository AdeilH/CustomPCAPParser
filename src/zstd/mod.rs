//! From-scratch zstd decompression, following RFC 8878.

pub mod xxhash;
// bitreader, fse, huffman, frame/block decode follow in later steps.

/// Errors produced while decoding a zstd stream.
#[derive(Debug)]
pub enum ZstdError {
    /// Input ended in the middle of a structure.
    UnexpectedEof(&'static str),
    /// A magic number did not match.
    BadMagic { expected: u32, got: u32 },
    /// A field had a value the format forbids.
    Corrupted(&'static str),
    /// A legal-in-principle feature this decoder does not implement
    /// (e.g. external dictionaries).
    Unsupported(&'static str),
}

impl std::fmt::Display for ZstdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ZstdError::UnexpectedEof(what) => write!(f, "unexpected end of input while reading {what}"),
            ZstdError::BadMagic { expected, got } => {
                write!(f, "bad magic number: expected 0x{expected:08x}, got 0x{got:08x}")
            }
            ZstdError::Corrupted(what) => write!(f, "corrupt data: {what}"),
            ZstdError::Unsupported(what) => write!(f, "unsupported: {what}"),
        }
    }
}

impl std::error::Error for ZstdError {}

pub type Result<T> = std::result::Result<T, ZstdError>;

/// Read a little-endian `u32` from `data[pos..]` if there is room.
#[allow(dead_code)] // used by later steps of the roadmap
pub(crate) fn read_u32_le(data: &[u8], pos: usize) -> Result<u32> {
    let end = pos.checked_add(4).ok_or(ZstdError::Corrupted("offset overflow"))?;
    if end > data.len() {
        return Err(ZstdError::UnexpectedEof("u32"));
    }
    Ok(u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]))
}

/// Read a little-endian `u24` (zstd block headers) from `data[pos..]`.
#[allow(dead_code)] // used by later steps of the roadmap
pub(crate) fn read_u24_le(data: &[u8], pos: usize) -> Result<u32> {
    if pos + 3 > data.len() {
        return Err(ZstdError::UnexpectedEof("u24"));
    }
    Ok(u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], 0]))
}
