//! pcap file format parsing (classic `libpcap` format).
//!
//! This step covers the 24-byte global header; per-packet record parsing
//! follows in a later step. Reference: the libpcap file format description
//! (https://ietf.org/archive/id/draft-gharris-opsawg-pcap-00.html).

use std::fmt;

/// Errors produced while parsing pcap structures.
#[derive(Debug)]
pub enum PcapError {
    /// Input ended in the middle of a structure.
    UnexpectedEof(&'static str),
    /// First four bytes were not a known pcap magic number.
    BadMagic { got: [u8; 4] },
}

impl fmt::Display for PcapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PcapError::UnexpectedEof(what) => write!(f, "unexpected end of pcap data while reading {what}"),
            PcapError::BadMagic { got } => {
                write!(f, "not a pcap file: magic {:02x?} {:02x?} {:02x?} {:02x?}", got[0], got[1], got[2], got[3])
            }
        }
    }
}

impl std::error::Error for PcapError {}

/// The pcap magic number variants: byte order x timestamp resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcapMagic {
    /// 0xa1b2c3d4, little-endian file.
    MicrosecondsLe,
    /// 0xa1b2c3d4, big-endian file.
    MicrosecondsBe,
    /// 0xa1b23c4d, little-endian file.
    NanosecondsLe,
    /// 0xa1b23c4d, big-endian file.
    NanosecondsBe,
}

impl PcapMagic {
    fn from_bytes(bytes: [u8; 4]) -> Option<PcapMagic> {
        match bytes {
            [0xd4, 0xc3, 0xb2, 0xa1] => Some(PcapMagic::MicrosecondsLe),
            [0xa1, 0xb2, 0xc3, 0xd4] => Some(PcapMagic::MicrosecondsBe),
            [0x4d, 0x3c, 0xb2, 0xa1] => Some(PcapMagic::NanosecondsLe),
            [0xa1, 0xb2, 0x3c, 0x4d] => Some(PcapMagic::NanosecondsBe),
            _ => None,
        }
    }

    pub fn is_big_endian(self) -> bool {
        matches!(self, PcapMagic::MicrosecondsBe | PcapMagic::NanosecondsBe)
    }

    /// Timestamp resolution in fractions per second.
    pub fn resolution(self) -> u32 {
        match self {
            PcapMagic::MicrosecondsLe | PcapMagic::MicrosecondsBe => 1_000_000,
            PcapMagic::NanosecondsLe | PcapMagic::NanosecondsBe => 1_000_000_000,
        }
    }
}

impl fmt::Display for PcapMagic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (order, res) = match self {
            PcapMagic::MicrosecondsLe => ("little-endian", "microsecond"),
            PcapMagic::MicrosecondsBe => ("big-endian", "microsecond"),
            PcapMagic::NanosecondsLe => ("little-endian", "nanosecond"),
            PcapMagic::NanosecondsBe => ("big-endian", "nanosecond"),
        };
        write!(f, "{res}, {order}")
    }
}

/// Well-known link-layer header types (LINKTYPE_ values from the tcpdump
/// link-layer header types registry). Unrecognized values are preserved as
/// [`LinkType::Other`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkType(pub u32);

impl LinkType {
    pub const NULL: LinkType = LinkType(0);
    pub const ETHERNET: LinkType = LinkType(1);
    pub const AX25: LinkType = LinkType(3);
    pub const IEEE802_5: LinkType = LinkType(6);
    pub const ARCNET_LINUX: LinkType = LinkType(7);
    pub const SLIP: LinkType = LinkType(8);
    pub const PPP: LinkType = LinkType(9);
    pub const FDDI: LinkType = LinkType(10);
    pub const ATM_RFC1483: LinkType = LinkType(100);
    pub const RAW: LinkType = LinkType(101);
    pub const LINUX_SLL: LinkType = LinkType(113);
    pub const LTALK: LinkType = LinkType(114);
    pub const DOCSIS: LinkType = LinkType(143);
    pub const IEEE802_11_RADIO: LinkType = LinkType(127);
    pub const LINUX_SLL2: LinkType = LinkType(276);

    pub fn name(self) -> &'static str {
        match self {
            LinkType::NULL => "NULL (BSD loopback)",
            LinkType::ETHERNET => "Ethernet",
            LinkType::AX25 => "AX.25",
            LinkType::IEEE802_5 => "IEEE 802.5",
            LinkType::ARCNET_LINUX => "ARCnet (Linux)",
            LinkType::SLIP => "SLIP",
            LinkType::PPP => "PPP",
            LinkType::FDDI => "FDDI",
            LinkType::ATM_RFC1483 => "ATM RFC 1483",
            LinkType::RAW => "Raw IP",
            LinkType::LINUX_SLL => "Linux cooked (SLL)",
            LinkType::LINUX_SLL2 => "Linux cooked v2 (SLL2)",
            LinkType::LTALK => "Localtalk",
            LinkType::DOCSIS => "DOCSIS",
            LinkType::IEEE802_11_RADIO => "802.11 with radiotap",
            LinkType(_) => "unknown",
        }
    }
}

impl fmt::Display for LinkType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.0, self.name())
    }
}

/// The pcap global (file) header.
#[derive(Debug, Clone)]
pub struct GlobalHeader {
    pub magic: PcapMagic,
    pub version_major: u16,
    pub version_minor: u16,
    /// Local time zone offset in seconds (historically always 0).
    pub thiszone: i32,
    /// Accuracy of timestamps (historically always 0).
    pub sigfigs: u32,
    /// Max captured length of a packet.
    pub snaplen: u32,
    /// Link-layer header type.
    pub network: LinkType,
}

impl GlobalHeader {
    pub const SIZE: usize = 24;

    /// Parse the global header at the start of `data`.
    pub fn parse(data: &[u8]) -> Result<GlobalHeader, PcapError> {
        if data.len() < Self::SIZE {
            return Err(PcapError::UnexpectedEof("global header"));
        }
        let mut magic_bytes = [0u8; 4];
        magic_bytes.copy_from_slice(&data[..4]);
        let magic = PcapMagic::from_bytes(magic_bytes)
            .ok_or(PcapError::BadMagic { got: magic_bytes })?;

        let rd16 = |b: &[u8]| -> u16 {
            if magic.is_big_endian() {
                u16::from_be_bytes([b[0], b[1]])
            } else {
                u16::from_le_bytes([b[0], b[1]])
            }
        };
        let rd32 = |b: &[u8]| -> u32 {
            if magic.is_big_endian() {
                u32::from_be_bytes([b[0], b[1], b[2], b[3]])
            } else {
                u32::from_le_bytes([b[0], b[1], b[2], b[3]])
            }
        };

        Ok(GlobalHeader {
            magic,
            version_major: rd16(&data[4..]),
            version_minor: rd16(&data[6..]),
            thiszone: rd32(&data[8..]) as i32,
            sigfigs: rd32(&data[12..]),
            snaplen: rd32(&data[16..]),
            network: LinkType(rd32(&data[20..])),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn le_header(magic: [u8; 4]) -> Vec<u8> {
        let mut d = Vec::new();
        d.extend_from_slice(&magic);
        d.extend_from_slice(&2u16.to_le_bytes());
        d.extend_from_slice(&4u16.to_le_bytes());
        d.extend_from_slice(&0i32.to_le_bytes());
        d.extend_from_slice(&0u32.to_le_bytes());
        d.extend_from_slice(&262_144u32.to_le_bytes());
        d.extend_from_slice(&1u32.to_le_bytes());
        assert_eq!(d.len(), GlobalHeader::SIZE);
        d
    }

    #[test]
    fn parses_nanosecond_little_endian() {
        // The variant the real captures use.
        let h = GlobalHeader::parse(&le_header([0x4d, 0x3c, 0xb2, 0xa1])).unwrap();
        assert_eq!(h.magic, PcapMagic::NanosecondsLe);
        assert!(!h.magic.is_big_endian());
        assert_eq!(h.magic.resolution(), 1_000_000_000);
        assert_eq!((h.version_major, h.version_minor), (2, 4));
        assert_eq!(h.snaplen, 262_144);
        assert_eq!(h.network, LinkType::ETHERNET);
        assert_eq!(h.network.name(), "Ethernet");
    }

    #[test]
    fn parses_all_four_magic_variants() {
        let h = GlobalHeader::parse(&le_header([0xd4, 0xc3, 0xb2, 0xa1])).unwrap();
        assert_eq!(h.magic, PcapMagic::MicrosecondsLe);
        let h = GlobalHeader::parse(&le_header([0x4d, 0x3c, 0xb2, 0xa1])).unwrap();
        assert_eq!(h.magic, PcapMagic::NanosecondsLe);

        // Big-endian files store the same magic bytes in reversed order.
        let mut d = le_header([0xa1, 0xb2, 0xc3, 0xd4]);
        // Overwrite fields in big-endian to keep them meaningful.
        d[4..6].copy_from_slice(&2u16.to_be_bytes());
        d[6..8].copy_from_slice(&4u16.to_be_bytes());
        d[16..20].copy_from_slice(&262_144u32.to_be_bytes());
        d[20..24].copy_from_slice(&1u32.to_be_bytes());
        let h = GlobalHeader::parse(&d).unwrap();
        assert_eq!(h.magic, PcapMagic::MicrosecondsBe);
        assert!(h.magic.is_big_endian());
        assert_eq!(h.snaplen, 262_144);
        assert_eq!(h.network, LinkType::ETHERNET);

        let mut d = le_header([0xa1, 0xb2, 0x3c, 0x4d]);
        d[4..6].copy_from_slice(&2u16.to_be_bytes());
        d[6..8].copy_from_slice(&4u16.to_be_bytes());
        let h = GlobalHeader::parse(&d).unwrap();
        assert_eq!(h.magic, PcapMagic::NanosecondsBe);
    }

    #[test]
    fn rejects_unknown_magic() {
        let mut d = le_header([0x4d, 0x3c, 0xb2, 0xa1]);
        d[0] = 0x00;
        assert!(matches!(
            GlobalHeader::parse(&d),
            Err(PcapError::BadMagic { got: [0x00, 0x3c, 0xb2, 0xa1] })
        ));
    }

    #[test]
    fn rejects_truncated_header() {
        let d = le_header([0x4d, 0x3c, 0xb2, 0xa1]);
        assert!(matches!(
            GlobalHeader::parse(&d[..23]),
            Err(PcapError::UnexpectedEof("global header"))
        ));
    }
}
