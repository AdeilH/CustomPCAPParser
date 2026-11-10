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
    /// A field had a value the format forbids.
    Corrupted(&'static str),
}

impl fmt::Display for PcapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PcapError::UnexpectedEof(what) => write!(f, "unexpected end of pcap data while reading {what}"),
            PcapError::BadMagic { got } => {
                write!(f, "not a pcap file: magic {:02x?} {:02x?} {:02x?} {:02x?}", got[0], got[1], got[2], got[3])
            }
            PcapError::Corrupted(what) => write!(f, "corrupt pcap data: {what}"),
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

    /// An iterator over the packet records following the global header.
    ///
    /// Note: records whose `incl_len` exceeds `snaplen` are tolerated (some
    /// historic tools wrote such files; tcpdump reads them too).
    pub fn records<'a>(&self, data: &'a [u8]) -> RecordReader<'a> {
        RecordReader {
            data: &data[Self::SIZE..],
            pos: 0,
            big_endian: self.magic.is_big_endian(),
        }
    }
}

/// The 16-byte per-packet record header.
#[derive(Debug, Clone, Copy)]
pub struct PacketRecordHeader {
    /// Seconds since the Unix epoch.
    pub ts_sec: u32,
    /// Fraction of the second: microseconds or nanoseconds per the magic.
    pub ts_frac: u32,
    /// Bytes of packet data present in this file (the slice length).
    pub incl_len: u32,
    /// Packet length as it was on the wire.
    pub orig_len: u32,
}

impl PacketRecordHeader {
    pub const SIZE: usize = 16;

    /// Timestamp as a human-readable UTC string, e.g.
    /// `2023-08-22 00:20:00.027865639 UTC` (fraction digits depend on the
    /// file's resolution).
    pub fn timestamp_string(&self, magic: PcapMagic) -> String {
        timestamp_string(self.ts_sec, self.ts_frac, magic)
    }
}

/// Format a (seconds, fraction) timestamp per the file's resolution.
pub fn timestamp_string(ts_sec: u32, ts_frac: u32, magic: PcapMagic) -> String {
    let (y, mo, d, h, mi, s) = civil_from_timestamp(ts_sec as i64);
    let frac = if magic.resolution() == 1_000_000_000 {
        format!(".{:09}", ts_frac)
    } else {
        format!(".{:06}", ts_frac)
    };
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{mi:02}:{s:02}{frac} UTC")
}

/// One packet record: its header and the captured bytes.
#[derive(Debug, Clone, Copy)]
pub struct PacketRecord<'a> {
    pub header: PacketRecordHeader,
    pub data: &'a [u8],
}

/// Iterator over packet records (classic pcap format).
#[derive(Debug)]
pub struct RecordReader<'a> {
    data: &'a [u8],
    pos: usize,
    big_endian: bool,
}

impl<'a> RecordReader<'a> {
    /// Total consumed bytes so far (used by callers to detect trailing junk
    /// vs. a clean end when iteration stops with an error).
    pub fn consumed(&self) -> usize {
        self.pos
    }
}

impl<'a> Iterator for RecordReader<'a> {
    type Item = Result<PacketRecord<'a>, PcapError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos == self.data.len() {
            return None; // clean end
        }
        if self.pos + PacketRecordHeader::SIZE > self.data.len() {
            return Some(Err(PcapError::UnexpectedEof("record header")));
        }
        let be = self.big_endian;
        let rd32 = |b: &[u8]| -> u32 {
            if be {
                u32::from_be_bytes([b[0], b[1], b[2], b[3]])
            } else {
                u32::from_le_bytes([b[0], b[1], b[2], b[3]])
            }
        };
        let hdr_bytes = &self.data[self.pos..self.pos + PacketRecordHeader::SIZE];
        let header = PacketRecordHeader {
            ts_sec: rd32(&hdr_bytes[0..]),
            ts_frac: rd32(&hdr_bytes[4..]),
            incl_len: rd32(&hdr_bytes[8..]),
            orig_len: rd32(&hdr_bytes[12..]),
        };

        // The file cannot contain more than was on the wire.
        if header.incl_len > header.orig_len {
            return Some(Err(PcapError::Corrupted(
                "record incl_len exceeds orig_len",
            )));
        }
        let incl = header.incl_len as usize;
        let data_end = self.pos + PacketRecordHeader::SIZE + incl;
        if data_end > self.data.len() {
            return Some(Err(PcapError::UnexpectedEof("record data")));
        }

        let record = PacketRecord {
            header,
            data: &self.data[self.pos + PacketRecordHeader::SIZE..data_end],
        };
        self.pos = data_end;
        Some(Ok(record))
    }
}

/// Convert Unix seconds to `(year, month, day, hour, minute, second)` in UTC
/// (Howard Hinnant's civil-from-days algorithm; no timezone tables needed).
fn civil_from_timestamp(ts: i64) -> (i64, u32, u32, u32, u32, u32) {
    let days = ts.div_euclid(86_400);
    let secs = ts.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    (
        y,
        m,
        d,
        (secs / 3600) as u32,
        ((secs % 3600) / 60) as u32,
        (secs % 60) as u32,
    )
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
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

    /// A full little-endian file with `n` records of the given sizes.
    fn le_file_with_records(sizes: &[(u32, u32, &[u8])]) -> Vec<u8> {
        let mut d = le_header([0x4d, 0x3c, 0xb2, 0xa1]);
        for (i, &(incl, orig, payload)) in sizes.iter().enumerate() {
            assert_eq!(incl as usize, payload.len());
            d.extend_from_slice(&((1_000_000 + i as u32)).to_le_bytes()); // ts_sec
            d.extend_from_slice(&(i as u32 * 111).to_le_bytes()); // ts_frac
            d.extend_from_slice(&incl.to_le_bytes());
            d.extend_from_slice(&orig.to_le_bytes());
            d.extend_from_slice(payload);
        }
        d
    }

    #[test]
    fn walks_records_to_exact_end() {
        let d = le_file_with_records(&[
            (4, 60, &[1, 2, 3, 4]),
            (0, 100, &[]), // zero-length capture is legal
            (2, 2, &[9, 9]),
        ]);
        let h = GlobalHeader::parse(&d).unwrap();
        let mut reader = h.records(&d);
        let mut seen = Vec::new();
        for rec in &mut reader {
            let rec = rec.unwrap();
            assert_eq!(rec.header.ts_frac as usize % 111, 0);
            seen.push((rec.header.incl_len, rec.header.orig_len, rec.data.len()));
        }
        assert_eq!(
            seen,
            vec![(4, 60, 4), (0, 100, 0), (2, 2, 2)],
            "incl/orig/slice lengths"
        );
        assert_eq!(reader.consumed(), d.len() - GlobalHeader::SIZE);
    }

    #[test]
    fn rejects_incl_len_above_orig_len() {
        let d = le_file_with_records(&[(2, 2, &[7, 7])]);
        let mut d = d;
        // Patch first record's incl_len above orig_len.
        let off = GlobalHeader::SIZE + 8;
        d[off..off + 4].copy_from_slice(&3u32.to_le_bytes());
        let h = GlobalHeader::parse(&d).unwrap();
        assert!(matches!(
            h.records(&d).next(),
            Some(Err(PcapError::Corrupted("record incl_len exceeds orig_len")))
        ));
    }

    #[test]
    fn rejects_truncated_record_data() {
        let d = le_file_with_records(&[(4, 60, &[1, 2, 3, 4])]);
        let h = GlobalHeader::parse(&d).unwrap();
        // Cut off the payload bytes.
        assert!(matches!(
            h.records(&d[..d.len() - 2]).next(),
            Some(Err(PcapError::UnexpectedEof("record data")))
        ));
    }

    #[test]
    fn rejects_trailing_junk() {
        let d = le_file_with_records(&[(2, 2, &[7, 7])]);
        let mut d = d;
        d.extend_from_slice(&[0xAB]); // 1 trailing byte: neither a record nor the end
        let h = GlobalHeader::parse(&d).unwrap();
        let mut it = h.records(&d);
        assert!(it.next().unwrap().is_ok());
        assert!(matches!(
            it.next(),
            Some(Err(PcapError::UnexpectedEof("record header")))
        ));
    }

    #[test]
    fn big_endian_records() {
        // Same record, big-endian byte order.
        let mut d = le_header([0xa1, 0xb2, 0x3c, 0x4d]); // nanosecond BE
        d[4..6].copy_from_slice(&2u16.to_be_bytes());
        d[6..8].copy_from_slice(&4u16.to_be_bytes());
        d.extend_from_slice(&1_000_000u32.to_be_bytes());
        d.extend_from_slice(&5u32.to_be_bytes());
        d.extend_from_slice(&3u32.to_be_bytes());
        d.extend_from_slice(&10u32.to_be_bytes());
        d.extend_from_slice(&[1, 2, 3]);
        let h = GlobalHeader::parse(&d).unwrap();
        let rec = h.records(&d).next().unwrap().unwrap();
        assert_eq!((rec.header.ts_sec, rec.header.ts_frac), (1_000_000, 5));
        assert_eq!((rec.header.incl_len, rec.header.orig_len), (3, 10));
        assert_eq!(rec.data, &[1, 2, 3]);
    }

    #[test]
    fn timestamp_strings() {
        let hdr = |ts_sec, ts_frac| PacketRecordHeader {
            ts_sec,
            ts_frac,
            incl_len: 0,
            orig_len: 0,
        };
        let nano = PcapMagic::NanosecondsLe;
        let micro = PcapMagic::MicrosecondsLe;
        assert_eq!(hdr(0, 0).timestamp_string(nano), "1970-01-01 00:00:00.000000000 UTC");
        assert_eq!(hdr(86_399, 999_999_999).timestamp_string(nano), "1970-01-01 23:59:59.999999999 UTC");
        assert_eq!(hdr(86_400, 1).timestamp_string(micro), "1970-01-02 00:00:00.000001 UTC");
        assert_eq!(hdr(951_782_400, 0).timestamp_string(micro), "2000-02-29 00:00:00.000000 UTC");
        assert_eq!(hdr(4_294_967_295, 0).timestamp_string(nano), "2106-02-07 06:28:15.000000000 UTC");
        // The real capture's first record.
        assert_eq!(
            hdr(1_692_663_600, 27_865_639).timestamp_string(nano),
            "2023-08-22 00:20:00.027865639 UTC"
        );
    }
}
