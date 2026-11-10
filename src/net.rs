//! Ethernet / IPv4 / UDP dissection — the L2-L4 chain between pcap records
//! and the XDP payload.

/// Errors produced while dissecting packet headers.
#[derive(Debug)]
pub enum NetError {
    UnexpectedEof(&'static str),
    Corrupted(&'static str),
    /// EtherType / IP protocol we do not dissect.
    Unsupported(&'static str),
}

impl std::fmt::Display for NetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetError::UnexpectedEof(what) => write!(f, "unexpected end of packet while reading {what}"),
            NetError::Corrupted(what) => write!(f, "corrupt packet: {what}"),
            NetError::Unsupported(what) => write!(f, "unsupported: {what}"),
        }
    }
}

impl std::error::Error for NetError {}

pub type Result<T> = std::result::Result<T, NetError>;

pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_VLAN: u16 = 0x8100;
pub const IPPROTO_UDP: u8 = 17;

/// A parsed Ethernet frame; IEEE 802.1Q VLAN tags are peeled off (all of
/// them, so QinQ works too) and the inner EtherType is reported.
#[derive(Debug)]
pub struct EthFrame<'a> {
    pub dst: [u8; 6],
    pub src: [u8; 6],
    /// Inner EtherType after any VLAN tags.
    pub ethertype: u16,
    /// VLAN IDs in outermost-first order, empty if untagged.
    pub vlans: Vec<u16>,
    pub payload: &'a [u8],
}

pub fn parse_ethernet(data: &[u8]) -> Result<EthFrame<'_>> {
    if data.len() < 14 {
        return Err(NetError::UnexpectedEof("ethernet header"));
    }
    let mut frame = EthFrame {
        dst: data[0..6].try_into().unwrap(),
        src: data[6..12].try_into().unwrap(),
        ethertype: u16::from_be_bytes([data[12], data[13]]),
        vlans: Vec::new(),
        payload: &data[14..],
    };
    // Peel 802.1Q tags (4 bytes: TCI + inner EtherType).
    while frame.ethertype == ETHERTYPE_VLAN {
        if frame.payload.len() < 4 {
            return Err(NetError::UnexpectedEof("vlan tag"));
        }
        let tci = u16::from_be_bytes([frame.payload[0], frame.payload[1]]);
        frame.vlans.push(tci & 0xFFF);
        frame.ethertype = u16::from_be_bytes([frame.payload[2], frame.payload[3]]);
        frame.payload = &frame.payload[4..];
    }
    Ok(frame)
}

/// A parsed IPv4 packet; `payload` covers the declared total length minus
/// the header (Ethernet padding is excluded).
#[derive(Debug)]
pub struct Ipv4Packet<'a> {
    pub src: [u8; 4],
    pub dst: [u8; 4],
    pub protocol: u8,
    pub payload: &'a [u8],
}

pub fn parse_ipv4(data: &[u8]) -> Result<Ipv4Packet<'_>> {
    if data.len() < 20 {
        return Err(NetError::UnexpectedEof("ipv4 header"));
    }
    if data[0] >> 4 != 4 {
        return Err(NetError::Unsupported("non-IPv4 internet layer"));
    }
    let ihl = (data[0] & 0xF) as usize * 4;
    if ihl < 20 {
        return Err(NetError::Corrupted("ipv4 header length below 20 bytes"));
    }
    if data.len() < ihl {
        return Err(NetError::UnexpectedEof("ipv4 options"));
    }
    let total_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    if total_len < ihl || total_len > data.len() {
        return Err(NetError::Corrupted("ipv4 total length out of range"));
    }
    Ok(Ipv4Packet {
        src: data[12..16].try_into().unwrap(),
        dst: data[16..20].try_into().unwrap(),
        protocol: data[9],
        payload: &data[ihl..total_len],
    })
}

/// A parsed UDP datagram; `payload` is authoritative per the UDP length
/// field, which excludes the Ethernet minimum-size padding.
#[derive(Debug)]
pub struct UdpDatagram<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: &'a [u8],
}

pub fn parse_udp(data: &[u8]) -> Result<UdpDatagram<'_>> {
    if data.len() < 8 {
        return Err(NetError::UnexpectedEof("udp header"));
    }
    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);
    let len = u16::from_be_bytes([data[4], data[5]]) as usize;
    if len < 8 || len > data.len() {
        return Err(NetError::Corrupted("udp length out of range"));
    }
    Ok(UdpDatagram {
        src_port,
        dst_port,
        payload: &data[8..len],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn udp_packet(payload: &[u8], src: u16, dst: u16) -> Vec<u8> {
        let mut d = Vec::new();
        d.extend_from_slice(&src.to_be_bytes());
        d.extend_from_slice(&dst.to_be_bytes());
        d.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        d.extend_from_slice(&[0, 0]); // checksum
        d.extend_from_slice(payload);
        d
    }

    #[test]
    fn parses_vlan_stacked_ethernet() {
        let mut d = vec![0u8; 14 + 8 + 6];
        d[0..6].copy_from_slice(&[1, 0, 0x5e, 1, 2, 3]);
        d[12..14].copy_from_slice(&ETHERTYPE_VLAN.to_be_bytes());
        let mut p = 14;
        d[p..p + 2].copy_from_slice(&0x008Eu16.to_be_bytes()); // VLAN 142
        d[p + 2..p + 4].copy_from_slice(&ETHERTYPE_VLAN.to_be_bytes());
        p += 4;
        d[p..p + 2].copy_from_slice(&0x0096u16.to_be_bytes()); // VLAN 150
        d[p + 2..p + 4].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        let f = parse_ethernet(&d).unwrap();
        assert_eq!(f.ethertype, ETHERTYPE_IPV4);
        assert_eq!(f.vlans, vec![142, 150]);
        assert_eq!(f.dst, [1, 0, 0x5e, 1, 2, 3]);
    }

    #[test]
    fn ipv4_respects_total_length_not_padding() {
        // Build a 20-byte IPv4 header with total_length = 20 + payload, then
        // append 6 bytes of Ethernet padding.
        let payload = [0xAAu8; 10];
        let total = (20 + payload.len()) as u16;
        let mut d = Vec::new();
        d.push(0x45); // version 4, IHL 5
        d.push(0); // DSCP
        d.extend_from_slice(&total.to_be_bytes());
        d.extend_from_slice(&[0, 0, 0, 0]); // id, flags, offset
        d.push(64); // ttl
        d.push(IPPROTO_UDP);
        d.extend_from_slice(&[0, 0]); // checksum
        d.extend_from_slice(&[10, 0, 0, 1]);
        d.extend_from_slice(&[233, 125, 89, 195]);
        d.extend_from_slice(&payload);
        d.extend_from_slice(&[0u8; 6]); // padding
        let ip = parse_ipv4(&d).unwrap();
        assert_eq!(ip.protocol, IPPROTO_UDP);
        assert_eq!(ip.src, [10, 0, 0, 1]);
        assert_eq!(ip.dst, [233, 125, 89, 195]);
        assert_eq!(ip.payload, &payload);
    }

    #[test]
    fn udp_payload_is_length_delimited() {
        let data = udp_packet(&[1, 2, 3, 4, 5, 6, 7, 8], 23500, 23500);
        // Simulate Ethernet padding appended beyond the UDP length.
        let mut padded = data.clone();
        padded.extend_from_slice(&[0u8; 4]);
        let u = parse_udp(&padded).unwrap();
        assert_eq!(u.payload.len(), 8);
        assert_eq!((u.src_port, u.dst_port), (23500, 23500));
    }

    #[test]
    fn rejects_bogus_lengths() {
        assert!(parse_ethernet(&[0u8; 13]).is_err());
        assert!(parse_ipv4(&[0x65, 0, 0, 0]).is_err()); // version 6
        // UDP length field declaring 4 bytes (< header size).
        let bad = [0x00, 0x01, 0x00, 0x02, 0x00, 0x04, 0x00, 0x00, 0xAA];
        assert!(parse_udp(&bad).is_err());
        // UDP length beyond the buffer.
        let bad = [0x00, 0x01, 0x00, 0x02, 0x00, 0x20, 0x00, 0x00, 0xAA];
        assert!(parse_udp(&bad).is_err());
    }
}
