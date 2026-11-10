//! XDP (eXpress Data Protocol) payload parsing.
//!
//! Implements the NYSE XDP packet layer and message framing from the
//! *XDP Common Client Specification* (v2.1f), plus the market-data message
//! set of the *NYSE Pillar Integrated Feed Client Specification* (the feed
//! carried by the `ny4-xase-pillar-*` captures):
//!
//! - Packet header (16 bytes): PktSize, DeliveryFlag, NumberMsgs, SeqNum,
//!   SendTime, SendTimeNS — all little-endian.
//! - Message framing: `MsgSize u16` + `MsgType u16` header per message;
//!   messages tile the packet exactly (never straddle packets).
//! - Common messages: Sequence Number Reset (1), Source Time Reference (2),
//!   Symbol Index Mapping (3), Security Status (34), Refresh Header (35).
//! - Pillar Integrated Feed messages: Add Order (100), Modify Order (101),
//!   Delete Order (102), Order Execution (103), Replace Order (104),
//!   Imbalance (105), Add Order Refresh (106), Non-Displayed Trade (110).
//!
//! Per the spec, price fields are integer numerators — the decimal point is
//! `PriceScaleCode` decimal places from the symbol's Symbol Index Mapping
//! message; prices are therefore kept raw here.
//!
//! Use this module through the [`crate::feeds::PacketParser`] seam
//! ([`XdpParser`]) or call the free functions directly for lower-level
//! control.

use std::collections::HashMap;
use std::fmt;

use super::{Event, FeedError, PacketParser};

/// Errors produced while decoding XDP structures.
#[derive(Debug)]
pub enum XdpError {
    UnexpectedEof(&'static str),
    Corrupted(&'static str),
}

impl std::fmt::Display for XdpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            XdpError::UnexpectedEof(what) => write!(f, "unexpected end of XDP data while reading {what}"),
            XdpError::Corrupted(what) => write!(f, "corrupt XDP data: {what}"),
        }
    }
}

impl std::error::Error for XdpError {}

pub type Result<T> = std::result::Result<T, XdpError>;

/// DeliveryFlag values (XDP Common Client Specification, Section 2.1).
pub const DELIVERY_HEARTBEAT: u8 = 1;
pub const DELIVERY_FAILOVER: u8 = 10;
pub const DELIVERY_ORIGINAL: u8 = 11;
pub const DELIVERY_SEQ_RESET: u8 = 12;
pub const DELIVERY_RETRANS_SINGLE: u8 = 13;
pub const DELIVERY_RETRANS_PART: u8 = 15;
pub const DELIVERY_REFRESH_SINGLE: u8 = 17;
pub const DELIVERY_REFRESH_START: u8 = 18;
pub const DELIVERY_REFRESH_PART: u8 = 19;
pub const DELIVERY_REFRESH_END: u8 = 20;
pub const DELIVERY_UNAVAILABLE: u8 = 21;

/// Human-readable name for a DeliveryFlag value.
pub fn delivery_name(flag: u8) -> &'static str {
    match flag {
        DELIVERY_HEARTBEAT => "heartbeat",
        DELIVERY_FAILOVER => "failover",
        DELIVERY_ORIGINAL => "original",
        DELIVERY_SEQ_RESET => "sequence reset",
        DELIVERY_RETRANS_SINGLE => "retransmission (single)",
        DELIVERY_RETRANS_PART => "retransmission (part)",
        DELIVERY_REFRESH_SINGLE => "refresh (single)",
        DELIVERY_REFRESH_START => "refresh (start)",
        DELIVERY_REFRESH_PART => "refresh (part)",
        DELIVERY_REFRESH_END => "refresh (end)",
        DELIVERY_UNAVAILABLE => "message unavailable",
        _ => "unknown",
    }
}

/// Well-known message types across the common + Pillar Integrated specs.
pub mod msg_type {
    pub const SEQ_NUMBER_RESET: u16 = 1;
    pub const SOURCE_TIME_REFERENCE: u16 = 2;
    pub const SYMBOL_INDEX_MAPPING: u16 = 3;
    pub const RETRANS_REQUEST: u16 = 10;
    pub const REFRESH_REQUEST: u16 = 15;
    pub const HEARTBEAT_RESPONSE: u16 = 12;
    pub const REQUEST_RESPONSE: u16 = 11;
    pub const MESSAGE_UNAVAILABLE: u16 = 31;
    pub const SYMBOL_CLEAR: u16 = 32;
    pub const SECURITY_STATUS: u16 = 34;
    pub const REFRESH_HEADER: u16 = 35;
    pub const ADD_ORDER: u16 = 100;
    pub const MODIFY_ORDER: u16 = 101;
    pub const DELETE_ORDER: u16 = 102;
    pub const ORDER_EXECUTION: u16 = 103;
    pub const REPLACE_ORDER: u16 = 104;
    pub const IMBALANCE: u16 = 105;
    pub const ADD_ORDER_REFRESH: u16 = 106;
    pub const NON_DISPLAYED_TRADE: u16 = 110;
    pub const CROSS_TRADE: u16 = 111;
}

/// Human-readable name for a message type (common + Pillar Integrated).
pub fn msg_type_name(t: u16) -> &'static str {
    match t {
        msg_type::SEQ_NUMBER_RESET => "Sequence Number Reset",
        msg_type::SOURCE_TIME_REFERENCE => "Source Time Reference",
        msg_type::SYMBOL_INDEX_MAPPING => "Symbol Index Mapping",
        msg_type::RETRANS_REQUEST => "Retransmission Request",
        msg_type::HEARTBEAT_RESPONSE => "Heartbeat Response",
        msg_type::REQUEST_RESPONSE => "Request Response",
        msg_type::REFRESH_REQUEST => "Refresh Request",
        msg_type::MESSAGE_UNAVAILABLE => "Message Unavailable",
        msg_type::SYMBOL_CLEAR => "Symbol Clear",
        msg_type::SECURITY_STATUS => "Security Status",
        msg_type::REFRESH_HEADER => "Refresh Header",
        msg_type::ADD_ORDER => "Add Order",
        msg_type::MODIFY_ORDER => "Modify Order",
        msg_type::DELETE_ORDER => "Delete Order",
        msg_type::ORDER_EXECUTION => "Order Execution",
        msg_type::REPLACE_ORDER => "Replace Order",
        msg_type::IMBALANCE => "Imbalance",
        msg_type::ADD_ORDER_REFRESH => "Add Order Refresh",
        msg_type::NON_DISPLAYED_TRADE => "Non-Displayed Trade",
        msg_type::CROSS_TRADE => "Cross Trade",
        _ => "Unknown",
    }
}

/// The 16-byte XDP packet header.
#[derive(Debug, Clone, Copy)]
pub struct PacketHeader {
    /// Total packet size in bytes, including this header (== UDP payload).
    pub pkt_size: u16,
    pub delivery_flag: u8,
    pub num_msgs: u8,
    /// Sequence number of the first message in the packet.
    pub seq_num: u32,
    /// Publication time, seconds since the Unix epoch.
    pub send_time: u32,
    /// Nanosecond offset from `send_time`.
    pub send_time_ns: u32,
}

impl PacketHeader {
    pub const SIZE: usize = 16;

    /// Parse and validate the header at the start of a UDP payload.
    /// `PktSize` must equal `data.len()`.
    pub fn parse(data: &[u8]) -> Result<(PacketHeader, Messages<'_>)> {
        if data.len() < Self::SIZE {
            return Err(XdpError::UnexpectedEof("XDP packet header"));
        }
        let pkt_size = u16::from_le_bytes([data[0], data[1]]);
        if pkt_size as usize != data.len() {
            return Err(XdpError::Corrupted("PktSize does not match payload length"));
        }
        let header = PacketHeader {
            pkt_size,
            delivery_flag: data[2],
            num_msgs: data[3],
            seq_num: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
            send_time: u32::from_le_bytes([data[8], data[9], data[10], data[11]]),
            send_time_ns: u32::from_le_bytes([data[12], data[13], data[14], data[15]]),
        };
        Ok((header, Messages { data: &data[Self::SIZE..], pos: 0, remaining: header.num_msgs as usize }))
    }
}

/// The 4-byte message header every XDP message starts with.
#[derive(Debug, Clone, Copy)]
pub struct MessageHeader {
    /// Size of this message in bytes (header included).
    pub size: u16,
    pub msg_type: u16,
}

/// Iterator over the messages of one XDP packet. Yields
/// `(MessageHeader, message body after the 4-byte header)`.
#[derive(Debug)]
pub struct Messages<'a> {
    data: &'a [u8],
    pos: usize,
    remaining: usize,
}

impl<'a> Messages<'a> {
    fn next_raw(&mut self) -> Option<Result<(MessageHeader, &'a [u8])>> {
        if self.remaining == 0 {
            if self.pos != self.data.len() {
                return Some(Err(XdpError::Corrupted("trailing bytes after last message")));
            }
            return None;
        }
        if self.pos + 4 > self.data.len() {
            return Some(Err(XdpError::UnexpectedEof("message header")));
        }
        let size = u16::from_le_bytes([self.data[self.pos], self.data[self.pos + 1]]);
        let msg_type = u16::from_le_bytes([self.data[self.pos + 2], self.data[self.pos + 3]]);
        if size < 4 {
            return Some(Err(XdpError::Corrupted("message size below header size")));
        }
        let end = self.pos + size as usize;
        if end > self.data.len() {
            return Some(Err(XdpError::Corrupted("message extends past packet end")));
        }
        let hdr = MessageHeader { size, msg_type };
        let body = &self.data[self.pos + 4..end];
        self.pos = end;
        self.remaining -= 1;
        Some(Ok((hdr, body)))
    }
}

impl<'a> Iterator for Messages<'a> {
    type Item = Result<(MessageHeader, &'a [u8])>;
    fn next(&mut self) -> Option<Self::Item> {
        self.next_raw()
    }
}

/// Fully decode one message (header + body) into a typed [`Message`].
pub fn decode(header: MessageHeader, body: &[u8]) -> Result<Message<'_>> {
    let le32 = |b: &[u8]| u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    let le64 = |b: &[u8]| {
        u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
    };
    let need = |n: usize| -> Result<()> {
        if body.len() < n {
            Err(XdpError::UnexpectedEof("message body"))
        } else {
            Ok(())
        }
    };
    // ASCII fields are null- or blank-padded; trim both. (A `fn`, not a
    // closure, so the returned borrow shares the input's lifetime.)
    fn ascii(b: &[u8]) -> &str {
        let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
        std::str::from_utf8(&b[..end])
            .unwrap_or("")
            .trim_end_matches(' ')
    }

    let msg = match header.msg_type {
        msg_type::SEQ_NUMBER_RESET => {
            // MsgSize 14 includes the 4-byte header: the body is 10 bytes.
            need(10)?;
            Message::SequenceNumberReset {
                source_time: le32(&body[0..4]),
                source_time_ns: le32(&body[4..8]),
                product_id: body[8],
                channel_id: body[9],
            }
        }
        msg_type::SOURCE_TIME_REFERENCE => {
            need(12)?;
            Message::SourceTimeReference {
                id: le32(&body[0..4]),
                source_time: le32(&body[8..12]),
            }
        }
        msg_type::SYMBOL_INDEX_MAPPING => {
            need(30)?;
            Message::SymbolIndexMapping {
                symbol_index: le32(&body[0..4]),
                symbol: ascii(&body[4..15]),
                market_id: u16::from_le_bytes([body[16], body[17]]),
                system_id: body[18],
                exchange_code: body[19],
                price_scale_code: body[20],
                security_type: body[21],
                lot_size: u16::from_le_bytes([body[22], body[23]]),
                prev_close_price: le32(&body[24..28]),
                prev_close_volume: le32(&body[28..32]),
            }
        }
        msg_type::SECURITY_STATUS => {
            need(21)?;
            Message::SecurityStatus {
                source_time: le32(&body[0..4]),
                source_time_ns: le32(&body[4..8]),
                symbol_index: le32(&body[8..12]),
                symbol_seq_num: le32(&body[12..16]),
                security_status: body[16],
                halt_condition: body[17],
            }
        }
        msg_type::REFRESH_HEADER => {
            need(4)?;
            Message::RefreshHeader {
                current_refresh_pkt: u16::from_le_bytes([body[0], body[1]]),
                total_refresh_pkts: u16::from_le_bytes([body[2], body[3]]),
                last_seq_num: if body.len() >= 8 { Some(le32(&body[4..8])) } else { None },
                last_symbol_seq_num: if body.len() >= 12 { Some(le32(&body[8..12])) } else { None },
            }
        }
        msg_type::ADD_ORDER => {
            need(34)?;
            Message::AddOrder {
                source_time_ns: le32(&body[0..4]),
                symbol_index: le32(&body[4..8]),
                symbol_seq_num: le32(&body[8..12]),
                order_id: le64(&body[12..20]),
                price: le32(&body[20..24]),
                volume: le32(&body[24..28]),
                side: body[28],
                firm_id: ascii(&body[29..34]),
            }
        }
        msg_type::MODIFY_ORDER => {
            need(30)?;
            Message::ModifyOrder {
                source_time_ns: le32(&body[0..4]),
                symbol_index: le32(&body[4..8]),
                symbol_seq_num: le32(&body[8..12]),
                order_id: le64(&body[12..20]),
                price: le32(&body[20..24]),
                volume: le32(&body[24..28]),
                position_change: body[28],
                side: body[29],
            }
        }
        msg_type::DELETE_ORDER => {
            need(20)?;
            Message::DeleteOrder {
                source_time_ns: le32(&body[0..4]),
                symbol_index: le32(&body[4..8]),
                symbol_seq_num: le32(&body[8..12]),
                order_id: le64(&body[12..20]),
            }
        }
        msg_type::ORDER_EXECUTION => {
            need(38)?;
            Message::Execution {
                source_time_ns: le32(&body[0..4]),
                symbol_index: le32(&body[4..8]),
                symbol_seq_num: le32(&body[8..12]),
                order_id: le64(&body[12..20]),
                trade_id: le32(&body[20..24]),
                price: le32(&body[24..28]),
                volume: le32(&body[28..32]),
                printable: body[32],
                trade_conditions: [body[34], body[35], body[36], body[37]],
            }
        }
        msg_type::REPLACE_ORDER => {
            need(38)?;
            Message::ReplaceOrder {
                source_time_ns: le32(&body[0..4]),
                symbol_index: le32(&body[4..8]),
                symbol_seq_num: le32(&body[8..12]),
                order_id: le64(&body[12..20]),
                new_order_id: le64(&body[20..28]),
                price: le32(&body[28..32]),
                volume: le32(&body[32..36]),
                side: body[36],
            }
        }
        msg_type::IMBALANCE => {
            // Leading fields only; the tail varies by auction type/session.
            need(24)?;
            Message::Imbalance {
                source_time: le32(&body[0..4]),
                source_time_ns: le32(&body[4..8]),
                symbol_index: le32(&body[8..12]),
                symbol_seq_num: le32(&body[12..16]),
                reference_price: le32(&body[16..20]),
                paired_qty: le32(&body[20..24]),
            }
        }
        msg_type::ADD_ORDER_REFRESH => {
            need(38)?;
            Message::AddOrderRefresh {
                source_time: le32(&body[0..4]),
                source_time_ns: le32(&body[4..8]),
                symbol_index: le32(&body[8..12]),
                symbol_seq_num: le32(&body[12..16]),
                order_id: le64(&body[16..24]),
                price: le32(&body[24..28]),
                volume: le32(&body[28..32]),
                side: body[32],
                firm_id: ascii(&body[33..38]),
            }
        }
        msg_type::NON_DISPLAYED_TRADE => {
            need(29)?;
            Message::NonDisplayedTrade {
                source_time_ns: le32(&body[0..4]),
                symbol_index: le32(&body[4..8]),
                symbol_seq_num: le32(&body[8..12]),
                trade_id: le32(&body[12..16]),
                price: le32(&body[16..20]),
                volume: le32(&body[20..24]),
                printable: body[24],
                trade_conditions: [body[25], body[26], body[27], body[28]],
            }
        }
        _ => Message::Other { msg_type: header.msg_type },
    };
    Ok(msg)
}

/// A decoded XDP message. Fields are little-endian per the spec; price
/// fields are raw integer numerators (see module docs).
#[derive(Debug, Clone, PartialEq)]
pub enum Message<'a> {
    SequenceNumberReset {
        source_time: u32,
        source_time_ns: u32,
        product_id: u8,
        channel_id: u8,
    },
    SourceTimeReference {
        /// Matching engine partition (TXN).
        id: u32,
        source_time: u32,
    },
    SymbolIndexMapping {
        symbol_index: u32,
        symbol: &'a str,
        market_id: u16,
        system_id: u8,
        exchange_code: u8,
        price_scale_code: u8,
        security_type: u8,
        lot_size: u16,
        prev_close_price: u32,
        prev_close_volume: u32,
    },
    SecurityStatus {
        source_time: u32,
        source_time_ns: u32,
        symbol_index: u32,
        symbol_seq_num: u32,
        security_status: u8,
        halt_condition: u8,
    },
    RefreshHeader {
        current_refresh_pkt: u16,
        total_refresh_pkts: u16,
        last_seq_num: Option<u32>,
        last_symbol_seq_num: Option<u32>,
    },
    AddOrder {
        source_time_ns: u32,
        symbol_index: u32,
        symbol_seq_num: u32,
        order_id: u64,
        price: u32,
        volume: u32,
        side: u8,
        firm_id: &'a str,
    },
    ModifyOrder {
        source_time_ns: u32,
        symbol_index: u32,
        symbol_seq_num: u32,
        order_id: u64,
        price: u32,
        volume: u32,
        position_change: u8,
        side: u8,
    },
    DeleteOrder {
        source_time_ns: u32,
        symbol_index: u32,
        symbol_seq_num: u32,
        order_id: u64,
    },
    Execution {
        source_time_ns: u32,
        symbol_index: u32,
        symbol_seq_num: u32,
        order_id: u64,
        trade_id: u32,
        price: u32,
        volume: u32,
        printable: u8,
        trade_conditions: [u8; 4],
    },
    ReplaceOrder {
        source_time_ns: u32,
        symbol_index: u32,
        symbol_seq_num: u32,
        order_id: u64,
        new_order_id: u64,
        price: u32,
        volume: u32,
        side: u8,
    },
    Imbalance {
        source_time: u32,
        source_time_ns: u32,
        symbol_index: u32,
        symbol_seq_num: u32,
        reference_price: u32,
        paired_qty: u32,
    },
    AddOrderRefresh {
        source_time: u32,
        source_time_ns: u32,
        symbol_index: u32,
        symbol_seq_num: u32,
        order_id: u64,
        price: u32,
        volume: u32,
        side: u8,
        firm_id: &'a str,
    },
    NonDisplayedTrade {
        source_time_ns: u32,
        symbol_index: u32,
        symbol_seq_num: u32,
        trade_id: u32,
        price: u32,
        volume: u32,
        printable: u8,
        trade_conditions: [u8; 4],
    },
    Other {
        msg_type: u16,
    },
}

impl Message<'_> {
    /// Message type number this variant corresponds to.
    pub fn msg_type(&self) -> u16 {
        match self {
            Message::SequenceNumberReset { .. } => msg_type::SEQ_NUMBER_RESET,
            Message::SourceTimeReference { .. } => msg_type::SOURCE_TIME_REFERENCE,
            Message::SymbolIndexMapping { .. } => msg_type::SYMBOL_INDEX_MAPPING,
            Message::SecurityStatus { .. } => msg_type::SECURITY_STATUS,
            Message::RefreshHeader { .. } => msg_type::REFRESH_HEADER,
            Message::AddOrder { .. } => msg_type::ADD_ORDER,
            Message::ModifyOrder { .. } => msg_type::MODIFY_ORDER,
            Message::DeleteOrder { .. } => msg_type::DELETE_ORDER,
            Message::Execution { .. } => msg_type::ORDER_EXECUTION,
            Message::ReplaceOrder { .. } => msg_type::REPLACE_ORDER,
            Message::Imbalance { .. } => msg_type::IMBALANCE,
            Message::AddOrderRefresh { .. } => msg_type::ADD_ORDER_REFRESH,
            Message::NonDisplayedTrade { .. } => msg_type::NON_DISPLAYED_TRADE,
            Message::Other { msg_type } => *msg_type,
        }
    }
}

/// Convenience: parse a full Ethernet frame down to the XDP layer, when the
/// packet is IPv4/UDP. Returns the UDP payload (the XDP packet).
pub fn udp_payload_of(record_data: &[u8]) -> crate::net::Result<&[u8]> {
    let frame = crate::net::parse_ethernet(record_data)?;
    if frame.ethertype != crate::net::ETHERTYPE_IPV4 {
        return Err(crate::net::NetError::Unsupported("non-IPv4 ethernet frame"));
    }
    let ip = crate::net::parse_ipv4(frame.payload)?;
    if ip.protocol != crate::net::IPPROTO_UDP {
        return Err(crate::net::NetError::Unsupported("non-UDP ip packet"));
    }
    let udp = crate::net::parse_udp(ip.payload)?;
    Ok(udp.payload)
}

impl fmt::Display for Message<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Message::SequenceNumberReset { source_time, source_time_ns, product_id, channel_id } => {
                write!(f, "SeqReset t{source_time}.{source_time_ns:09} product {product_id} channel {channel_id}")
            }
            Message::SourceTimeReference { id, source_time } => {
                write!(f, "TimeRef partition {id} second {source_time}")
            }
            Message::SymbolIndexMapping { symbol_index, symbol, market_id, price_scale_code, .. } => {
                write!(f, "SymMap sym#{symbol_index} \"{symbol}\" market {market_id} scale {price_scale_code}")
            }
            Message::SecurityStatus { symbol_index, security_status, halt_condition, .. } => {
                write!(
                    f,
                    "SecStatus sym#{symbol_index} status {} halt {}",
                    *security_status as char, *halt_condition as char
                )
            }
            Message::RefreshHeader { current_refresh_pkt, total_refresh_pkts, .. } => {
                write!(f, "RefreshHdr pkt {current_refresh_pkt}/{}", total_refresh_pkts)
            }
            Message::AddOrder { symbol_index, symbol_seq_num, order_id, price, volume, side, firm_id, .. } => {
                write!(
                    f,
                    "AddOrder sym#{symbol_index} seq {symbol_seq_num} order {order_id:016x} price {price} vol {volume} side {}{}",
                    *side as char,
                    if firm_id.is_empty() { String::new() } else { format!(" firm {firm_id}") }
                )
            }
            Message::ModifyOrder { symbol_index, order_id, price, volume, side, .. } => {
                write!(f, "ModifyOrder sym#{symbol_index} order {order_id:016x} price {price} vol {volume} side {}", *side as char)
            }
            Message::DeleteOrder { symbol_index, order_id, .. } => {
                write!(f, "DeleteOrder sym#{symbol_index} order {order_id:016x}")
            }
            Message::Execution { symbol_index, order_id, trade_id, price, volume, printable, .. } => {
                write!(
                    f,
                    "Execution sym#{symbol_index} order {order_id:016x} trade {trade_id} price {price} vol {volume} printable {printable}"
                )
            }
            Message::ReplaceOrder { symbol_index, order_id, new_order_id, price, volume, side, .. } => {
                write!(
                    f,
                    "ReplaceOrder sym#{symbol_index} order {order_id:016x} -> {new_order_id:016x} price {price} vol {volume} side {}",
                    *side as char
                )
            }
            Message::Imbalance { symbol_index, reference_price, paired_qty, .. } => {
                write!(f, "Imbalance sym#{symbol_index} refprice {reference_price} paired {paired_qty}")
            }
            Message::AddOrderRefresh { symbol_index, order_id, price, volume, side, .. } => {
                write!(
                    f,
                    "AddOrderRefresh sym#{symbol_index} order {order_id:016x} price {price} vol {volume} side {}",
                    *side as char
                )
            }
            Message::NonDisplayedTrade { symbol_index, trade_id, price, volume, printable, .. } => {
                write!(
                    f,
                    "NonDisplayedTrade sym#{symbol_index} trade {trade_id} price {price} vol {volume} printable {printable}"
                )
            }
            Message::Other { msg_type } => write!(f, "MsgType {msg_type}"),
        }
    }
}

/// [`PacketParser`] for NYSE XDP (Pillar Integrated Feed) captures.
///
/// Dissects Ethernet/VLAN/IPv4/UDP down to the XDP packet layer, decodes
/// every message, and accumulates the per-capture statistics rendered by
/// [`summarize`](PacketParser::summarize). Non-IP frames on the same capture
/// are tolerated and counted as `non_feed_packets`; XDP-layer corruption is
/// a hard error.
#[derive(Debug, Default)]
pub struct XdpParser {
    /// XDP packets successfully parsed.
    pub packets: u64,
    /// Messages decoded across all packets.
    pub messages: u64,
    /// Frames that could not be dissected to a UDP payload (e.g. non-IP).
    pub non_feed_packets: u64,
    /// Packet count per DeliveryFlag value.
    pub delivery: HashMap<u8, u64>,
    /// Message count per message type.
    pub types: HashMap<u16, u64>,
    /// Rendered first Add Order message, if any was seen.
    pub first_add_order: Option<String>,
}

impl PacketParser for XdpParser {
    fn name(&self) -> &'static str {
        "xdp"
    }

    fn describe(&self) -> &'static str {
        "NYSE XDP (Pillar Integrated Feed)"
    }

    fn parse_packet<'a>(
        &mut self,
        packet: &'a [u8],
    ) -> std::result::Result<Vec<Event<'a>>, FeedError> {
        self.packets += 1;
        let payload = match udp_payload_of(packet) {
            Ok(p) => p,
            // Captures may mix in frames without a feed payload (ARP, ...).
            Err(crate::net::NetError::Unsupported(_)) => {
                self.non_feed_packets += 1;
                return Ok(Vec::new());
            }
            Err(e) => return Err(e.into()),
        };
        let (hdr, msgs) = PacketHeader::parse(payload)?;
        *self.delivery.entry(hdr.delivery_flag).or_default() += 1;

        let mut events = Vec::new();
        for m in msgs {
            let (mhdr, body) = m?;
            let msg = decode(mhdr, body)?;
            if self.first_add_order.is_none() {
                if let Message::AddOrder { symbol_index, symbol_seq_num, price, volume, side, .. } =
                    &msg
                {
                    self.first_add_order = Some(format!(
                        "Add Order sym#{symbol_index} seq {symbol_seq_num} price {price} vol {volume} side {}",
                        *side as char
                    ));
                }
            }
            *self.types.entry(msg.msg_type()).or_default() += 1;
            self.messages += 1;
            events.push(Event::Xdp(msg));
        }
        Ok(events)
    }

    fn summarize(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "xdp payload (NYSE XDP — Pillar Integrated Feed):\n"
        ));
        out.push_str(&format!(
            "  packets:  {} ({} non-feed frames)\n",
            self.packets, self.non_feed_packets
        ));
        let mut flags: Vec<_> = self.delivery.iter().collect();
        flags.sort_by_key(|(f, n)| (std::cmp::Reverse(**n), **f));
        let flag_str = flags
            .iter()
            .map(|(f, n)| format!("{} {} ({})", n, delivery_name(**f), f))
            .collect::<Vec<_>>()
            .join(", ");
        out.push_str(&format!("  delivery: {flag_str}\n"));
        out.push_str(&format!("  messages: {}\n", self.messages));
        let mut types: Vec<_> = self.types.iter().collect();
        types.sort_by_key(|(t, _)| **t);
        for (t, n) in types {
            out.push_str(&format!(
                "    {:>5} {:<24} {}\n",
                t,
                msg_type_name(*t),
                n
            ));
        }
        if let Some(s) = &self.first_add_order {
            out.push_str(&format!("  first market message: {s}\n"));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn le_append(v: &mut Vec<u8>, x: &[u8]) {
        v.extend_from_slice(x);
    }

    /// Packet header bytes: LE pkt_size must be patched after building.
    fn build_packet(delivery: u8, msgs: &[Vec<u8>]) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(&0u16.to_le_bytes()); // patched below
        p.push(delivery);
        p.push(msgs.len() as u8);
        p.extend_from_slice(&100u32.to_le_bytes()); // seq
        p.extend_from_slice(&1_692_709_200u32.to_le_bytes()); // 13:00:00 UTC
        p.extend_from_slice(&945_411u32.to_le_bytes());
        for m in msgs {
            le_append(&mut p, m);
        }
        let n = p.len() as u16;
        p[0..2].copy_from_slice(&n.to_le_bytes());
        p
    }

    fn message(msg_type: u16, body: &[u8]) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(&((4 + body.len()) as u16).to_le_bytes());
        m.extend_from_slice(&msg_type.to_le_bytes());
        m.extend_from_slice(body);
        m
    }

    #[test]
    fn heartbeat_packet_has_no_messages() {
        let p = build_packet(DELIVERY_HEARTBEAT, &[]);
        assert_eq!(p.len(), 16);
        let (hdr, mut msgs) = PacketHeader::parse(&p).unwrap();
        assert_eq!(hdr.num_msgs, 0);
        assert_eq!(hdr.seq_num, 100);
        assert_eq!(hdr.send_time, 1_692_709_200);
        assert_eq!(hdr.send_time_ns, 945_411);
        assert!(msgs.next().is_none());
    }

    #[test]
    fn pkt_size_mismatch_rejected() {
        let mut p = build_packet(DELIVERY_ORIGINAL, &[]);
        p[0..2].copy_from_slice(&999u16.to_le_bytes());
        assert!(matches!(
            PacketHeader::parse(&p),
            Err(XdpError::Corrupted("PktSize does not match payload length"))
        ));
    }

    #[test]
    fn source_time_reference_roundtrip() {
        let mut body = Vec::new();
        body.extend_from_slice(&54u32.to_le_bytes()); // partition id
        body.extend_from_slice(&0u32.to_le_bytes()); // reserved
        body.extend_from_slice(&1_692_709_200u32.to_le_bytes());
        let p = build_packet(DELIVERY_ORIGINAL, &[message(2, &body)]);
        let (_, mut msgs) = PacketHeader::parse(&p).unwrap();
        let (hdr, body) = msgs.next().unwrap().unwrap();
        assert_eq!(hdr.msg_type, 2);
        match decode(hdr, body).unwrap() {
            Message::SourceTimeReference { id, source_time } => {
                assert_eq!(id, 54);
                assert_eq!(source_time, 1_692_709_200);
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn real_capture_add_order_decodes() {
        // Bytes straight from the capture (record #2 of pillar-b 13:00):
        // msg size 39, type 100.
        let m: Vec<u8> = [
            0x27, 0x00, 0x64, 0x00, 0x4b, 0xfb, 0x09, 0x00, 0x73, 0xe4, 0x00, 0x00, 0x2f, 0x00,
            0x00, 0x00, 0xd0, 0x2a, 0x02, 0x00, 0x00, 0x09, 0x36, 0x00, 0xa0, 0x3b, 0x46, 0x01,
            0x64, 0x00, 0x00, 0x00, 0x42, 0x20, 0x20, 0x20, 0x20, 0x20, 0x00,
        ]
        .to_vec();
        let hdr = MessageHeader { size: 39, msg_type: 100 };
        match decode(hdr, &m[4..]).unwrap() {
            Message::AddOrder { source_time_ns, symbol_index, symbol_seq_num, order_id, price, volume, side, firm_id } => {
                assert_eq!(source_time_ns, 654_155);
                assert_eq!(symbol_index, 58_483);
                assert_eq!(symbol_seq_num, 47);
                assert_eq!(order_id, u64::from_le_bytes([
                    0xd0, 0x2a, 0x02, 0x00, 0x00, 0x09, 0x36, 0x00,
                ]));
                // Numerator with scale 6 => $21.38.
                assert_eq!(price, 21_380_000);
                assert_eq!(volume, 100);
                assert_eq!(side, b'B');
                assert_eq!(firm_id, "");
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn real_capture_symbol_index_mapping_decodes() {
        // Type 3 from the refresh sequence: symbol WSM, NYSE American feed
        // (market id 9), NYSE-listed ('N'), price scale 6, prev close
        // $128.91 (0x07ADCA30 / 10^6). Values verbatim from the capture.
        let mut m = Vec::new();
        m.extend_from_slice(&44u16.to_le_bytes());
        m.extend_from_slice(&3u16.to_le_bytes());
        m.extend_from_slice(&10_051u32.to_le_bytes()); // SymbolIndex
        let mut sym = b"WSM".to_vec();
        sym.resize(11, 0); // 11-byte null-padded ASCII field
        m.extend_from_slice(&sym);
        m.push(0); // Reserved
        m.extend_from_slice(&9u16.to_le_bytes()); // MarketID: NYSE American
        m.push(0x35); // SystemID
        m.push(b'N'); // ExchangeCode: NYSE-listed
        m.push(6); // PriceScaleCode
        m.push(b'C'); // SecurityType: common stock
        m.extend_from_slice(&100u16.to_le_bytes()); // LotSize
        m.extend_from_slice(&0x07AD_CA30u32.to_le_bytes()); // PrevClosePrice
        m.extend_from_slice(&0u32.to_le_bytes()); // PrevCloseVolume
        // Tail as observed (price resolution, round lot, MPV, unit, rsv).
        m.extend_from_slice(&[0x4e, 0x64, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(m.len(), 44);
        assert_eq!(m.len(), 44);
        let hdr = MessageHeader { size: 44, msg_type: 3 };
        match decode(hdr, &m[4..]).unwrap() {
            Message::SymbolIndexMapping { symbol_index, symbol, market_id, exchange_code, price_scale_code, security_type, lot_size, prev_close_price, .. } => {
                assert_eq!(symbol_index, 10_051);
                assert_eq!(symbol, "WSM");
                assert_eq!(market_id, 9); // NYSE American Equities
                assert_eq!(exchange_code, b'N');
                assert_eq!(price_scale_code, 6);
                assert_eq!(security_type, b'C');
                assert_eq!(lot_size, 100);
                assert_eq!(prev_close_price, 0x07AD_CA30);
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn refresh_header_full_and_short() {
        // Full: 16 bytes. Short: 8 bytes (seq fields dropped).
        let full = message(35, &[1, 0, 1, 0, 0xae, 0x27, 0x01, 0x00, 3, 0, 0, 0]);
        let short = message(35, &[2, 0, 3, 0]);
        let p = build_packet(DELIVERY_REFRESH_START, &[full]);
        let (_, mut msgs) = PacketHeader::parse(&p).unwrap();
        let (hdr, body) = msgs.next().unwrap().unwrap();
        match decode(hdr, body).unwrap() {
            Message::RefreshHeader { current_refresh_pkt, total_refresh_pkts, last_seq_num, last_symbol_seq_num } => {
                assert_eq!((current_refresh_pkt, total_refresh_pkts), (1, 1));
                assert_eq!(last_seq_num, Some(0x127AE));
                assert_eq!(last_symbol_seq_num, Some(3));
            }
            other => panic!("wrong variant: {other:?}"),
        }
        let p = build_packet(DELIVERY_REFRESH_PART, &[short]);
        let (_, mut msgs) = PacketHeader::parse(&p).unwrap();
        let (hdr, body) = msgs.next().unwrap().unwrap();
        match decode(hdr, body).unwrap() {
            Message::RefreshHeader { current_refresh_pkt, total_refresh_pkts, last_seq_num, last_symbol_seq_num } => {
                assert_eq!((current_refresh_pkt, total_refresh_pkts), (2, 3));
                assert_eq!(last_seq_num, None);
                assert_eq!(last_symbol_seq_num, None);
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn multiple_messages_tile_exactly() {
        let m1 = message(2, &[54, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let mut b = Vec::new();
        b.extend_from_slice(&636_235u32.to_le_bytes());
        b.extend_from_slice(&58_483u32.to_le_bytes());
        b.extend_from_slice(&48u32.to_le_bytes());
        b.extend_from_slice(&[0xd0, 0x2a, 0x02, 0x00, 0x00, 0x09, 0x36, 0x00]);
        b.push(0);
        let m2 = message(102, &b);
        let p = build_packet(DELIVERY_ORIGINAL, &[m1, m2]);
        let (hdr, mut msgs) = PacketHeader::parse(&p).unwrap();
        assert_eq!(hdr.num_msgs, 2);
        let (h1, _) = msgs.next().unwrap().unwrap();
        let (h2, b2) = msgs.next().unwrap().unwrap();
        assert_eq!((h1.msg_type, h2.msg_type), (2, 102));
        match decode(h2, b2).unwrap() {
            Message::DeleteOrder { symbol_seq_num, .. } => assert_eq!(symbol_seq_num, 48),
            other => panic!("wrong variant: {other:?}"),
        }
        assert!(msgs.next().is_none());
    }

    #[test]
    fn sequence_number_reset_decodes() {
        // MsgSize 14 (header included): SourceTime, SourceTimeNS,
        // ProductID, ChannelID. Regression test: this message appears in
        // the pillar-a captures (session boundaries) and the decoder must
        // not require the spec size twice.
        let mut m = Vec::new();
        m.extend_from_slice(&14u16.to_le_bytes());
        m.extend_from_slice(&1u16.to_le_bytes());
        m.extend_from_slice(&1_692_663_600u32.to_le_bytes());
        m.extend_from_slice(&0u32.to_le_bytes());
        m.push(1); // ProductID
        m.push(8); // ChannelID
        assert_eq!(m.len(), 14);
        let hdr = MessageHeader { size: 14, msg_type: 1 };
        match decode(hdr, &m[4..]).unwrap() {
            Message::SequenceNumberReset { source_time, source_time_ns, product_id, channel_id } => {
                assert_eq!(source_time, 1_692_663_600);
                assert_eq!(source_time_ns, 0);
                assert_eq!((product_id, channel_id), (1, 8));
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn truncated_message_rejected() {
        let mut m = message(100, &[0u8; 30]); // claims 34 bytes total, fine on its own
        let mut p = build_packet(DELIVERY_ORIGINAL, &[m.clone()]);
        // Chop the packet tail: PktSize no longer matches.
        p.truncate(p.len() - 5);
        assert!(PacketHeader::parse(&p).is_err());
        // A message whose size field exceeds the packet: craft raw, with
        // num_msgs patched to 1 so the iterator actually visits it.
        let mut raw = build_packet(DELIVERY_ORIGINAL, &[]);
        m[0..2].copy_from_slice(&500u16.to_le_bytes());
        raw.extend_from_slice(&m);
        raw[3] = 1;
        let n = raw.len() as u16;
        raw[0..2].copy_from_slice(&n.to_le_bytes());
        let (_, mut msgs) = PacketHeader::parse(&raw).unwrap();
        assert!(matches!(
            msgs.next(),
            Some(Err(XdpError::Corrupted("message extends past packet end")))
        ));
    }

    #[test]
    fn unknown_message_type_passes_through() {
        let p = build_packet(DELIVERY_ORIGINAL, &[message(250, &[1, 2, 3, 4])]);
        let (_, mut msgs) = PacketHeader::parse(&p).unwrap();
        let (hdr, body) = msgs.next().unwrap().unwrap();
        match decode(hdr, body).unwrap() {
            Message::Other { msg_type } => assert_eq!(msg_type, 250),
            other => panic!("wrong variant: {other:?}"),
        }
    }
}
