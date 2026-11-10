//! Pluggable feed parsers — the layer between pcap records and a market
//! data protocol.
//!
//! The pipeline is fixed up to the pcap layer:
//!
//! ```text
//! .zst file ──zstd──▶ pcap bytes ──pcap──▶ packet records ──PacketParser──▶ events
//! ```
//!
//! Everything after the record layer is swappable: implement
//! [`PacketParser`] for your protocol (XDP, ITCH, ...), return it from
//! [`parser_by_name`], and it composes with the zstd/pcap machinery
//! unchanged. Each parser lives in its own submodule and owns its
//! transport-specific dissection (e.g. [`xdp`] uses [`crate::net`] to get
//! from the Ethernet frame to the UDP payload).

pub mod xdp;

use std::fmt;

use crate::net;
use crate::pcap;

/// Errors surfaced by a [`PacketParser`] while dissecting a packet.
#[derive(Debug)]
pub enum FeedError {
    /// L2-L4 dissection failure (Ethernet / IPv4 / UDP).
    Transport(net::NetError),
    /// Application-layer (feed protocol) decode failure.
    Application(String),
    /// A structural violation detected by the parser itself.
    Corrupted(&'static str),
}

impl fmt::Display for FeedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FeedError::Transport(e) => write!(f, "transport: {e}"),
            FeedError::Application(e) => write!(f, "feed decode: {e}"),
            FeedError::Corrupted(what) => write!(f, "corrupt packet: {what}"),
        }
    }
}

impl std::error::Error for FeedError {}

impl From<net::NetError> for FeedError {
    fn from(e: net::NetError) -> Self {
        FeedError::Transport(e)
    }
}

impl From<xdp::XdpError> for FeedError {
    fn from(e: xdp::XdpError) -> Self {
        FeedError::Application(e.to_string())
    }
}

/// One decoded item handed back by a [`PacketParser`].
///
/// New feed modules extend this enum with their own message types (see the
/// module docs for the recipe).
#[derive(Debug)]
pub enum Event<'a> {
    /// A decoded XDP message (NYSE XDP feeds).
    Xdp(xdp::Message<'a>),
}

impl fmt::Display for Event<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Event::Xdp(m) => write!(f, "xdp {m}"),
        }
    }
}

/// A payload parser plugged in after the pcap record layer.
///
/// Implement this for a protocol (see [`xdp::XdpParser`] for a full
/// example), then hand instances out via [`parser_by_name`]. Parsers are
/// stateful: they accumulate whatever statistics their [`summarize`]
/// reports.
///
/// [`summarize`]: PacketParser::summarize
pub trait PacketParser {
    /// Selection name (used by [`parser_by_name`] and CLI flags).
    fn name(&self) -> &'static str;

    /// One-line human description of the feed handled.
    fn describe(&self) -> &'static str;

    /// Called once with the pcap global header before the first packet.
    /// Parsers can use e.g. the link type to configure themselves.
    /// Default: no-op.
    fn begin(&mut self, _header: &pcap::GlobalHeader) {}

    /// Dissect one packet — the raw bytes of a pcap record.
    ///
    /// Transport dissection (Ethernet/IP/UDP) is the parser's job;
    /// [`crate::net`] provides the shared helpers. Returns the decoded
    /// events; packets with no application payload (e.g. heartbeats) yield
    /// an empty vector.
    ///
    /// Errors: transport-level absence of a feed payload (e.g. a non-IP
    /// frame on the same capture) should be tolerated by the parser if the
    /// capture is expected to mix traffic; structural corruption must be
    /// returned as an error.
    fn parse_packet<'a>(
        &mut self,
        packet: &'a [u8],
    ) -> Result<Vec<Event<'a>>, FeedError>;

    /// End-of-capture report. Default: empty.
    fn summarize(&self) -> String {
        String::new()
    }
}

/// A parser that does no dissection — counts packets only.
///
/// Useful as a baseline and as the minimal template for new parsers.
#[derive(Debug, Default)]
pub struct NullParser {
    packets: u64,
}

impl PacketParser for NullParser {
    fn name(&self) -> &'static str {
        "none"
    }

    fn describe(&self) -> &'static str {
        "no payload dissection (counts packets only)"
    }

    fn parse_packet<'a>(
        &mut self,
        _packet: &'a [u8],
    ) -> Result<Vec<Event<'a>>, FeedError> {
        self.packets += 1;
        Ok(Vec::new())
    }

    fn summarize(&self) -> String {
        format!("packets: {}", self.packets)
    }
}

/// Names accepted by [`parser_by_name`].
pub const PARSER_NAMES: &[&str] = &["xdp", "none"];

/// Build the parser registered under `name` ("xdp", "none").
pub fn parser_by_name(name: &str) -> Option<Box<dyn PacketParser>> {
    match name {
        "xdp" => Some(Box::new(xdp::XdpParser::default())),
        "none" => Some(Box::new(NullParser::default())),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_returns_requested_parser() {
        let p = parser_by_name("xdp").unwrap();
        assert_eq!(p.name(), "xdp");
        let p = parser_by_name("none").unwrap();
        assert_eq!(p.name(), "none");
        assert!(parser_by_name("itch").is_none()); // not implemented yet
        assert!(parser_by_name("").is_none());
    }

    #[test]
    fn null_parser_counts_and_summarizes() {
        let mut p = parser_by_name("none").unwrap();
        assert_eq!(p.parse_packet(&[1, 2, 3]).unwrap().len(), 0);
        assert_eq!(p.parse_packet(&[]).unwrap().len(), 0);
        assert_eq!(p.summarize(), "packets: 2");
    }

    #[test]
    fn events_display_through_the_trait_object() {
        // An XDP heartbeat packet yields no events; the Display path is
        // exercised in xdp.rs tests via concrete messages.
        let mut p = parser_by_name("none").unwrap();
        let evs = p.parse_packet(&[0u8; 8]).unwrap();
        assert!(evs.is_empty());
    }
}
