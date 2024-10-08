use std::fmt;

use byteorder::ReadBytesExt;
use serde::Serialize;

use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

use enum_from::EnumTryFrom;

/// The header flags' first bit is 0 or 1 meaning a question or a response. Better is to use an enum which is
/// both clearer and type oriented.
#[derive(Debug, Default, Clone, Copy, PartialEq, EnumTryFrom, FromNetwork, Serialize)]
#[repr(u8)]
#[from_network(TryFrom)]
pub enum PacketType {
    #[default]
    Query = 0,
    Response = 1,
}

impl fmt::Display for PacketType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // output depends on whether it's a query or a response
        // because some fields are unnecessary when Query or Response
        match *self {
            PacketType::Query => write!(f, "QUERY"),
            PacketType::Response => write!(f, "RESPONSE"),
        }
    }
}
