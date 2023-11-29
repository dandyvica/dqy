// Defines the OPT RR when received
//use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

use crate::buffer::Buffer;

pub struct OptOption {
    pub code: u16,
    pub length: u16,
    pub data: Buffer,
}

#[derive(Debug, Default, FromNetwork)]
pub struct ExtendedRcode {
    pub extented_rcode: u8,
    pub version: u8,
    pub doz: u16,
}
