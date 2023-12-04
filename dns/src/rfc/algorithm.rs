use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

use enum_from::{EnumDisplay, EnumFromStr, EnumTryFrom};

#[derive(
    Debug,
    Default,
    Copy,
    Clone,
    PartialEq,
    EnumFromStr,
    EnumTryFrom,
    EnumDisplay,
    FromNetwork,
)]
#[repr(u8)]
#[allow(non_camel_case_types)]
pub enum Algorithm {
    #[default]
    DELETE = 0,
    RSAMD5 = 1,
    DH = 2,
    DSA = 3,
    RSASHA1 = 5,
    DSA_NSEC3_SHA1 = 6,
    RSASHA1_NSEC3_SHA1 = 7,
    RSASHA256 = 8,
    RSASHA512 = 10,
    ECC_GOST = 12,
    ECDSAP256SHA256 = 13,
    ECDSAP384SHA384 = 14,
    ED25519 = 15,
    ED448 = 16,
    INDIRECT = 252,
    PRIVATEDNS = 253,
    PRIVATEOID = 254,

    #[fallback]
    Reserved(u8)
}
