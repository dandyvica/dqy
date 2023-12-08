use std::fmt;

use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

use super::char_string::CharacterString;

// HINFO RR
#[derive(Debug, Default, FromNetwork)]
pub struct HINFO<'a> {
    cpu: CharacterString<'a>,
    os: CharacterString<'a>,
}

impl<'a> fmt::Display for HINFO<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "cpu:{} os:{}", self.cpu, self.os,)
    }
}
