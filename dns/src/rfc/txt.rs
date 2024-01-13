use std::fmt;

use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

use serde::Serialize;

use super::char_string::CharacterString;

// MX RR
#[derive(Debug, Default, FromNetwork, Serialize)]
pub struct TXT<'a>(pub CharacterString<'a>);

impl<'a> fmt::Display for TXT<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        rfc::{rdata::RData, response::Response},
        test_rdata,
        tests::get_packets,
    };

    use type2network::FromNetworkOrder;

    use super::TXT;

    test_rdata!(
        rdata,
        "./tests/txt.pcap",
        false,
        1,
        RData::TXT,
        (|x: &TXT, i: usize| {
            match i {
                0 => assert_eq!(x.to_string(), "Descriptive text. Completely overloaded for all sorts of things. RFC1035 (1987)"),
                1 => assert_eq!(x.to_string(), "Format: <text>"),
                _ => panic!("data not is the pcap file"),
            }
        })
    );
}
