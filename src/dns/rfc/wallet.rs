use std::fmt;

use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

use serde::Serialize;

use super::char_string::CharacterString;

// MX RR
#[derive(Debug, Default, FromNetwork, Serialize)]
pub struct WALLET {
    pub abbrev: CharacterString,
    pub address: CharacterString,
}

impl fmt::Display for WALLET {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.abbrev, self.address)
    }
}

// #[cfg(test)]
// mod tests {
//     use crate::{
//         dns::rfc::{rdata::RData, response::Response},
//         dns::tests::get_packets,
//         test_rdata,
//     };

//     use type2network::FromNetworkOrder;

//     use super::WALLET;

//     test_rdata!(
//         rdata,
//         "./tests/pcap/txt.pcap",
//         false,
//         1,
//         RData::TXT,
//         (|x: &TXT, i: usize| {
//             match i {
//                 0 => assert_eq!(
//                     x.to_string(),
//                     "Descriptive text. Completely overloaded for all sorts of things. RFC1035 (1987)"
//                 ),
//                 1 => assert_eq!(x.to_string(), "Format: <text>"),
//                 _ => panic!("data not is the pcap file"),
//             }
//         })
//     );
// }
