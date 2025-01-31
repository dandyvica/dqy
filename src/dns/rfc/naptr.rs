use std::fmt;

use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

use serde::Serialize;

use super::{char_string::CharacterString, domain::DomainName};

// 1  1  1  1  1  1
// 0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                     ORDER                     |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                   PREFERENCE                  |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// /                     FLAGS                     /
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// /                   SERVICES                    /
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// /                    REGEXP                     /
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// /                  REPLACEMENT                  /
// /                                               /
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Default, FromNetwork, Serialize)]
pub struct NAPTR {
    order: u16,
    preference: u16,
    flags: CharacterString,
    services: CharacterString,
    regex: CharacterString,
    replacement: DomainName,
}

impl fmt::Display for NAPTR {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} \"{}\" \"{}\" \"{}\" {}",
            self.order, self.preference, self.flags, self.services, self.regex, self.replacement
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        dns::rfc::{rdata::RData, response::Response},
        dns::tests::get_packets,
        test_rdata,
    };

    use type2network::FromNetworkOrder;

    use super::NAPTR;

    test_rdata!(
        rdata,
        "./tests/pcap/naptr.pcap",
        false,
        1,
        RData::NAPTR,
        (|x: &NAPTR, i: usize| {
            match i {
                0 => assert_eq!(
                    x.to_string(),
                    "10 10 \"u\" \"smtp+E2U\" \"!.*([^.]+[^.]+)$!mailto:postmaster@$1!i\" ."
                ),
                1 => assert_eq!(
                    x.to_string(),
                    "20 10 \"s\" \"http+N2L+N2C+N2R\" \"\" www.netmeister.org."
                ),
                _ => panic!("data not is the pcap file"),
            }
        })
    );
}
