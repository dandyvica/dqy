use std::fmt;

use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

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
#[derive(Debug, Default, FromNetwork)]
pub(super) struct NAPTR<'a> {
    order: u16,
    preference: u16,
    flags: CharacterString<'a>,
    services: CharacterString<'a>,
    regex: CharacterString<'a>,
    replacement: DomainName<'a>,
}

impl<'a> fmt::Display for NAPTR<'a> {
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
        error::DNSResult,
        rfc::{rdata::RData, response::Response},
        test_rdata,
        tests::{get_pcap_buffer, read_pcap_sample},
    };

    use type2network::FromNetworkOrder;

    use super::NAPTR;

    test_rdata!(
        rdata,
        "./tests/naptr.pcap",
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
