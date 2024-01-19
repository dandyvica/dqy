use std::fmt;

use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

use serde::Serialize;

use super::char_string::CharacterString;

// HINFO RR
#[derive(Debug, Default, FromNetwork, Serialize)]
pub struct HINFO {
    cpu: CharacterString,
    os: CharacterString,
}

impl fmt::Display for HINFO {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.cpu, self.os)
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

    use super::HINFO;

    test_rdata!(
        rdata,
        "./tests/hinfo.pcap",
        false,
        1,
        RData::HINFO,
        (|x: &HINFO, _| {
            assert_eq!(&x.to_string(), "PDP-11 UNIX");
        })
    );
}
