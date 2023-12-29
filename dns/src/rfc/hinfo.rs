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
        write!(f, "{} {}", self.cpu, self.os)
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

    use super::HINFO;

    test_rdata!(
        rdata,
        "./tests/hinfo.pcap",
        RData::HINFO,
        (|x: &HINFO, _| {
            assert_eq!(&x.to_string(), "PDP-11 UNIX");
        })
    );
}
