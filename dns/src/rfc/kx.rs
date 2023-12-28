use std::fmt;

use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

use super::domain::DomainName;

// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                  PREFERENCE                   |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// /                   EXCHANGER                   /
// /                                               /
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#[derive(Debug, Default, FromNetwork)]
pub(super) struct KX<'a> {
    preference: u16,
    exchanger: DomainName<'a>,
}

impl<'a> fmt::Display for KX<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.preference, self.exchanger)
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

    use super::KX;

    test_rdata!(
        "./tests/kx.pcap",
        RData::KX,
        (|x: &KX, _| {
            assert_eq!(&x.to_string(), "1 panix.netmeister.org.");
        })
    );
}
