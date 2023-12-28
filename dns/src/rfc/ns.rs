use std::fmt;

use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

use super::domain::DomainName;

// NS resource record
#[derive(Debug, Default, FromNetwork)]
pub struct NS<'a>(pub DomainName<'a>);

impl<'a> fmt::Display for NS<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
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

    use super::NS;

    test_rdata!(
        "./tests/ns.pcap",
        RData::NS,
        (|x: &NS, _| {
            assert_eq!(&x.to_string(), "panix.netmeister.org.");
        })
    );
}
