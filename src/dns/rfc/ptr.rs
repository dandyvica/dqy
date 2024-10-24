use std::fmt;

use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

use serde::Serialize;

use super::domain::DomainName;

// CNAME resource record
#[derive(Debug, Default, FromNetwork, Serialize)]
pub struct PTR(DomainName);

impl fmt::Display for PTR {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
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

    use super::PTR;

    test_rdata!(
        rdata,
        "./tests/pcap/ptr.pcap",
        false,
        1,
        RData::PTR,
        (|x: &PTR, _| {
            assert_eq!(&x.to_string(), "ptr.dns.netmeister.org.");
        })
    );
}
