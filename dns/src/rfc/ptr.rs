use std::fmt;

use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

use super::domain::DomainName;

// CNAME resource record
#[derive(Debug, Default, FromNetwork)]
pub struct PTR<'a>(DomainName<'a>);

impl<'a> fmt::Display for PTR<'a> {
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
        tests::get_packets,
    };

    use type2network::FromNetworkOrder;

    use super::PTR;

    test_rdata!(
        rdata,
        "./tests/ptr.pcap",
        false,
        1,
        RData::PTR,
        (|x: &PTR, _| {
            assert_eq!(&x.to_string(), "ptr.dns.netmeister.org.");
        })
    );
}
