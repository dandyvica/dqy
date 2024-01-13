use std::fmt;

use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

use serde::Serialize;

use super::domain::DomainName;

// NS resource record
#[derive(Debug, Default, FromNetwork, Serialize)]
pub struct NS<'a>(pub DomainName<'a>);

impl<'a> fmt::Display for NS<'a> {
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

    use super::NS;

    test_rdata!(
        rdata,
        "./tests/ns.pcap",
        false,
        1,
        RData::NS,
        (|x: &NS, _| {
            assert_eq!(&x.to_string(), "panix.netmeister.org.");
        })
    );
}
