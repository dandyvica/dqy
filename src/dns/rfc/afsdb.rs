use std::fmt;

use serde::Serialize;
use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

use super::domain::DomainName;

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Default, FromNetwork, Serialize)]
pub struct AFSDB {
    subtype: u16,
    hostname: DomainName,
}

impl fmt::Display for AFSDB {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} ", self.subtype, self.hostname)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        dns::rfc::{afsdb::AFSDB, rdata::RData, response::Response},
        dns::tests::get_packets,
        test_rdata,
    };

    use type2network::FromNetworkOrder;

    test_rdata!(
        rdata,
        "./tests/pcap/afsdb.pcap",
        false,
        1,
        RData::AFSDB,
        (|x: &AFSDB, _| {
            assert_eq!(x.subtype, 1u16);
            assert_eq!(x.hostname.to_string(), "panix.netmeister.org.");
        })
    );
}
