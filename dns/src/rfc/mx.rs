use std::fmt;

use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

use serde::Serialize;

use super::domain::DomainName;

// MX RR
#[derive(Debug, Default, FromNetwork, Serialize)]
pub struct MX {
    pub preference: u16, // A 16 bit integer which specifies the preference given to
    // this RR among others at the same owner.  Lower values
    // are preferred.
    pub exchange: DomainName, // A <domain-name> which specifies a host willing to act as a mail exchange for the owner name.
}

impl fmt::Display for MX {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.preference, self.exchange)
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

    use super::MX;

    test_rdata!(
        rdata,
        "./tests/mx.pcap",
        false,
        1,
        RData::MX,
        (|x: &MX, _| {
            assert_eq!(&x.to_string(), "50 panix.netmeister.org.");
        })
    );
}
