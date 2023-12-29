use std::fmt;

use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

use super::domain::DomainName;

// MX RR
#[derive(Debug, Default, FromNetwork)]
pub struct MX<'a> {
    pub preference: u16, // A 16 bit integer which specifies the preference given to
    // this RR among others at the same owner.  Lower values
    // are preferred.
    pub exchange: DomainName<'a>, // A <domain-name> which specifies a host willing to act as a mail exchange for the owner name.
}

impl<'a> fmt::Display for MX<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.preference, self.exchange)
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

    use super::MX;

    test_rdata!(
        rdata,
        "./tests/mx.pcap",
        RData::MX,
        (|x: &MX, _| {
            assert_eq!(&x.to_string(), "50 panix.netmeister.org.");
        })
    );
}
