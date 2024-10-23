use std::fmt;

use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

use serde::Serialize;

use super::domain::DomainName;

#[derive(Debug, Default, FromNetwork, Serialize)]
pub(super) struct RP {
    mbox: DomainName,
    hostname: DomainName,
}

impl fmt::Display for RP {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.mbox, self.hostname)
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

    use super::RP;

    test_rdata!(
        rdata,
        "./tests/pcap/rp.pcap",
        false,
        1,
        RData::RP,
        (|x: &RP, _| {
            assert_eq!(
                &x.to_string(),
                "jschauma.netmeister.org. contact.netmeister.org."
            );
        })
    );
}
