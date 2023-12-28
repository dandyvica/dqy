use std::fmt;

use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

use super::domain::DomainName;

#[derive(Debug, Default, FromNetwork)]
pub(super) struct RP<'a> {
    mbox: DomainName<'a>,
    hostname: DomainName<'a>,
}

impl<'a> fmt::Display for RP<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.mbox, self.hostname)
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

    use super::RP;

    test_rdata!(
        "./tests/rp.pcap",
        RData::RP,
        (|x: &RP, _| {
            assert_eq!(
                &x.to_string(),
                "jschauma.netmeister.org. contact.netmeister.org."
            );
        })
    );
}
