use std::fmt;

use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

use super::domain::DomainName;

// CNAME resource record
#[derive(Debug, Default, FromNetwork)]
pub struct CNAME<'a>(DomainName<'a>);

impl<'a> fmt::Display for CNAME<'a> {
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

    use super::CNAME;

    test_rdata!(
        rdata,
        "./tests/cname.pcap",
        false,
        1,
        RData::CNAME,
        (|x: &CNAME, _| {
            assert_eq!(x.to_string(), "cname-txt.dns.netmeister.org.");
        })
    );
}
