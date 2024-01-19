use std::fmt;

use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

use serde::Serialize;

use super::domain::DomainName;

// CNAME resource record
#[derive(Debug, Default, FromNetwork, Serialize)]
pub struct CNAME(DomainName);

impl fmt::Display for CNAME {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

pub type DNAME = CNAME;

#[cfg(test)]
mod tests {
    use crate::{
        rfc::{cname::DNAME, rdata::RData, response::Response},
        test_rdata,
        tests::get_packets,
    };

    use type2network::FromNetworkOrder;

    use super::CNAME;

    test_rdata!(
        rdata_cname,
        "./tests/cname.pcap",
        false,
        1,
        RData::CNAME,
        (|x: &CNAME, _| {
            assert_eq!(x.to_string(), "cname-txt.dns.netmeister.org.");
        })
    );

    test_rdata!(
        rdata,
        "./tests/dname.pcap",
        false,
        1,
        RData::DNAME,
        (|x: &DNAME, _| {
            assert_eq!(&x.to_string(), "dns.netmeister.org.");
        })
    );
}
