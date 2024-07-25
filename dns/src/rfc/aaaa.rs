use std::{fmt, net::Ipv6Addr};

use serde::Serialize;
use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

// AAAA resource record
#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, PartialEq, FromNetwork, Serialize)]
pub struct AAAA(pub Ipv6Addr);

impl Default for AAAA {
    fn default() -> Self {
        Self(Ipv6Addr::UNSPECIFIED)
    }
}

impl fmt::Display for AAAA {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;

    use crate::{
        rfc::{aaaa::AAAA, rdata::RData, response::Response},
        test_rdata,
        tests::get_packets,
    };

    use type2network::FromNetworkOrder;

    test_rdata!(
        rdata,
        "./tests/aaaa.pcap",
        false,
        1,
        RData::AAAA,
        (|x: &AAAA, _| {
            let addr = Ipv6Addr::from(x.0).to_string();
            assert_eq!(addr, "2001:470:30:84:e276:63ff:fe72:3900");
        })
    );
}
