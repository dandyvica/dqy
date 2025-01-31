use std::{fmt, net::Ipv4Addr};

use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

use serde::Serialize;

// A resource record
#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, PartialEq, FromNetwork, Serialize)]
pub struct A(pub Ipv4Addr);

impl Default for A {
    fn default() -> Self {
        Self(Ipv4Addr::UNSPECIFIED)
    }
}

impl fmt::Display for A {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use crate::{
        dns::rfc::{a::A, rdata::RData, response::Response},
        dns::tests::get_packets,
        test_rdata,
    };

    use type2network::FromNetworkOrder;

    test_rdata!(
        rdata,
        "./tests/pcap/a.pcap",
        false,
        1,
        RData::A,
        (|x: &A, _| {
            let addr = Ipv4Addr::from(x.0).to_string();
            assert_eq!(addr, "166.84.7.99");
        })
    );
}
