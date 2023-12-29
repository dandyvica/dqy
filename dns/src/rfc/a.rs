use std::{fmt, net::Ipv4Addr};

use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

// A resource record
#[derive(Debug, Default, FromNetwork)]
pub struct A(pub(super) u32);

impl fmt::Display for A {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", Ipv4Addr::from(self.0))
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use crate::{
        error::DNSResult,
        rfc::{a::A, rdata::RData, response::Response},
        test_rdata,
        tests::{get_pcap_buffer, read_pcap_sample},
    };

    use type2network::FromNetworkOrder;

    test_rdata!(
        rdata,
        "./tests/a.pcap",
        RData::A,
        (|x: &A, _| {
            let addr = Ipv4Addr::from(x.0).to_string();
            assert_eq!(addr, "166.84.7.99");
        })
    );
}
