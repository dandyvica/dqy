use std::fmt;

use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

// AAAA resource record
#[derive(Debug, Default, FromNetwork)]
pub struct AAAA([u8; 16]);

impl fmt::Display for AAAA {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", std::net::Ipv6Addr::from(self.0))
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;

    use crate::{
        error::DNSResult,
        rfc::{aaaa::AAAA, rdata::RData, response::Response},
        test_rdata,
        tests::{get_pcap_buffer, read_pcap_sample},
    };

    use type2network::FromNetworkOrder;

    test_rdata!(
        "./tests/aaaa.pcap",
        RData::AAAA,
        (|x: &AAAA, _| {
            let addr = Ipv6Addr::from(x.0).to_string();
            assert_eq!(addr, "2001:470:30:84:e276:63ff:fe72:3900");
        })
    );
}
