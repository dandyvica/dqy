//! Definition of the SRV record (https://datatracker.ietf.org/doc/html/rfc2782)
use std::fmt;

// use log::trace;
use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

use serde::Serialize;

use super::domain::DomainName;

// https://datatracker.ietf.org/doc/html/rfc2782
#[derive(Debug, Default, FromNetwork, Serialize)]
pub struct SRV {
    priority: u16,
    weight: u16,
    port: u16,
    target: DomainName,
}

impl fmt::Display for SRV {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} {}",
            self.priority, self.weight, self.port, self.target
        )?;

        Ok(())
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

    use super::SRV;

    test_rdata!(
        rdata,
        "./tests/srv.pcap",
        false,
        1,
        RData::SRV,
        (|x: &SRV, _| {
            assert_eq!(&x.to_string(), "0 1 80 panix.netmeister.org.");
        })
    );
}
