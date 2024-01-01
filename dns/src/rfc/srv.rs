//! Definition of the SRV record (https://datatracker.ietf.org/doc/html/rfc2782)
use std::fmt;

// use log::trace;
use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

use super::{domain::DomainName, type_bitmaps::TypeBitMaps};

use crate::new_rd_length;

// https://datatracker.ietf.org/doc/html/rfc2782
#[derive(Debug, Default, FromNetwork)]
pub struct SRV<'a> {
    priority: u16,
    weight: u16,
    port: u16,
    target: DomainName<'a>,
}

impl<'a> fmt::Display for SRV<'a> {
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
        error::DNSResult,
        rfc::{rdata::RData, response::Response},
        test_rdata,
        tests::{get_pcap_buffer, read_pcap_sample},
    };

    use type2network::FromNetworkOrder;

    use super::SRV;

    test_rdata!(
        rdata,
        "./tests/srv.pcap",
        RData::SRV,
        (|x: &SRV, _| {
            assert_eq!(&x.to_string(), "0 1 80 panix.netmeister.org.");
        })
    );
}
