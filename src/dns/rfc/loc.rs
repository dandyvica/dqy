use std::fmt;

use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

use serde::Serialize;

// LOC RR (https://datatracker.ietf.org/doc/html/rfc1876)
#[derive(Debug, Default, FromNetwork, Serialize)]
pub struct LOC {
    pub(super) version: u8,
    pub(super) size: u8,
    pub(super) horiz_pre: u8,
    pub(super) vert_pre: u8,
    pub(super) latitude1: u16,
    pub(super) latitude2: u16,
    pub(super) longitude1: u16,
    pub(super) longitude2: u16,
    pub(super) altitude1: u16,
    pub(super) altitude2: u16,
}

impl fmt::Display for LOC {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} {} {} {} {} {} {} {}",
            self.version,
            self.size,
            self.horiz_pre,
            self.vert_pre,
            self.latitude1,
            self.latitude2,
            self.longitude1,
            self.longitude2,
            self.altitude1,
            self.altitude2,
        )
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

    use super::LOC;

    test_rdata!(
        rdata,
        "./tests/pcap/loc.pcap",
        false,
        1,
        RData::LOC,
        (|x: &LOC, _| {
            assert_eq!(&x.to_string(), "0 18 22 19 35005 44968 28703 37840 152 39528");
        })
    );
}
