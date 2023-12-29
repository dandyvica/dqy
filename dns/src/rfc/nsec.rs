use std::fmt;

// use log::trace;
use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

use super::{domain::DomainName, type_bitmaps::TypeBitMaps};

// 1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |   Hash Alg.   |     Flags     |          Iterations           |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  Salt Length  |                     Salt                      /
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[derive(Debug, Default, FromNetwork)]
pub(super) struct NSEC<'a> {
    // transmistted through RR deserialization
    #[deser(ignore)]
    rd_length: u16,

    domain: DomainName<'a>,

    #[deser(with_code( self.types = TypeBitMaps::new(self.rd_length - self.domain.len() as u16); ))]
    types: TypeBitMaps,
}

// auto-implement new
//new_rd_length!(NSEC<'a>);
impl<'a> NSEC<'a> {
    pub fn new(len: u16) -> Self {
        let mut x = Self::default();
        x.rd_length = len;

        x
    }
}

impl<'a> fmt::Display for NSEC<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.domain, self.types)
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

    use super::NSEC;

    test_rdata!(
        rdata,
        "./tests/nsec.pcap",
        RData::NSEC,
        (|x: &NSEC, _| {
            assert_eq!(&x.to_string(), "nsec3.dns.netmeister.org. TXT RRSIG NSEC");
        })
    );
}
