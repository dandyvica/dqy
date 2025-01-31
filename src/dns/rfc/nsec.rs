use std::fmt;

// use log::trace;
use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

use serde::Serialize;

use crate::new_rd_length;

use super::{domain::DomainName, type_bitmaps::TypeBitMaps};

// 1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |   Hash Alg.   |     Flags     |          Iterations           |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  Salt Length  |                     Salt                      /
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Default, FromNetwork, Serialize)]
pub struct NSEC {
    // transmistted through RR deserialization
    #[from_network(ignore)]
    rd_length: u16,

    domain: DomainName,

    #[from_network(with_code( self.types = TypeBitMaps::new(self.rd_length - self.domain.len() as u16); ))]
    types: TypeBitMaps,
}

// auto-implement new
new_rd_length!(NSEC);

impl fmt::Display for NSEC {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.domain, self.types)
    }
}

// Custom serialization
// use serde::{ser::SerializeMap, Serialize, Serializer};
// impl Serialize for NSEC {
//     fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
//     where
//         S: Serializer,
//     {
//         let mut seq = serializer.serialize_map(Some(2))?;
//         seq.serialize_entry("domain", &self.domain)?;
//         seq.serialize_entry("protocol", &self.protocol)?;
//         seq.serialize_entry("algorithm", &self.algorithm.to_string())?;
//         seq.serialize_entry("key", &self.key.as_b64())?;
//         seq.end()
//     }
// }

#[cfg(test)]
mod tests {
    use crate::{
        dns::rfc::{rdata::RData, response::Response},
        dns::tests::get_packets,
        test_rdata,
    };

    use type2network::FromNetworkOrder;

    use super::NSEC;

    test_rdata!(
        rdata,
        "./tests/pcap/nsec.pcap",
        false,
        1,
        RData::NSEC,
        (|x: &NSEC, _| {
            assert_eq!(&x.to_string(), "nsec3.dns.netmeister.org. TXT RRSIG NSEC");
        })
    );
}
