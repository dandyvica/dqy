use std::fmt;

// use log::trace;
use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

use super::type_bitmaps::TypeBitMaps;

use crate::new_rd_length;

// https://www.rfc-editor.org/rfc/rfc7477.html#section-2.1
// 1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                          SOA Serial                           |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |       Flags                   |            Type Bit Map       /
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// /                     Type Bit Map (continued)                  /
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Default, FromNetwork)]
pub struct CSYNC {
    // transmistted through RR deserialization
    #[from_network(ignore)]
    pub(super) rd_length: u16,

    soa_serial: u32,
    flags: u16,

    #[from_network(with_code( self.types = TypeBitMaps::new(self.rd_length - 6); ))]
    types: TypeBitMaps,
}

// auto-implement new
new_rd_length!(CSYNC);

impl fmt::Display for CSYNC {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {}", self.soa_serial, self.flags, self.types)?;

        Ok(())
    }
}

// Custom serialization
use serde::{ser::SerializeMap, Serialize, Serializer};
impl Serialize for CSYNC {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_map(Some(3))?;
        seq.serialize_entry("soa_serial", &self.soa_serial)?;
        seq.serialize_entry("flags", &self.flags)?;
        seq.serialize_entry("types", &self.types.to_string())?;
        seq.end()
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

    use super::CSYNC;

    test_rdata!(
        rdata,
        "./tests/csync.pcap",
        false,
        1,
        RData::CSYNC,
        (|x: &CSYNC, _| {
            assert_eq!(&x.to_string(), "2021071001 3 NS");
        })
    );
}
