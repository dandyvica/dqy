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
#[derive(Debug, Default, FromNetwork)]
pub struct CSYNC {
    // transmistted through RR deserialization
    #[deser(ignore)]
    pub(super) rd_length: u16,

    soa_serial: u32,
    flags: u16,

    #[deser(with_code( self.types = TypeBitMaps::new(self.rd_length - 6); ))]
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

#[cfg(test)]
mod tests {
    use crate::{
        error::DNSResult,
        rfc::{rdata::RData, response::Response},
        test_rdata,
        tests::{get_pcap_buffer, read_pcap_sample},
    };

    use type2network::FromNetworkOrder;

    use super::CSYNC;

    test_rdata!(
        "./tests/csync.pcap",
        RData::CSYNC,
        (|x: &CSYNC, _| {
            assert_eq!(&x.to_string(), "2021071001 3 NS");
        })
    );
}
