use std::fmt;

// use log::trace;
use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

use serde::{Serialize, Serializer};

use crate::{buffer::Buffer, new_rd_length};

// https://datatracker.ietf.org/doc/html/rfc4701#section-3.1
#[derive(Debug, Default, FromNetwork)]
pub struct DHCID {
    // transmistted through RR deserialization
    #[deser(ignore)]
    pub(super) rd_length: u16,

    #[deser(with_code( self.data = Buffer::with_capacity(self.rd_length); ))]
    data: Buffer,
}

// auto-implement new
new_rd_length!(DHCID);

impl fmt::Display for DHCID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.data.as_b64())
    }
}

impl Serialize for DHCID {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.data.as_b64())
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

    use super::DHCID;

    test_rdata!(
        rdata,
        "./tests/dhcid.pcap",
        false,
        1,
        RData::DHCID,
        (|x: &DHCID, _| {
            assert_eq!(
                &x.to_string(),
                "AAIBMmFjOTc1NzMyMTk0ZWE1ZTBhN2MzN2M4MzE2NTFiM2M="
            );
        })
    );
}
