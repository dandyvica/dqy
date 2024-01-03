use std::fmt;

// use log::trace;
use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

use base64::{engine::general_purpose, Engine as _};

use crate::{databuf::BufferMut, new_rd_length};

// https://datatracker.ietf.org/doc/html/rfc4701#section-3.1
#[derive(Debug, Default, FromNetwork)]
pub struct DHCID<'a> {
    // transmistted through RR deserialization
    #[deser(ignore)]
    pub(super) rd_length: u16,

    #[deser(with_code( self.data = BufferMut::with_capacity(self.rd_length); ))]
    data: BufferMut<'a>,
}

// auto-implement new
new_rd_length!(DHCID<'a>);

impl<'a> fmt::Display for DHCID<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b64 = general_purpose::STANDARD.encode(&self.data);
        write!(f, "{}", b64)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        error::DNSResult,
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
