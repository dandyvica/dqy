use std::fmt;

// use log::trace;
use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

use base64::{engine::general_purpose, Engine as _};

use crate::{buffer::Buffer, new_rd_length};

// https://datatracker.ietf.org/doc/html/rfc4701#section-3.1
#[derive(Debug, Default, FromNetwork)]
pub struct DHCID {
    // transmistted through RR deserialization
    #[deser(ignore)]
    pub(super) rd_length: u16,

    #[deser(with_code( self.data = Buffer::new(self.rd_length); ))]
    data: Buffer,
}

// auto-implement new
new_rd_length!(DHCID);

impl fmt::Display for DHCID {
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
        tests::{get_pcap_buffer, read_pcap_sample},
    };

    use type2network::FromNetworkOrder;

    use super::DHCID;

    test_rdata!(
        rdata,
        "./tests/dhcid.pcap",
        RData::DHCID,
        (|x: &DHCID, _| {
            assert_eq!(
                &x.to_string(),
                "AAIBMmFjOTc1NzMyMTk0ZWE1ZTBhN2MzN2M4MzE2NTFiM2M="
            );
        })
    );
}
