use std::fmt;

use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

use crate::{buffer::Buffer, new_rd_length};

// https://www.rfc-editor.org/rfc/rfc8976
// 1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                             Serial                            |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |    Scheme     |Hash Algorithm |                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
// |                             Digest                            |
// /                                                               /
// /                                                               /
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[derive(Debug, Default, FromNetwork)]
pub(super) struct ZONEMD {
    #[deser(ignore)]
    rd_length: u16,

    serial: u32,
    scheme: u8,
    hash_algorithm: u8,

    #[deser(with_code( self.digest = Buffer::new(self.rd_length - 6); ))]
    digest: Buffer,
}

// auto-implement new
new_rd_length!(ZONEMD);

impl fmt::Display for ZONEMD {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} {}",
            self.serial, self.scheme, self.hash_algorithm, self.digest
        )
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

    use super::ZONEMD;

    test_rdata!(
        rdata,
        "./tests/zonemd.pcap",
        RData::ZONEMD,
        (|x: &ZONEMD, _| {
            assert_eq!(&x.to_string(), "2021071219 1 1 4274F6BC562CF8CE512B21AAA4CCC1EB9F4FAAAECD01642D0A07BDEA890C8845849D615CC590F54BAC7E87B9E41ED");
        })
    );
}
