use std::fmt;

use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

use crate::{buffer::Buffer, new_rd_length};

// 1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  Cert. Usage  |   Selector    | Matching Type |               /
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               /
// /                                                               /
// /                 Certificate Association Data                  /
// /                                                               /
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[derive(Debug, Default, FromNetwork)]
pub(super) struct TLSA {
    #[deser(ignore)]
    rd_length: u16,

    cert_usage: u8,
    selector: u8,
    matching_type: u8,

    #[deser(with_code( self.data = Buffer::new(self.rd_length - 3); ))]
    data: Buffer,
}

// auto-implement new
new_rd_length!(TLSA);

impl fmt::Display for TLSA {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} {}",
            self.cert_usage, self.selector, self.matching_type, self.data
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

    use super::TLSA;

    test_rdata!(
        "./tests/tlsa.pcap",
        RData::TLSA,
        (|x: &TLSA, _| {
            assert_eq!(
                &x.to_string(),
                "3 1 1 8CE14CBE1FAFAE9FB25845D335E0E416BC2FAE02E8746689C06DA59C1F9382"
            );
        })
    );
}
