use std::fmt;

use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

use crate::{databuf::BufferMut, new_rd_length};

use super::algorithm::Algorithm;

// The RDATA for a DS RR consists of a 2 octet Key Tag field, a 1 octet
// Algorithm field, a 1 octet Digest Type field, and a Digest field.
//
//                      1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |           Key Tag             |  Algorithm    |  Digest Type  |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// /                                                               /
// /                            Digest                             /
// /                                                               /
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Default, FromNetwork)]
pub struct DS<'a> {
    #[deser(ignore)]
    pub(super) rd_length: u16,

    key_tag: u16,
    algorithm: Algorithm,
    digest_type: u8,

    #[deser(with_code( self.digest = BufferMut::with_capacity(self.rd_length - 4); ))]
    pub(super) digest: BufferMut<'a>,
}

// auto-implement new
new_rd_length!(DS<'a>);

impl<'a> fmt::Display for DS<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} {:?}",
            self.key_tag, self.algorithm, self.digest_type, self.digest
        )
    }
}

#[allow(clippy::upper_case_acronyms)]
pub(super) type DLV<'a> = DS<'a>;

#[allow(clippy::upper_case_acronyms)]
pub(super) type CDS<'a> = DS<'a>;

#[cfg(test)]
mod tests {
    use crate::{
        error::DNSResult,
        rfc::{rdata::RData, response::Response},
        test_rdata,
        tests::get_packets,
    };

    use type2network::FromNetworkOrder;

    use super::DS;

    test_rdata!(
        rdata_ds,
        "./tests/ds.pcap",
        false,
        1,
        RData::DS,
        (|x: &DS, _| {
            assert_eq!(&x.to_string(), "56393 ECDSAP256SHA256 2 BD36DD608262A02683721FA19E2F7B474F531BB3179CC0A0C38FF0CA11657");
        })
    );

    test_rdata!(
        rdata_dlv,
        "./tests/dlv.pcap",
        false,
        1,
        RData::DLV,
        (|x: &DS, _| {
            assert_eq!(&x.to_string(), "56039 ECDSAP256SHA256 2 414805B43928FC573F0704A2C1B5A10BAA2878DE26B8535DDE77517C154CE9F");
        })
    );

    test_rdata!(
        rdata_cds,
        "./tests/cds.pcap",
        false,
        1,
        RData::CDS,
        (|x: &DS, _| {
            assert_eq!(&x.to_string(), "56039 ECDSAP256SHA256 2 414805B43928FC573F0704A2C1B5A10BAA2878DE26B8535DDE77517C154CE9F");
        })
    );
}
