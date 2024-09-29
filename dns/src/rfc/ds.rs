use std::fmt;

use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

use crate::{buffer::Buffer, new_rd_length};

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
pub struct DS {
    #[from_network(ignore)]
    pub(super) rd_length: u16,

    key_tag: u16,
    algorithm: Algorithm,
    digest_type: u8,

    #[from_network(with_code( self.digest = Buffer::with_capacity(self.rd_length - 4); ))]
    pub(super) digest: Buffer,
}

// auto-implement new
new_rd_length!(DS);

impl fmt::Display for DS {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} {:?}",
            self.key_tag, self.algorithm, self.digest_type, self.digest
        )
    }
}

// Custom serialization
use serde::{ser::SerializeMap, Serialize, Serializer};
impl Serialize for DS {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_map(Some(4))?;
        seq.serialize_entry("key_tag", &self.key_tag)?;
        seq.serialize_entry("algorithm", &self.algorithm.to_string())?;
        seq.serialize_entry("digest_type", &self.digest_type)?;
        seq.serialize_entry("digest", &self.digest.to_b64())?;
        seq.end()
    }
}

#[allow(clippy::upper_case_acronyms)]
pub(super) type DLV = DS;

#[allow(clippy::upper_case_acronyms)]
pub(super) type CDS = DS;

#[cfg(test)]
mod tests {
    use crate::{
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
