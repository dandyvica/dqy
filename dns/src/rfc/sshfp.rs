use std::fmt;

// use log::trace;
use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

use crate::{databuf::BufferMut, new_rd_length};

// https://datatracker.ietf.org/doc/html/rfc4255#section-3
// 1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |   algorithm   |    fp type    |                               /
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               /
// /                                                               /
// /                          fingerprint                          /
// /                                                               /
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[derive(Debug, Default, FromNetwork)]
pub struct SSHFP<'a> {
    // transmistted through RR deserialization
    #[deser(ignore)]
    pub(super) rd_length: u16,

    algorithm: u8,
    fp_type: u8,

    #[deser(with_code( self.fingerprint = BufferMut::with_capacity(self.rd_length - 2); ))]
    fingerprint: BufferMut<'a>,
}

// auto-implement new
new_rd_length!(SSHFP<'a>);

impl<'a> fmt::Display for SSHFP<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {:?}",
            self.algorithm, self.fp_type, self.fingerprint
        )
    }
}

// Custom serialization
use serde::{ser::SerializeMap, Serialize, Serializer};
impl<'a> Serialize for SSHFP<'a> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_map(Some(3))?;
        seq.serialize_entry("algorithm", &self.algorithm)?;
        seq.serialize_entry("fp_type", &self.fp_type)?;
        seq.serialize_entry("fingerprint", &self.fingerprint.to_string())?;
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

    use super::SSHFP;

    test_rdata!(
        rdata,
        "./tests/sshfp.pcap",
        false,
        1,
        RData::SSHFP,
        (|x: &SSHFP, i: usize| {
            match i {
                0 => assert_eq!(x.to_string(), "1 1 53A76D5284C91E14DEC9AD1A757DA123B95B081"),
                1 => assert_eq!(
                    x.to_string(),
                    "3 2 62475A22F1E4F09594206539AAFF90A6EDAABAB1BA6F4A67AB396177455CF84"
                ),
                _ => panic!("data not is the pcap file"),
            }
        })
    );
}
