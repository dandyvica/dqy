use std::fmt;

use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

// https://datatracker.ietf.org/doc/html/rfc7043#section-4
// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                          EUI-64 Address                       |
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[derive(Debug, Default, FromNetwork)]
pub struct EUI64(u64);

impl fmt::Display for EUI64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let buf: Vec<_> = self.0.to_be_bytes().iter().map(|c| format!("{:x?}", c)).collect();
        write!(f, "{}", buf.join("-"))
    }
}

// Custom serialization
use serde::{Serialize, Serializer};
impl Serialize for EUI64 {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        dns::rfc::{rdata::RData, response::Response},
        dns::tests::get_packets,
        test_rdata,
    };

    use type2network::FromNetworkOrder;

    use super::EUI64;

    test_rdata!(
        rdata,
        "./tests/pcap/eui64.pcap",
        false,
        1,
        RData::EUI64,
        (|x: &EUI64, _| {
            assert_eq!(&x.to_string(), "be-a2-b9-ff-fe-82-32-a7");
        })
    );
}
