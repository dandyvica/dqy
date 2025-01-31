use std::fmt;

use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

use crate::{dns::buffer::Buffer, new_rd_length};

// https://datatracker.ietf.org/doc/html/rfc7553
// 1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |          Priority             |          Weight               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// /                                                               /
// /                             Target                            /
// /                                                               /
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Default, FromNetwork)]
pub struct URI {
    #[from_network(ignore)]
    rd_length: u16,

    priority: u16,
    weight: u16,

    #[from_network(with_code( self.target = Buffer::with_capacity(self.rd_length - 4); ))]
    target: Buffer,
}

// auto-implement new
new_rd_length!(URI);

impl fmt::Display for URI {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} \"{}\"",
            self.priority,
            self.weight,
            String::from_utf8_lossy(&self.target)
        )
    }
}

// Custom serialization
use serde::{ser::SerializeMap, Serialize, Serializer};
impl Serialize for URI {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_map(Some(3))?;
        seq.serialize_entry("priority", &self.priority)?;
        seq.serialize_entry("weight", &self.weight)?;
        seq.serialize_entry("target", &String::from_utf8_lossy(&self.target))?;
        seq.end()
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

    use super::URI;

    test_rdata!(
        rdata,
        "./tests/pcap/uri.pcap",
        false,
        1,
        RData::URI,
        (|x: &URI, _| {
            assert_eq!(&x.to_string(), "10 1 \"https://www.netmeister.org/blog/dns-rrs.html\"");
        })
    );
}
