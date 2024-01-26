use std::fmt;

use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

use crate::{buffer::Buffer, new_rd_length};

// https://datatracker.ietf.org/doc/html/rfc8659
//-------------------------------------------------------------------------------------
// CAA
//-------------------------------------------------------------------------------------

// +0-1-2-3-4-5-6-7-|0-1-2-3-4-5-6-7-|
// | Flags          | Tag Length = n |
// +----------------+----------------+...+---------------+
// | Tag char 0     | Tag char 1     |...| Tag char n-1  |
// +----------------+----------------+...+---------------+
// +----------------+----------------+.....+----------------+
// | Value byte 0   | Value byte 1   |.....| Value byte m-1 |
// +----------------+----------------+.....+----------------+
#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Default, FromNetwork, Serialize)]
pub(super) struct CAA {
    // transmistted through RR deserialization
    #[serde(skip_serializing)]
    #[deser(ignore)]
    rd_length: u16,

    flags: u8,
    tag_length: u8,

    #[deser(with_code( self.tag_key = Buffer::with_capacity(self.tag_length); ))]
    tag_key: Buffer,

    #[deser(with_code( self.tag_value = Buffer::with_capacity(self.rd_length - self.tag_length as u16 - 2 ); ))]
    tag_value: Buffer,
}

// auto-implement new
new_rd_length!(CAA);

impl fmt::Display for CAA {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} \"{}\"",
            self.flags,
            self.tag_key,
            self.tag_value
        )
    }
}

use serde::Serialize;
// impl Serialize for CAA {
//     fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
//     where
//         S: Serializer,
//     {
//         let mut seq = serializer.serialize_map(Some(3))?;
//         seq.serialize_entry("flags", &self.flags)?;
//         seq.serialize_entry("tag_key", &self.tag_key.to_string())?;
//         seq.serialize_entry("tag_value", &self.tag_value.to_string())?;
//         seq.end()
//     }
// }

#[cfg(test)]
mod tests {
    use crate::{
        rfc::{rdata::RData, response::Response},
        test_rdata,
        tests::get_packets,
    };

    use type2network::FromNetworkOrder;

    use super::CAA;

    test_rdata!(
        rdata,
        "./tests/caa.pcap",
        false,
        1,
        RData::CAA,
        (|x: &CAA, i: usize| {
            match i {
                0 => assert_eq!(x.to_string(), "0 issue \";\""),
                1 => assert_eq!(x.to_string(), "0 issuewild \";\""),
                2 => assert_eq!(x.to_string(), "0 iodef \"mailto:abuse@netmeister.org\""),
                _ => panic!("data not is the pcap file"),
            }
        })
    );
}
