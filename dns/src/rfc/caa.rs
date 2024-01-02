use std::fmt;

use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

use crate::{buffer::Buffer, new_rd_length, butter_mut::BufferMut};

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
#[derive(Debug, Default, FromNetwork)]
pub(super) struct CAA<'a> {
    // transmistted through RR deserialization
    #[deser(ignore)]
    rd_length: u16,

    flags: u8,
    tag_length: u8,

    #[deser(with_code( self.tag_key = BufferMut::new(self.tag_length); ))]
    tag_key: BufferMut<'a>,

    #[deser(with_code( self.tag_value = BufferMut::new(self.rd_length - self.tag_length as u16 - 2 ); ))]
    tag_value: BufferMut<'a>,
}

// auto-implement new
new_rd_length!(CAA<'a>);

impl<'a> fmt::Display for CAA<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} \"{}\"",
            self.flags,
            self.tag_key.to_string(),
            self.tag_value.to_string()
        )
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
